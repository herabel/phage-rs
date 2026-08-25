mod hasher;
mod cache;
mod detector;
mod scanner;

#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;
use crate::cache::{FileCache};
use aya::maps::Array;
use phage_agent_common::EventPayload;
use std::env::args;

pub const CACHE_PATH: &str = "/var/cache/phage_cache.bin";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let args = args().collect::<Vec<_>>();

    if args.get(1).map(|s| s.as_str()) == Some("scan") {
        let mut cache = FileCache::new_or_load(CACHE_PATH, 150_000);
        let directory = args.get(2).map(|s| s.as_str()).unwrap_or(".");
        let output = scanner::scan_directory(&args, directory, &mut cache).await?;
        println!(
            "[SCAN COMPLETE] Scanned: {} | Cached: {} | Elapsed: {:?} | Threats: {}",
            output.files_scanned, output.cache_hits, output.elapsed, output.threats
        );
        cache.save_to_file(CACHE_PATH)?;
        return Ok(());
    }

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/phage-agent"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    let targets = vec![
        ("sys_enter_execve", "syscalls", "sys_enter_execve"),
        ("sys_enter_openat", "syscalls", "sys_enter_openat"),
        ("sys_enter_unlinkat", "syscalls", "sys_enter_unlinkat"),
        ("sys_enter_connect", "syscalls", "sys_enter_connect"),
        ("sys_enter_bind", "syscalls", "sys_enter_bind"),
        ("sys_enter_accept", "syscalls", "sys_enter_accept"),
        ("sys_enter_init_module", "syscalls", "sys_enter_init_module"),
        ("sys_enter_finit_module", "syscalls", "sys_enter_finit_module"),
        ("sys_enter_chmod", "syscalls", "sys_enter_chmod"),
        ("sys_enter_fchmodat", "syscalls", "sys_enter_fchmodat"),
    ];

    for (prog_name, category, syscall_name) in targets {
        let program: &mut aya::programs::TracePoint = ebpf
            .program_mut(prog_name)
            .ok_or_else(|| anyhow::anyhow!("Program '{}' not found in BPF binary", prog_name))?
            .try_into()?;

        program.load()?;
        program.attach(category, syscall_name)?;
        println!("Successfully attached tracepoint: {}", syscall_name);
    }

    let mut self_pid_map: Array<_, u32> = Array::try_from(ebpf.map_mut("SELF_PID").expect("SELF_PID map not found"))?;
    let current_pid = std::process::id();
    self_pid_map.set(0, current_pid, 0)?;
    println!("Registered Agent Self-PID: {} in kernel map", current_pid);

    let ring_buf = aya::maps::RingBuf::try_from(
        ebpf.take_map("RING_BUF").ok_or_else(|| anyhow::anyhow!("RING_BUF not found"))?
    )?;
    let mut async_ring_buf = tokio::io::unix::AsyncFd::new(ring_buf)?;
    let mut cache = FileCache::new_or_load(CACHE_PATH, 150_000);
    println!("All targets attached. Waiting for Ctrl-C...");

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                println!("\nExiting and saving cache...");
                let _ = cache.save_to_file(CACHE_PATH);
                break;
            },

            _guard_res = async_ring_buf.readable_mut() => {
                let mut guard = match async_ring_buf.readable_mut().await {
                    Ok(guard) => guard,
                    Err(e) => {
                        eprintln!("Error waiting on ringbuf: {e}");
                        break;
                    }
                };
                let ring_buf = guard.get_inner_mut();
                while let Some(item) = ring_buf.next() {
                    let event = unsafe { &*(item.as_ptr() as *const phage_agent_common::SyscallEvent) };

                    let start = std::time::Instant::now();

                    match event.payload {
                        EventPayload::Execve(ref exec) => {
                            let args_str = exec.args_str();
                            let path_str = exec.filename_str();
                            let path = std::path::Path::new(path_str);

                            match detector::evaluate(*event) {
                                detector::Decision::Deny {reason} => {
                                    unsafe {
                                        libc::kill(event.header.pid as i32, libc::SIGKILL);
                                    }
                                    let elapsed = start.elapsed();
                                    println!("🔴🔴🔴 [THREAT DETECTED & KILLED in {:>6?}] PID: {} | File: {} | Reason: {} 🔴🔴🔴",
                                             elapsed, event.header.pid, path_str, reason );
                                }
                                detector::Decision::Allow => {
                                    if let Ok((file_hash, is_hit)) = FileCache::get_or_hash(&mut cache, path){
                                        let elapsed = start.elapsed();
                                        let hex_hash = blake3::Hash::from_bytes(file_hash).to_hex();
                                        let tag = if is_hit { "🟢 [CACHE HIT]" } else { "🔴 [CACHE MISS]" };
                                        println!(
                                            "{} PID: {} | ELP: {:>6?} | UID: {} | Syscall: execve (59) | Path: {} | Args: {} | blake3: {}",
                                            tag, event.header.pid, elapsed, event.header.uid, path_str, args_str, hex_hash
                                        );
                                    }
                                }
                            }
                        }
                        EventPayload::Openat(openat) => {
                            let comm_str = event.header.comm_str();
                            if let Some(path_str) = event.payload.filename_str(){
                                match detector::evaluate(*event) {
                                    detector::Decision::Deny {reason} => {
                                        unsafe {
                                            libc::kill(event.header.pid as i32, libc::SIGKILL);
                                        }
                                        let elapsed = start.elapsed();
                                        println!("🔴🔴🔴 [THREAT DETECTED & KILLED in {:>6?}] PID: {} | File: {} | Reason: {} 🔴🔴🔴",
                                                 elapsed, event.header.pid, path_str, reason );
                                    }
                                    detector::Decision::Allow => {
                                        if let Some(filename_str) = event.payload.filename_str() {
                                            println!("📝 [FILE WRITE] PID: {} | UID: {} | Syscall: openat (1) | Path: {} | Process: {}", event.header.pid, event.header.uid, filename_str, comm_str);
                                        };
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                guard.clear_ready();
            }
        }
    }

    Ok(())
}
