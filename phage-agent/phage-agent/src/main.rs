mod hasher;
mod cache;

#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;
use crate::cache::{FileCache};




#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

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
        ("sys_enter_write", "syscalls", "sys_enter_write"),
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

    let ring_buf = aya::maps::RingBuf::try_from(
        ebpf.take_map("RING_BUF").ok_or_else(|| anyhow::anyhow!("RING_BUF not found"))?
    )?;
    let mut async_ring_buf = tokio::io::unix::AsyncFd::new(ring_buf)?;
    tokio::task::spawn(async move {
        let mut cache = FileCache::new(10_000);
        loop {
            let mut guard = match async_ring_buf.readable_mut().await {
                Ok(guard) => guard,
                Err(e) => {
                    eprintln!("Error waiting on ringbuf: {e}");
                    break;
                }
            };
            let ring_buf = guard.get_inner_mut();
            let start = std::time::Instant::now();
            while let Some(item) = ring_buf.next() {
                let event = unsafe { &*(item.as_ptr() as *const phage_agent_common::SyscallEvent) };
                let path_str = std::str::from_utf8(event.filename_bytes()).unwrap_or("<invalid utf8>");
                let path = std::path::Path::new(path_str);

                let start = std::time::Instant::now();
                if let Ok((file_hash, is_hit)) = FileCache::get_or_hash(&mut cache, path){
                    let elapsed = start.elapsed();
                    let hex_hash = blake3::Hash::from_bytes(file_hash).to_hex();
                    let tag = if is_hit { "🟢 [CACHE HIT]" } else { "🔴 [CACHE MISS]" };
                    println!(
                        "{} PID: {} | ELP: {:>6?} | UID: {} | Syscall: {} | Path: {} | blake3: {}",
                        tag, event.pid, elapsed, event.uid, event.syscall_id, path_str, hex_hash
                    );
                }
            }
            guard.clear_ready();
        }
    });

    println!("All targets attached. Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    println!("Exiting...");

    Ok(())
}
