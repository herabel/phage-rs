#![no_std]
#![no_main]

use aya_ebpf::{
    macros::tracepoint,
    programs::TracePointContext,
    maps::RingBuf,
};
use aya_ebpf::helpers::bpf_probe_read_user_str_bytes;
use aya_ebpf::macros::map;
use aya_log_ebpf::info;
use phage_agent_common::SyscallEvent;

mod data_helpers;

#[map]
static RING_BUF: RingBuf = RingBuf::with_byte_size(256 * 1024, 0); // 256KB ring buffer

// Files
//////////////////////////////////////////////////////////////////////////

#[tracepoint(category = "syscalls", name = "sys_enter_execve")]
pub fn sys_enter_execve(ctx: TracePointContext) -> i32 {
    try_sys_enter_execve(ctx).unwrap_or_else(|ret| ret)
}

fn try_sys_enter_execve(ctx: TracePointContext) -> Result<i32, i32> {
    let (pid, comm) = data_helpers::get_process_info().unwrap_or((0, [0u8; 16]));

    if let Ok(filename_ptr) = unsafe { ctx.read_at::<*const u8>(16) } {
        let syscall_id: u32 = unsafe { ctx.read_at::<i32>(8)? as u32 };
        let args_pointer = unsafe { ctx.read_at::<*const *const u8>(24)? };
        if let Some(mut entry) = RING_BUF.reserve::<SyscallEvent>(0) {
            let event = entry.as_mut_ptr();
            unsafe {
                (*event).pid = pid;
                (*event).uid = aya_ebpf::helpers::bpf_get_current_uid_gid() as u32;
                (*event).syscall_id = syscall_id;
                (*event).comm = comm;
                (*event).args_len = 0;


                if let Ok(path_bytes) = bpf_probe_read_user_str_bytes(
                    filename_ptr, &mut (*event).filename
                ) {
                    (*event).filename_len = path_bytes.len() as u32;

                    let arg1_ptr: *const u8 = unsafe {
                        aya_ebpf::helpers::bpf_probe_read_user(args_pointer.add(1)).unwrap_or(core::ptr::null())
                    };

                    if !arg1_ptr.is_null() {
                        if let Ok(args_bytes) = unsafe {
                            bpf_probe_read_user_str_bytes(arg1_ptr, &mut (*event).args)
                        } {
                            (*event).args_len = args_bytes.len() as u32;
                        }
                    }
                    entry.submit(0);
                } else {
                    entry.discard(0);
                }
            }
        }
    }

    Ok(0)
}

#[tracepoint(category = "syscalls", name = "sys_enter_write")]
pub fn sys_enter_write(ctx: TracePointContext) -> i32 {
    try_sys_enter_write(ctx).unwrap_or_else(|ret| ret)
}

fn try_sys_enter_write(ctx: TracePointContext) -> Result<i32, i32> {
    let (pid, comm) = data_helpers::get_process_info().unwrap_or((0, [0u8;16]));
    let mut len = 0;
    while len < comm.len() && comm[len] != 0 {
        len += 1;
    }

    let clean_bytes = &comm[..len];

    let comm_str = unsafe { core::str::from_utf8_unchecked(clean_bytes) };
    if !data_helpers::is_blacklisted(comm_str) { info!(&ctx, "PID: {}, Write Action from: {}", pid, comm_str); }
    Ok(0)
}

#[tracepoint(category = "syscalls", name = "sys_enter_openat")]
pub fn sys_enter_openat(ctx: TracePointContext) -> i32 {
    try_sys_enter_openat(ctx).unwrap_or_else(|ret| ret)
}

fn try_sys_enter_openat(ctx: TracePointContext) -> Result<i32, i32> {
    let (pid, comm) = data_helpers::get_process_info().unwrap_or((0, [0u8; 16]));

    let mut len = 0;
    while len < comm.len() && comm[len] != 0 {
        len += 1;
    }
    let comm_str = unsafe { core::str::from_utf8_unchecked(&comm[..len]) };

    if let Ok(filename_ptr) = unsafe { ctx.read_at::<*const u8>(24) } {
        let mut path_buf = [0u8; 128];

        if let Ok(path_bytes) = unsafe { bpf_probe_read_user_str_bytes(filename_ptr, &mut path_buf) } {
            let path_str = unsafe { core::str::from_utf8_unchecked(path_bytes) };

            if !data_helpers::is_blacklisted(comm_str) {
                info!(&ctx, "PID: {}, Open: {}, File: {}", pid, comm_str, path_str);
            }
        }
    }
    Ok(0)
}

#[tracepoint(category = "syscalls", name = "sys_enter_unlinkat")]
pub fn sys_enter_unlinkat(ctx: TracePointContext) -> i32 {
    try_sys_enter_unlinkat(ctx).unwrap_or_else(|ret| ret)
}

fn try_sys_enter_unlinkat(ctx: TracePointContext) -> Result<i32, i32> {
    let (pid, comm) = data_helpers::get_process_info().unwrap_or((0, [0u8; 16]));

    let mut len = 0;
    while len < comm.len() && comm[len] != 0 {
        len += 1;
    }
    let comm_str = unsafe { core::str::from_utf8_unchecked(&comm[..len]) };

    if let Ok(filename_ptr) = unsafe { ctx.read_at::<*const u8>(24) } {
        let mut path_buf = [0u8; 128];

        if let Ok(path_bytes) = unsafe { bpf_probe_read_user_str_bytes(filename_ptr, &mut path_buf) } {
            let path_str = unsafe { core::str::from_utf8_unchecked(path_bytes) };

            if !data_helpers::is_blacklisted(comm_str) {
                info!(&ctx, "PID: {}, Unlink: {}, Path: {}", pid, comm_str, path_str);
            }
        }
    }
    Ok(0)
}

// Network
//////////////////////////////////////////////////////////////////////////
#[tracepoint(category = "syscalls", name = "sys_enter_connect")]
pub fn sys_enter_connect(ctx: TracePointContext) -> i32 {
    try_sys_enter_connect(ctx).unwrap_or_else(|ret| ret)
}

fn try_sys_enter_connect(ctx: TracePointContext) -> Result<i32, i32> {
    let (pid, comm) = data_helpers::get_process_info().unwrap_or((0, [0u8; 16]));

    let mut len = 0;
    while len < comm.len() && comm[len] != 0 {
        len += 1;
    }
    let comm_str = unsafe { core::str::from_utf8_unchecked(&comm[..len]) };

    if !data_helpers::is_blacklisted(comm_str) {
        info!(&ctx, "PID: {}, Connection event from: {}", pid, comm_str);
    }
    Ok(0)
}

#[tracepoint(category = "syscalls", name = "sys_enter_bind")]
pub fn sys_enter_bind(ctx: TracePointContext) -> i32 {
    try_sys_enter_bind(ctx).unwrap_or_else(|ret| ret)
}

fn try_sys_enter_bind(ctx: TracePointContext) -> Result<i32, i32> {
    let (pid, comm) = data_helpers::get_process_info().unwrap_or((0, [0u8; 16]));

    let mut len = 0;
    while len < comm.len() && comm[len] != 0 {
        len += 1;
    }
    let comm_str = unsafe { core::str::from_utf8_unchecked(&comm[..len]) };

    if !data_helpers::is_blacklisted(comm_str) {
        info!(&ctx, "PID: {}, Bind event from: {}", pid, comm_str);
    }
    Ok(0)
}

#[tracepoint(category = "syscalls", name = "sys_enter_accept")]
pub fn sys_enter_accept(ctx: TracePointContext) -> i32 {
    try_sys_enter_accept(ctx).unwrap_or_else(|ret| ret)
}

fn try_sys_enter_accept(ctx: TracePointContext) -> Result<i32, i32> {
    let (pid, comm) = data_helpers::get_process_info().unwrap_or((0, [0u8; 16]));

    let mut len = 0;
    while len < comm.len() && comm[len] != 0 {
        len += 1;
    }
    let comm_str = unsafe { core::str::from_utf8_unchecked(&comm[..len]) };

    if !data_helpers::is_blacklisted(comm_str) {
        info!(&ctx, "PID: {}, Accept connection event from: {}", pid, comm_str);
    }

    Ok(0)
}

// Dangerous
//////////////////////////////////////////////////////////////////////////

#[tracepoint(category = "syscalls", name = "sys_enter_init_module")]
pub fn sys_enter_init_module(ctx: TracePointContext) -> i32 {
    try_sys_enter_init_module(ctx).unwrap_or_else(|ret| ret)
}

fn try_sys_enter_init_module(ctx: TracePointContext) -> Result<i32, i32> {
    let (pid, comm) = data_helpers::get_process_info().unwrap_or((0, [0u8; 16]));
    let mut len = 0;
    while len < comm.len() && comm[len] != 0 {
        len += 1;
    }
    let comm_str = unsafe { core::str::from_utf8_unchecked(&comm[..len]) };
    if !data_helpers::is_blacklisted(comm_str) {
        info!(&ctx, "ALERT: Kernel Module Load (sys_enter_init_module) from PID: {}, Process: {}", pid, comm_str);
    }
    Ok(0)
}

#[tracepoint(category = "syscalls", name = "sys_enter_finit_module")]
pub fn sys_enter_finit_module(ctx: TracePointContext) -> i32 {
    try_sys_enter_finit_module(ctx).unwrap_or_else(|ret| ret)
}

fn try_sys_enter_finit_module(ctx: TracePointContext) -> Result<i32, i32> {
    let (pid, comm) = data_helpers::get_process_info().unwrap_or((0, [0u8; 16]));
    let mut len = 0;
    while len < comm.len() && comm[len] != 0 {
        len += 1;
    }
    let comm_str = unsafe { core::str::from_utf8_unchecked(&comm[..len]) };
    if !data_helpers::is_blacklisted(comm_str) {
        info!(&ctx, "\nALERT: Kernel Module Load (sys_enter_init_module) from PID: {}, Process: {}\n", pid, comm_str);
    }
    Ok(0)
}

#[tracepoint(category = "syscalls", name = "sys_enter_chmod")]
pub fn sys_enter_chmod(ctx: TracePointContext) -> i32 {
    try_sys_enter_chmod(ctx).unwrap_or_else(|ret| ret)
}

fn try_sys_enter_chmod(ctx: TracePointContext) -> Result<i32, i32> {
    let (pid, comm) = data_helpers::get_process_info().unwrap_or((0, [0u8; 16]));

    let mut len = 0;
    while len < comm.len() && comm[len] != 0 {
        len += 1;
    }
    let comm_str = unsafe { core::str::from_utf8_unchecked(&comm[..len]) };

    if let Ok(filename_ptr) = unsafe { ctx.read_at::<*const u8>(16) } {
        let mut path_buf = [0u8; 128];

        if let Ok(path_bytes) = unsafe { bpf_probe_read_user_str_bytes(filename_ptr, &mut path_buf) } {
            let path_str = unsafe { core::str::from_utf8_unchecked(path_bytes) };

            if !data_helpers::is_blacklisted(comm_str) {
                info!(&ctx, "PID: {}, Chmod: {}, File: {}", pid, comm_str, path_str);
            }
        }
    }
    Ok(0)
}

#[tracepoint(category = "syscalls", name = "sys_enter_fchmodat")]
pub fn sys_enter_fchmodat(ctx: TracePointContext) -> i32 {
    try_sys_enter_fchmodat(ctx).unwrap_or_else(|ret| ret)
}

fn try_sys_enter_fchmodat(ctx: TracePointContext) -> Result<i32, i32> {
    let (pid, comm) = data_helpers::get_process_info().unwrap_or((0, [0u8; 16]));

    let mut len = 0;
    while len < comm.len() && comm[len] != 0 {
        len += 1;
    }
    let comm_str = unsafe { core::str::from_utf8_unchecked(&comm[..len]) };

    if let Ok(filename_ptr) = unsafe { ctx.read_at::<*const u8>(24) } {
        let mut path_buf = [0u8; 128];

        if let Ok(path_bytes) = unsafe { bpf_probe_read_user_str_bytes(filename_ptr, &mut path_buf) } {
            let path_str = unsafe { core::str::from_utf8_unchecked(path_bytes) };

            if !data_helpers::is_blacklisted(comm_str) {
                info!(&ctx, "PID: {}, Chmod: {}, File: {}", pid, comm_str, path_str);
            }
        }
    }
    Ok(0)
}

#[cfg(target_arch = "bpf")] // for building project directly on host architecture
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 4] = *b"GPL\0";
