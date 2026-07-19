#![no_std]
#![no_main]
use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid},
    macros::tracepoint,
    programs::TracePointContext,
};
use aya_log_ebpf::info;
mod data_helpers;


#[tracepoint(category = "syscalls", name = "sys_enter_execve")]
pub fn sys_enter_execve(ctx: TracePointContext) -> i32 {
    try_sys_enter_execve(ctx).unwrap_or_else(|ret| ret)
}

fn try_sys_enter_execve(ctx: TracePointContext) -> Result<i32, i32> {
    let (pid, comm) = data_helpers::get_process_info().unwrap_or((0, [0u8;16]));
    let mut len = 0;
    while len < comm.len() && comm[len] != 0 {
        len += 1;
    }

    let clean_bytes = &comm[..len];

    let comm_str = unsafe { core::str::from_utf8_unchecked(clean_bytes) };
    info!(&ctx, "PID: {}, Executed: {}", pid, comm_str);
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
    if comm_str != "tokio-rt-worker"
        && comm_str != "tokio-runtime-w"
        && comm_str != "sshd"
        && comm_str != "DefaultDispatch"
        && comm_str != "sudo"
        && !comm_str.starts_with("Flush:Tcp")
    {
        info!(&ctx, "PID: {}, Write Action from: {}", pid, comm_str);
    }
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 9] = *b"AGPLv3.0\0";
