#![no_std]
#![no_main]

use aya_ebpf::{macros::btf_tracepoint, programs::BtfTracePointContext};
use aya_log_ebpf::info;

#[btf_tracepoint(function = "sys_enter_execve")]
pub fn sys_enter_execve(ctx: BtfTracePointContext) -> i32 {
    match try_sys_enter_execve(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_execve(ctx: BtfTracePointContext) -> Result<i32, i32> {
    info!(&ctx, "tracepoint sys_enter_execve called");
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"AGPLv3.0";
