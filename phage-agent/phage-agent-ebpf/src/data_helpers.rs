use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid},
};
#[inline(always)]
pub fn get_process_info() -> Result<(u32, [u8; 16]), i32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    if let Ok(comm) = bpf_get_current_comm() {
        Ok((pid, comm))
    } else {
        Err(-1)
    }
}