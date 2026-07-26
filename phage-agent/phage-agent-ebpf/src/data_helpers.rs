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

#[inline(always)]
pub fn is_blacklisted(string: &str) -> bool {
    match string {
        "phage-agent"
        | "sudo"
        | "sshd"
        | "avahi-daemon"
        | "plymouthd"
        | "systemd-oomd"
        | "systemd-journal"
        | "rtkit-daemon"
        | "DefaultDispatch"
        | "tr"
        | "cat"
        | "locale"
        | "locale-check"
        | "jspawnhelper"
        | "ps"
        | "JVMResponsivene"  => return true,
        _ => {}
    }

    if string.starts_with("Flush:Tcp")
        || string.starts_with("tokio-")
        || string.starts_with("Scheduler for")
        || string.starts_with("atcher-worker")
        || string.starts_with("tcher-worker")
        || string.starts_with("remote-dev-")
    {
        return true;
    }
    return false
}