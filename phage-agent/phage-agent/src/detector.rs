use phage_agent_common::SyscallEvent;

pub enum Decision {
    Allow,
    Deny { reason: &'static str },
}

pub fn evaluate(event: &SyscallEvent) -> Decision {
    let path  = event.filename_str();
    let _args = event.args_bytes();

    let comm_end = event.comm.iter().position(|&c| c == 0).unwrap_or(event.comm.len());
    let comm = std::str::from_utf8(&event.comm[..comm_end]).unwrap_or("<invalid utf8>");

    let let_is_web_server = comm.starts_with("nginx")
        || comm.starts_with("apache")
        || comm.starts_with("caddy")
        || event.uid == 33 // debian/ubuntu
        || event.uid == 48 // rhel/centos
        || event.uid == 65534 // nobody
        || event.uid == 99; // nobody, but arch/rhel
    let is_shell = path.ends_with("/sh") || path.ends_with("/bash") || path.ends_with("/dash");
    if let_is_web_server && is_shell {
        return Decision::Deny{
            reason: "Web Server spawned shell (Webshell attack | MITRE ATT&CK: T1505.003 / T1190)",
        };
    }

    if path.starts_with("/dev/shm/")
        || path.starts_with("/tmp/")
        || path.starts_with("/var/tmp/")
        || path.starts_with("memfd:")
        || path.starts_with("/proc/self/fd/"){
        return Decision::Deny{
            reason: "Executable launched from shared memory (In-memory payload | MITRE ATT&CK: T1027.004 / T1564.001)"
        }
    }

    Decision::Allow
}