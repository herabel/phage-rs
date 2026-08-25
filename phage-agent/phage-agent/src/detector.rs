use phage_agent_common::{EventPayload, SyscallEvent};

pub enum Decision {
    Allow,
    Deny { reason: &'static str },
}

pub fn evaluate(mut event: SyscallEvent) -> Decision {
    if let EventPayload::Execve(ref mut exec) = event.payload {
        let path  = exec.filename_str();
        let _args = exec.args_bytes();

        let comm = event.header.comm_str();

        let let_is_web_server = comm.starts_with("nginx")
            || comm.starts_with("apache")
            || comm.starts_with("caddy")
            || event.header.uid == 33 // debian/ubuntu
            || event.header.uid == 48 // rhel/centos
            || event.header.uid == 65534 // nobody
            || event.header.uid == 99; // nobody, but arch/rhel
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
    }


    Decision::Allow
}