use phage_agent_common::{EventPayload, SyscallEvent};

pub enum Decision {
    Allow,
    Deny { reason: &'static str },
}

pub fn evaluate(mut event: SyscallEvent) -> Decision {
    match event.payload {
        EventPayload::Execve(ref mut exec) => {
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
        EventPayload::Openat(ref mut openat) =>
            {
                if let Some(path) = event.payload.filename_str() {
                    let comm = event.header.comm_str();
                    if path.starts_with("/etc/ld.so.preload")
                        || ( path.starts_with("/etc/shadow") && comm.starts_with("passwd") && comm.starts_with("useradd") )
                        || path.starts_with("/etc/gshadow")
                        || ( path.starts_with("/etc/sudoers") && comm.starts_with("visudo") )
                        || ( path.starts_with("/etc/cron") && !comm.starts_with("crontab") )
                        || path.starts_with("/var/spool/cron/")
                        || ( path.contains("/.ssh/id_") && comm.starts_with("ssh-keygen") ){
                        return Decision::Deny {
                            reason: "Credential Access / Hijacking (MITRE ATT&CK: T1003 | T1574)"
                        }
                    }
                }
            }
        _ => {
            return Decision::Deny{ reason: "unknown event"}
        }
    }



    Decision::Allow
}