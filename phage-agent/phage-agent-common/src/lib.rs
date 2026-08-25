#![no_std]

use core::str;
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ExecveData {
    pub filename: [u8; 256],
    pub filename_len: u32,
    pub args: [u8; 256],
    pub args_len: u32,
}

impl ExecveData {
    pub fn filename_bytes(&self) -> &[u8] {
        let len = (self.filename_len as usize).min(self.filename.len());
        &self.filename[..len]
    }

    pub fn args_bytes(&self) -> &[u8] {
        let len = (self.args_len as usize).min(self.args.len());
        &self.args[..len]
    }

    pub fn filename_str(&self) -> &str {
        str::from_utf8(self.filename_bytes()).unwrap_or("<invalid utf8>")
    }

    pub fn args_str(&self) -> &str {
        str::from_utf8(self.args_bytes()).unwrap_or("<invalid utf8>")
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OpenatData {
    pub filename: [u8; 256],
    pub filename_len: u32,
    pub flags: u32, // O_CREAT and friends
}
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct UnlinkatData {
    pub filename: [u8; 256],
    pub filename_len: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ConnectData {
    pub ip: [u8; 16], // IPv4 and IPv6
    pub port: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CommonHeader {
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
}

impl CommonHeader {
    pub fn comm_bytes(&self) -> &[u8] {
        let len = self.comm.iter().position(|&b| b == 0).unwrap_or(self.comm.len());
        &self.comm[..len]
    }
    pub fn comm_str(&self) -> &str {
        str::from_utf8(self.comm_bytes()).unwrap_or("<invalid utf8>")
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub enum EventPayload {
    Execve(ExecveData),
    Openat(OpenatData),
    Unlinkat(UnlinkatData),
    Connect(ConnectData),
}

impl EventPayload{

    pub fn filename_bytes(&self) -> Option<&[u8]> {
        match self {
            &EventPayload::Execve(ref execve) => {
                let len = (execve.filename_len as usize).min(execve.filename.len());
                Some(&execve.filename[..len])
            }
            &EventPayload::Openat(ref openat) => {
                let len = (openat.filename_len as usize).min(openat.filename.len());
                Some(&openat.filename[..len])
            }
            &EventPayload::Unlinkat(ref unlinkat) => {
                let len = (unlinkat.filename_len as usize).min(unlinkat.filename.len());
                Some(&unlinkat.filename[..len])
            }
            _ => None
        }

    }

    pub fn filename_str(&self) -> Option<&str> {
        let bytes = self.filename_bytes()?;
        Some(str::from_utf8(bytes).unwrap_or("<invalid utf8>"))
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SyscallEvent {
    pub header: CommonHeader,
    pub payload: EventPayload,
}

/// Creates a zero-initialized [`EventPayload`].
///
/// Traditional `new()` constructor passing `[u8;256]` by value would duplicate
/// the buffer on the stack, which bloats the stack by creating 256 bytes for arguments + 256 bytes for struct.
/// But Linux provides only 512 bytes of kernel stack limit for eBPF and ignoring this issue might provoke `stack limit exceeded`.
///
/// So this zeroed structure must be populated through mutable references.
impl EventPayload {
    pub const fn empty_execve() -> Self {
        EventPayload::Execve(ExecveData {
            filename: [0; 256],
            filename_len: 0,
            args: [0; 256],
            args_len: 0,
        })
    }
    pub const fn empty_openat() -> Self {
        EventPayload::Openat(OpenatData {
            filename: [0; 256],
            filename_len: 0,
            flags: 0,
        })
    }
    pub const fn empty_unlinkat() -> Self {
        EventPayload::Unlinkat(UnlinkatData {
            filename: [0; 256],
            filename_len: 0,
        })
    }
    pub const fn empty_connect() -> Self {
        EventPayload::Connect(ConnectData {
            ip: [0; 16],
            port: 0,
        })
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SyscallEvent {}