#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SyscallEvent {
    pub pid: u32,
    pub uid: u32,
    pub syscall_id: u32,
    pub comm: [u8; 16],        // Process name (16 bytes is a limit of Linux comm)
    pub filename: [u8; 256],   // Path
    pub filename_len: u32,
    pub args: [u8; 256],
    pub args_len: u32,
}

impl SyscallEvent {
    /// Creates a zero-initialized [`SyscallEvent`].
    ///
    /// Traditional `new()` constructor passing `[u8;256]` by value would duplicate
    /// the buffer on the stack, which bloats the stack by creating 256 bytes for arguments + 256 bytes for struct.
    /// But Linux provides only 512 bytes of kernel stack limit for eBPF and ignoring this issue might provoke `stack limit exceeded`.
    ///
    /// So this zeroed structure must be populated through mutable references.
    pub const fn zeroed() -> Self {
        SyscallEvent{
            pid: 0,
            uid: 0,
            syscall_id: 0,
            comm: [0;16],
            filename: [0;256],
            filename_len: 0,
            args: [0;256],
            args_len: 0,
        }
    }

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
#[cfg(feature = "user")]
unsafe impl aya::Pod for SyscallEvent {}