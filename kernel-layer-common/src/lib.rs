//! Types shared between the eBPF kernel program and the user-space daemon.
//!
//! This crate must remain `#![no_std]` compatible because it is compiled
//! into the eBPF program which runs in kernel context without the standard
//! library. User-space code can enable the `user` feature to get additional
//! trait implementations that require `std`.

#![no_std]

/// Maximum length of a file path stored in a `FileOpenedEvent`.
/// Longer paths are truncated. 256 bytes covers most practical paths.
pub const MAX_PATH_LEN: usize = 256;

/// An event emitted when a file is opened via the `openat` syscall.
///
/// Written by the eBPF tracepoint program into the ring buffer.
/// Read by the user-space daemon and forwarded to the Event Bus.
///
/// Must be `#[repr(C)]` so the layout is identical in kernel and user-space.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileOpenedEvent {
    /// Process ID of the calling process.
    pub pid: u32,
    /// User ID of the calling process.
    pub uid: u32,
    /// Monotonic timestamp in nanoseconds (from bpf_ktime_get_ns).
    pub timestamp_ns: u64,
    /// Return value of openat: file descriptor on success, negative errno on failure.
    pub ret: i64,
    /// Null-terminated file path, truncated to MAX_PATH_LEN bytes.
    pub path: [u8; MAX_PATH_LEN],
}

// Safety: FileOpenedEvent is a plain C struct with no pointers.
// It is safe to send across threads in user-space.
#[cfg(feature = "user")]
unsafe impl Send for FileOpenedEvent {}

/// Maximum length of a process comm field (Linux TASK_COMM_LEN).
pub const MAX_COMM_LEN: usize = 16;

/// An event emitted when a process calls execve.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessExecEvent {
    pub pid: u32,
    pub uid: u32,
    pub timestamp_ns: u64,
    pub comm: [u8; MAX_COMM_LEN],
    pub filename: [u8; MAX_PATH_LEN],
}

#[cfg(feature = "user")]
unsafe impl Send for ProcessExecEvent {}

/// An event emitted when a process writes to a file descriptor.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileWrittenEvent {
    pub pid: u32,
    pub uid: u32,
    pub timestamp_ns: u64,
    pub fd: u64,
    pub count: u64,
}

#[cfg(feature = "user")]
unsafe impl Send for FileWrittenEvent {}

/// Maximum length of an IP address stored as a string.
pub const MAX_ADDR_LEN: usize = 46;

/// An event emitted on a TCP state transition to ESTABLISHED.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetStateEvent {
    pub pid: u32,
    pub uid: u32,
    pub timestamp_ns: u64,
    pub af: u16,       // AF_INET=2, AF_INET6=10
    pub sport: u16,
    pub dport: u16,
    pub _pad: u16,
    pub saddr: [u8; 4],
    pub daddr: [u8; 4],
    pub saddr_v6: [u8; 16],
    pub daddr_v6: [u8; 16],
    pub oldstate: u32,
    pub newstate: u32,
}

#[cfg(feature = "user")]
unsafe impl Send for NetStateEvent {}
