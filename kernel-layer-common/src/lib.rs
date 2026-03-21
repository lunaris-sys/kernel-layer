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
