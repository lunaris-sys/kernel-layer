#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
    helpers::{bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_user_str_bytes},
};
use aya_log_ebpf::debug;
use kernel_layer_common::{FileOpenedEvent, MAX_PATH_LEN};

/// Ring buffer shared between the eBPF program and the user-space daemon.
/// Capacity: 256KB. Each FileOpenedEvent is ~280 bytes so this holds ~900 events.
/// The user-space daemon drains this continuously; the capacity is a safety buffer.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Tracepoint attached to sys_enter_openat.
///
/// The tracepoint fires on every openat syscall entry. We read the filename
/// from user-space memory and write a FileOpenedEvent into the ring buffer.
///
/// We use the entry tracepoint (sys_enter) rather than exit (sys_exit) because
/// the filename pointer is available at entry. The return value is not yet known
/// at entry; we record 0 as a placeholder. A future improvement would attach a
/// second tracepoint to sys_exit_openat to capture the return value.
#[tracepoint]
pub fn file_opened(ctx: TracePointContext) -> u32 {
    match try_file_opened(ctx) {
        Ok(()) => 0,
        Err(_) => 0, // Never fail; just drop the event on error.
    }
}

fn try_file_opened(ctx: TracePointContext) -> Result<(), i64> {
    // sys_enter_openat tracepoint args layout:
    //   +0:  __syscall_nr (int)
    //   +8:  dfd (int)
    //   +16: filename (const char __user *)
    //   +24: flags (int)
    //   +32: mode (umode_t)
    let filename_ptr = unsafe {
        ctx.read_at::<u64>(16).map_err(|_| -1i64)? as *const u8
    };

    let uid_gid = unsafe { bpf_get_current_uid_gid() };
    let uid = (uid_gid & 0xffffffff) as u32;
    let pid = (unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() } >> 32) as u32;
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    // Reserve space in the ring buffer.
    let mut entry = EVENTS.reserve::<FileOpenedEvent>(0).ok_or(-1i64)?;

    // Write fields directly into the reserved ring buffer slot.
    // We use unsafe because we are writing into a raw memory region.
    let event = unsafe { entry.assume_init_mut() };
    event.pid = pid;
    event.uid = uid;
    event.timestamp_ns = timestamp_ns;
    event.ret = 0; // Placeholder; return value not available at entry.
    event.path = [0u8; MAX_PATH_LEN];

    // Copy the filename from user-space into the event.
    // bpf_probe_read_user_str_bytes reads a null-terminated string safely.
    unsafe {
        let _ = bpf_probe_read_user_str_bytes(
            filename_ptr,
            &mut event.path,
        );
    }

    debug!(&ctx, "openat pid={} uid={}", pid, uid);

    entry.submit(0);
    Ok(())
}

/// Required by the eBPF verifier: every eBPF program must handle panics.
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// License declaration required by the kernel for certain eBPF helper functions.
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
