/// Normalizer: reads FileOpenedEvents from the eBPF ring buffer,
/// applies deduplication and path filtering, and forwards to the Event Bus.

use aya::maps::RingBuf;
use kernel_layer_common::FileOpenedEvent;
use log::{debug, warn};
use std::{
    collections::HashMap,
    io::Write,
    os::unix::net::UnixStream,
    time::{Duration, Instant},
};

/// Paths that are never interesting. We discard events for files under these prefixes.
const BLOCKED_PREFIXES: &[&str] = &[
    "/proc/",
    "/sys/",
    "/dev/",
    "/run/",
    "/tmp/",
    "/usr/lib/",
    "/usr/share/",
    "/usr/bin/",
    "/usr/sbin/",
    "/lib/",
    "/lib64/",
];

/// Deduplication window: if the same (pid, path) pair is seen within this
/// duration, the second event is dropped.
const DEDUP_WINDOW: Duration = Duration::from_millis(100);

/// Entry in the deduplication table.
struct DedupEntry {
    last_seen: Instant,
}

/// Run the normalizer loop. Blocks until the ring buffer is dropped.
pub fn run(mut ring_buf: RingBuf<&mut aya::maps::MapData>, producer_socket: &str) {
    let mut dedup: HashMap<(u32, String), DedupEntry> = HashMap::new();
    let mut stream: Option<UnixStream> = None;

    loop {
        // Poll the ring buffer for new events.
        // RingBuf::next() returns None when the buffer is empty.
        while let Some(item) = ring_buf.next() {
            let event = match bytemuck_event(&item) {
                Some(e) => e,
                None => continue,
            };

            let path = match path_from_event(event) {
                Some(p) => p,
                None => continue,
            };

            // Path filter: drop uninteresting paths.
            if is_blocked(&path) {
                continue;
            }

            // Deduplication: drop if same (pid, path) seen recently.
            let key = (event.pid, path.clone());
            let now = Instant::now();
            if let Some(entry) = dedup.get_mut(&key) {
                if now.duration_since(entry.last_seen) < DEDUP_WINDOW {
                    debug!("dedup: dropping duplicate event for {path}");
                    continue;
                }
                entry.last_seen = now;
            } else {
                dedup.insert(key.clone(), DedupEntry { last_seen: now });
            }

            // Evict stale dedup entries periodically to prevent unbounded growth.
            if dedup.len() > 10_000 {
                dedup.retain(|_, v| now.duration_since(v.last_seen) < DEDUP_WINDOW * 10);
            }

            debug!("file.opened pid={} path={}", event.pid, path);

            // Forward to Event Bus.
            // TODO Phase 2A: encode as protobuf Event and send to producer socket.
            // For now we log to verify the pipeline works end-to-end.
            let _ = &stream; // suppress unused warning until protobuf encoding is added
        }

        // Sleep briefly to avoid busy-polling the ring buffer.
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Extract a UTF-8 path string from a FileOpenedEvent.
fn path_from_event(event: &FileOpenedEvent) -> Option<String> {
    // Find the null terminator.
    let end = event.path.iter().position(|&b| b == 0).unwrap_or(event.path.len());
    let bytes = &event.path[..end];
    std::str::from_utf8(bytes).ok().map(|s| s.to_string())
}

/// Check if a path starts with any blocked prefix.
fn is_blocked(path: &str) -> bool {
    BLOCKED_PREFIXES.iter().any(|prefix| path.starts_with(prefix))
}

/// Reinterpret the raw ring buffer bytes as a FileOpenedEvent.
/// Returns None if the size does not match.
fn bytemuck_event(bytes: &[u8]) -> Option<&FileOpenedEvent> {
    if bytes.len() < std::mem::size_of::<FileOpenedEvent>() {
        warn!("ring buffer item too small: {} bytes", bytes.len());
        return None;
    }
    // Safety: FileOpenedEvent is #[repr(C)] with no padding issues for this read.
    // We verify the size above.
    Some(unsafe { &*(bytes.as_ptr() as *const FileOpenedEvent) })
}
