/// Normalizer: reads FileOpenedEvents from the eBPF ring buffer,
/// applies deduplication and path filtering, and forwards to the Event Bus
/// as length-prefixed protobuf messages.

use aya::maps::RingBuf;
use kernel_layer_common::FileOpenedEvent;
use log::{debug, info, warn};
use prost::Message as _;
use std::{
    collections::HashMap,
    io::Write,
    os::unix::net::UnixStream,
    time::{Duration, Instant},
};
use uuid::Uuid;

/// Paths that are never interesting.
const BLOCKED_PREFIXES: &[&str] = &[
    "/proc/",
    "/sys/",
    "/dev/",
    "/run/",
    "/tmp/",
    "/usr/lib/",
    "/usr/lib64/",
    "/usr/share/",
    "/usr/bin/",
    "/usr/sbin/",
    "/lib/",
    "/lib64/",
];

/// Deduplication window.
const DEDUP_WINDOW: Duration = Duration::from_millis(100);

struct DedupEntry {
    last_seen: Instant,
}

// Include generated protobuf types.
mod proto {
    include!(concat!(env!("OUT_DIR"), "/lunaris.eventbus.rs"));
}

/// Run the normalizer loop. Blocks until the ring buffer is dropped.
pub fn run(mut ring_buf: RingBuf<&'static mut aya::maps::MapData>, producer_socket: &str, session_id: &str) {
    let mut dedup: HashMap<(u32, String), DedupEntry> = HashMap::new();
    let mut stream: Option<UnixStream> = None;

    info!("normalizer started, forwarding to {}", producer_socket);

    loop {
        while let Some(item) = ring_buf.next() {
            let event = match bytemuck_event(&item) {
                Some(e) => e,
                None => continue,
            };

            let path = match path_from_event(event) {
                Some(p) => p,
                None => continue,
            };

            if is_blocked(&path) {
                continue;
            }

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

            if dedup.len() > 10_000 {
                dedup.retain(|_, v| now.duration_since(v.last_seen) < DEDUP_WINDOW * 10);
            }

            debug!("file.opened pid={} path={}", event.pid, path);

            // Encode and forward to Event Bus.
            if let Some(msg) = encode_event(event, &path, session_id) {
                if let Err(e) = send_with_reconnect(&mut stream, producer_socket, &msg) {
                    warn!("failed to send event to Event Bus: {e}");
                }
            }
        }

        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Encode a FileOpenedEvent as a length-prefixed protobuf Event message.
///
/// The payload field contains an encoded `FileOpenedPayload` protobuf so that
/// downstream consumers (knowledge promotion) can decode it with
/// `FileOpenedPayload::decode(payload)`.
fn encode_event(event: &FileOpenedEvent, path: &str, session_id: &str) -> Option<Vec<u8>> {
    let file_payload = proto::FileOpenedPayload {
        path: path.to_string(),
        app_id: format!("ebpf:{}", event.pid),
        flags: 0,
    };

    let proto_event = proto::Event {
        id: Uuid::now_v7().to_string(),
        r#type: "file.opened".to_string(),
        timestamp: event.timestamp_ns as i64,
        source: "ebpf".to_string(),
        pid: event.pid,
        session_id: session_id.to_string(),
        payload: file_payload.encode_to_vec(),
    };

    let encoded = proto_event.encode_to_vec();
    let len = u32::try_from(encoded.len()).ok()?;
    let mut out = Vec::with_capacity(4 + encoded.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&encoded);
    Some(out)
}

/// Send bytes to the Event Bus, reconnecting once if the connection is broken.
fn send_with_reconnect(
    stream: &mut Option<UnixStream>,
    socket_path: &str,
    msg: &[u8],
) -> Result<(), std::io::Error> {
    for attempt in 0..2u8 {
        if stream.is_none() {
            match UnixStream::connect(socket_path) {
                Ok(s) => {
                    info!("connected to Event Bus at {}", socket_path);
                    *stream = Some(s);
                }
                Err(e) => {
                    if attempt == 0 {
                        warn!("Event Bus not available, will retry: {e}");
                        std::thread::sleep(Duration::from_secs(1));
                        continue;
                    }
                    return Err(e);
                }
            }
        }

        match stream.as_mut().unwrap().write_all(msg) {
            Ok(()) => return Ok(()),
            Err(e) => {
                *stream = None;
                if attempt == 1 {
                    return Err(e);
                }
            }
        }
    }
    Ok(())
}

fn path_from_event(event: &FileOpenedEvent) -> Option<String> {
    let end = event.path.iter().position(|&b| b == 0).unwrap_or(event.path.len());
    let bytes = &event.path[..end];
    std::str::from_utf8(bytes).ok().map(|s| s.to_string())
}

fn is_blocked(path: &str) -> bool {
    BLOCKED_PREFIXES.iter().any(|prefix| path.starts_with(prefix))
}

fn bytemuck_event(bytes: &[u8]) -> Option<&FileOpenedEvent> {
    if bytes.len() < std::mem::size_of::<FileOpenedEvent>() {
        warn!("ring buffer item too small: {} bytes", bytes.len());
        return None;
    }
    Some(unsafe { &*(bytes.as_ptr() as *const FileOpenedEvent) })
}
