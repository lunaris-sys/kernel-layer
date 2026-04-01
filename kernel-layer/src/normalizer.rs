/// Normalizer: reads events from multiple eBPF ring buffers,
/// applies deduplication and filtering, and forwards to the Event Bus
/// as length-prefixed protobuf messages.

use aya::maps::RingBuf;
use kernel_layer_common::{
    FileOpenedEvent, FileWrittenEvent, NetStateEvent, ProcessExecEvent, MAX_PATH_LEN,
};
use log::{debug, info, warn};
use prost::Message as _;
use std::{
    collections::HashMap,
    io::Write,
    os::unix::net::UnixStream,
    time::{Duration, Instant},
};
use uuid::Uuid;

const BLOCKED_PREFIXES: &[&str] = &[
    "/proc/", "/sys/", "/dev/", "/run/", "/tmp/",
    "/usr/lib/", "/usr/lib64/", "/usr/share/", "/usr/bin/",
    "/usr/sbin/", "/lib/", "/lib64/",
];

const DEDUP_WINDOW_OPEN: Duration = Duration::from_millis(100);
const DEDUP_WINDOW_WRITE: Duration = Duration::from_millis(500);
const DEDUP_WINDOW_EXEC: Duration = Duration::from_secs(1);
const DEDUP_WINDOW_NET: Duration = Duration::from_secs(1);

struct DedupEntry {
    last_seen: Instant,
}

mod proto {
    include!(concat!(env!("OUT_DIR"), "/lunaris.eventbus.rs"));
}

/// Run the normalizer loop. Blocks until the ring buffers are dropped.
pub fn run<T: std::borrow::Borrow<aya::maps::MapData>>(
    mut ring_open: RingBuf<T>,
    mut ring_exec: RingBuf<T>,
    mut ring_write: RingBuf<T>,
    mut ring_net: RingBuf<T>,
    producer_socket: &str,
    session_id: &str,
) {
    let mut dedup_open: HashMap<(u32, String), DedupEntry> = HashMap::new();
    let mut dedup_write: HashMap<(u32, u64), DedupEntry> = HashMap::new();
    let mut dedup_exec: HashMap<(u32, String), DedupEntry> = HashMap::new();
    let mut dedup_net: HashMap<(u32, u16, u16), DedupEntry> = HashMap::new();
    let mut stream: Option<UnixStream> = None;

    info!("normalizer started, forwarding to {}", producer_socket);

    loop {
        let mut had_event = false;

        // --- file.opened ---
        while let Some(item) = ring_open.next() {
            had_event = true;
            if let Some(msg) = handle_file_opened(&item, session_id, &mut dedup_open) {
                send(&mut stream, producer_socket, &msg);
            }
        }

        // --- process.started ---
        while let Some(item) = ring_exec.next() {
            had_event = true;
            if let Some(msg) = handle_process_exec(&item, session_id, &mut dedup_exec) {
                send(&mut stream, producer_socket, &msg);
            }
        }

        // --- file.written ---
        while let Some(item) = ring_write.next() {
            had_event = true;
            if let Some(msg) = handle_file_written(&item, session_id, &mut dedup_write) {
                send(&mut stream, producer_socket, &msg);
            }
        }

        // --- network ---
        while let Some(item) = ring_net.next() {
            had_event = true;
            if let Some(msg) = handle_net_state(&item, session_id, &mut dedup_net) {
                send(&mut stream, producer_socket, &msg);
            }
        }

        if !had_event {
            std::thread::sleep(Duration::from_millis(1));
        }

        // Periodic dedup cleanup
        cleanup_dedup(&mut dedup_open, DEDUP_WINDOW_OPEN * 10);
        cleanup_dedup(&mut dedup_write, DEDUP_WINDOW_WRITE * 10);
        cleanup_dedup(&mut dedup_exec, DEDUP_WINDOW_EXEC * 10);
        cleanup_dedup_net(&mut dedup_net, DEDUP_WINDOW_NET * 10);
    }
}

fn cleanup_dedup<K: std::hash::Hash + Eq>(map: &mut HashMap<K, DedupEntry>, max_age: Duration) {
    if map.len() > 10_000 {
        let now = Instant::now();
        map.retain(|_, v| now.duration_since(v.last_seen) < max_age);
    }
}

fn cleanup_dedup_net(map: &mut HashMap<(u32, u16, u16), DedupEntry>, max_age: Duration) {
    if map.len() > 10_000 {
        let now = Instant::now();
        map.retain(|_, v| now.duration_since(v.last_seen) < max_age);
    }
}

// ===== file.opened handler =====

fn handle_file_opened(
    item: &[u8],
    session_id: &str,
    dedup: &mut HashMap<(u32, String), DedupEntry>,
) -> Option<Vec<u8>> {
    let event = bytemuck_cast::<FileOpenedEvent>(item)?;
    let path = extract_string(&event.path)?;

    if is_blocked(&path) {
        return None;
    }
    if !dedup_check(dedup, (event.pid, path.clone()), DEDUP_WINDOW_OPEN) {
        return None;
    }

    debug!("file.opened pid={} path={}", event.pid, path);

    let payload = proto::FileOpenedPayload {
        path: path.clone(),
        app_id: format!("ebpf:{}", event.pid),
        flags: 0,
    };
    encode_envelope("file.opened", event.pid, event.timestamp_ns, session_id, payload.encode_to_vec())
}

// ===== process.started handler =====

fn handle_process_exec(
    item: &[u8],
    session_id: &str,
    dedup: &mut HashMap<(u32, String), DedupEntry>,
) -> Option<Vec<u8>> {
    let event = bytemuck_cast::<ProcessExecEvent>(item)?;
    let filename = extract_string(&event.filename).unwrap_or_default();
    let comm = extract_string(&event.comm).unwrap_or_default();

    if !dedup_check(dedup, (event.pid, filename.clone()), DEDUP_WINDOW_EXEC) {
        return None;
    }

    debug!("process.started pid={} comm={} filename={}", event.pid, comm, filename);

    let payload = proto::ProcessLifecyclePayload {
        event_type: "started".into(),
        pid: event.pid,
        ppid: 0,
        comm,
        exit_code: 0,
    };
    encode_envelope("process.started", event.pid, event.timestamp_ns, session_id, payload.encode_to_vec())
}

// ===== file.written handler =====

fn handle_file_written(
    item: &[u8],
    session_id: &str,
    dedup: &mut HashMap<(u32, u64), DedupEntry>,
) -> Option<Vec<u8>> {
    let event = bytemuck_cast::<FileWrittenEvent>(item)?;

    if !dedup_check(dedup, (event.pid, event.fd), DEDUP_WINDOW_WRITE) {
        return None;
    }

    // Resolve fd to path via /proc. Falls back to fd:N if the process is gone.
    let path = resolve_fd(event.pid, event.fd);

    if is_blocked(&path) {
        return None;
    }

    debug!("file.written pid={} fd={} path={} bytes={}", event.pid, event.fd, path, event.count);

    let payload = proto::FileWrittenPayload {
        path,
        app_id: format!("ebpf:{}", event.pid),
        bytes: event.count,
    };
    encode_envelope("file.written", event.pid, event.timestamp_ns, session_id, payload.encode_to_vec())
}

/// Resolve a file descriptor to a path via /proc/pid/fd/N.
fn resolve_fd(pid: u32, fd: u64) -> String {
    let link = format!("/proc/{pid}/fd/{fd}");
    std::fs::read_link(&link)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| format!("fd:{fd}"))
}

// ===== network handler =====

fn handle_net_state(
    item: &[u8],
    session_id: &str,
    dedup: &mut HashMap<(u32, u16, u16), DedupEntry>,
) -> Option<Vec<u8>> {
    let event = bytemuck_cast::<NetStateEvent>(item)?;

    if !dedup_check(dedup, (event.pid, event.dport, event.sport), DEDUP_WINDOW_NET) {
        return None;
    }

    let (remote_addr, direction) = format_net_event(event);

    debug!("network.{direction} pid={} remote={remote_addr}", event.pid);

    let payload = proto::NetworkConnectionPayload {
        app_id: format!("ebpf:{}", event.pid),
        remote_addr,
        protocol: "tcp".into(),
        direction,
    };

    let event_type = format!("network.{}", payload.direction);
    encode_envelope(&event_type, event.pid, event.timestamp_ns, session_id, payload.encode_to_vec())
}

fn format_net_event(event: &NetStateEvent) -> (String, String) {
    // Determine direction: if sport is a well-known port (< 1024), it's likely inbound.
    // Otherwise outbound. This is a heuristic.
    let direction = if event.sport < 1024 { "accept" } else { "connect" };

    let remote = if event.af == 2 {
        // IPv4
        let d = &event.daddr;
        format!("{}:{}", format_ipv4(d), event.dport)
    } else {
        // IPv6
        format!("[{}]:{}", format_ipv6(&event.daddr_v6), event.dport)
    };

    (remote, direction.into())
}

fn format_ipv4(addr: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
}

fn format_ipv6(addr: &[u8; 16]) -> String {
    let words: Vec<String> = (0..8)
        .map(|i| {
            let hi = addr[i * 2] as u16;
            let lo = addr[i * 2 + 1] as u16;
            format!("{:x}", (hi << 8) | lo)
        })
        .collect();
    words.join(":")
}

// ===== Shared helpers =====

fn dedup_check<K: std::hash::Hash + Eq + Clone>(
    map: &mut HashMap<K, DedupEntry>,
    key: K,
    window: Duration,
) -> bool {
    let now = Instant::now();
    if let Some(entry) = map.get_mut(&key) {
        if now.duration_since(entry.last_seen) < window {
            return false;
        }
        entry.last_seen = now;
    } else {
        map.insert(key, DedupEntry { last_seen: now });
    }
    true
}

fn bytemuck_cast<T: Copy>(bytes: &[u8]) -> Option<&T> {
    if bytes.len() < std::mem::size_of::<T>() {
        warn!("ring buffer item too small: {} bytes (expected {})", bytes.len(), std::mem::size_of::<T>());
        return None;
    }
    Some(unsafe { &*(bytes.as_ptr() as *const T) })
}

fn extract_string(buf: &[u8]) -> Option<String> {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let s = std::str::from_utf8(&buf[..end]).ok()?.to_string();
    if s.is_empty() { None } else { Some(s) }
}

fn is_blocked(path: &str) -> bool {
    BLOCKED_PREFIXES.iter().any(|prefix| path.starts_with(prefix))
}

fn encode_envelope(
    event_type: &str,
    pid: u32,
    timestamp_ns: u64,
    session_id: &str,
    payload: Vec<u8>,
) -> Option<Vec<u8>> {
    let proto_event = proto::Event {
        id: Uuid::now_v7().to_string(),
        r#type: event_type.to_string(),
        timestamp: timestamp_ns as i64,
        source: "ebpf".to_string(),
        pid,
        session_id: session_id.to_string(),
        payload,
    };

    let encoded = proto_event.encode_to_vec();
    let len = u32::try_from(encoded.len()).ok()?;
    let mut out = Vec::with_capacity(4 + encoded.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&encoded);
    Some(out)
}

fn send(stream: &mut Option<UnixStream>, socket_path: &str, msg: &[u8]) {
    if let Err(e) = send_with_reconnect(stream, socket_path, msg) {
        warn!("failed to send event to Event Bus: {e}");
    }
}

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
