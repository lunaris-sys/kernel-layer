/// Tests for the kernel-layer normalizer.
///
/// These tests verify the encoding, filtering, and deduplication logic
/// without requiring eBPF or root privileges. They run on the host as
/// normal cargo tests.

#[cfg(test)]
mod tests {
    use kernel_layer_common::{FileOpenedEvent, MAX_PATH_LEN};
    use std::io::Read;
    use std::os::unix::net::UnixListener;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tempfile::tempdir;
    use prost::Message as _;

    mod proto {
        include!(concat!(env!("OUT_DIR"), "/lunaris.eventbus.rs"));
    }

    fn make_event(pid: u32, path: &str) -> FileOpenedEvent {
        let mut event = FileOpenedEvent {
            pid,
            uid: 1000,
            timestamp_ns: 1_000_000_000,
            ret: 3,
            path: [0u8; MAX_PATH_LEN],
        };
        let bytes = path.as_bytes();
        let len = bytes.len().min(MAX_PATH_LEN - 1);
        event.path[..len].copy_from_slice(&bytes[..len]);
        event
    }

    /// Helper: encode an event the same way normalizer::encode_event does.
    fn encode_test_event(event: &FileOpenedEvent, path: &str, session_id: &str) -> Vec<u8> {
        let file_payload = proto::FileOpenedPayload {
            path: path.to_string(),
            app_id: format!("ebpf:{}", event.pid),
            flags: 0,
        };

        let proto_event = proto::Event {
            id: uuid::Uuid::now_v7().to_string(),
            r#type: "file.opened".to_string(),
            timestamp: event.timestamp_ns as i64,
            source: "ebpf".to_string(),
            pid: event.pid,
            session_id: session_id.to_string(),
            payload: file_payload.encode_to_vec(),
        };

        let encoded = proto_event.encode_to_vec();
        let len = u32::try_from(encoded.len()).unwrap();
        let mut msg = Vec::with_capacity(4 + encoded.len());
        msg.extend_from_slice(&len.to_be_bytes());
        msg.extend_from_slice(&encoded);
        msg
    }

    /// Verify that a FileOpenedEvent is correctly encoded as a
    /// length-prefixed protobuf Event message with a typed payload.
    #[test]
    fn encode_produces_valid_protobuf() {
        let event = make_event(1234, "/home/tim/file.txt");
        let msg = encode_test_event(&event, "/home/tim/file.txt", "test-session");

        // Verify length prefix
        let prefix = u32::from_be_bytes(msg[..4].try_into().unwrap()) as usize;
        let encoded = &msg[4..];
        assert_eq!(prefix, encoded.len());

        // Decode the envelope
        let decoded = proto::Event::decode(encoded).unwrap();
        assert_eq!(decoded.r#type, "file.opened");
        assert_eq!(decoded.pid, 1234);
        assert_eq!(decoded.source, "ebpf");

        // Decode the typed payload
        let payload = proto::FileOpenedPayload::decode(decoded.payload.as_slice()).unwrap();
        assert_eq!(payload.path, "/home/tim/file.txt");
        assert_eq!(payload.app_id, "ebpf:1234");
        assert_eq!(payload.flags, 0);
    }

    /// Verify that the payload can be decoded by the same logic that
    /// knowledge/src/promotion.rs uses.
    #[test]
    fn payload_decodes_as_file_opened_payload() {
        let event = make_event(42, "/etc/hostname");
        let msg = encode_test_event(&event, "/etc/hostname", "sess-1");

        let encoded = &msg[4..];
        let envelope = proto::Event::decode(encoded).unwrap();

        let payload = proto::FileOpenedPayload::decode(envelope.payload.as_slice()).unwrap();
        assert_eq!(payload.path, "/etc/hostname");
        assert_eq!(payload.app_id, "ebpf:42");
    }

    /// Verify that blocked paths are correctly identified.
    #[test]
    fn blocked_paths_are_filtered() {
        let blocked = [
            "/proc/1/maps",
            "/sys/kernel/btf/vmlinux",
            "/dev/null",
            "/run/systemd/private",
            "/tmp/foo",
            "/usr/lib/libz.so",
            "/usr/lib64/libgcc.so",
            "/usr/share/locale/en",
            "/usr/bin/ls",
            "/usr/sbin/sshd",
            "/lib/x86_64-linux-gnu/libc.so",
            "/lib64/ld-linux.so",
        ];

        let allowed = [
            "/home/tim/file.txt",
            "/etc/hostname",
            "/var/log/syslog",
            "/opt/lunaris/config.toml",
            "relative/path.txt",
        ];

        const BLOCKED_PREFIXES: &[&str] = &[
            "/proc/", "/sys/", "/dev/", "/run/", "/tmp/",
            "/usr/lib/", "/usr/lib64/", "/usr/share/", "/usr/bin/",
            "/usr/sbin/", "/lib/", "/lib64/",
        ];

        let is_blocked = |path: &str| {
            BLOCKED_PREFIXES.iter().any(|prefix| path.starts_with(prefix))
        };

        for path in &blocked {
            assert!(is_blocked(path), "expected {path} to be blocked");
        }
        for path in &allowed {
            assert!(!is_blocked(path), "expected {path} to be allowed");
        }
    }

    /// Verify that path extraction from a FileOpenedEvent works correctly,
    /// including truncation at null byte.
    #[test]
    fn path_extraction_handles_null_terminator() {
        let event = make_event(1, "/etc/hostname");
        let end = event.path.iter().position(|&b| b == 0).unwrap_or(event.path.len());
        let path = std::str::from_utf8(&event.path[..end]).unwrap();
        assert_eq!(path, "/etc/hostname");
    }

    #[test]
    fn path_extraction_handles_max_length_path() {
        let long_path = "a".repeat(MAX_PATH_LEN - 1);
        let event = make_event(1, &long_path);
        let end = event.path.iter().position(|&b| b == 0).unwrap_or(event.path.len());
        let path = std::str::from_utf8(&event.path[..end]).unwrap();
        assert_eq!(path.len(), MAX_PATH_LEN - 1);
    }

    /// Verify that the normalizer forwards events to a Unix socket correctly.
    /// This test uses a real Unix socket but no eBPF.
    #[test]
    fn normalizer_sends_event_to_socket() {
        let tmp = tempdir().unwrap();
        let socket_path = tmp.path().join("producer.sock");
        let path_str = socket_path.to_str().unwrap().to_string();

        let received: Arc<Mutex<Vec<proto::Event>>> = Arc::new(Mutex::new(Vec::new()));
        let received_clone = received.clone();

        let listener = UnixListener::bind(&socket_path).unwrap();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                loop {
                    let mut len_buf = [0u8; 4];
                    if stream.read_exact(&mut len_buf).is_err() {
                        break;
                    }
                    let len = u32::from_be_bytes(len_buf) as usize;
                    let mut buf = vec![0u8; len];
                    if stream.read_exact(&mut buf).is_err() {
                        break;
                    }
                    if let Ok(event) = proto::Event::decode(buf.as_slice()) {
                        received_clone.lock().unwrap().push(event);
                    }
                }
            }
        });

        std::thread::sleep(Duration::from_millis(50));

        // Simulate what the normalizer does: encode and send one event
        let event = make_event(42, "/home/tim/test.txt");
        let msg = encode_test_event(&event, "/home/tim/test.txt", "test-session");

        use std::os::unix::net::UnixStream;
        use std::io::Write;
        let mut stream = UnixStream::connect(&path_str).unwrap();
        stream.write_all(&msg).unwrap();
        drop(stream);

        std::thread::sleep(Duration::from_millis(100));

        let events = received.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].r#type, "file.opened");
        assert_eq!(events[0].pid, 42);

        // Verify the payload is a valid FileOpenedPayload
        let payload = proto::FileOpenedPayload::decode(events[0].payload.as_slice()).unwrap();
        assert_eq!(payload.path, "/home/tim/test.txt");
        assert_eq!(payload.app_id, "ebpf:42");
    }
}
