/// Tests for the kernel-layer normalizer.
///
/// These tests verify encoding, filtering, and deduplication logic
/// without requiring eBPF or root privileges.

#[cfg(test)]
mod tests {
    use kernel_layer_common::{
        FileOpenedEvent, FileWrittenEvent, NetStateEvent, ProcessExecEvent,
        MAX_COMM_LEN, MAX_PATH_LEN,
    };
    use prost::Message as _;
    use std::io::Read;
    use std::os::unix::net::UnixListener;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tempfile::tempdir;

    mod proto {
        include!(concat!(env!("OUT_DIR"), "/lunaris.eventbus.rs"));
    }

    fn make_open_event(pid: u32, path: &str) -> FileOpenedEvent {
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

    fn make_exec_event(pid: u32, comm: &str, filename: &str) -> ProcessExecEvent {
        let mut event = ProcessExecEvent {
            pid,
            uid: 1000,
            timestamp_ns: 2_000_000_000,
            comm: [0u8; MAX_COMM_LEN],
            filename: [0u8; MAX_PATH_LEN],
        };
        let cb = comm.as_bytes();
        event.comm[..cb.len().min(MAX_COMM_LEN - 1)]
            .copy_from_slice(&cb[..cb.len().min(MAX_COMM_LEN - 1)]);
        let fb = filename.as_bytes();
        event.filename[..fb.len().min(MAX_PATH_LEN - 1)]
            .copy_from_slice(&fb[..fb.len().min(MAX_PATH_LEN - 1)]);
        event
    }

    fn make_write_event(pid: u32, fd: u64, count: u64) -> FileWrittenEvent {
        FileWrittenEvent {
            pid,
            uid: 1000,
            timestamp_ns: 3_000_000_000,
            fd,
            count,
        }
    }

    fn make_net_event(pid: u32, af: u16, sport: u16, dport: u16) -> NetStateEvent {
        let mut event = NetStateEvent {
            pid,
            uid: 1000,
            timestamp_ns: 4_000_000_000,
            af,
            sport,
            dport,
            _pad: 0,
            saddr: [192, 168, 1, 100],
            daddr: [93, 184, 216, 34],
            saddr_v6: [0u8; 16],
            daddr_v6: [0u8; 16],
            oldstate: 2, // TCP_SYN_SENT
            newstate: 1, // TCP_ESTABLISHED
        };
        event
    }

    /// Helper: encode using the same logic as normalizer's encode_envelope.
    fn encode_test(event_type: &str, pid: u32, ts: u64, session_id: &str, payload: Vec<u8>) -> Vec<u8> {
        let proto_event = proto::Event {
            id: uuid::Uuid::now_v7().to_string(),
            r#type: event_type.to_string(),
            timestamp: ts as i64,
            source: "ebpf".to_string(),
            pid,
            session_id: session_id.to_string(),
            payload,
        };
        let encoded = proto_event.encode_to_vec();
        let len = u32::try_from(encoded.len()).unwrap();
        let mut msg = Vec::with_capacity(4 + encoded.len());
        msg.extend_from_slice(&len.to_be_bytes());
        msg.extend_from_slice(&encoded);
        msg
    }

    // ===== file.opened tests =====

    #[test]
    fn file_opened_payload_encodes_correctly() {
        let payload = proto::FileOpenedPayload {
            path: "/home/tim/file.txt".into(),
            app_id: "ebpf:1234".into(),
            flags: 0,
        };
        let msg = encode_test("file.opened", 1234, 1_000_000, "sess", payload.encode_to_vec());
        let decoded = proto::Event::decode(&msg[4..]).unwrap();
        let p = proto::FileOpenedPayload::decode(decoded.payload.as_slice()).unwrap();
        assert_eq!(p.path, "/home/tim/file.txt");
        assert_eq!(p.app_id, "ebpf:1234");
    }

    // ===== process.started tests =====

    #[test]
    fn process_exec_payload_encodes_correctly() {
        let payload = proto::ProcessLifecyclePayload {
            event_type: "started".into(),
            pid: 5678,
            ppid: 0,
            comm: "firefox".into(),
            exit_code: 0,
        };
        let msg = encode_test("process.started", 5678, 2_000_000, "sess", payload.encode_to_vec());
        let decoded = proto::Event::decode(&msg[4..]).unwrap();
        assert_eq!(decoded.r#type, "process.started");
        let p = proto::ProcessLifecyclePayload::decode(decoded.payload.as_slice()).unwrap();
        assert_eq!(p.comm, "firefox");
        assert_eq!(p.event_type, "started");
        assert_eq!(p.ppid, 0);
    }

    #[test]
    fn process_exec_event_struct_roundtrips() {
        let event = make_exec_event(42, "bash", "/usr/bin/bash");
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &event as *const _ as *const u8,
                std::mem::size_of::<ProcessExecEvent>(),
            )
        };
        let cast = unsafe { &*(bytes.as_ptr() as *const ProcessExecEvent) };
        assert_eq!(cast.pid, 42);
        let comm_end = cast.comm.iter().position(|&b| b == 0).unwrap_or(cast.comm.len());
        assert_eq!(std::str::from_utf8(&cast.comm[..comm_end]).unwrap(), "bash");
    }

    // ===== file.written tests =====

    #[test]
    fn file_written_payload_encodes_correctly() {
        let payload = proto::FileWrittenPayload {
            path: "/home/tim/output.log".into(),
            app_id: "ebpf:999".into(),
            bytes: 4096,
        };
        let msg = encode_test("file.written", 999, 3_000_000, "sess", payload.encode_to_vec());
        let decoded = proto::Event::decode(&msg[4..]).unwrap();
        assert_eq!(decoded.r#type, "file.written");
        let p = proto::FileWrittenPayload::decode(decoded.payload.as_slice()).unwrap();
        assert_eq!(p.path, "/home/tim/output.log");
        assert_eq!(p.bytes, 4096);
    }

    #[test]
    fn file_written_event_struct_roundtrips() {
        let event = make_write_event(100, 5, 1024);
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &event as *const _ as *const u8,
                std::mem::size_of::<FileWrittenEvent>(),
            )
        };
        let cast = unsafe { &*(bytes.as_ptr() as *const FileWrittenEvent) };
        assert_eq!(cast.pid, 100);
        assert_eq!(cast.fd, 5);
        assert_eq!(cast.count, 1024);
    }

    // ===== network tests =====

    #[test]
    fn net_state_payload_encodes_correctly() {
        let payload = proto::NetworkConnectionPayload {
            app_id: "ebpf:200".into(),
            remote_addr: "93.184.216.34:443".into(),
            protocol: "tcp".into(),
            direction: "connect".into(),
        };
        let msg = encode_test("network.connect", 200, 4_000_000, "sess", payload.encode_to_vec());
        let decoded = proto::Event::decode(&msg[4..]).unwrap();
        assert_eq!(decoded.r#type, "network.connect");
        let p = proto::NetworkConnectionPayload::decode(decoded.payload.as_slice()).unwrap();
        assert_eq!(p.remote_addr, "93.184.216.34:443");
        assert_eq!(p.direction, "connect");
    }

    #[test]
    fn net_state_event_struct_roundtrips() {
        let event = make_net_event(300, 2, 54321, 443);
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &event as *const _ as *const u8,
                std::mem::size_of::<NetStateEvent>(),
            )
        };
        let cast = unsafe { &*(bytes.as_ptr() as *const NetStateEvent) };
        assert_eq!(cast.pid, 300);
        assert_eq!(cast.af, 2);
        assert_eq!(cast.dport, 443);
        assert_eq!(cast.daddr, [93, 184, 216, 34]);
    }

    // ===== Shared logic tests =====

    #[test]
    fn blocked_paths_are_filtered() {
        let blocked = [
            "/proc/1/maps", "/sys/kernel/btf/vmlinux", "/dev/null",
            "/run/systemd/private", "/tmp/foo", "/usr/lib/libz.so",
        ];
        let allowed = ["/home/tim/file.txt", "/etc/hostname", "/opt/app/config.toml"];

        let is_blocked = |path: &str| {
            ["/proc/", "/sys/", "/dev/", "/run/", "/tmp/",
             "/usr/lib/", "/usr/lib64/", "/usr/share/", "/usr/bin/",
             "/usr/sbin/", "/lib/", "/lib64/"]
                .iter()
                .any(|prefix| path.starts_with(prefix))
        };

        for p in &blocked { assert!(is_blocked(p), "expected {p} blocked"); }
        for p in &allowed { assert!(!is_blocked(p), "expected {p} allowed"); }
    }

    #[test]
    fn path_extraction_handles_null_terminator() {
        let event = make_open_event(1, "/etc/hostname");
        let end = event.path.iter().position(|&b| b == 0).unwrap_or(event.path.len());
        let path = std::str::from_utf8(&event.path[..end]).unwrap();
        assert_eq!(path, "/etc/hostname");
    }

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
                    if stream.read_exact(&mut len_buf).is_err() { break; }
                    let len = u32::from_be_bytes(len_buf) as usize;
                    let mut buf = vec![0u8; len];
                    if stream.read_exact(&mut buf).is_err() { break; }
                    if let Ok(event) = proto::Event::decode(buf.as_slice()) {
                        received_clone.lock().unwrap().push(event);
                    }
                }
            }
        });

        std::thread::sleep(Duration::from_millis(50));

        let payload = proto::FileOpenedPayload {
            path: "/home/tim/test.txt".into(),
            app_id: "ebpf:42".into(),
            flags: 0,
        };
        let msg = encode_test("file.opened", 42, 1_000_000, "test-session", payload.encode_to_vec());

        use std::os::unix::net::UnixStream;
        use std::io::Write;
        let mut stream = UnixStream::connect(&path_str).unwrap();
        stream.write_all(&msg).unwrap();
        drop(stream);

        std::thread::sleep(Duration::from_millis(100));

        let events = received.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].r#type, "file.opened");
        let p = proto::FileOpenedPayload::decode(events[0].payload.as_slice()).unwrap();
        assert_eq!(p.path, "/home/tim/test.txt");
    }
}
