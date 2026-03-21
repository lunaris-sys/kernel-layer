# kernel-layer

Lunaris kernel-layer is the eBPF-based event source for the Lunaris data pipeline. It attaches a tracepoint to `sys_enter_openat`, reads file access events from the kernel via a ring buffer, and forwards them to the Lunaris Event Bus as protobuf messages.

This is the component that gives the knowledge graph its raw data. Without kernel-layer, the graph only knows what applications explicitly report. With it, the graph sees every file access system-wide.

## How it works

```
openat() syscall in any process
    ↓  [eBPF tracepoint in kernel]
ring buffer (256KB)
    ↓  [user-space daemon reads]
normalizer (dedup, path filter, UUID assignment)
    ↓  [protobuf over Unix socket]
Event Bus → Knowledge Daemon → SQLite + Ladybug
```

The eBPF program runs in kernel context with a panic handler and a `Dual MIT/GPL` license declaration required by the kernel. The user-space daemon loads the compiled eBPF binary and bridges it to the rest of the Lunaris stack.

## Workspace structure

```
kernel-layer/           workspace root
├── kernel-layer/       user-space daemon
├── kernel-layer-ebpf/  eBPF program (compiled for bpfel-unknown-none)
└── kernel-layer-common/  shared types (FileOpenedEvent, MAX_PATH_LEN)
```

`kernel-layer-common` compiles for both targets and must stay `#![no_std]` compatible.

## Building

The eBPF program requires nightly Rust and the `bpfel-unknown-none` target:

```bash
# eBPF program
cargo +nightly build \
  -Z build-std=core \
  --target bpfel-unknown-none \
  -p kernel-layer-ebpf \
  --release

# User-space daemon
cargo build -p kernel-layer
```

## Running

Must run as root or with `CAP_BPF` + `CAP_PERFMON`.

```bash
LUNARIS_PRODUCER_SOCKET=/run/lunaris/event-bus-producer.sock \
LUNARIS_SESSION_ID=$(cat /run/lunaris/session-id) \
RUST_LOG=info \
sudo ./kernel-layer
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `LUNARIS_PRODUCER_SOCKET` | `/run/lunaris/event-bus-producer.sock` | Event Bus producer socket |
| `LUNARIS_SESSION_ID` | generated UUID v7 | Session ID attached to all events |

## Normalizer

Before forwarding to the Event Bus, every event goes through the normalizer:

- **Path filter:** drops events for `/proc/`, `/sys/`, `/dev/`, `/run/`, `/tmp/`, `/usr/lib/`, `/usr/lib64/`, `/usr/share/`, `/usr/bin/`, `/usr/sbin/`, `/lib/`, `/lib64/`
- **Deduplication:** drops identical (pid, path) pairs seen within 100ms
- **Dedup table eviction:** table is pruned when it exceeds 10k entries

## Development

eBPF programs cannot be tested on the host without risk. All development and testing happens inside a QEMU VM. See [distro/vm/](../distro/vm/) for scripts to set up the VM and start the full dev environment.

```bash
# Run all tests (no eBPF required)
cargo test -p kernel-layer

# Start full stack in VM
cd ../distro && just dev
```

## Testing

```bash
cargo test -p kernel-layer  # normalizer unit tests, no root required
```

The normalizer tests cover protobuf encoding, path filtering, path extraction from `FileOpenedEvent`, and socket forwarding. They do not test eBPF program loading, which requires root and a VM.

## Part of

[Lunaris](https://github.com/lunaris-sys) — a Linux desktop OS built around a system-wide knowledge graph.
