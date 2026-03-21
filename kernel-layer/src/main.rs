//! Lunaris kernel-layer daemon.
//!
//! Loads the eBPF program into the kernel, reads FileOpenedEvents from the
//! ring buffer, and forwards them to the Lunaris Event Bus.
//!
//! Must run as root (or with CAP_BPF + CAP_PERFMON).

use anyhow::{Context, Result};
use aya::{
    Ebpf,
    maps::RingBuf,
    programs::TracePoint,
};
use aya_log::EbpfLogger;
use kernel_layer_common::FileOpenedEvent;
use log::{debug, info, warn};
use std::ffi::CStr;
use tokio::signal;

mod normalizer;

const DEFAULT_PRODUCER_SOCKET: &str = "/run/lunaris/event-bus-producer.sock";

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let producer_socket = std::env::var("LUNARIS_PRODUCER_SOCKET")
        .unwrap_or_else(|_| DEFAULT_PRODUCER_SOCKET.to_string());

    info!("starting kernel-layer daemon");

    // Load the eBPF program embedded at build time by aya-build.
    // include_bytes_aligned! ensures the bytes are aligned for eBPF loading.
    let ebpf_owned = Box::leak(Box::new(Ebpf::load(aya::include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/kernel-layer-ebpf"
    ))
    .context("failed to load eBPF program")?));
    let ebpf: &'static mut _ = ebpf_owned;
    #[allow(unused_mut)]
    let mut ebpf = ebpf;

    // Initialize eBPF logger so debug!() calls in the eBPF program appear here.
    if let Err(e) = EbpfLogger::init(&mut ebpf) {
        warn!("eBPF logger init failed (non-fatal): {e}");
    }

    // Attach the tracepoint to sys_enter_openat.
    let program: &mut TracePoint = ebpf
        .program_mut("file_opened")
        .context("program 'file_opened' not found")?
        .try_into()?;
    program.load()?;
    program
        .attach("syscalls", "sys_enter_openat")
        .context("failed to attach tracepoint to sys_enter_openat")?;

    info!("eBPF tracepoint attached to sys_enter_openat");

    // Get a handle to the ring buffer map.
    let ring_buf = RingBuf::try_from(ebpf.map_mut("EVENTS").context("EVENTS map not found")?)?;

    // Spawn the normalizer that reads from the ring buffer and forwards to Event Bus.
    let normalizer_handle =
        tokio::task::spawn_blocking(move || normalizer::run(ring_buf, &producer_socket));

    // Wait for Ctrl-C.
    signal::ctrl_c().await?;
    info!("shutting down");

    drop(normalizer_handle);
    Ok(())
}
