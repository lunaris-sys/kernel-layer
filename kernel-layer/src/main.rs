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
use log::{info, warn};
use tokio::signal;

mod normalizer;

const DEFAULT_PRODUCER_SOCKET: &str = "/run/lunaris/event-bus-producer.sock";

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let producer_socket = std::env::var("LUNARIS_PRODUCER_SOCKET")
        .unwrap_or_else(|_| DEFAULT_PRODUCER_SOCKET.to_string());

    // Read or generate session ID.
    let session_id = std::env::var("LUNARIS_SESSION_ID")
        .unwrap_or_else(|_| uuid::Uuid::now_v7().to_string());

    info!("starting kernel-layer daemon");
    info!("session_id={session_id}");

    let ebpf_owned = Box::leak(Box::new(Ebpf::load(aya::include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/kernel-layer-ebpf"
    ))
    .context("failed to load eBPF program")?));

    let ebpf: &'static mut _ = ebpf_owned;

    if let Err(e) = EbpfLogger::init(ebpf) {
        warn!("eBPF logger init failed (non-fatal): {e}");
    }

    let program: &mut TracePoint = ebpf
        .program_mut("file_opened")
        .context("program 'file_opened' not found")?
        .try_into()?;
    program.load()?;
    program
        .attach("syscalls", "sys_enter_openat")
        .context("failed to attach tracepoint to sys_enter_openat")?;

    info!("eBPF tracepoint attached to sys_enter_openat");

    let ring_buf = RingBuf::try_from(ebpf.map_mut("EVENTS").context("EVENTS map not found")?)?;

    let producer_socket_clone = producer_socket.clone();
    let session_id_clone = session_id.clone();
    tokio::task::spawn_blocking(move || {
        normalizer::run(ring_buf, &producer_socket_clone, &session_id_clone)
    });

    signal::ctrl_c().await?;
    info!("shutting down");
    Ok(())
}
#[cfg(test)]
mod normalizer_tests;
