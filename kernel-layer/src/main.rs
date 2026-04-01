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

    // Load and attach all programs first (before taking map references).
    {
        let prog: &mut TracePoint = ebpf
            .program_mut("file_opened")
            .context("program 'file_opened' not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("syscalls", "sys_enter_openat")
            .context("failed to attach to sys_enter_openat")?;
        info!("eBPF tracepoint attached to sys_enter_openat");
    }
    {
        let prog: &mut TracePoint = ebpf
            .program_mut("process_exec")
            .context("program 'process_exec' not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("sched", "sched_process_exec")
            .context("failed to attach to sched_process_exec")?;
        info!("eBPF tracepoint attached to sched_process_exec");
    }
    {
        let prog: &mut TracePoint = ebpf
            .program_mut("file_written")
            .context("program 'file_written' not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("syscalls", "sys_enter_write")
            .context("failed to attach to sys_enter_write")?;
        info!("eBPF tracepoint attached to sys_enter_write");
    }
    {
        let prog: &mut TracePoint = ebpf
            .program_mut("net_state_change")
            .context("program 'net_state_change' not found")?
            .try_into()?;
        prog.load()?;
        prog.attach("sock", "inet_sock_set_state")
            .context("failed to attach to inet_sock_set_state")?;
        info!("eBPF tracepoint attached to inet_sock_set_state");
    }

    // Take ownership of maps (avoids multiple mutable borrows of ebpf).
    let ring_buf = RingBuf::try_from(ebpf.take_map("EVENTS").context("EVENTS map not found")?)?;
    let ring_buf_exec = RingBuf::try_from(ebpf.take_map("EXEC_EVENTS").context("EXEC_EVENTS map not found")?)?;
    let ring_buf_write = RingBuf::try_from(ebpf.take_map("WRITE_EVENTS").context("WRITE_EVENTS map not found")?)?;
    let ring_buf_net = RingBuf::try_from(ebpf.take_map("NET_EVENTS").context("NET_EVENTS map not found")?)?;

    let producer_socket_clone = producer_socket.clone();
    let session_id_clone = session_id.clone();
    tokio::task::spawn_blocking(move || {
        normalizer::run(
            ring_buf,
            ring_buf_exec,
            ring_buf_write,
            ring_buf_net,
            &producer_socket_clone,
            &session_id_clone,
        )
    });

    signal::ctrl_c().await?;
    info!("shutting down");
    Ok(())
}
#[cfg(test)]
mod normalizer_tests;
