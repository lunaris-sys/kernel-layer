use aya_build::{Package, Toolchain};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compile proto types for use in normalizer.rs
    prost_build::compile_protos(&["proto/event.proto"], &["proto/"])?;

    // Tell Cargo to rerun if eBPF source changes
    println!("cargo:rerun-if-changed=../kernel-layer-ebpf/src/main.rs");

    // Note: aya-build 0.1.3 has a naming conflict when package == binary name.
    // We trigger the eBPF build manually via the justfile instead.
    let _ = (Package::default(), Toolchain::default()); // suppress unused import warnings
    Ok(())
}
