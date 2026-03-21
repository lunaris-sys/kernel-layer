use aya_build::cargo_metadata;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // aya-build compiles the eBPF crate and embeds the resulting object file
    // into the user-space binary. At runtime we load it with Ebpf::load().
    let metadata = cargo_metadata()?;
    aya_build::build_ebpf(
        &metadata,
        &["kernel-layer-ebpf"],
        &aya_build::BuildOptions::default(),
    )?;
    Ok(())
}
