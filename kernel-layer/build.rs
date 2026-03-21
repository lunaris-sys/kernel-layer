fn main() {
    // aya-build 0.1.3 has a bug where it fails when the package name matches
    // the binary name. We skip it and reference the eBPF binary directly.
    // The eBPF binary must be built separately with:
    //   cargo +nightly build -Z build-std=core --target bpfel-unknown-none -p kernel-layer-ebpf --release
    println!("cargo:rerun-if-changed=../kernel-layer-ebpf/src/main.rs");
}
