//! Puts `eravm_memory.x` on the linker search path for the `-Teravm_memory.x`
//! link-arg in `.cargo/config.toml`. It carries its own name so it can never be
//! shadowed by riscv_common's `memory.x`, which is on the same search path.

fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo::rustc-link-search={dir}");
    println!("cargo::rerun-if-changed=eravm_memory.x");
}
