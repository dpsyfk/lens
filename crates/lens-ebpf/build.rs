use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=src/lens-discovery.bpf.c");
    println!("cargo:rerun-if-env-changed=CLANG");
    let enabled = env::var_os("CARGO_FEATURE_RUNTIME").is_some();
    let linux = env::var("CARGO_CFG_TARGET_OS").is_ok_and(|value| value == "linux");
    if !enabled || !linux {
        return;
    }

    let source = PathBuf::from("src/lens-discovery.bpf.c");
    let output =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set")).join("lens-discovery.bpf.o");
    let clang = env::var_os("CLANG").unwrap_or_else(|| "clang".into());
    let status = Command::new(clang)
        .args(["-target", "bpf", "-O2", "-g", "-Wall", "-Werror", "-c"])
        .arg(&source)
        .arg("-o")
        .arg(&output)
        .status()
        .expect("failed to execute clang; Linux eBPF builds require clang with the BPF target");
    assert!(
        status.success(),
        "clang failed to compile the Lens eBPF probe"
    );
}
