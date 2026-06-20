use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=../../../Makefile");
    println!("cargo:rerun-if-changed=../../../tools/emp_wire_probe.cpp");
    println!("cargo:rerun-if-changed=../../../tools/ag2pc_transport_probe.cpp");
    println!("cargo:rerun-if-env-changed=SHACHAIN2PC_BUILD_CPP_PROBES");

    let env_enabled = env::var("SHACHAIN2PC_BUILD_CPP_PROBES").as_deref() == Ok("1");
    let feature_enabled = env::var("CARGO_FEATURE_CPP_PROBES").is_ok();
    if !env_enabled && !feature_enabled {
        return;
    }

    build_cpp_probe(".build/ag2pc_transport_probe");
}

fn build_cpp_probe(target: &str) {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let repo_root = manifest_dir.join("../../..");
    let status = Command::new("make")
        .arg(target)
        .current_dir(&repo_root)
        .status()
        .unwrap_or_else(|_| panic!("failed to run make {target}"));
    assert!(status.success(), "failed to build {target}");
}
