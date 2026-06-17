use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=../../../Makefile");
    println!("cargo:rerun-if-changed=../../../tools/emp_wire_probe.cpp");
    println!("cargo:rerun-if-env-changed=SHACHAIN2PC_BUILD_CPP_PROBES");

    if env::var_os("CARGO_FEATURE_CPP_PROBES").is_none()
        && env::var("SHACHAIN2PC_BUILD_CPP_PROBES").as_deref() != Ok("1")
    {
        return;
    }

    build_cpp_probe();
}

fn build_cpp_probe() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let repo_root = manifest_dir.join("../../..");
    let status = Command::new("make")
        .arg(".build/emp_wire_probe")
        .current_dir(&repo_root)
        .status()
        .expect("failed to run make .build/emp_wire_probe");
    assert!(status.success(), "failed to build .build/emp_wire_probe");
}
