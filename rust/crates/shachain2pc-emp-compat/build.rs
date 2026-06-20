use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=../../../Makefile");
    println!("cargo:rerun-if-changed=../../../tools/csw_probe.cpp");
    println!("cargo:rerun-if-changed=../../../tools/ag2pc_triple_pool_probe.cpp");
    println!("cargo:rerun-if-changed=../../../tools/ag2pc_protocol_probe.cpp");
    println!("cargo:rerun-if-changed=../../../tools/ag2pc_compute_probe.cpp");
    println!("cargo:rerun-if-changed=../../../tools/softspoken_probe.cpp");
    println!("cargo:rerun-if-env-changed=SHACHAIN2PC_BUILD_CPP_PROBES");

    if env::var("SHACHAIN2PC_BUILD_CPP_PROBES").as_deref() != Ok("1") {
        return;
    }

    build_cpp_probe();
}

fn build_cpp_probe() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let repo_root = manifest_dir.join("../../..");
    for target in [
        ".build/csw_probe",
        ".build/ag2pc_triple_pool_probe",
        ".build/ag2pc_protocol_probe",
        ".build/ag2pc_compute_probe",
        ".build/softspoken_probe",
    ] {
        let status = Command::new("make")
            .arg(target)
            .current_dir(&repo_root)
            .status()
            .unwrap_or_else(|_| panic!("failed to run make {target}"));
        assert!(status.success(), "failed to build {target}");
    }
}
