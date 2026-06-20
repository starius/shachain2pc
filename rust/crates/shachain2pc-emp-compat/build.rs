use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=../../../Makefile");
    println!("cargo:rerun-if-changed=../../../tools/otco_probe.cpp");
    println!("cargo:rerun-if-changed=../../../tools/iknp_probe.cpp");
    println!("cargo:rerun-if-changed=../../../tools/fpre_setup_probe.cpp");
    println!("cargo:rerun-if-changed=../../../tools/fpre_generate_probe.cpp");
    println!("cargo:rerun-if-changed=../../../tools/fpre_check_probe.cpp");
    println!("cargo:rerun-if-changed=../../../tools/fpre_refill_probe.cpp");
    println!("cargo:rerun-if-changed=../../../tools/c2pc_independent_probe.cpp");
    println!("cargo:rerun-if-changed=../../../tools/c2pc_dependent_probe.cpp");
    println!("cargo:rerun-if-changed=../../../tools/c2pc_online_probe.cpp");
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
        ".build/otco_probe",
        ".build/iknp_probe",
        ".build/fpre_setup_probe",
        ".build/fpre_generate_probe",
        ".build/fpre_check_probe",
        ".build/fpre_refill_probe",
        ".build/c2pc_independent_probe",
        ".build/c2pc_dependent_probe",
        ".build/c2pc_online_probe",
    ] {
        let status = Command::new("make")
            .arg(target)
            .current_dir(&repo_root)
            .status()
            .unwrap_or_else(|_| panic!("failed to run make {target}"));
        assert!(status.success(), "failed to build {target}");
    }
}
