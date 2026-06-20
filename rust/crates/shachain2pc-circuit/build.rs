use std::path::PathBuf;

// Resolve the SHA-256 compression Bristol gadget at build time so lib.rs can
// include_str! it into the binary (no runtime file dependency). Prefer EMP_PREFIX
// (the nix-built emp in /nix/store); fall back to the repo-root .deps/emp layout.
fn main() {
    const SUFFIX: &str = "include/emp-tool/circuits/files/bristol_format/sha-256.txt";
    let path = match std::env::var("EMP_PREFIX") {
        Ok(prefix) if !prefix.is_empty() => PathBuf::from(prefix).join(SUFFIX),
        _ => PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("../../..")
            .join(".deps/emp")
            .join(SUFFIX),
    };
    println!("cargo:rustc-env=SHA256_BRISTOL_PATH={}", path.display());
    println!("cargo:rerun-if-env-changed=EMP_PREFIX");
    println!("cargo:rerun-if-changed={}", path.display());
}
