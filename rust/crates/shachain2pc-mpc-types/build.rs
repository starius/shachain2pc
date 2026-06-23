fn main() -> Result<(), Box<dyn std::error::Error>> {
    prost_build::compile_protos(&["proto/mpc.proto"], &["proto"])?;
    println!("cargo:rerun-if-changed=proto/mpc.proto");
    Ok(())
}
