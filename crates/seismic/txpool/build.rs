//! Build script for compiling ECSD protobuf definitions.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("proto/ecsd.proto")?;
    Ok(())
}
