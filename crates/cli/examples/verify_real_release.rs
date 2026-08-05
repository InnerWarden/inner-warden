//! Verify a REAL release artifact using the PRODUCTION verifier source.
//!
//! Not a unit test: it needs bytes downloaded from the release. `#[path]` pulls
//! in the real module rather than a copy, so a passing run is evidence about the
//! shipping code and not about a reimplementation.
#[path = "../src/release_verify.rs"]
mod release_verify;

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = args.next().expect("usage: <dir> <asset-name>");
    let name = args.next().expect("usage: <dir> <asset-name>");
    let bytes = std::fs::read(format!("{dir}/{name}")).expect("binary");
    let sha = std::fs::read_to_string(format!("{dir}/{name}.sha256")).expect("sha sidecar");
    let sig = std::fs::read_to_string(format!("{dir}/{name}.sig")).expect("sig sidecar");

    match release_verify::verify_release(&bytes, &sha, &sig) {
        Ok(()) => println!("VERIFICADO  {name}  ({} bytes)", bytes.len()),
        Err(e) => {
            eprintln!("FALHOU  {name}: {e}");
            std::process::exit(1);
        }
    }

    // And prove it REFUSES a tampered copy of the same artifact.
    let mut tampered = bytes.clone();
    if let Some(b) = tampered.last_mut() {
        *b ^= 0xff;
    }
    match release_verify::verify_release(&tampered, &sha, &sig) {
        Err(e) => println!("RECUSADO   (byte alterado): {e}"),
        Ok(()) => {
            eprintln!("FALHA GRAVE: aceitou um binario adulterado");
            std::process::exit(1);
        }
    }
}
