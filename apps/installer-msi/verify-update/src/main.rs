//! Release acceptance helper using the updater's own verification library.
//! This program verifies bytes only; it never runs an installer.
use base64::Engine;
use minisign_verify::{PublicKey, Signature};
use std::path::Path;

fn decoded(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path)?;
    let bytes = base64::engine::general_purpose::STANDARD.decode(text.trim())?;
    Ok(String::from_utf8(bytes)?)
}

fn verify() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 3 {
        return Err("usage: verify-update PUBLIC-KEY SIGNATURE ARTIFACT".into());
    }
    let key = PublicKey::decode(&decoded(Path::new(&args[0]))?)?;
    let signature = Signature::decode(&decoded(Path::new(&args[1]))?)?;
    let content = std::fs::read(&args[2])?;
    key.verify(&content, &signature, true)?;
    Ok(())
}

fn main() {
    if let Err(error) = verify() {
        eprintln!("Update verification refused: {error}");
        std::process::exit(1);
    }
    println!("Update signature verified.");
}
