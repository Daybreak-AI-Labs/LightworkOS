//! `maverick-verify-audit` — prove a Lightwork audit day-file's Ed25519 hash
//! chain is intact, with one self-contained binary and no Python.
//!
//!   maverick-verify-audit path/to/2026-06-18.ndjson
//!
//! Exit 0 and `OK: N rows verified` if the chain is intact; non-zero with a
//! human-readable report of the FIRST break otherwise. Semantics mirror
//! `maverick audit verify` (see maverick.audit.signing.verify_chain): an
//! entirely-unsigned log is UNVERIFIABLE (exit 1), not "clean".

use clap::Parser;
use maverick_verify_audit::{verify_file, ChainBreak, KeySource};
use std::path::PathBuf;
use std::process::ExitCode;

/// Independent Ed25519 hash-chain verifier for Lightwork audit logs.
#[derive(Parser, Debug)]
#[command(
    name = "maverick-verify-audit",
    version,
    about = "Independently verify a Lightwork Ed25519 hash-chained NDJSON audit log.",
    long_about = "Verifies the same signed hash chain as `maverick audit verify`, with no \
Python required, so an auditor or procurement reviewer can prove a log is intact from a \
single binary. Exit 0 if intact; non-zero plus a report of the first break otherwise."
)]
struct Args {
    /// Audit day-file (NDJSON), e.g. 2026-06-18.ndjson.
    file: PathBuf,

    /// Trust exactly this raw Ed25519 public key (hex). Use the externally-held
    /// pubkey for true third-party tamper-evidence; overrides --keys-dir.
    #[arg(long, value_name = "HEX")]
    pubkey: Option<String>,

    /// Directory of `<key_id>.pub` files (default: ~/.maverick/audit/keys).
    #[arg(long, value_name = "DIR")]
    keys_dir: Option<PathBuf>,

    /// Print every break, not just the first.
    #[arg(long)]
    all: bool,
}

fn default_keys_dir() -> PathBuf {
    // The Python legacy default (signing._LEGACY_KEY_DIR): ~/.maverick/audit/keys.
    // MAVERICK_HOME (== maverick.paths.maverick_home) overrides the .maverick root
    // so a custom home resolves consistently with the writer.
    let root = std::env::var_os("MAVERICK_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".maverick")))
        .unwrap_or_else(|| PathBuf::from(".maverick"));
    root.join("audit").join("keys")
}

fn main() -> ExitCode {
    let args = Args::parse();

    let keys = match &args.pubkey {
        Some(hex) => KeySource::Pinned(hex.clone()),
        None => {
            let dir = args.keys_dir.clone().unwrap_or_else(default_keys_dir);
            eprintln!(
                "warning: no --pubkey given; trusting public keys under {}. For \
                 third-party tamper-evidence, pass the externally-held --pubkey.",
                dir.display()
            );
            KeySource::KeysDir(dir)
        }
    };

    let breaks = verify_file(&args.file, &keys);

    if breaks.is_empty() {
        // Match the writer's vocabulary: report rows verified.
        let n = count_rows(&args.file);
        println!("OK: {} rows verified ({})", n, args.file.display());
        return ExitCode::SUCCESS;
    }

    // An entirely-unsigned log: one actionable line, still non-zero (parity with
    // the CLI's UNVERIFIABLE branch).
    if breaks.iter().all(|b| b.reason == "unsigned") {
        eprintln!(
            "UNVERIFIABLE: {} — {} unsigned row(s); audit signing is off. The log carries \
             no hash chain, so it cannot be proven intact. Enable [audit] sign = true \
             (or MAVERICK_AUDIT_SIGN=1) so future rows are tamper-evident.",
            args.file.display(),
            breaks.len()
        );
        return ExitCode::FAILURE;
    }

    report(&args.file, &breaks, args.all);
    ExitCode::FAILURE
}

fn report(file: &std::path::Path, breaks: &[ChainBreak], all: bool) {
    eprintln!("FAIL: {} issue(s) in {}", breaks.len(), file.display());
    let shown: &[ChainBreak] = if all { breaks } else { &breaks[..1] };
    for b in shown {
        if b.line_no == 0 {
            eprintln!("  {} — {}", b.reason, b.detail);
        } else {
            eprintln!("  line {}: {} — {}", b.line_no, b.reason, b.detail);
        }
    }
    if !all && breaks.len() > 1 {
        eprintln!(
            "  ... and {} more (pass --all to list every break)",
            breaks.len() - 1
        );
    }
}

/// Count non-blank rows for the success message. Best-effort: the chain already
/// verified, so a read error here only affects the printed count.
fn count_rows(path: &std::path::Path) -> usize {
    std::fs::read_to_string(path)
        .map(|t| t.lines().filter(|l| !l.trim().is_empty()).count())
        .unwrap_or(0)
}
