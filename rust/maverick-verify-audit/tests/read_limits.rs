use maverick_verify_audit::{verify_file, KeySource};
use std::fs::File;

#[test]
fn oversized_segments_are_refused_before_verification() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("oversized.ndjson");
    File::create(&path)
        .unwrap()
        .set_len(512 * 1024 * 1024 + 1)
        .unwrap();
    let breaks = verify_file(&path, &KeySource::Pinned("02".repeat(32)));
    assert_eq!(breaks.len(), 1);
    assert_eq!(breaks[0].reason, "unreadable_segment");
    assert!(breaks[0].detail.contains("size limit"));
}

#[test]
fn segments_over_the_old_64_mib_limit_are_read() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("busy-day.ndjson");
    std::fs::write(&path, "\n".repeat(64 * 1024 * 1024 + 1)).unwrap();
    let breaks = verify_file(&path, &KeySource::Pinned("02".repeat(32)));
    assert!(breaks.is_empty(), "{breaks:?}");
}

#[test]
fn malformed_segments_stop_after_a_bounded_failure_report() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("malformed.ndjson");
    std::fs::write(&path, "not-json\n".repeat(1001)).unwrap();
    let breaks = verify_file(&path, &KeySource::Pinned("02".repeat(32)));
    assert_eq!(breaks.len(), 1000);
    assert!(breaks.iter().all(|item| item.reason == "malformed"));
}

#[test]
fn capped_unsigned_report_warns_and_states_no_exact_count() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("unsigned.ndjson");
    std::fs::write(&path, "{\"event\": \"x\"}\n".repeat(1001)).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_maverick-verify-audit"))
        .arg("--keys-dir")
        .arg(directory.path().join("keys"))
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    let warning = stderr.find("failure report limit").expect(&stderr);
    let verdict = stderr.find("UNVERIFIABLE").expect(&stderr);
    assert!(warning < verdict, "{stderr}");
    assert!(stderr.contains("at least 1000 unsigned row(s)"), "{stderr}");
    assert!(!stderr.contains("— 1000 unsigned row(s)"), "{stderr}");
}
