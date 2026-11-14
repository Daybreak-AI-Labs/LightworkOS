use maverick_verify_audit::{verify_file, KeySource};
use std::fs::File;

#[test]
fn oversized_segments_are_refused_before_verification() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("oversized.ndjson");
    File::create(&path)
        .unwrap()
        .set_len(64 * 1024 * 1024 + 1)
        .unwrap();
    let breaks = verify_file(&path, &KeySource::Pinned("02".repeat(32)));
    assert_eq!(breaks.len(), 1);
    assert_eq!(breaks[0].reason, "unreadable_segment");
    assert!(breaks[0].detail.contains("size limit"));
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
