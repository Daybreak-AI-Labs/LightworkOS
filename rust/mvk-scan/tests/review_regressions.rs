use mvk_scan::phash::{average_hash_from_pixels, average_hash_from_rgb_bytes};

#[test]
fn oversized_dimensions_are_errors_without_panics() {
    for (width, height) in [(usize::MAX, 8), (usize::MAX / 8 + 1, 8), (8, usize::MAX)] {
        assert!(average_hash_from_pixels(&[], width, height).is_err());
        assert!(average_hash_from_rgb_bytes(&[], width, height).is_err());
    }
}
