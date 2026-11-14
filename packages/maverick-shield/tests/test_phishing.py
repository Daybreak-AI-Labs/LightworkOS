"""Phishing-content detector.

Unit tests for the heuristic detector + the Shield.scan_output wiring.
"""
from __future__ import annotations

from maverick_shield import Shield, ShieldVerdict
from maverick_shield.phishing import detect_phishing


class TestDetector:
    def test_benign_not_flagged(self):
        v = detect_phishing(
            "Here is the report you requested. See https://example.com/report.")
        assert not v.suspicious
        assert v.severity == "none"

    def test_empty_text(self):
        assert not detect_phishing("").suspicious
        assert not detect_phishing(None).suspicious  # type: ignore[arg-type]

    def test_full_phishing_combo_is_high(self):
        text = (
            "Verify your account now! Your account will be suspended within 24 "
            "hours. Sign in here: http://paypa1.com/login")
        v = detect_phishing(text)
        assert v.suspicious
        assert v.severity == "high"
        assert any("credential" in r for r in v.reasons)
        assert any("urgency" in r for r in v.reasons)

    def test_link_text_target_mismatch(self):
        v = detect_phishing("Click [https://paypal.com](http://evil.example.com)")
        assert v.suspicious
        assert any("different domain" in r for r in v.reasons)

    def test_brand_lookalike_host(self):
        v = detect_phishing("Update your billing information at http://g00gle.com")
        assert v.suspicious
        assert any("lookalike" in r for r in v.reasons)

    def test_raw_ip_url(self):
        v = detect_phishing("Confirm your password at http://203.0.113.7/account")
        assert v.suspicious
        assert any("raw-IP" in r for r in v.reasons)

    def test_punycode_host(self):
        v = detect_phishing("Confirm your identity: https://xn--80ak6aa92e.com/verify")
        assert v.suspicious

    def test_link_patterns_linear_on_unterminated_openers(self):
        # Every "[" / "<a" used to scan to the end of the text (40,000 "["
        # took ~6.5 s). A real mismatched link after the decoys still counts.
        import time

        start = time.perf_counter()
        detect_phishing("[" * 40_000)
        detect_phishing("<a " * 13_000)
        assert time.perf_counter() - start < 2.0
        for decoys, link in (
            ("[" * 2000, " [paypal.com](http://evil.example/login)"),
            ("<a " * 700, '<a class="x" href="https://evil.example/">chase.com</a>'),
        ):
            v = detect_phishing(decoys + link)
            assert any("different domain" in r for r in v.reasons)


class TestShieldWiring:
    def test_scan_output_blocks_high_phishing(self):
        s = Shield(profile="balanced", backend="auto", warn_if_missing=False)
        text = (
            "Verify your account now! Your account will be suspended within 24 "
            "hours. Sign in: http://paypa1.com/login")
        verdict = s.scan_output(text)
        assert isinstance(verdict, ShieldVerdict)
        assert not verdict.allowed
        assert any("phishing" in r for r in verdict.reasons)

    def test_scan_output_allows_benign(self):
        s = Shield(profile="balanced", backend="auto", warn_if_missing=False)
        assert s.scan_output("Here is the summary you requested.").allowed

    def test_low_threshold_blocks_link_mismatch(self):
        s = Shield(profile="balanced", block_threshold="low", backend="auto",
                   warn_if_missing=False)
        verdict = s.scan_output("Click [https://paypal.com](http://evil.example.com)")
        assert not verdict.allowed

    def test_off_profile_skips_phishing(self):
        s = Shield(profile="off", backend="none", warn_if_missing=False)
        text = "Verify your account at http://paypa1.com within 24 hours."
        assert s.scan_output(text).allowed
