"""Verifier calibration interlock: the self-improvement safety guardrail.

The verifier's confidence is the label the donation flywheel learns from, so a
drifted verifier must freeze learning. These cover the assessment math, the
persisted-verdict freeze gate, and the interlock wired into donation.write_record.
"""
from __future__ import annotations

import json

from maverick import calibration
from maverick.calibration import CalibrationSample, assess


def _samples(pairs):
    return [CalibrationSample(confidence=c, correct=k) for c, k in pairs]


class TestAssess:
    def test_well_calibrated_is_adequate(self):
        # Confident on correct, unconfident on incorrect -> good discrimination.
        pairs = [(0.9, True)] * 15 + [(0.2, False)] * 15
        r = assess(_samples(pairs), min_samples=20, min_discrimination=0.15)
        assert r.adequate is True
        assert r.discrimination > 0.5

    def test_drifted_verifier_is_inadequate(self):
        # High confidence on BOTH correct and incorrect -> no discrimination.
        pairs = [(0.9, True)] * 15 + [(0.85, False)] * 15
        r = assess(_samples(pairs), min_samples=20, min_discrimination=0.15)
        assert r.adequate is False
        assert "discrimination" in r.reason

    def test_inverted_verifier_is_inadequate(self):
        # Worse than useless: more confident on the wrong answers.
        pairs = [(0.3, True)] * 15 + [(0.8, False)] * 15
        r = assess(_samples(pairs), min_samples=20, min_discrimination=0.15)
        assert r.adequate is False
        assert r.discrimination < 0

    def test_too_few_samples_is_inadequate(self):
        r = assess(_samples([(0.9, True), (0.1, False)]), min_samples=20)
        assert r.adequate is False
        assert "not enough" in r.reason

    def test_one_class_only_is_inadequate(self):
        pairs = [(0.9, True)] * 30
        r = assess(_samples(pairs), min_samples=20)
        assert r.adequate is False
        assert "both correct and incorrect" in r.reason

    def test_confidence_clamped(self):
        # Out-of-range confidences don't blow up the math.
        pairs = [(5.0, True)] * 15 + [(-1.0, False)] * 15
        r = assess(_samples(pairs), min_samples=20, min_discrimination=0.15)
        assert r.adequate is True
        assert 0.0 <= r.brier <= 1.0


class TestLedgerAndVerdict:
    def test_record_and_load_roundtrip(self, tmp_path):
        p = tmp_path / "cal.ndjson"
        assert calibration.record_sample(
            0.9, True, source="t", evaluator_id="judge:v2", path=p) is True
        assert calibration.record_sample(0.1, False, path=p) is True
        loaded = calibration.load_samples(path=p)
        assert len(loaded) == 2
        assert loaded[0].correct is True and loaded[1].correct is False
        assert loaded[0].evaluator_id == "judge:v2"
        assert loaded[1].evaluator_id == ""

    def test_non_finite_confidence_is_never_the_most_confident(self, tmp_path):
        p = tmp_path / "cal.ndjson"
        assert calibration.record_sample(float("nan"), True, path=p) is True
        with open(p, "a", encoding="utf-8") as f:
            f.write('{"confidence": NaN, "correct": true}\n')
        assert [s.confidence for s in calibration.load_samples(path=p)] == [0.0]

    def test_run_assessment_persists_verdict(self, tmp_path):
        sp = tmp_path / "cal.ndjson"
        vp = tmp_path / "verdict.json"
        for _ in range(15):
            calibration.record_sample(0.9, True, path=sp)
            calibration.record_sample(0.2, False, path=sp)
        report = calibration.run_assessment(samples_path=sp, verdict_path=vp)
        assert report.adequate is True
        assert vp.exists()

    def test_narrow_assessment_leaves_the_learning_freeze_verdict_alone(
        self, tmp_path, monkeypatch,
    ):
        """A one-source, one-checker assessment must not unfreeze (or freeze)
        tenant-wide learning by overwriting the general verdict."""
        general, receipt = tmp_path / "verdict.json", tmp_path / "receipt.json"
        monkeypatch.setattr(calibration, "_verdict_path", lambda: general)
        monkeypatch.setattr(calibration, "_risk_verdict_path", lambda: receipt)
        sp = tmp_path / "cal.ndjson"
        for _ in range(15):
            calibration.record_sample(0.9, True, source="s", evaluator_id="judge:A", path=sp)
            calibration.record_sample(0.2, False, source="s", evaluator_id="judge:A", path=sp)
        general.write_text('{"adequate": false}', encoding="utf-8")
        report = calibration.run_assessment(
            samples_path=sp, evaluator_id="judge:A", sources={"s"}, min_samples=20)
        assert report.adequate is True
        assert json.loads(general.read_text(encoding="utf-8")) == {"adequate": False}
        assert json.loads(receipt.read_text(encoding="utf-8"))["evaluator_id"] == "judge:A"

    def test_load_samples_skips_non_object_json_lines(self, tmp_path):
        p = tmp_path / "cal.ndjson"
        p.write_text(
            '[]\n"x"\n{"confidence": 0.7, "correct": true, "ts": 1, "source": "t"}\n',
            encoding="utf-8",
        )

        loaded = calibration.load_samples(path=p)

        assert len(loaded) == 1
        assert loaded[0].confidence == 0.7
        assert loaded[0].correct is True

    def test_bound_assessment_filters_evaluator_and_current_window(
        self, tmp_path, monkeypatch,
    ):
        samples_path = tmp_path / "cal.ndjson"
        verdict_path = tmp_path / "receipt.json"
        monkeypatch.setattr(calibration, "_settings", lambda: {
            **calibration._DEFAULTS,
            "min_samples": 20,
            "min_discrimination": 0.15,
        })

        # Old evidence from the right judge and current evidence from the wrong
        # judge must not enter this exact current-cycle assessment.
        monkeypatch.setattr(calibration.time, "time", lambda: 50.0)
        for _ in range(20):
            calibration.record_sample(
                0.99, False, evaluator_id="judge:A", path=samples_path)
        monkeypatch.setattr(calibration.time, "time", lambda: 200.0)
        for _ in range(20):
            calibration.record_sample(
                0.99, False, evaluator_id="judge:B", path=samples_path)
        for _ in range(15):
            calibration.record_sample(
                0.9, True, evaluator_id="judge:A", path=samples_path)
            calibration.record_sample(
                0.1, False, evaluator_id="judge:A", path=samples_path)

        report = calibration.run_assessment(
            samples_path=samples_path, verdict_path=verdict_path,
            evaluator_id="judge:A", since=100.0)
        assert report.adequate is True and report.n == 30
        receipt = json.loads(verdict_path.read_text(encoding="utf-8"))
        assert receipt["schema"] == "maverick-calibration-receipt-v2"
        assert receipt["evaluator_id"] == "judge:A"
        assert receipt["evidence_since"] == 100.0
        assert receipt["sample_min_ts"] == receipt["sample_max_ts"] == 200.0


class TestLearningFrozen:
    def test_off_by_default(self, tmp_path, monkeypatch):
        # enforce defaults off -> never frozen even with no verdict.
        monkeypatch.setattr(calibration, "_settings", lambda: {
            "enforce": False, "min_samples": 20, "min_discrimination": 0.15,
        })
        assert calibration.learning_frozen(verdict_path=tmp_path / "none.json") is False

    def test_enforced_but_no_verdict_does_not_freeze(self, tmp_path, monkeypatch):
        monkeypatch.setattr(calibration, "_settings", lambda: {
            "enforce": True, "min_samples": 20, "min_discrimination": 0.15,
        })
        # No assessment has run -> no evidence of drift -> not frozen.
        assert calibration.learning_frozen(verdict_path=tmp_path / "none.json") is False

    def test_enforced_inadequate_verdict_freezes(self, tmp_path, monkeypatch):
        monkeypatch.setattr(calibration, "_settings", lambda: {
            "enforce": True, "min_samples": 20, "min_discrimination": 0.15,
        })
        vp = tmp_path / "verdict.json"
        vp.write_text('{"adequate": false}', encoding="utf-8")
        assert calibration.learning_frozen(verdict_path=vp) is True

    def test_enforced_adequate_verdict_does_not_freeze(self, tmp_path, monkeypatch):
        monkeypatch.setattr(calibration, "_settings", lambda: {
            "enforce": True, "min_samples": 20, "min_discrimination": 0.15,
        })
        vp = tmp_path / "verdict.json"
        vp.write_text('{"adequate": true}', encoding="utf-8")
        assert calibration.learning_frozen(verdict_path=vp) is False

    def test_enforced_non_object_verdict_fails_open(self, tmp_path, monkeypatch):
        monkeypatch.setattr(calibration, "_settings", lambda: {
            "enforce": True, "min_samples": 20, "min_discrimination": 0.15,
        })
        vp = tmp_path / "verdict.json"
        vp.write_text('[]', encoding="utf-8")
        assert calibration.learning_frozen(verdict_path=vp) is False


class TestLearningFrozenSafe:
    """The shared fail-open wrapper dreaming.rehearse,
    dreaming._consolidate_learning, and orchestrator's per-run distillation
    gate all delegate to, replacing three independent copies of the same
    try/except."""

    def test_passes_through_when_not_frozen(self, monkeypatch):
        monkeypatch.setattr(calibration, "learning_frozen", lambda: False)
        assert calibration.learning_frozen_safe() is False

    def test_passes_through_when_frozen(self, monkeypatch):
        monkeypatch.setattr(calibration, "learning_frozen", lambda: True)
        assert calibration.learning_frozen_safe() is True

    def test_fails_open_on_exception(self, monkeypatch):
        def _boom():
            raise RuntimeError("verdict store unreadable")
        monkeypatch.setattr(calibration, "learning_frozen", _boom)
        assert calibration.learning_frozen_safe() is False

    def test_takes_no_arguments(self, monkeypatch):
        # No existing caller has ever needed a custom verdict_path; a
        # zero-arg replacement (the natural monkeypatch/test-double shape)
        # must work, not raise a TypeError that then reads as "not frozen"
        # for the wrong reason.
        calls = []
        monkeypatch.setattr(calibration, "learning_frozen",
                            lambda: calls.append(1) or True)
        assert calibration.learning_frozen_safe() is True
        assert calls == [1]


class TestCollectFromCoding:
    def test_off_by_default(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_CALIBRATION_COLLECT_CODING", raising=False)
        monkeypatch.setattr(calibration, "_settings", lambda: dict(calibration._DEFAULTS))
        assert calibration.collect_from_coding_enabled() is False

    def test_env_enables(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_CALIBRATION_COLLECT_CODING", "1")
        assert calibration.collect_from_coding_enabled() is True

    def test_config_enables(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_CALIBRATION_COLLECT_CODING", raising=False)
        monkeypatch.setattr(calibration, "_settings", lambda: {
            **calibration._DEFAULTS, "collect_from_coding": True,
        })
        assert calibration.collect_from_coding_enabled() is True


class TestDonationInterlock:
    def test_frozen_learning_blocks_gold_trajectory(self, tmp_path, monkeypatch):
        """A trajectory that WOULD donate is refused when calibration is frozen."""
        from maverick import donation
        from maverick.donation import TrajectoryRecord

        monkeypatch.setattr(donation, "_donations_enabled", lambda: True)
        monkeypatch.setattr(donation, "_text_donations_enabled", lambda: False)
        # Drifted verifier -> learning frozen.
        monkeypatch.setattr("maverick.calibration.learning_frozen", lambda: True)

        rec = TrajectoryRecord(
            task_brief_hash="abc", outcome="success",
            verifier_confidence=0.95, disagreement_entropy=0.9,
        )
        out = donation.write_record(rec, outbox=tmp_path / "outbox")
        assert out is None  # gold trajectory, but frozen -> not written

    def test_unfrozen_learning_allows_gold_trajectory(self, tmp_path, monkeypatch):
        from maverick import donation
        from maverick.donation import TrajectoryRecord

        monkeypatch.setattr(donation, "_donations_enabled", lambda: True)
        monkeypatch.setattr(donation, "_text_donations_enabled", lambda: False)
        monkeypatch.setattr("maverick.calibration.learning_frozen", lambda: False)

        rec = TrajectoryRecord(
            task_brief_hash="abc", outcome="success",
            verifier_confidence=0.95, disagreement_entropy=0.9,
        )
        out = donation.write_record(rec, outbox=tmp_path / "outbox")
        assert out is not None and out.exists()
