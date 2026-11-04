"""Reward-laundering interlock: adversarial-probe resistance in calibration.

Natural discrimination catches a verifier that has *drifted*. Resistance
catches one that is being *gamed* -- it stays sharp on everyday traffic while
its edge on crafted adversarial probes collapses. These pin that the metric is
computed correctly, that it only freezes when configured, and that it never
perturbs the historical (probe-free) path.
"""
from __future__ import annotations

from maverick import calibration
from maverick.calibration import CalibrationSample, assess, record_probe, record_sample


def _natural(pairs):
    return [CalibrationSample(confidence=c, correct=k) for c, k in pairs]


def _probes(pairs):
    return [CalibrationSample(confidence=c, correct=k, adversarial=True) for c, k in pairs]


class TestResistanceMetric:
    def test_no_probes_leaves_resistance_none(self):
        # Historical path: no adversarial samples -> nothing to measure.
        r = assess(_natural([(0.9, True)] * 15 + [(0.2, False)] * 15),
                   min_samples=20, min_discrimination=0.15)
        assert r.resistance is None
        assert r.adversarial_discrimination is None
        assert r.adequate is True

    def test_sharp_on_probes_gives_high_resistance(self):
        # Natural disc 0.7, adversarial disc 0.7 -> resistance ~1.0.
        samples = (_natural([(0.9, True)] * 15 + [(0.2, False)] * 15)
                   + _probes([(0.9, True)] * 15 + [(0.2, False)] * 15))
        r = assess(samples, min_samples=20, min_discrimination=0.15)
        assert r.adversarial_discrimination is not None
        assert abs(r.resistance - 1.0) < 1e-6

    def test_gamed_judge_gives_low_resistance(self):
        # Sharp on natural (0.7) but no edge on adversarial probes (0.0).
        samples = (_natural([(0.9, True)] * 15 + [(0.2, False)] * 15)
                   + _probes([(0.8, True)] * 15 + [(0.8, False)] * 15))
        r = assess(samples, min_samples=20, min_discrimination=0.15)
        assert abs(r.adversarial_discrimination) < 1e-6
        assert abs(r.resistance) < 1e-6

    def test_drift_measured_on_natural_subset_only(self):
        # Adversarial probes are deliberately hard; they must NOT drag down the
        # everyday-calibration number the drift gate reads.
        samples = (_natural([(0.9, True)] * 15 + [(0.2, False)] * 15)   # disc 0.7
                   + _probes([(0.5, True)] * 15 + [(0.5, False)] * 15))  # disc 0.0
        r = assess(samples, min_samples=20, min_discrimination=0.15)
        assert abs(r.discrimination - 0.7) < 1e-6  # natural only, not diluted


class TestResistanceFreeze:
    def test_off_by_default_advisory_only(self):
        # min_resistance defaults 0.0 -> a gamed judge is MEASURED but not frozen.
        samples = (_natural([(0.9, True)] * 15 + [(0.2, False)] * 15)
                   + _probes([(0.8, True)] * 15 + [(0.8, False)] * 15))
        r = assess(samples, min_samples=20, min_discrimination=0.15)  # min_resistance None -> 0.0
        assert r.resistance is not None and r.resistance < 0.5
        assert r.adequate is True  # advisory: not frozen

    def test_configured_floor_freezes_gamed_judge(self):
        samples = (_natural([(0.9, True)] * 15 + [(0.2, False)] * 15)
                   + _probes([(0.8, True)] * 15 + [(0.8, False)] * 15))
        r = assess(samples, min_samples=20, min_discrimination=0.15, min_resistance=0.5)
        assert r.adequate is False
        assert "laundering" in r.reason

    def test_configured_floor_passes_robust_judge(self):
        samples = (_natural([(0.9, True)] * 15 + [(0.2, False)] * 15)
                   + _probes([(0.9, True)] * 15 + [(0.2, False)] * 15))
        r = assess(samples, min_samples=20, min_discrimination=0.15, min_resistance=0.5)
        assert r.adequate is True
        assert "resistance" in r.reason

    def test_drift_still_dominates_when_natural_fails(self):
        # If natural discrimination itself fails, that's the freeze reason --
        # not resistance (which is undefined when the base edge is gone).
        samples = (_natural([(0.9, True)] * 15 + [(0.85, False)] * 15)   # disc ~0.05
                   + _probes([(0.9, True)] * 15 + [(0.2, False)] * 15))
        r = assess(samples, min_samples=20, min_discrimination=0.15, min_resistance=0.5)
        assert r.adequate is False
        assert "separates correct from incorrect" in r.reason


class TestLedgerRoundTrip:
    def test_probe_is_tagged_and_loads(self, tmp_path):
        p = tmp_path / "cal.ndjson"
        assert record_sample(0.9, True, path=p) is True
        assert record_probe(0.8, False, source="probe", path=p) is True
        loaded = calibration.load_samples(path=p)
        assert len(loaded) == 2
        assert loaded[0].adversarial is False
        assert loaded[1].adversarial is True

    def test_legacy_line_without_tag_defaults_natural(self, tmp_path):
        p = tmp_path / "cal.ndjson"
        p.write_text('{"confidence": 0.7, "correct": true}\n', encoding="utf-8")
        loaded = calibration.load_samples(path=p)
        assert len(loaded) == 1 and loaded[0].adversarial is False

    def test_current_resistance_reads_ledger(self, tmp_path):
        p = tmp_path / "cal.ndjson"
        for _ in range(15):
            record_sample(0.9, True, path=p)
            record_sample(0.2, False, path=p)
            record_probe(0.8, True, path=p)
            record_probe(0.8, False, path=p)
        res = calibration.current_resistance(path=p)
        assert res is not None and res < 0.5  # gamed on probes

    def test_current_resistance_none_without_probes(self, tmp_path):
        p = tmp_path / "cal.ndjson"
        for _ in range(15):
            record_sample(0.9, True, path=p)
            record_sample(0.2, False, path=p)
        assert calibration.current_resistance(path=p) is None


def test_verdict_dict_carries_resistance():
    samples = (_natural([(0.9, True)] * 15 + [(0.2, False)] * 15)
               + _probes([(0.8, True)] * 15 + [(0.8, False)] * 15))
    d = assess(samples, min_samples=20, min_discrimination=0.15).to_dict()
    assert "resistance" in d and "adversarial_discrimination" in d
    assert d["resistance"] is not None
