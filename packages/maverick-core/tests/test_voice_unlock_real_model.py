"""Voice unlock with the real SpeechBrain ECAPA speaker model.

Skipped unless the optional voice-unlock extra is installed and two folders
are named: ``MAVERICK_TEST_SPEAKER_MODEL`` (a local copy of
speechbrain/spkrec-ecapa-voxceleb) and ``MAVERICK_TEST_SPEAKER_SAMPLES``
(16-bit WAV files ``spk1_snt1..4.wav`` and ``spk2_snt1.wav``, e.g. from
SpeechBrain's own ``tests/samples/ASR``). Nothing is downloaded here.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

MODEL = os.environ.get("MAVERICK_TEST_SPEAKER_MODEL", "")
SAMPLES = os.environ.get("MAVERICK_TEST_SPEAKER_SAMPLES", "")

pytestmark = pytest.mark.skipif(
    not (MODEL and SAMPLES), reason="no local speaker model and samples named")


def test_real_model_accepts_the_speaker_and_rejects_another(tmp_path, monkeypatch):
    pytest.importorskip("speechbrain")
    from maverick.voice_unlock import (
        LIVE_DEFAULT_THRESHOLD,
        EcapaEmbedder,
        VoiceGate,
        readiness,
    )

    monkeypatch.setenv("MAVERICK_VOICE_UNLOCK", "1")
    assert readiness(MODEL) is None
    clip = {name: (Path(SAMPLES) / f"{name}.wav").read_bytes()
            for name in ("spk1_snt1", "spk1_snt2", "spk1_snt3", "spk1_snt4", "spk2_snt1")}
    gate = VoiceGate(EcapaEmbedder(MODEL), store_path=tmp_path / "profiles.json",
                     threshold=LIVE_DEFAULT_THRESHOLD)
    assert gate.enroll("spk1", [clip["spk1_snt1"], clip["spk1_snt2"], clip["spk1_snt3"]]) == 192
    same = gate.decide("spk1", clip["spk1_snt4"])
    other = gate.decide("spk1", clip["spk2_snt1"])
    assert same.companion_ok is True and same.score > 0.6
    assert other.companion_ok is False and other.score < 0.3
