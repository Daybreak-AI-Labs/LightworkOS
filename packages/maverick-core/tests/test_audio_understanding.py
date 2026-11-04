"""CLAP audio understanding: pure ranking math + tool wiring with
injected fake embedders. Offline; the real CLAP adapter is never loaded."""
from __future__ import annotations

import io
import json
import sys
import wave
from types import SimpleNamespace

from maverick.tools.audio_understanding import (
    audio_understanding,
    cosine,
    decode_wav,
    rank_labels,
)


def _wav_bytes(n: int = 16, channels: int = 1, rate: int = 8000) -> bytes:
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(channels)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes((16384).to_bytes(2, "little", signed=True) * n * channels)
    return buf.getvalue()


def _fake_text_embed(labels):
    # Deterministic orthogonal-ish vectors per label.
    table = {
        "dog barking": [1.0, 0.0, 0.0],
        "glass breaking": [0.0, 1.0, 0.0],
        "siren": [0.0, 0.0, 1.0],
    }
    return [table[label] for label in labels]


def _tool(tmp_path, audio_vec=(0.9, 0.1, 0.0)):
    return audio_understanding(
        sandbox=SimpleNamespace(workdir=tmp_path),
        audio_embed=lambda b: list(audio_vec),
        text_embed=_fake_text_embed,
    )


# ---- pure math ----

def test_cosine_identical_orthogonal_zero():
    assert cosine([1.0, 0.0], [1.0, 0.0]) == 1.0
    assert cosine([1.0, 0.0], [0.0, 1.0]) == 0.0
    assert cosine([0.0, 0.0], [1.0, 1.0]) == 0.0       # zero vector
    assert cosine([1.0], [1.0, 0.0]) == 0.0            # length mismatch


def test_rank_labels_orders_best_first_with_stable_ties():
    ranked = rank_labels(
        [1.0, 0.0],
        ["b", "a", "c"],
        [[0.0, 1.0], [0.0, 1.0], [1.0, 0.0]],
    )
    assert ranked[0] == ("c", 1.0)
    assert [label for label, _ in ranked[1:]] == ["a", "b"]  # tie -> alphabetical


def test_rank_labels_length_mismatch_raises():
    try:
        rank_labels([1.0], ["a"], [])
    except ValueError as e:
        assert "same length" in str(e)
    else:
        raise AssertionError("expected ValueError")


# ---- WAV decoding (stdlib) ----

def test_decode_wav_mono_and_stereo_downmix():
    mono, rate = decode_wav(_wav_bytes(n=4))
    assert rate == 8000 and len(mono) == 4
    assert abs(mono[0] - 0.5) < 1e-3                   # 16384/32768
    stereo, _ = decode_wav(_wav_bytes(n=4, channels=2))
    assert len(stereo) == 4                            # downmixed to mono


def test_decode_wav_rejects_malformed_as_valueerror():
    # Malformed / truncated bytes make stdlib ``wave`` raise wave.Error or
    # EOFError; decode_wav must normalise those to ValueError so the tool's
    # _run (which only catches ValueError/ImportError) returns an error string
    # rather than letting the exception escape.
    for bad in (b"", b"\xff" * 100, b"RIFFxxxxWAVE"):
        try:
            decode_wav(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"expected ValueError for {bad!r}")


def test_decode_wav_rejects_oversized_audio(monkeypatch):
    # Without a cap, decode_wav would materialize one Python float per PCM
    # sample -> in-process OOM on attacker-sized audio. The cap must reject
    # before allocating, both on raw byte length and on a lying/huge header.
    import maverick.tools.audio_understanding as au

    monkeypatch.setattr(au, "MAX_AUDIO_BYTES", 64)
    big = _wav_bytes(n=1000)  # well over 64 bytes
    try:
        au.decode_wav(big)
    except ValueError as e:
        assert "too large" in str(e)
    else:
        raise AssertionError("expected ValueError for oversized audio")
    # A small, in-cap clip still decodes fine.
    monkeypatch.setattr(au, "MAX_AUDIO_BYTES", 64 * 1024 * 1024)
    mono, _ = au.decode_wav(_wav_bytes(n=4))
    assert len(mono) == 4


def test_tool_rejects_oversized_audio_file(tmp_path, monkeypatch):
    import maverick.tools.audio_understanding as au

    monkeypatch.setattr(au, "MAX_AUDIO_BYTES", 64)
    audio = tmp_path / "big.wav"
    audio.write_bytes(_wav_bytes(n=1000))
    out = _tool(tmp_path).fn({"op": "embed", "audio_path": str(audio)})
    assert out.startswith("ERROR") and "too large" in out


def test_decode_wav_rejects_non_16bit():
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(1)
        w.setframerate(8000)
        w.writeframes(b"\x00\x01")
    try:
        decode_wav(buf.getvalue())
    except ValueError as e:
        assert "16-bit" in str(e)
    else:
        raise AssertionError("expected ValueError")


# ---- tool: classify / embed ----

def test_classify_ranks_labels(tmp_path):
    audio = tmp_path / "clip.wav"
    audio.write_bytes(_wav_bytes())
    out = _tool(tmp_path).fn({
        "op": "classify",
        "audio_path": str(audio),
        "labels": ["glass breaking", "dog barking", "siren"],
    })
    assert out.startswith("top: dog barking")
    lines = out.splitlines()
    assert lines[1].strip().startswith("dog barking")
    assert len(lines) == 4  # top line + 3 ranked labels


def test_classify_is_default_op_and_validates_labels(tmp_path):
    audio = tmp_path / "clip.wav"
    audio.write_bytes(_wav_bytes())
    t = _tool(tmp_path)
    assert "top:" in t.fn({"audio_path": str(audio), "labels": ["siren"]})
    assert "labels" in t.fn({"audio_path": str(audio)})            # missing
    assert t.fn({"audio_path": str(audio), "labels": [" "]}).startswith("ERROR")


def test_embed_returns_json_vector(tmp_path):
    audio = tmp_path / "clip.wav"
    audio.write_bytes(_wav_bytes())
    out = _tool(tmp_path).fn({"op": "embed", "audio_path": str(audio)})
    assert json.loads(out) == [0.9, 0.1, 0.0]


def test_missing_file_and_unknown_op(tmp_path):
    t = _tool(tmp_path)
    assert "not found" in t.fn({"audio_path": str(tmp_path / "nope.wav"),
                                "labels": ["siren"]})
    assert "audio_path is required" in t.fn({"labels": ["siren"]})
    assert "unknown op" in t.fn({"op": "bogus", "audio_path": "x.wav"})


def test_sandbox_confines_audio_path(tmp_path):
    class _SB:
        workdir = str(tmp_path)
    t = audio_understanding(sandbox=_SB(), audio_embed=lambda b: [1.0],
                            text_embed=lambda ls: [[1.0] for _ in ls])
    out = t.fn({"audio_path": "../../etc/passwd", "labels": ["siren"]})
    assert out.startswith("ERROR") and "escapes the workspace" in out


def test_default_embedder_reports_actionable_install_hint(tmp_path, monkeypatch):
    # Hide transformers so the default CLAP adapter's lazy import fails.
    monkeypatch.setitem(sys.modules, "transformers", None)
    monkeypatch.setitem(sys.modules, "torch", None)
    import maverick.tools.audio_understanding as au
    monkeypatch.setattr(au, "_clap", None)
    audio = tmp_path / "clip.wav"
    audio.write_bytes(_wav_bytes())
    out = audio_understanding(sandbox=SimpleNamespace(workdir=tmp_path)).fn({"audio_path": str(audio), "labels": ["siren"]})
    assert out.startswith("ERROR") and "packages/maverick-core[clap]" in out


def test_factory_registered_in_base_registry():
    from maverick.tools import base_registry

    class _W:
        pass

    names = set(getattr(base_registry(world=_W(), sandbox=None), "_tools", {}).keys())
    assert "audio_understanding" in names
