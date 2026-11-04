"""Voice biometric unlock: companion-factor-only, local, deletable."""
from __future__ import annotations

import json

import pytest
from maverick import file_lock
from maverick.file_lock import private_path_is_restricted
from maverick.voice_unlock import DEFAULT_THRESHOLD, VoiceGate


def _embedder(profile_vec):
    """Maps audio bytes to a vector near profile_vec; b"other" far away."""
    def embed(audio: bytes):
        if audio.startswith(b"other"):
            return [-x for x in profile_vec]
        return profile_vec
    return embed


@pytest.fixture
def gate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_VOICE_UNLOCK", "1")
    return VoiceGate(_embedder([0.6, 0.8, 0.0]),
                     store_path=tmp_path / "profiles.json")


def test_enroll_requires_three_samples(gate):
    with pytest.raises(ValueError, match=">= 3 samples"):
        gate.enroll("alice", [b"one", b"two"])


def test_enroll_score_decide(gate):
    gate.enroll("alice", [b"a1", b"a2", b"a3"])
    assert gate.score("alice", b"a-new") == pytest.approx(1.0)
    d = gate.decide("alice", b"a-new")
    assert d.companion_ok is True
    assert "companion factor only" in d.reason


def test_wrong_voice_rejected(gate):
    gate.enroll("alice", [b"a1", b"a2", b"a3"])
    d = gate.decide("alice", b"other-voice")
    assert d.companion_ok is False
    assert "below threshold" in d.reason


def test_unenrolled_rejected(gate):
    d = gate.decide("ghost", b"x")
    assert d.companion_ok is False and "not enrolled" in d.reason


def test_disabled_by_default(tmp_path, monkeypatch):
    monkeypatch.delenv("MAVERICK_VOICE_UNLOCK", raising=False)
    monkeypatch.setattr("maverick.config.load_config", dict)
    g = VoiceGate(_embedder([1.0, 0.0]), store_path=tmp_path / "p.json")
    g_enabled_bypass = g  # enrollment works; DECIDE refuses while disabled
    g_enabled_bypass.enroll("alice", [b"a", b"b", b"c"])
    d = g.decide("alice", b"a")
    assert d.companion_ok is False and "disabled" in d.reason


def test_delete_profile_is_first_class(gate):
    gate.enroll("alice", [b"a1", b"a2", b"a3"])
    assert gate.profiles() == ["alice"]
    assert gate.delete_profile("alice") is True
    assert gate.profiles() == []
    assert gate.delete_profile("alice") is False


def test_store_holds_embeddings_not_audio(gate, tmp_path):
    gate.enroll("alice", [b"RAW-AUDIO-1", b"RAW-AUDIO-2", b"RAW-AUDIO-3"])
    raw = (tmp_path / "profiles.json").read_bytes()
    assert b"RAW-AUDIO" not in raw          # never raw audio
    # The embedding [0.6, 0.8, 0.0] is stored only inside the sealed value. Check every field
    # but the enrolment time, whose digits can contain "0.6" by chance.
    profile = json.loads(raw)["alice"]
    assert set(profile) == {"sealed", "enrolled_at", "samples"}
    clear = json.dumps({key: value for key, value in profile.items() if key != "enrolled_at"})
    assert "0.6" not in clear and "0.8" not in clear
    assert private_path_is_restricted(tmp_path / "profiles.json", 0o600)


def test_threshold_configurable(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_VOICE_UNLOCK", "1")
    strict = VoiceGate(_embedder([1.0, 0.0]), threshold=1.01,
                       store_path=tmp_path / "p.json")
    strict.enroll("alice", [b"a", b"b", b"c"])
    assert strict.decide("alice", b"a").companion_ok is False
    assert DEFAULT_THRESHOLD == 0.80


def test_store_created_without_readable_temp_window(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_VOICE_UNLOCK", "1")
    gate = VoiceGate(_embedder([0.6, 0.8, 0.0]),
                     store_path=tmp_path / "private" / "profiles.json")

    private_before_write = []
    real_secure_mkstemp = file_lock._secure_mkstemp

    def inspect_private_temp(directory, *, prefix, suffix, mode):
        fd, tmp = real_secure_mkstemp(
            directory,
            prefix=prefix,
            suffix=suffix,
            mode=mode,
        )
        private_before_write.append(private_path_is_restricted(tmp, mode))
        return fd, tmp

    monkeypatch.setattr(file_lock, "_secure_mkstemp", inspect_private_temp)

    gate.enroll("alice", [b"a1", b"a2", b"a3"])

    # The profile store (and, on first use, the at-rest key that seals it).
    assert private_before_write and all(private_before_write)
    assert private_path_is_restricted(tmp_path / "private", 0o700)
    assert private_path_is_restricted(tmp_path / "private" / "profiles.json", 0o600)
    assert not list((tmp_path / "private").glob("*.tmp"))


def test_concurrent_enroll_does_not_lose_profiles(gate):
    """enroll does a load-modify-save; without the lock two concurrent enrolls
    of different speakers clobber each other. All N must survive."""
    import threading

    n = 16

    def do(i: int):
        gate.enroll(f"spk{i:03d}", [b"a1", b"a2", b"a3"])

    threads = [threading.Thread(target=do, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(gate.profiles()) == n


def test_custom_parent_is_verified_without_acl_takeover(tmp_path, monkeypatch):
    parent = tmp_path / "caller-owned"
    parent.mkdir()
    seen = []
    monkeypatch.setattr(
        file_lock,
        "ensure_private_directory",
        lambda path: pytest.fail(f"custom parent was mutated: {path}"),
    )
    monkeypatch.setattr(
        file_lock,
        "require_private_directory",
        lambda path: seen.append(path),
    )
    gate = VoiceGate(
        _embedder([0.6, 0.8, 0.0]),
        store_path=parent / "profiles.json",
    )

    gate._ensure_parent()

    assert seen == [parent]


def test_profile_is_bound_to_its_person(gate, tmp_path):
    """A sealed profile copied under another name does not open."""
    import json

    gate.enroll("alice", [b"a1", b"a2", b"a3"])
    path = tmp_path / "profiles.json"
    data = json.loads(path.read_text())
    data["mallory"] = data["alice"]
    path.write_text(json.dumps(data))
    assert gate.score("alice", b"a") == pytest.approx(1.0)
    assert gate.score("mallory", b"a") is None
