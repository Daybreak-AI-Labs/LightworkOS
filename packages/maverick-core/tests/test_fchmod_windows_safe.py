"""Atomic private writes must not crash on Windows, where os.fchmod doesn't
exist (AttributeError). mkstemp already creates the file owner-only; the chmod
is a POSIX hardening that should be skipped, not fatal."""
from __future__ import annotations

import os

import pytest


@pytest.fixture
def _no_fchmod(monkeypatch):
    """Simulate Windows: os.fchmod raises AttributeError when called."""
    def _boom(*_a, **_k):
        raise AttributeError("module 'os' has no attribute 'fchmod'")
    # Python 3.12 on Windows has no attribute; newer builds may expose a stub.
    monkeypatch.setattr(os, "fchmod", _boom, raising=False)


def test_sealing_atomic_write_survives_no_fchmod(_no_fchmod, tmp_path):
    pytest.importorskip("cryptography")
    from maverick.audit import sealing
    p = tmp_path / "seal.bin"
    sealing._atomic_write_bytes(p, b"hello-bytes")
    assert p.read_bytes() == b"hello-bytes"


def test_learning_cache_save_survives_no_fchmod(_no_fchmod, tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick.cache.learning import LearningCache
    cache = LearningCache(path=tmp_path / "lc.json")
    cache.put("task-x", "result-y", verified_by="verifier:t-1")
    assert (tmp_path / "lc.json").exists()


def test_remediation_config_write_survives_no_fchmod(_no_fchmod, tmp_path):
    from maverick.remediation import _write_config_atomic
    p = tmp_path / "config.toml"
    _write_config_atomic(p, "key = 1\n", prior="")
    assert p.read_text() == "key = 1\n"
