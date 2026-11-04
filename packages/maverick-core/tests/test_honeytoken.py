"""honeytoken: decoy-credential mint + exfiltration tripwire."""
from __future__ import annotations

from maverick.tools.honeytoken import honeytoken


def _mint(**kw):
    return honeytoken().fn({"op": "mint", **kw})


def _scan(text):
    return honeytoken().fn({"op": "scan", "text": text})


def test_mint_returns_recognizable_token():
    out = _mint(label="db", kind="aws")
    assert out.startswith("OK") and "MAVHT_aws_" in out


def test_mint_tokens_are_unique():
    a = _mint().split()[-1]
    b = _mint().split()[-1]
    assert a != b


def test_scan_clean_when_absent():
    assert _scan("nothing secret here").startswith("CLEAN")


def test_scan_trips_on_planted_token():
    token = _mint(label="x").split()[-1]
    out = _scan(f"leaking creds: {token} oops")
    assert out.startswith("TRIPPED") and token in out


def test_bad_kind_errors():
    assert _mint(kind="nonsense").startswith("ERROR")
