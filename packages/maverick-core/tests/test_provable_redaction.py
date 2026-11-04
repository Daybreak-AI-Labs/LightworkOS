"""Provable redaction: fixpoint redaction + proof, and the redact tool."""
from __future__ import annotations

from maverick import provable_redaction as pr
from maverick.tools.redact import redact_tool

_SECRET = "AKIAIOSFODNN7EXAMPLE"
_EMAIL = "alice@example.com"


def test_redacts_secret_and_pii_and_proves_clean():
    text = f"key {_SECRET} and mail {_EMAIL} please"
    proof = pr.redact_proven(text)
    assert proof.proven is True
    assert proof.residual == []
    assert _SECRET not in proof.redacted
    assert _EMAIL not in proof.redacted
    assert "[REDACTED:" in proof.redacted
    assert proof.passes >= 1


def test_clean_text_is_proven_in_one_pass():
    proof = pr.redact_proven("nothing sensitive here")
    assert proof.proven is True
    assert proof.redacted == "nothing sensitive here"
    assert proof.passes == 1


def test_empty_text():
    proof = pr.redact_proven("")
    assert proof.proven is True and proof.passes == 0


def test_verify_redacted_flags_residue_and_passes_clean():
    assert pr.verify_redacted(f"token {_SECRET}")  # non-empty: residue present
    assert pr.verify_redacted("all clear") == []


def test_redacted_output_is_idempotent():
    once = pr.redact_proven(f"{_SECRET} {_EMAIL}")
    twice = pr.redact_proven(once.redacted)
    assert twice.proven and twice.redacted == once.redacted and twice.passes == 1


def test_not_proven_when_bound_hit(monkeypatch):
    # A detector that never reports clean -> redact_proven exhausts max_passes
    # and returns NOT proven with the residual, instead of a false guarantee.
    monkeypatch.setattr(pr, "_scan_all", lambda t: ["secret:never_clean"])
    proof = pr.redact_proven("whatever", max_passes=3)
    assert proof.proven is False
    assert proof.residual == ["secret:never_clean"]
    assert proof.passes == 3


# ---- redact tool ----

def test_tool_redact_op():
    out = redact_tool().fn({"op": "redact", "text": f"key {_SECRET}"})
    assert "PROVEN clean" in out
    assert _SECRET not in out


def test_tool_verify_op():
    assert "RESIDUAL" in redact_tool().fn({"op": "verify", "text": f"k {_SECRET}"})
    assert "clean" in redact_tool().fn({"op": "verify", "text": "nothing here"})


def test_tool_requires_text():
    assert redact_tool().fn({"op": "redact"}).startswith("ERROR")


def test_tool_default_op_is_redact():
    out = redact_tool().fn({"text": f"mail {_EMAIL}"})
    assert _EMAIL not in out and "pass(es)" in out


def test_tool_registered():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        workdir = "."

    names = set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}).keys())
    assert "redact" in names
