"""Signed approve/reject tokens for actionable channel approvals."""
from __future__ import annotations

import time

import pytest
from maverick.flow import approvals


@pytest.fixture(autouse=True)
def _secret(monkeypatch):
    monkeypatch.setenv("MAVERICK_FLOW_APPROVAL_SECRET", "test-signing-secret")  # pragma: allowlist secret


def test_mint_verify_roundtrip():
    tok = approvals.mint_token("run-1", "approved", cursor="a", prompt="ok?", updated=123.0)
    assert tok
    claim = approvals.verify_token(tok)
    assert claim == {"run_id": "run-1", "decision": "approved",
                     "cursor": "a", "prompt": "ok?", "updated": 123.0,
                     "tenant": "", "assignee": "", "owner": "",
                     "binding_sha256": ""}


def test_token_roundtrip_binds_exact_reviewed_operation():
    binding = "a" * 64
    token = approvals.mint_token(
        "run-bound", "approved", cursor="gate", prompt="ship?",
        updated=12.0, binding_sha256=binding,
    )
    assert approvals.verify_token(token)["binding_sha256"] == binding
    assert approvals.mint_token(
        "run-bound", "approved", cursor="gate", prompt="ship?",
        updated=12.0, binding_sha256="not-a-digest",
    ) is None


def test_reject_token_carries_its_decision():
    claim = approvals.verify_token(approvals.mint_token("run-2", "rejected", cursor="b", prompt="stop?", updated=456.0))
    assert claim["decision"] == "rejected"


def test_tampered_token_is_rejected():
    tok = approvals.mint_token("run-1", "approved", cursor="a", prompt="ok?", updated=123.0)
    body, _, sig = tok.partition(".")
    # flip the last hex char of the signature
    bad = body + "." + sig[:-1] + ("0" if sig[-1] != "0" else "1")
    assert approvals.verify_token(bad) is None


def test_non_ascii_signature_is_rejected_not_raised():
    tok = approvals.mint_token("run-1", "approved", cursor="a", prompt="ok?", updated=123.0)
    body, _, sig = tok.partition(".")
    # The link's query string is attacker-controlled: a non-ASCII signature is
    # an invalid link, not a TypeError from the comparison.
    assert approvals.verify_token(body + "." + "é" * len(sig)) is None


def test_swapped_body_is_rejected():
    # a body from a different run won't match the signature of this one
    other = approvals.mint_token("run-OTHER", "approved", cursor="a", prompt="ok?", updated=123.0).partition(".")[0]
    sig = approvals.mint_token("run-1", "approved", cursor="a", prompt="ok?", updated=123.0).partition(".")[2]
    assert approvals.verify_token(f"{other}.{sig}") is None


def test_expired_token_is_rejected():
    past = time.time() - 10
    tok = approvals.mint_token("run-1", "approved", cursor="a", prompt="ok?", updated=123.0, ttl=1, now=past)
    assert approvals.verify_token(tok, now=past) is not None   # valid at mint instant
    assert approvals.verify_token(tok, now=past + 5) is None    # well past the 1s ttl
    assert approvals.verify_token(tok) is None                 # and vs real now (~10s later)


def test_invalid_decision_mints_nothing():
    assert approvals.mint_token("run-1", "maybe", cursor="a", prompt="ok?", updated=123.0) is None


def test_no_secret_fails_closed(monkeypatch):
    monkeypatch.delenv("MAVERICK_FLOW_APPROVAL_SECRET", raising=False)
    # no [webhooks] secret either -> mint + verify both fail closed
    assert approvals.mint_token("run-1", "approved", cursor="a", prompt="ok?", updated=123.0) is None
    assert approvals.verify_token("anything.deadbeef") is None


def test_approval_secret_must_not_equal_an_external_webhook_secret(monkeypatch):
    monkeypatch.setenv("MAVERICK_LINEAR_WEBHOOK_SECRET", "test-signing-secret")
    assert approvals.mint_token("run-1", "approved", cursor="a", updated=123.0) is None


def test_approval_links_build_both_urls():
    links = approvals.approval_links("https://ops.example.com/", "run-9", cursor="approve", prompt="ship?", updated=789.0)
    assert links["approve"].startswith("https://ops.example.com/flow/approve?token=")
    assert "/flow/approve?token=" in links["reject"]
    # each link's token verifies to the matching decision
    atok = links["approve"].split("token=")[1]
    rtok = links["reject"].split("token=")[1]
    assert approvals.verify_token(atok)["decision"] == "approved"
    assert approvals.verify_token(rtok)["decision"] == "rejected"


def test_tenant_claim_selects_same_tenant_secret_during_public_verify(monkeypatch):
    from maverick.paths import current_tenant_id

    secrets = {"": "root-secret", "acme": "acme-secret", "globex": "globex-secret"}
    monkeypatch.setattr(
        approvals,
        "_secret",
        lambda: secrets.get(current_tenant_id() or ""),
    )
    token = approvals.mint_token(
        "run-acme", "approved", cursor="gate", prompt="ship?",
        updated=12.0, tenant="acme",
    )
    assert token
    # Verification begins in the unscoped public app context but must select
    # the signed tenant's key before authenticating and returning the claim.
    claim = approvals.verify_token(token)
    assert claim and claim["tenant"] == "acme" and claim["run_id"] == "run-acme"
