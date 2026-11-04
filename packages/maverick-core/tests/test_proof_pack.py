"""The Proof Pack composes real evidence into one signed, honest bundle.

The hard sections (governance / reliability / perf) run against the real code
here; the key-gated sections report their status honestly and never fabricate a
number. See maverick/proof_pack.py and proof/run_proof.py.
"""
from __future__ import annotations

import json
import time
from types import SimpleNamespace

import pytest
from maverick import proof_pack


class _FakeWorld:
    """Duck-typed world: enough for compounding_metric + workforce_value."""

    def __init__(self, goals, episodes):
        self._goals = goals
        self._episodes = episodes

    def list_goals(self, limit=2000, **kw):
        return self._goals

    def list_episodes(self, goal_id=None, limit=5000, **kw):
        if goal_id is None:
            return self._episodes
        return [e for e in self._episodes if e.goal_id == goal_id]

    def get_goal(self, goal_id):
        return next((g for g in self._goals if g.id == goal_id), None)

    def close(self):
        pass


def test_build_runs_hard_sections_and_is_honest(monkeypatch, tmp_path):
    # Deterministic: no provider key -> benchmarks NOT_RUN.
    monkeypatch.setattr("maverick.config.any_provider_configured", lambda: False)

    from maverick.world_model import WorldModel
    world = WorldModel(tmp_path / "world.db")  # empty -> learning INSUFFICIENT_DATA
    manifest = proof_pack.build(world=world)
    world.close()

    assert manifest["kind"] == "maverick-proof-pack"
    secs = manifest["sections"]
    assert set(secs) == {"governance", "reliability", "perf_sla", "shield_asr",
                         "learning_curve", "benchmarks"}

    # Hard, real, offline sections must pass on the same runner CI uses.
    assert secs["governance"]["status"] == "PASS", secs["governance"]
    assert secs["reliability"]["status"] == "PASS", secs["reliability"]
    assert secs["perf_sla"]["status"] == "PASS", secs["perf_sla"]
    assert manifest["passed"] is True

    # Honest reporting of what can't run here.
    assert secs["learning_curve"]["status"] == "INSUFFICIENT_DATA"
    assert secs["benchmarks"]["status"] == "NOT_RUN"
    assert "run_eval" in secs["benchmarks"]["data"]["reproduce"]
    # The ASR harness is repo-only; either it ran or it degraded cleanly.
    assert secs["shield_asr"]["status"] in {"PASS", "SKIPPED"}

    # The governance section carries all seven guarantees, none failed.
    guarantees = secs["governance"]["data"]["guarantees"]
    assert len(guarantees) == 7
    assert not [g for g in guarantees if not g["passed"]]


def test_build_releases_only_owned_world_handles(monkeypatch):
    import maverick.world_model as world_model

    world = _FakeWorld([], [])
    closed = []
    monkeypatch.setattr(world_model, "open_world", lambda: world)
    monkeypatch.setattr(
        world_model, "close_world_if_owned", lambda candidate: closed.append(candidate)
    )
    evidence = proof_pack.Evidence("test", proof_pack.PASS, "ok", hard=True)
    for name in (
        "collect_governance",
        "collect_reliability",
        "collect_perf_sla",
        "collect_shield_asr",
        "collect_benchmarks",
    ):
        monkeypatch.setattr(proof_pack, name, lambda: evidence)
    monkeypatch.setattr(
        proof_pack,
        "collect_learning",
        lambda candidate, *, human_cost=None: evidence,
    )

    proof_pack.build()

    assert closed == [world]


def test_perf_sla_section_retries_a_transient_breach(monkeypatch):
    # A noisy-neighbor p95 breach on the first attempt must not fail the pack
    # when the immediate re-probe passes; a genuine regression (breaching both
    # attempts) still fails. Thresholds stay untouched.
    from maverick import perf_sla
    bad = perf_sla.SLAResult("world_read_p95_ms", 26.7, 25.0)
    good = perf_sla.SLAResult("world_read_p95_ms", 0.5, 25.0)
    monkeypatch.setattr(perf_sla, "run_all", lambda: [bad])
    monkeypatch.setattr(perf_sla, "CHECKS", (lambda: good,))
    ev = proof_pack.collect_perf_sla()
    assert ev.status == "PASS"
    assert ev.data["results"][0]["measured"] == 0.5   # the re-probe is reported
    monkeypatch.setattr(perf_sla, "CHECKS", (lambda: bad,))
    assert proof_pack.collect_perf_sla().status == "FAIL"


def test_learning_curve_reports_real_compounding():
    now = time.time()  # recent, so workforce_value's 90-day window counts them
    goal = SimpleNamespace(id=1, title="reconcile vendor statements", domain="finance")
    costs = [1.0, 1.0, 0.9, 0.5, 0.4, 0.3]  # later (warm) runs cheaper than early (cold)
    episodes = [
        SimpleNamespace(goal_id=1, cost_dollars=c, outcome="done",
                        started_at=now - (len(costs) - i) * 10.0)
        for i, c in enumerate(costs)
    ]
    ev = proof_pack.collect_learning(_FakeWorld([goal], episodes))

    assert ev.status == "PASS"
    assert ev.data["compounding"], "expected at least one task-class report"
    rep = ev.data["compounding"][0]
    assert rep["improving"] is True
    assert rep["warm_cost"] < rep["cold_cost"]
    assert ev.data["workforce_value"]["deliverables"] == 6


def test_signature_is_tamper_evident():
    pytest.importorskip("cryptography")
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ed25519

    manifest = {"kind": "maverick-proof-pack", "version": 1, "passed": True,
                "sections": {}, "issued_at": 0.0}
    signed = proof_pack.sign(dict(manifest))
    sig = signed.get("signature")
    assert sig and sig["alg"] == "ed25519"

    def _payload(m):
        return json.dumps({k: v for k, v in m.items() if k != "signature"},
                          sort_keys=True, separators=(",", ":")).encode("utf-8")

    pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(sig["pubkey"]))
    pub.verify(bytes.fromhex(sig["sig"]), _payload(signed))  # clean: no raise

    tampered = dict(signed)
    tampered["passed"] = False  # flip the headline verdict
    with pytest.raises(InvalidSignature):
        pub.verify(bytes.fromhex(sig["sig"]), _payload(tampered))


def test_render_markdown_is_executive_readable():
    manifest = {
        "issued_at": 0.0, "passed": True, "hard_sections": ["governance"],
        "environment": {"python": "3.12.0", "platform": "linux", "provider_configured": False},
        "sections": {
            "governance": {"status": "PASS", "summary": "5 proven", "hard": True, "data": {}},
            "benchmarks": {"status": "NOT_RUN", "summary": "no key", "hard": False, "data": {}},
        },
    }
    md = proof_pack.render_markdown(manifest)
    assert "# Lightwork — Proof Pack" in md
    assert "ALL HARD GUARANTEES HOLD" in md
    assert "`governance`" in md and "NOT RUN" in md


def test_ci_gate_fails_on_hard_failure(monkeypatch, tmp_path):
    base = {
        "kind": "maverick-proof-pack", "version": 1, "issued_at": 0.0,
        "environment": {}, "hard_sections": ["governance"],
        "sections": {"governance": {"status": "FAIL", "summary": "broke",
                                    "hard": True, "data": {}}},
        "passed": False,
    }
    monkeypatch.setattr(proof_pack, "sign", lambda m: m)
    monkeypatch.setattr(proof_pack, "build", lambda **kw: dict(base))
    assert proof_pack.main(["--ci", "-o", str(tmp_path)]) == 1

    ok = dict(base)
    ok["passed"] = True
    ok["sections"] = {"governance": {"status": "PASS", "summary": "ok",
                                     "hard": True, "data": {}}}
    monkeypatch.setattr(proof_pack, "build", lambda **kw: dict(ok))
    assert proof_pack.main(["--ci", "-o", str(tmp_path)]) == 0


class TestVerify:
    """The proof manifest must have a shipped, fail-closed verifier."""

    def _signed(self):
        m = {"kind": "maverick-proof-pack", "version": 1, "issued_at": 1.0,
             "sections": {}, "hard_sections": [], "passed": True}
        return proof_pack.sign(m)

    def test_roundtrip_verifies_with_trusted_anchor(self):
        m = self._signed()
        if not m.get("signature"):
            pytest.skip("cryptography/audit key unavailable")
        anchor = m["signature"]["pubkey"]
        ok, reason = proof_pack.verify(m, trusted_pubkey_hex=anchor)
        assert ok, reason

    def test_embedded_key_without_anchor_fails_closed(self):
        m = self._signed()
        if not m.get("signature"):
            pytest.skip("cryptography/audit key unavailable")
        ok, reason = proof_pack.verify(m)
        assert not ok and "trusted pubkey" in reason

    def test_tamper_fails(self):
        m = self._signed()
        if not m.get("signature"):
            pytest.skip("cryptography/audit key unavailable")
        m["passed"] = False  # flip a field after signing
        ok, reason = proof_pack.verify(m, trusted_pubkey_hex=m["signature"]["pubkey"])
        assert not ok and "does not verify" in reason

    def test_wrong_anchor_fails(self):
        m = self._signed()
        if not m.get("signature"):
            pytest.skip("cryptography/audit key unavailable")
        ok, reason = proof_pack.verify(m, trusted_pubkey_hex="ab" * 32)
        assert not ok and "anchor" in reason

    def test_unsigned_fails_closed(self):
        ok, reason = proof_pack.verify({"kind": "x", "signature": None})
        assert not ok and "unsigned" in reason
