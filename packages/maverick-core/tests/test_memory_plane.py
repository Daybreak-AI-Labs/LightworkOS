"""Tests for the Institutional Memory plane attestation.

The cross-vendor property is the point, and it is the easiest thing here to
oversell: a plane with one vendor connected has demonstrated nothing, and a
plane whose records cannot be attributed has demonstrated less than nothing.
Most of these tests pin the gradings that refuse to claim it.
"""
from __future__ import annotations

import json

import pytest
from maverick import memory_plane as mp
from maverick.attestation_verify import (
    FAILS,
    HOLDS,
    INDETERMINATE,
    NOT_APPLICABLE,
)

crypto = pytest.importorskip(
    "cryptography", reason="attestations are always signed")


@pytest.fixture(autouse=True)
def _fresh_audit_writer(monkeypatch):
    """Rebind the process-global audit writer to this test's home.

    ``writer._default`` is created once with whatever ``data_dir("audit")``
    resolved to first, so without this a later test's ``record()`` calls land in
    an earlier test's temp directory and the attestation reads an empty chain.
    """
    from maverick.audit import writer
    monkeypatch.setattr(writer, "_default", None, raising=False)
    writer._defaults.clear()
    yield
    writer._defaults.clear()


def _key() -> str:
    from maverick.attestation import publisher_key
    return publisher_key()[1]


def _roster(vendors=()):
    return {"agents": [{"agent_id": "agent-1", "vendor": v} for v in vendors]}


def _log_activity(vendors=(), records=0, unprovenanced=0, recalls=0):
    """Write real signed fleet-activity rows -- the evidence the bundle reads.

    Deliberately the production shape: ``fleet_memory._audit`` is what stamps
    these, so a change to its payload keys breaks these tests rather than
    silently emptying the attestation.
    """
    from maverick.audit.signing import AuditSigner
    from maverick.paths import data_dir
    root = data_dir("audit")
    root.mkdir(parents=True, exist_ok=True)
    signer = AuditSigner(root / "2026-01-01.ndjson")

    def _row(**kw):
        assert signer.write({"ts": 1767225000.0, "kind": "learning_update",
                             "agent": "fleet_memory", **kw})
    per = (records // len(vendors)) if vendors else 0
    for vendor in vendors:
        for _ in range(per):
            _row(fleet="ingest", source=f"{vendor}:agent-1", fleet_kind="lesson")
        for _ in range(recalls):
            _row(fleet="recall", source=f"{vendor}:agent-1")
    for _ in range(unprovenanced):
        _row(fleet="ingest", source="")


@pytest.fixture
def fleet(monkeypatch):
    """Roster from a test-controlled reply; activity from the signed chain."""
    import maverick.fleet_memory as fm
    state = {"status": _roster(), "enabled": True}
    monkeypatch.setattr(fm, "status", lambda: state["status"])
    monkeypatch.setattr(fm, "enabled", lambda: state["enabled"])
    state["roster"] = lambda *v: state.update({"status": _roster(v)})
    return state


def _bundle(**kw) -> dict:
    return mp.sign(mp.build(now=1767225600.0, **kw))


def _claim(result, name):
    return next(c for c in result.claims if c.name == name)


def _verify(bundle):
    return mp.verify(bundle, trusted_key_hex=_key())


class _Goal:
    def __init__(self, gid, domain):
        self.id, self.domain, self.title = gid, domain, "do the thing"


class _Episode:
    def __init__(self, cost, outcome, ts):
        self.cost_dollars, self.outcome, self.started_at = cost, outcome, ts


class _World:
    """Minimal world model: goals per department with cost trending down."""

    def __init__(self, plan):
        self._plan = plan

    def list_goals(self, limit=2000, **kw):
        return [_Goal(i, dept) for i, (dept, _) in enumerate(self._plan)]

    def list_episodes(self, goal_id=None, **kw):
        _dept, costs = self._plan[goal_id]
        return [_Episode(c, "success", float(i)) for i, c in enumerate(costs)]


# ---- the cross-vendor claim: the easiest thing to oversell ------------------

def test_one_vendor_is_not_cross_vendor(fleet):
    """A pass here would sell the one property the model vendors structurally
    cannot copy on the strength of an empty room."""
    fleet["roster"]("anthropic")
    _log_activity(vendors=("anthropic",), records=10)
    claim = _claim(_verify(_bundle()), "cross_vendor")
    assert claim.status == NOT_APPLICABLE
    assert "nothing crossed a vendor boundary" in claim.detail


def test_no_vendors_at_all_is_inapplicable(fleet):
    claim = _claim(_verify(_bundle()), "cross_vendor")
    assert claim.status == NOT_APPLICABLE


def test_two_vendors_sharing_the_plane_holds(fleet):
    fleet["roster"]("anthropic", "microsoft")
    _log_activity(vendors=("anthropic", "microsoft"), records=20)
    claim = _claim(_verify(_bundle()), "cross_vendor")
    assert claim.status == HOLDS
    assert "2 contributing vendors" in claim.detail


def test_registered_vendors_without_records_prove_nothing(fleet):
    """Registering an agent is not the same as it having contributed."""
    fleet["roster"]("anthropic", "microsoft")  # registered, never contributed
    claim = _claim(_verify(_bundle()), "cross_vendor")
    assert claim.status == NOT_APPLICABLE
    assert "0 contributing vendor(s)" in claim.detail


def test_unattributable_records_fail_the_claim(fleet):
    """A lesson of unknown origin is exactly what the governed plane exists to
    prevent, so it is a failure rather than a smaller pass."""
    fleet["roster"]("anthropic", "microsoft")
    _log_activity(vendors=("anthropic", "microsoft"), records=20, unprovenanced=3)
    result = _verify(_bundle())
    claim = _claim(result, "cross_vendor")
    assert claim.status == FAILS
    assert not result.ok


def test_an_unreadable_plane_is_not_an_empty_plane(monkeypatch):
    """'No cross-vendor activity' and 'we could not read the plane' are
    opposite findings, and the first is what the second would masquerade as."""
    import maverick.fleet_memory as fm

    def _boom():
        raise RuntimeError("inbox unreadable")
    monkeypatch.setattr(fm, "status", _boom)
    bundle = _bundle()
    assert any("unreadable" in w for w in bundle["warnings"])
    assert _claim(_verify(bundle), "cross_vendor").status == INDETERMINATE


def test_a_disabled_plane_reports_its_totals_as_historical(fleet):
    fleet["roster"]("anthropic", "microsoft")
    _log_activity(vendors=("anthropic", "microsoft"), records=20)
    fleet["enabled"] = False
    claim = _claim(_verify(_bundle()), "cross_vendor")
    assert claim.status == HOLDS
    assert any("switched off" in n for n in claim.notes)


# ---- the compounding claim: it must not be fakeable --------------------------

def test_too_few_runs_is_unproven_not_absent_improvement(fleet):
    claim = _claim(_verify(_bundle()), "compounding")
    assert claim.status == INDETERMINATE
    assert "noise rather than evidence" in claim.detail


def test_a_department_getting_cheaper_holds(fleet):
    world = _World([("finance", [10.0, 10.0, 10.0, 2.0, 2.0, 2.0])])
    claim = _claim(_verify(_bundle(world=world)), "compounding")
    assert claim.status == HOLDS
    assert "1 of 1" in claim.detail


def test_a_plane_that_has_not_paid_off_says_so(fleet):
    """An honest negative result, not an integrity failure — but the customer
    is told rather than shown a green badge."""
    world = _World([("finance", [2.0, 2.0, 2.0, 10.0, 10.0, 10.0])])
    result = _verify(_bundle(world=world))
    claim = _claim(result, "compounding")
    assert claim.status == FAILS
    assert "0 of 1" in claim.detail
    assert not result.ok


def test_compounding_is_measured_per_department(fleet):
    world = _World([("finance", [10.0] * 3 + [2.0] * 3),
                    ("legal", [5.0] * 3 + [1.0] * 3)])
    curves = mp.compounding_by_department(world)
    assert {c.department for c in curves} == {"finance", "legal"}
    assert all(c.improving for c in curves)


def test_a_goal_with_no_department_lands_in_unassigned(fleet):
    world = _World([("", [10.0] * 3 + [2.0] * 3)])
    curves = mp.compounding_by_department(world)
    assert curves and curves[0].department == "unassigned"


def test_a_world_read_failure_degrades_to_no_curve(fleet):
    class _Broken:
        def list_goals(self, **kw):
            raise RuntimeError("db gone")
    assert mp.compounding_by_department(_Broken()) == []


def test_a_malformed_department_curve_fails(fleet):
    bundle = json.loads(json.dumps(_bundle()))
    bundle["claims"]["compounding"]["departments"] = ["not-an-object"]
    bundle.pop("signature")
    assert _claim(_verify(mp.sign(bundle)), "compounding").status == FAILS


# ---- isolation: honestly ungradable from inside one bundle ------------------

def test_isolation_is_not_claimed_from_a_single_bundle(fleet):
    """Every record is under this tenant's root because that is the only place
    we looked. A tautology dressed as a proof is worse than an admitted gap."""
    claim = _claim(_verify(_bundle()), "tenant_isolation")
    assert claim.status == NOT_APPLICABLE
    assert "comparing two tenants' bundles" in claim.detail
    assert any("tautology" in n for n in claim.notes)


def test_the_tenant_root_is_published_as_a_digest_not_a_path(fleet):
    """A filesystem layout is not something an attestation should leak, and a
    digest is enough to compare two tenants."""
    binding = _bundle()["tenant_binding"]
    assert len(binding["root_sha256"]) == 64
    assert "/" not in json.dumps(binding)


# ---- the trust anchor shared with the platform attestation -----------------

def test_verification_fails_closed_without_a_trust_anchor(fleet):
    result = mp.verify(_bundle(), trusted_key_hex="")
    assert not result.ok
    assert "trusted public key is required" in result.reason


def test_a_bundle_signed_by_another_key_is_rejected(fleet):
    result = mp.verify(_bundle(), trusted_key_hex="ab" * 32)
    assert not result.ok
    assert "not the trusted key" in result.reason


def test_editing_the_body_breaks_the_signature(fleet):
    bundle = _bundle()
    bundle["claims"]["cross_vendor"]["vendors"] = ["anthropic", "microsoft"]
    assert not _verify(bundle).ok


def test_an_unsigned_bundle_is_refused(fleet):
    assert not _verify(mp.build(now=1.0)).ok


def test_a_foreign_kind_is_not_mistaken_for_a_memory_attestation(fleet):
    """The platform attestation and this one share a spine, not an identity."""
    from maverick import attestation
    other = attestation.sign(attestation.build(now=1.0))
    result = mp.verify(other, trusted_key_hex=_key())
    assert not result.ok
    assert "not a maverick-memory-plane" in result.reason


def test_an_unknown_schema_version_is_refused(fleet):
    bundle = json.loads(json.dumps(_bundle()))
    bundle["schema_version"] = 99
    bundle.pop("signature")
    assert not _verify(mp.sign(bundle)).ok


# ---- export / integration ---------------------------------------------------

def test_export_writes_a_bundle_that_verifies(fleet, tmp_path):
    fleet["roster"]("anthropic", "microsoft")
    _log_activity(vendors=("anthropic", "microsoft"), records=20)
    out = mp.export(tmp_path / "memory.json", now=1767225600.0)
    assert out.exists()
    result = mp.verify_file(out, trusted_key_hex=_key())
    assert result.ok
    assert _claim(result, "cross_vendor").status == HOLDS


def test_verify_of_a_missing_bundle_fails_closed(tmp_path):
    result = mp.verify_file(tmp_path / "nope.json", trusted_key_hex=_key())
    assert not result.ok
    assert "unreadable bundle" in result.reason


def test_a_bundle_that_proves_nothing_says_so(fleet):
    from maverick.attestation_verify import format_report
    result = _verify(_bundle())
    assert result.ok
    assert not any(c.status == HOLDS for c in result.claims)
    assert "establishes no claim" in format_report(result)


def test_the_real_fleet_memory_plane_is_readable_end_to_end(monkeypatch):
    """No monkeypatched status: prove the builder works against the module it
    is attesting, not just against a fixture shaped like it."""
    monkeypatch.setenv("MAVERICK_FLEET_MEMORY", "1")
    # Signing is ON by default in production; the suite's conftest sets
    # MAVERICK_SECURE_DEFAULT=0, which turns it off. The attestation counts only
    # signed rows, so the realistic posture has to be restored here.
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    import maverick.fleet_memory as fm
    assert fm.register_agent("agent-1", "microsoft", description="copilot")
    ok, reason = fm.ingest({
        "agent_id": "agent-1", "vendor": "microsoft", "kind": "lesson",
        "goal_text": "reconcile the ledger", "reflection": "check FX first",
        "domain": "finance"})
    assert ok, reason
    bundle = mp.build(now=1767225600.0)
    ev = bundle["claims"]["cross_vendor"]
    assert ev["available"] and ev["records"] == 1
    assert "microsoft" in ev["vendors"]
    assert ev["unprovenanced_records"] == 0


def test_a_vendor_that_is_not_on_the_roster_does_not_count(fleet):
    """`ingest` is fail-closed on registration, so an ingest naming an
    unregistered vendor should not exist. Treating one as evidence would let a
    forged or stale source string manufacture cross-vendor from one
    contributor."""
    fleet["roster"]("anthropic")
    _log_activity(vendors=("anthropic", "microsoft"), records=20)
    bundle = _bundle()
    ev = bundle["claims"]["cross_vendor"]
    assert ev["vendors"] == ["anthropic"]
    assert any("not on the roster" in w for w in bundle["warnings"])
    assert _claim(_verify(bundle), "cross_vendor").status == NOT_APPLICABLE


def test_negative_costs_cannot_manufacture_a_compounding_curve(fleet):
    """`improving` is a bare warm < cold comparison, which episodes logged at
    -$1e9 and -$1e12 satisfy beautifully. The claim's whole value is being the
    un-fakeable half of the attestation."""
    world = _World([("finance", [-1e9] * 3 + [-1e12] * 3)])
    curves = mp.compounding_by_department(world)
    assert curves and curves[0].improving is False
    assert _claim(_verify(_bundle(world=world)), "compounding").status == FAILS


def test_a_zero_cost_baseline_is_not_evidence(fleet):
    """A cold cost of 0 makes any warm cost look like a regression or a win
    depending on sign; neither is a measurement."""
    world = _World([("finance", [0.0] * 3 + [0.0] * 3)])
    curves = mp.compounding_by_department(world)
    assert all(not c.improving for c in curves)


def test_unsigned_fleet_rows_are_not_counted_as_evidence(fleet, monkeypatch):
    """The bundle's justification for preferring the chain over the inbox is
    that an audit row is signed. Counting bare rows would assert cross-vendor
    totals over evidence nobody signed."""
    from maverick.paths import data_dir
    root = data_dir("audit")
    root.mkdir(parents=True, exist_ok=True)
    (root / "2026-01-01.ndjson").write_text("\n".join(
        json.dumps({"ts": 1.0, "kind": "learning_update",
                    "agent": "fleet_memory", "fleet": "ingest",
                    "source": f"{v}:agent-1"})
        for v in ("anthropic", "microsoft")) + "\n", encoding="utf-8")
    fleet["roster"]("anthropic", "microsoft")
    bundle = mp.build(now=1767225600.0)
    assert bundle["claims"]["cross_vendor"]["records"] == 0
    assert any("carry no signature" in w for w in bundle["warnings"])


def test_the_verifier_recomputes_improving_from_the_numbers(fleet):
    """Trusting the published boolean let a bundle claim a department that got
    nine times more expensive and eight-tenths less reliable was compounding."""
    bundle = json.loads(json.dumps(_bundle()))
    bundle["claims"]["compounding"]["departments"] = [{
        "department": "sales", "runs": 50, "cold_cost": 1.0, "warm_cost": 9.0,
        "cold_success": 0.9, "warm_success": 0.1, "improving": True}]
    bundle.pop("signature")
    result = _verify(mp.sign(bundle))
    assert _claim(result, "compounding").status == FAILS


def test_the_verifier_rejects_a_negative_cost_curve_it_did_not_build(fleet):
    """`_is_real_cost_pair` ran only at build time, so a hand-made bundle
    carrying negative costs graded HOLDS at verify time."""
    bundle = json.loads(json.dumps(_bundle()))
    bundle["claims"]["compounding"]["departments"] = [{
        "department": "sales", "runs": 50, "cold_cost": -1e9,
        "warm_cost": -1e12, "cold_success": 1.0, "warm_success": 1.0,
        "improving": True}]
    bundle.pop("signature")
    assert _claim(_verify(mp.sign(bundle)), "compounding").status == FAILS


def test_a_missing_crypto_library_is_not_a_tamper_accusation(fleet, monkeypatch):
    """Telling a customer the publisher's signature is bad because an optional
    extra is absent is the worst possible way to report a missing dependency."""
    import maverick.memory_plane as mod
    bundle = _bundle()
    monkeypatch.setattr(mod, "_have_crypto", lambda: False)
    result = mp.verify(bundle, trusted_key_hex=_key())
    assert not result.ok
    assert "cryptography" in result.reason
    assert "does not verify" not in result.reason


def test_the_activity_scan_is_bounded_and_says_when_it_stopped(fleet,
                                                               monkeypatch):
    """Unsealing every day-file of a multi-year audit history on each export is
    not something an attestation should do, and a short count that looks total
    understates the very claim the bundle makes."""
    import maverick.memory_plane as mod
    from maverick.paths import data_dir
    monkeypatch.setattr(mod, "_MAX_ACTIVITY_DAYS", 2)
    root = data_dir("audit")
    root.mkdir(parents=True, exist_ok=True)
    from maverick.audit.signing import AuditSigner
    for day in ("2026-01-01", "2026-01-02", "2026-01-03", "2026-01-04"):
        s = AuditSigner(root / f"{day}.ndjson")
        assert s.write({"ts": 1.0, "kind": "learning_update",
                        "agent": "fleet_memory", "fleet": "ingest",
                        "source": "anthropic:agent-1"})
    fleet["roster"]("anthropic")
    bundle = mp.build(now=1767225600.0)
    assert bundle["claims"]["cross_vendor"]["records"] == 2
    assert any("lower bound" in w for w in bundle["warnings"])
