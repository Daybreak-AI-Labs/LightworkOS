"""Tests for the Agent Security Plane.

Two failure modes matter more than the happy path, and most of these tests are
about them. Reporting *no detections* from a deployment whose defenses are off
trains an analyst to stop looking. Reporting *contained* when only half the
containment landed leaves a live agent that everyone believes is locked out.
Both are the same shape: a plane that says more than its evidence supports.
"""
from __future__ import annotations

import json

import pytest
from maverick import agent_edr as edr

crypto = pytest.importorskip(
    "cryptography", reason="detections come off the signed audit chain")


@pytest.fixture
def audit_dir(tmp_path):
    d = tmp_path / "audit"
    d.mkdir()
    return d


def _write(audit_dir, rows, day="2026-01-01"):
    from maverick.audit.signing import AuditSigner
    signer = AuditSigner(audit_dir / f"{day}.ndjson")
    for row in rows:
        assert signer.write(dict(row))
    return audit_dir / f"{day}.ndjson"


def _row(kind, **kw):
    base = {"ts": 1_700_000_000.0, "kind": kind, "agent": "worker-1"}
    base.update(kw)
    return base


class _Registry:
    """Stand-in for a live swarm's QuarantineRegistry."""

    def __init__(self, seal_works=True):
        self.sealed = set()
        self._seal_works = seal_works

    def seal(self, agent, reason):
        if self._seal_works:
            self.sealed.add(agent)

    def is_sealed(self, agent):
        return agent in self.sealed

    def unseal_agent(self, agent):
        self.sealed.discard(agent)


# ---- detect -----------------------------------------------------------------

def test_enforcement_rows_become_normalized_detections(audit_dir):
    _write(audit_dir, [
        _row("shield_block", reason="injection in tool schema"),
        _row("egress_blocked", reason="POST to unknown host"),
        _row("capability_denied", tool="wire_transfer", reason="outside grant"),
    ])
    found = edr.detections(audit_dir=audit_dir)
    assert {d.kind for d in found} == {
        edr.INJECTION, edr.EGRESS_BREACH, edr.CAPABILITY_BREACH}
    assert all(d.subject == "worker-1" for d in found)


def test_an_unmapped_event_kind_is_not_invented_into_a_threat(audit_dir):
    """Silence beats guessing. A plane that manufactures detections from rows
    it does not understand teaches its operator to ignore it."""
    _write(audit_dir, [
        _row("tool_call", name="read_file"),
        _row("goal_start"),
        _row("some_future_kind", reason="unknown"),
    ])
    assert edr.detections(audit_dir=audit_dir) == []


def test_severity_is_derived_not_self_declared(audit_dir):
    """A compromised agent gets no say in how loudly its detection rings."""
    _write(audit_dir, [_row("shield_block", severity="low", reason="nothing to see")])
    found = edr.detections(audit_dir=audit_dir)
    assert found[0].severity == edr.HIGH


def test_detections_are_newest_first(audit_dir):
    _write(audit_dir, [
        _row("shield_block", ts=100.0, reason="first"),
        _row("shield_block", ts=300.0, reason="third"),
        _row("shield_block", ts=200.0, reason="second"),
    ])
    found = edr.detections(audit_dir=audit_dir)
    assert [d.ts for d in found] == [300.0, 200.0, 100.0]


def test_filters_narrow_by_subject_severity_and_time(audit_dir):
    _write(audit_dir, [
        _row("shield_block", agent="a", ts=100.0),
        _row("governance_denied", agent="b", ts=200.0),
        _row("shield_block", agent="b", ts=300.0),
    ])
    assert len(edr.detections(subject="b", audit_dir=audit_dir)) == 2
    assert len(edr.detections(min_severity=edr.HIGH, audit_dir=audit_dir)) == 2
    assert len(edr.detections(since=250.0, audit_dir=audit_dir)) == 1


def test_a_row_with_no_attributable_principal_is_still_reported(audit_dir):
    """An unattributed detection is still a detection; dropping it would hide
    exactly the events an attacker would prefer nobody counted."""
    _write(audit_dir, [{"ts": 1.0, "kind": "shield_block", "reason": "x"}])
    found = edr.detections(audit_dir=audit_dir)
    assert found[0].subject == "(unattributed)"


def test_a_malformed_row_does_not_abandon_the_file(audit_dir):
    path = _write(audit_dir, [_row("shield_block", reason="real")])
    path.write_text("{not json\n" + path.read_text(encoding="utf-8"),
                    encoding="utf-8")
    assert len(edr.detections(audit_dir=audit_dir)) == 1


def test_a_missing_audit_directory_is_empty_not_an_error(tmp_path):
    assert edr.detections(audit_dir=tmp_path / "nope") == []


def test_the_timeline_is_incident_order(audit_dir):
    _write(audit_dir, [
        _row("shield_block", ts=300.0), _row("shield_block", ts=100.0)])
    assert [d.ts for d in edr.timeline("worker-1", audit_dir=audit_dir)] == [
        100.0, 300.0]


def test_summary_counts_by_class_severity_and_subject(audit_dir):
    _write(audit_dir, [
        _row("shield_block", agent="a"), _row("shield_block", agent="a"),
        _row("governance_denied", agent="b")])
    s = edr.summary(edr.detections(audit_dir=audit_dir))
    assert s["total"] == 3
    assert s["by_kind"][edr.INJECTION] == 2
    assert s["top_subjects"][0] == ("a", 2)


# ---- posture: the context every detection needs -----------------------------

def test_posture_names_the_defenses_that_are_off(monkeypatch):
    import maverick.capability as cap
    monkeypatch.setattr(cap, "capability_enforced", lambda: False)
    p = edr.posture()
    assert "capabilities" in p.blind_spots
    assert any("not watched" in n for n in p.notes)


def test_posture_reads_the_real_enforcement_authorities(monkeypatch):
    """A posture that disagreed with what is actually enforced is worse than
    none, so it asks the same functions the hot path asks."""
    import maverick.capability as cap
    monkeypatch.setattr(cap, "capability_enforced", lambda: True)
    assert edr.posture().capabilities is True


def test_a_quiet_chain_under_blind_defenses_is_not_a_clean_bill(audit_dir,
                                                                monkeypatch):
    import maverick.capability as cap
    monkeypatch.setattr(cap, "capability_enforced", lambda: False)
    report = edr.incident_report("worker-1", audit_dir=audit_dir)
    text = edr.render_report(report)
    assert "no detections" in text
    assert "defenses OFF" in text
    assert "proves nothing" in text


def test_an_unsigned_chain_is_flagged_in_the_report(audit_dir):
    """Flagged from the rows actually read. An earlier version asked the posture
    whether `cryptography` was importable, which answers a different question
    and would call bare rows tamper-evident on any machine with the library."""
    (audit_dir / "2026-01-01.ndjson").write_text(
        json.dumps({"ts": 1.0, "kind": "shield_block", "agent": "w",
                    "reason": "x"}) + "\n", encoding="utf-8")
    text = edr.render_report(edr.incident_report("w", audit_dir=audit_dir))
    assert "UNSIGNED" in text
    assert "not tamper-evident" in text


# ---- respond ----------------------------------------------------------------

def test_containment_seals_the_live_swarm_and_revokes_authority(audit_dir):
    reg = _Registry()
    result = edr.contain("worker-1", reason="honeytoken", registry=reg)
    assert result.contained
    assert result.sealed and reg.is_sealed("worker-1")
    assert result.revoked == ["worker-1"]
    from maverick.revocation import shared
    assert shared().revoked()["worker-1"].protected is True


def test_a_run_scoped_seal_is_never_reported_as_durable():
    """Compartment seals live in a running swarm's memory; revocations are on
    disk. Blurring them would tell an operator an agent is locked out when the
    seal evaporates at process exit."""
    result = edr.contain("worker-1", reason="x", registry=_Registry())
    assert result.sealed is True
    assert result.seal_is_durable is False
    assert any("run-scoped" in n for n in result.notes)


def test_containment_without_a_live_swarm_says_nothing_was_sealed():
    result = edr.contain("worker-1", reason="x")
    assert result.sealed is False
    assert any("not sealed" in n for n in result.notes)
    assert result.contained  # the revocation still landed


def test_a_seal_that_does_not_take_effect_fails_the_containment():
    result = edr.contain("worker-1", reason="x", registry=_Registry(seal_works=False))
    assert not result.contained
    assert any("did not take effect" in f for f in result.failed)


def test_failed_live_seal_does_not_skip_other_restrictive_authorities():
    applied = []

    result = edr.contain(
        "worker-1",
        reason="x",
        registry=_Registry(seal_works=False),
        durable_apply=lambda: applied.append("external") or True,
    )

    assert applied == ["external"]
    assert result.revoked == ["worker-1"]
    assert not result.contained
    assert any("seal did not take effect" in failure for failure in result.failed)


def test_failed_revocation_does_not_skip_other_restrictive_authorities(monkeypatch):
    import maverick.revocation as rev

    class BrokenRevocationRegistry:
        def revoke(self, *_args, **_kwargs):
            raise OSError("revocation store unavailable")

        def revoked(self):
            return {}

    monkeypatch.setattr(rev, "shared", lambda: BrokenRevocationRegistry())
    registry = _Registry()
    applied = []

    result = edr.contain(
        "worker-1",
        reason="x",
        registry=registry,
        durable_apply=lambda: applied.append("external") or True,
    )

    assert registry.is_sealed("worker-1")
    assert applied == ["external"]
    assert not result.contained
    assert any("revoke failed" in failure for failure in result.failed)


def test_revocation_callback_cannot_apply_dependents_twice(monkeypatch):
    import maverick.revocation as rev

    class DuplicateCallbackRegistry:
        def revoke(self, principal, *, durable_apply=None, **_kwargs):
            assert durable_apply is not None
            durable_apply()
            durable_apply()

        def revoked(self):
            return {"worker-1": object()}

    monkeypatch.setattr(rev, "shared", lambda: DuplicateCallbackRegistry())
    applied = []

    result = edr.contain(
        "worker-1",
        reason="x",
        registry=_Registry(),
        durable_apply=lambda: applied.append("external") or True,
    )

    assert applied == ["external"]
    assert result.contained


def test_revocation_is_confirmed_rather_than_assumed(monkeypatch):
    """A write that silently did not land must not be reported as containment."""
    import maverick.revocation as rev
    snapshot_reads = []

    class _Fake:
        def revoke(
            self, principal, *, reason="", now=None, protected=False,
            durable_apply=None,
        ):
            if durable_apply is not None:
                durable_apply()
            return None
        def revoke_subtree(
            self, principal, edges, *, reason="", now=None, protected=False,
            durable_apply=None,
        ):
            if durable_apply is not None:
                durable_apply()
            return [principal]
        def revoked(self):
            snapshot_reads.append(1)
            return {}
    monkeypatch.setattr(rev, "shared", lambda: _Fake())
    result = edr.contain("worker-1", reason="x")
    assert not result.contained
    assert any("did not take effect" in f for f in result.failed)
    assert snapshot_reads == [1]


def test_containment_revokes_the_whole_capability_subtree():
    result = edr.contain("parent", reason="x",
                         edges={"parent": ["child-a", "child-b"]})
    assert set(result.revoked) == {"parent", "child-a", "child-b"}
    from maverick.revocation import is_revoked
    assert is_revoked("child-b")


def test_containment_is_idempotent():
    first = edr.contain("worker-1", reason="x", registry=_Registry())
    second = edr.contain("worker-1", reason="x again", registry=_Registry())
    assert first.contained and second.contained


def test_an_invalid_subject_is_refused():
    result = edr.contain("", reason="x")
    assert not result.contained
    assert "invalid subject" in result.failed


def test_release_reverses_a_containment():
    reg = _Registry()
    edr.contain("worker-1", reason="x", registry=reg)
    result = edr.release("worker-1", registry=reg)
    assert result.contained
    assert not reg.is_sealed("worker-1")
    from maverick.revocation import is_revoked
    assert not is_revoked("worker-1")


def test_releasing_something_never_contained_says_so():
    result = edr.release("never-touched")
    assert any("was not revoked" in n for n in result.notes)


def test_containment_submits_an_audit_row(tmp_path, monkeypatch):
    seen = {}
    import maverick.audit as audit
    monkeypatch.setattr(audit, "record",
                        lambda kind, **kw: seen.update({"kind": kind, **kw}))
    edr.contain("worker-1", reason="honeytoken tripped", registry=_Registry())
    assert seen["kind"] == "agent_edr_containment"
    assert seen["subject"] == "worker-1"
    assert seen["contained"] is True


def test_an_audit_failure_never_blocks_containment(monkeypatch):
    """Containment is the safety act; telemetry must not be able to veto it."""
    import maverick.audit as audit

    def _boom(*a, **k):
        raise RuntimeError("audit sink down")
    monkeypatch.setattr(audit, "record", _boom)
    result = edr.contain("worker-1", reason="x", registry=_Registry())
    assert result.contained
    assert result.audit_written is False


def test_strict_audit_refusal_propagates_after_containment(monkeypatch):
    import maverick.audit as audit
    from maverick.audit import AuditRefused
    from maverick.revocation import is_revoked

    def _refuse(*args, **kwargs):
        raise AuditRefused("strict audit guarantee")

    monkeypatch.setattr(audit, "record", _refuse)
    with pytest.raises(AuditRefused, match="strict audit"):
        edr.contain("worker-strict", reason="incident", registry=_Registry())
    assert is_revoked("worker-strict")


# ---- prove ------------------------------------------------------------------

def test_the_incident_report_carries_posture_timeline_and_state(audit_dir):
    _write(audit_dir, [
        _row("shield_block", ts=100.0, reason="injection"),
        _row("egress_blocked", ts=200.0, reason="exfil attempt")])
    edr.contain("worker-1", reason="incident")
    report = edr.incident_report("worker-1", audit_dir=audit_dir, now=5.0)
    assert report["currently_revoked"] is True
    assert [d["ts"] for d in report["detections"]] == [100.0, 200.0]
    assert report["summary"]["total"] == 2
    assert "posture" in report


def test_the_report_renders_without_detections(audit_dir):
    text = edr.render_report(edr.incident_report("nobody", audit_dir=audit_dir))
    assert "no detections in the reviewed window" in text


def test_detection_serializes_round_trip(audit_dir):
    _write(audit_dir, [_row("shield_block", reason="x", goal_id=7)])
    d = edr.detections(audit_dir=audit_dir)[0]
    payload = json.loads(json.dumps(d.to_dict()))
    assert payload["kind"] == edr.INJECTION
    assert payload["evidence"]["goal_id"] == 7


def test_containment_serializes_for_the_console():
    payload = edr.contain("w", reason="x", registry=_Registry()).to_dict()
    assert payload["contained"] is True
    assert payload["seal_is_durable"] is False


# ---- bounds, completeness and vacuous success -------------------------------
#
# Three defects a re-read of this module turned up, each the same shape as the
# ones it was written to prevent: a report that says more than it has.

def test_the_sweep_bound_keeps_the_newest_detections(audit_dir):
    """Day-files sort ascending, so an oldest-first sweep would fill the bound
    with history and silently drop the incident actually in progress."""
    for i, day in enumerate(("2026-01-01", "2026-01-02", "2026-01-03")):
        _write(audit_dir, [_row("shield_block", ts=100.0 + i,
                                reason=f"day{i}")] * 4, day=day)
    swept = edr.scan(audit_dir=audit_dir, limit=5)
    assert len(swept.found) == 5
    assert "day2" in {d.detail for d in swept.found}


def test_a_truncated_sweep_says_so(audit_dir):
    """A capped list that looks complete is how an analyst concludes they have
    seen everything."""
    _write(audit_dir, [_row("shield_block", reason="x")] * 6)
    assert edr.scan(audit_dir=audit_dir, limit=3).truncated is True
    assert edr.scan(audit_dir=audit_dir, limit=99).truncated is False


def test_the_bound_holds_across_day_files(audit_dir):
    for day in ("2026-01-01", "2026-01-02", "2026-01-03"):
        _write(audit_dir, [_row("shield_block", reason="x")] * 4, day=day)
    assert len(edr.scan(audit_dir=audit_dir, limit=5).found) == 5


def test_truncation_is_surfaced_in_the_report(audit_dir):
    _write(audit_dir, [_row("shield_block", agent="w", reason="x")] * 4)
    report = edr.incident_report("w", audit_dir=audit_dir)
    report["truncated"] = True
    assert "OLDER detections exist" in edr.render_report(report)


def test_signed_evidence_is_judged_from_the_rows_not_the_library(audit_dir):
    """`cryptography` being importable says nothing about whether signing was
    switched on. Bare rows must not be presented as tamper-evident."""
    (audit_dir / "2026-01-01.ndjson").write_text(
        json.dumps({"ts": 1.0, "kind": "shield_block", "agent": "w",
                    "reason": "x"}) + "\n", encoding="utf-8")
    swept = edr.scan(audit_dir=audit_dir)
    assert swept.unsigned_rows == 1
    assert swept.evidence_is_signed is False
    report = edr.incident_report("w", audit_dir=audit_dir)
    assert report["evidence_is_signed"] is False
    assert "not tamper-evident" in edr.render_report(report)


def test_signed_rows_are_recognized_as_signed(audit_dir):
    _write(audit_dir, [_row("shield_block", agent="w", reason="x")])
    swept = edr.scan(audit_dir=audit_dir)
    assert swept.unsigned_rows == 0
    assert swept.evidence_is_signed is True


def test_an_unreadable_day_makes_the_timeline_partial(audit_dir, monkeypatch):
    """A day we cannot read is a hole in the evidence, not an absence of
    detections."""
    _write(audit_dir, [_row("shield_block", agent="w", reason="x")])
    import maverick.audit.sealing as sealing

    def _boom(path, **kw):
        raise RuntimeError("sealed")
    monkeypatch.setattr(sealing, "segment_text", _boom)
    swept = edr.scan(audit_dir=audit_dir)
    assert swept.unreadable_days == ["2026-01-01"]
    assert swept.evidence_is_signed is False


def test_a_containment_asked_to_do_nothing_is_not_containment():
    """An empty failure list reading as success is the same laundering the rest
    of the module refuses."""
    result = edr.contain("victim", reason="x", seal=False, revoke=False)
    assert not result.contained
    assert "no containment action requested" in result.failed
    assert result.revoked == []


def test_a_hostile_detail_cannot_paint_a_fake_row_in_the_report(audit_dir):
    """Detail text is attacker-influenced. Left with its newlines it renders as
    extra report lines, so a crafted `reason` can paint a convincing
    `[low] FAKE CLEARED` row straight into the analyst's output."""
    _write(audit_dir, [_row(
        "shield_block", agent="w",
        reason="real\n  [low     ] FAKE CLEARED  nothing to see here")])
    det = edr.detections(audit_dir=audit_dir)[0]
    assert "\n" not in det.detail
    body = edr.render_report(edr.incident_report("w", audit_dir=audit_dir))
    fake_lines = [ln for ln in body.splitlines() if "FAKE CLEARED" in ln]
    assert len(fake_lines) == 1
    assert "real" in fake_lines[0]  # inline in the real row, not its own line


def test_a_hostile_subject_is_flattened_too(audit_dir):
    _write(audit_dir, [{"ts": 1.0, "kind": "shield_block",
                        "agent": "a\nb\tc", "reason": "x"}])
    assert edr.detections(audit_dir=audit_dir)[0].subject == "a b c"


# ---- code-review findings ---------------------------------------------------

def test_the_bound_keeps_the_newest_rows_within_one_day_file(audit_dir):
    """Day-files are walked newest-first, but rows INSIDE a file are append
    order. Walking those oldest-first refilled the bound with that morning and
    dropped the incident in progress -- and the report then said the opposite."""
    _write(audit_dir, [_row("shield_block", ts=1000.0 + i, reason=f"ev{i}")
                       for i in range(10)])
    swept = edr.scan(audit_dir=audit_dir, limit=3)
    assert swept.truncated
    assert {d.detail for d in swept.found} == {"ev9", "ev8", "ev7"}


def test_a_poisoned_timestamp_cannot_crash_the_report(audit_dir):
    """`time.gmtime` raises on inf/NaN/1e18, so one hostile row would take down
    the artifact precisely when a hostile row is present."""
    path = audit_dir / "2026-01-01.ndjson"
    path.write_text("\n".join(
        f'{{"ts": {v}, "kind": "shield_block", "agent": "w", "reason": "x"}}'
        for v in ("Infinity", "NaN", "1e18", "-Infinity")) + "\n",
        encoding="utf-8")
    found = edr.detections(audit_dir=audit_dir)
    assert len(found) == 4
    assert all(d.ts == 0.0 for d in found)
    edr.render_report(edr.incident_report("w", audit_dir=audit_dir))


def test_terminal_control_bytes_cannot_repaint_the_report(audit_dir):
    """`str.split()` splits only on whitespace, so ESC survived it: a blocked
    URL carrying \\x1b[1A\\x1b[2K erases the real detection line above it."""
    _write(audit_dir, [_row("shield_block", agent="w",
                            reason="ok\x1b[2K\rFAKE CLEARED\x00 nothing")])
    detail = edr.detections(audit_dir=audit_dir)[0].detail
    assert "\x1b" not in detail and "\x00" not in detail and "\r" not in detail
    assert detail == "ok FAKE CLEARED nothing"


def test_posture_reports_whether_signing_is_ON_not_whether_crypto_imports(
        monkeypatch):
    """The library being installed says nothing about `[audit] sign`."""
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "0")
    p = edr.posture()
    assert p.audit_signing is False
    assert "audit_signing" in p.blind_spots
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    assert edr.posture().audit_signing is True


def test_an_air_gapped_deployment_is_not_reported_as_uncontrolled(monkeypatch,
                                                                  tmp_path):
    """`[egress] deny` is the key air_gap actually enforces. Probing keys no
    module writes made egress_control a blind spot on every deployment, and a
    warning that always fires trains the operator to ignore the list."""
    import maverick.config as cfg
    monkeypatch.setattr(cfg, "load_config", lambda: {"egress": {"deny": ["*"]}})
    assert edr.posture().egress_control is True


def test_zero_evidence_is_not_signed_evidence(tmp_path):
    """An analyst pointed at the wrong home read a signed-looking all-clear."""
    swept = edr.scan(audit_dir=tmp_path / "nope")
    assert swept.root_missing is True
    assert swept.evidence_is_signed is False
    text = edr.render_report(edr.incident_report("w", audit_dir=tmp_path / "nope"))
    assert "not tamper-evident" in text


def test_a_release_asked_to_do_nothing_is_not_a_release():
    result = edr.release("x", registry=None, unrevoke=False)
    assert not result.contained
    assert "no release action requested" in result.failed


def test_the_report_surfaces_the_posture_notes(audit_dir, monkeypatch):
    """The notes carry 'the timeline is partial' and 'revocation state
    unknown'; printing only blind_spots left them in --json alone."""
    _write(audit_dir, [_row("shield_block", agent="w", reason="x")])
    import maverick.audit.sealing as sealing

    def _boom(path, **kw):
        raise RuntimeError("sealed")
    monkeypatch.setattr(sealing, "segment_text", _boom)
    text = edr.render_report(edr.incident_report("w", audit_dir=audit_dir))
    assert "timeline is partial" in text


def test_an_unknown_revocation_state_never_renders_as_a_bare_none(audit_dir,
                                                                  monkeypatch):
    import maverick.revocation as rev
    monkeypatch.setattr(rev, "is_revoked",
                        lambda p: (_ for _ in ()).throw(RuntimeError("down")))
    report = edr.incident_report("w", audit_dir=audit_dir)
    assert "currently revoked: unknown" in edr.render_report(report)


def test_severity_matches_what_threat_hunt_would_say(audit_dir):
    """Two security surfaces rating the same signed row differently is the
    'six modules, six vocabularies' problem this plane exists to end."""
    from maverick.threat_hunt import _INDICATORS
    _write(audit_dir, [_row(k, reason="x") for k in
                       ("shield_block", "governance_denied", "secret_redacted")])
    for d in edr.detections(audit_dir=audit_dir):
        assert d.severity == _INDICATORS[d.source_event][1].lower()


def test_a_kill_switch_engagement_is_visible_to_the_plane(audit_dir):
    """`halt` and `consent_result` are threat_hunt indicators and produced no
    detection here, so a kill switch was invisible to the single security view."""
    _write(audit_dir, [_row("halt", reason="operator engaged HALT"),
                       _row("consent_result", reason="destructive action denied")])
    kinds = {d.source_event for d in edr.detections(audit_dir=audit_dir)}
    assert kinds == {"halt", "consent_result"}


def test_an_existing_but_empty_audit_dir_is_not_signed_evidence(audit_dir):
    """Distinct from a missing root: the directory is there and readable, and
    still nothing was read. Zero rows is zero evidence either way."""
    swept = edr.scan(audit_dir=audit_dir)
    assert swept.root_missing is False
    assert swept.signed_rows == 0
    assert swept.evidence_is_signed is False
    assert "not tamper-evident" in edr.render_report(
        edr.incident_report("w", audit_dir=audit_dir))


def test_one_unsigned_row_among_signed_ones_still_breaks_the_guarantee(audit_dir):
    """Signed rows present is not the test; ANY unsigned row means the chain
    is not tamper-evident, so the mixed case has to fail closed."""
    _write(audit_dir, [_row("shield_block", agent="w", reason="signed")])
    with open(audit_dir / "2026-01-01.ndjson", "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": 2.0, "kind": "shield_block",
                            "agent": "w", "reason": "bare"}) + "\n")
    swept = edr.scan(audit_dir=audit_dir)
    assert swept.signed_rows == 1 and swept.unsigned_rows == 1
    assert swept.evidence_is_signed is False
