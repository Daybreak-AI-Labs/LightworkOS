"""Governance assessments: auto-draft heuristics, the review lifecycle, drift
detection, scheduling, and audit export."""
from __future__ import annotations

import pytest
from maverick import assessments as A


@pytest.fixture(autouse=True)
def _isolate_home(monkeypatch, tmp_path):
    # Point the data home (and thus the register) at a scratch dir.
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))


HIGH_RISK = {
    "kind": "agent", "subject": "danger_bot", "description": "does risky things",
    "allow_tools": ["shell", "web_search", "file_write", "email"],
    "deny_tools": [], "max_risk": "high", "allow_paths": ["/etc"],
    "allow_hosts": ["api.example.com"], "mcp_servers": [], "knowledge_sources": ["hr_records"],
    "has_human_gate": False, "steps": 2,
}
SAFE = {
    "kind": "agent", "subject": "calm_bot", "description": "reads and summarizes",
    "allow_tools": ["read_file"], "deny_tools": [], "max_risk": "low",
    "allow_paths": [], "allow_hosts": [], "mcp_servers": [], "knowledge_sources": [],
    "has_human_gate": True, "steps": 1,
}


def _use_surface(monkeypatch, surface):
    monkeypatch.setattr(A, "subject_surface", lambda kind, name: dict(surface))


def test_auto_draft_flags_shell_and_missing_gate(monkeypatch):
    _use_surface(monkeypatch, HIGH_RISK)
    a = A.auto_draft("agent", "danger_bot", now=1000.0)
    assert set(a["lenses"]) == set(A.LENSES)
    sec = a["lenses"]["security"]["findings"]
    assert any(f["control"] == "Arbitrary code / shell execution" and f["severity"] == "high" for f in sec)
    ai = a["lenses"]["ai_risk"]["findings"]
    assert any(f["control"] == "Human oversight" and f["severity"] == "high" for f in ai)
    # reads + egress -> a high privacy transfer finding
    priv = a["lenses"]["privacy"]["findings"]
    assert any(f["severity"] == "high" for f in priv)


def test_safe_subject_has_no_high_findings(monkeypatch):
    _use_surface(monkeypatch, SAFE)
    a = A.auto_draft("agent", "calm_bot", now=1.0)
    highs = [f for lv in a["lenses"].values() for f in lv["findings"] if f["severity"] == "high"]
    assert highs == []


def test_template_limits_lenses(monkeypatch):
    _use_surface(monkeypatch, SAFE)
    a = A.auto_draft("agent", "calm_bot", template="security_only", now=1.0)
    assert list(a["lenses"]) == ["security"]


def test_refresh_creates_then_review_marks_reviewed(monkeypatch):
    _use_surface(monkeypatch, SAFE)
    a = A.refresh("agent", "calm_bot", now=1.0)
    assert a["status"] == "draft"
    for lens in A.LENSES:
        A.record_review("agent", "calm_bot", lens, "accepted", reviewer="ada",
                        cadence_days=30, now=2.0)
    got = A.get_assessment("agent", "calm_bot")
    assert got["status"] == "reviewed"
    assert got["due_at"] == pytest.approx(2.0 + 30 * 86400)
    # every open finding is now accepted
    assert all(f["status"] == "accepted"
               for lv in got["lenses"].values() for f in lv["findings"])


def test_drift_flips_reviewed_back_to_needs_review(monkeypatch):
    _use_surface(monkeypatch, SAFE)
    A.refresh("agent", "calm_bot", now=1.0)
    for lens in A.LENSES:
        A.record_review("agent", "calm_bot", lens, "accepted", now=2.0)
    assert A.get_assessment("agent", "calm_bot")["status"] == "reviewed"
    # The subject gains shell + high risk -> surface hash changes -> drift.
    _use_surface(monkeypatch, {**SAFE, "allow_tools": ["read_file", "shell"], "max_risk": "high"})
    a = A.refresh("agent", "calm_bot", now=3.0)
    assert a["status"] == "needs_review"
    assert a["lenses"]["security"]["status"] == "open"


def test_evidence_and_export(monkeypatch):
    _use_surface(monkeypatch, HIGH_RISK)
    A.refresh("agent", "danger_bot", now=1.0)
    A.add_evidence("agent", "danger_bot", "security",
                   "Arbitrary code / shell execution", "sandbox verified: ticket-42", now=2.0)
    rows = A.export_rows()
    assert any(r["evidence"] == "sandbox verified: ticket-42" for r in rows)
    assert {"kind", "subject", "lens", "control", "severity"} <= set(rows[0])


def test_due_lists_drafts_and_overdue(monkeypatch):
    _use_surface(monkeypatch, SAFE)
    A.refresh("agent", "calm_bot", now=1.0)                       # stays draft
    due = A.due_assessments(now=10.0)
    assert any(d["subject"] == "calm_bot" for d in due)


def test_unknown_subject_returns_none(monkeypatch):
    monkeypatch.setattr(A, "subject_surface", lambda kind, name: None)
    assert A.auto_draft("agent", "nope") is None
    assert A.refresh("agent", "nope") is None


def test_real_agent_surface_resolves():
    # Integration: a real built-in pack yields a surface (name varies, so just
    # assert the shape for any one agent).
    from maverick.domain_edit import list_agents
    agents = list_agents()
    if not agents:
        pytest.skip("no packs discovered in this environment")
    s = A.agent_surface(agents[0]["name"])
    assert s is not None and s["kind"] == "agent" and "allow_tools" in s


def test_prompt_only_gate_is_not_counted_as_human_oversight(monkeypatch):
    import maverick.domain_edit as domain_edit

    monkeypatch.setattr(domain_edit, "resolved_view", lambda _name: {
        "description": "generated medium-risk pack",
        "allow_tools": ["read_file"],
        "deny_tools": [],
        "max_risk": "medium",
        "workflow": [
            {"name": "approve", "gate": "approval"},
            {"name": "release", "gate": None},
        ],
        "declared_prompt_gate": "approval",
        "enforced_gate": None,
    })

    surface = A.agent_surface("generated")

    assert surface["declared_prompt_gate"] == "approval"
    assert surface["enforced_gate"] is None
    assert surface["has_human_gate"] is False
    findings = A._ai_risk_findings(surface)
    oversight = next(f for f in findings if f["control"] == "Human oversight")
    assert oversight["severity"] == "high"
    assert "prompt-only" in oversight["note"]


def test_review_writes_an_audit_event(monkeypatch, tmp_path):
    # A sign-off is anchored in the signed audit chain, not just the register.
    _use_surface(monkeypatch, SAFE)
    import maverick.audit.writer as w
    from maverick.audit.writer import AuditLog
    al = AuditLog(audit_dir=tmp_path / "audit")
    monkeypatch.setattr(w, "default_audit_log", lambda: al)
    A.refresh("agent", "calm_bot", now=1.0)
    A.record_review("agent", "calm_bot", "security", "accepted", reviewer="ada", now=2.0)
    reviews = [e for e in al.tail(200) if e.get("kind") == "assessment_review"]
    assert reviews and reviews[0]["decision"] == "accepted"
    assert reviews[0]["subject"] == "calm_bot" and reviews[0]["reviewer"] == "ada"


def test_sweep_due_refreshes_and_reports(monkeypatch):
    _use_surface(monkeypatch, SAFE)
    A.refresh("agent", "calm_bot", now=1.0)          # a draft -> due
    out = A.sweep_due(now=5.0)
    assert out["refreshed"] == 1
    assert any(d["subject"] == "calm_bot" for d in out["due"])


def test_refresh_on_change_only_touches_existing(monkeypatch):
    _use_surface(monkeypatch, SAFE)
    # No assessment yet -> a change is a no-op (doesn't spawn one).
    assert A.refresh_on_change("agent", "calm_bot") is None
    # Assess + accept, then a surface change re-drafts and flips to needs_review.
    A.refresh("agent", "calm_bot", now=1.0)
    for lens in A.LENSES:
        A.record_review("agent", "calm_bot", lens, "accepted", now=2.0)
    _use_surface(monkeypatch, {**SAFE, "allow_tools": ["read_file", "shell"], "max_risk": "high"})
    changed = A.refresh_on_change("agent", "calm_bot", now=3.0)
    assert changed is not None and changed["status"] == "needs_review"


def test_real_flow_surface_reports_flownode_tool_and_approval():
    from maverick.flow.ir import Flow, FlowNode
    from maverick.flow.store import save_flow

    save_flow(Flow(
        id="risky_flow",
        name="Risky flow",
        start="approve",
        nodes={
            "approve": FlowNode(
                id="approve", kind="approval", prompt="Approve send?", next="send",
            ),
            "send": FlowNode(id="send", kind="action", tool="email"),
        },
    ))

    surface = A.flow_surface("risky_flow")

    assert surface is not None
    assert surface["allow_tools"] == ["email"]
    assert surface["max_risk"] == "high"
    assert surface["has_human_gate"] is True
    assert surface["analysis_complete"] is True
    assert surface["approval_gaps"] == []

    draft = A.auto_draft("flow", "risky_flow", template="security_only", now=1.0)
    findings = draft["lenses"]["security"]["findings"]
    assert any(
        f["control"] == "Risk ceiling" and f["severity"] == "high"
        for f in findings
    )
