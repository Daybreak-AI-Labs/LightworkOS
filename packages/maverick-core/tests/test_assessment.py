"""Compliance assessment engine: templates, scoring, persistence, CLI."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner
from maverick.cli import main


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    # Keep saved assessments off the real ~/.maverick.
    from maverick import paths

    monkeypatch.setattr(paths, "maverick_home", lambda: tmp_path / "home")


def test_templates_registered_and_looked_up():
    from maverick.assessment import get_template, list_templates

    types = {t.type for t in list_templates()}
    # Core compliance templates + the finance suite (finance-agent-suite §6).
    assert types == {
        "pia",
        "dpia",
        "lia",
        "ccpa",
        "lgpd",
        "pipeda",
        "us_state_privacy",
        "iso27701",
        "cppa_admt",
        "colorado_admt",
        "nyc_ll144",
        "texas_traiga",
        "illinois_hb3773",
        "aira",
        "vendor_risk",
        "tia",
        "hipaa",
        "soc2",
        "iso27001",
        "iso42001",
        "nist_csf",
        "nist_800_53",
        "cis_v8",
        "pci_dss",
        "cmmc_l2",
        "fedramp_moderate",
        "sox_control",
        "fraud_risk",
        "itgc",
        "credit_risk",
        "close_readiness",
    }
    assert get_template("VENDOR_RISK").title == "Vendor Risk Assessment"  # case-insensitive
    assert get_template("nope") is None


def test_fedramp_catalog_tracks_the_2026_transition_source():
    from maverick.assessment import FRAMEWORK_SOURCES, get_template

    source = FRAMEWORK_SOURCES["fedramp_moderate"]
    template = get_template("fedramp_moderate")

    assert source["source_url"] == "https://www.fedramp.gov/2026/"
    assert "Class C" in source["version"]
    assert template is not None
    assert "Class C" in template.framework
    assert "screen" in template.description.lower()


def test_privacy_templates_dpia_lia_ccpa_score_and_route():
    from maverick.assessment import (
        AssessmentSession,
        get_template,
        template_department,
    )

    expected = {"dpia": 10, "lia": 10, "ccpa": 11}
    for type_, n_questions in expected.items():
        tpl = get_template(type_)
        assert tpl is not None and len(tpl.questions) == n_questions
        # New privacy frameworks belong to the privacy workspace, not finance.
        assert template_department(type_) == "privacy"
        # The safe answer to every question yields a clean, minimal result...
        clean = AssessmentSession(type=type_, subject="Clean")
        for q in tpl.questions:
            clean.record(q.id, "no" if q.risk_answer == "yes" else "yes")
        r = clean.evaluate()
        assert r.risk_rating == "minimal" and r.findings == []
        # ...and the risky answer to every question raises findings that roll up.
        risky = AssessmentSession(type=type_, subject="Risky")
        for q in tpl.questions:
            risky.record(q.id, q.risk_answer)
        rr = risky.evaluate()
        assert rr.risk_rating in ("high", "medium")
        assert len(rr.findings) == n_questions
    # The DPIA is a distinct, deeper instrument than the lightweight PIA.
    assert get_template("dpia").title != get_template("pia").title
    assert "Art. 35" in get_template("dpia").framework


def test_clean_answers_are_minimal_risk():
    from maverick.assessment import AssessmentSession, get_template

    tpl = get_template("pia")
    s = AssessmentSession(type="pia", subject="Marketing emails")
    for q in tpl.questions:
        s.record(q.id, "no" if q.risk_answer == "yes" else "yes")  # the safe answer
    r = s.evaluate()
    assert r.risk_rating == "minimal"
    assert r.findings == []
    assert r.answered == r.total


def test_risky_answers_score_findings_and_roll_up():
    from maverick.assessment import AssessmentSession

    s = AssessmentSession(type="vendor_risk", subject="Acme Corp")
    s.record("vr_dpa", "no")  # high (risk answer)
    s.record("vr_soc2", "yes")  # safe -> no finding
    s.record("vr_breach_history", "yes")  # medium (risk answer is "yes")
    s.record("vr_business_continuity", "unknown")  # low, unverified
    r = s.evaluate()

    assert r.risk_rating == "high"  # max severity among findings
    kinds = {f.question_id: f.kind for f in r.findings}
    assert kinds["vr_dpa"] == "risk"
    assert kinds["vr_breach_history"] == "risk"
    assert kinds["vr_business_continuity"] == "unverified"
    assert "vr_soc2" not in kinds
    assert r.answered == 3  # yes/no/na count; unknown does not


def test_every_builtin_template_records_and_scores_including_critical():
    from maverick.assessment import (
        AssessmentSession,
        list_templates,
        render_result_text,
    )

    for tpl in list_templates():
        s = AssessmentSession(type=tpl.type, subject="Acme Corp")
        for q in tpl.questions:
            s.record(q.id, q.risk_answer)  # verifies the pinned snapshot each time
        r = s.evaluate()
        assert len(r.findings) == len(tpl.questions), tpl.type
        assert {f.kind for f in r.findings} == {"risk"}, tpl.type
        if tpl.type == "texas_traiga":
            # A critical finding outranks high and is never scored as low.
            assert r.risk_rating == "high"
            first_finding = render_result_text(r).split("Findings")[1].splitlines()[1]
            assert first_finding.lstrip().startswith("[CRITICAL]")


def test_inherent_vs_residual_risk_pair():
    """Inherent = every applicable risk area (before crediting controls);
    residual = what the findings leave open. A control in place lowers
    residual but never lowers inherent; 'na' removes the area from both."""
    from maverick.assessment import AssessmentSession

    s = AssessmentSession(type="vendor_risk", subject="Acme Corp")
    s.record("vr_dpa", "yes")  # high area, CONTROLLED
    s.record("vr_encryption", "yes")  # high area, CONTROLLED
    s.record("vr_breach_history", "no")  # medium area, safe answer
    s.record("vr_deletion", "no")  # medium area, RISK answer
    s.record("vr_business_continuity", "na")  # out of scope entirely
    r = s.evaluate()

    assert r.inherent_risk == "high"  # high areas apply to this vendor
    assert r.residual_risk == "medium"  # only the deletion gap is open
    assert r.risk_rating == r.residual_risk  # back-compat alias
    assert r.risks_in_scope == 4  # the four non-na answers
    assert r.controls_in_place == 3  # dpa, encryption, breach history
    # Fully clean subject: both ratings collapse to minimal.
    s2 = AssessmentSession(type="vendor_risk", subject="Clean Corp")
    s2.record("vr_dpa", "na")
    r2 = s2.evaluate()
    assert (r2.inherent_risk, r2.residual_risk) == ("minimal", "minimal")
    assert r2.risks_in_scope == 0


def test_saved_summaries_carry_the_risk_pair(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    from maverick.assessment import AssessmentSession, list_saved, save_session

    s = AssessmentSession(type="pia", subject="Acme CRM")
    s.record("pia_transfers", "yes")  # high risk answer -> open finding
    s.record("pia_security", "yes")  # safe answer -> controlled
    save_session(s)
    row = next(r for r in list_saved() if r["id"] == s.id)
    assert row["inherent_risk"] == "high"
    assert row["residual_risk"] == "high"


def test_saved_heads_are_bounded_read_only_and_disclose_exact_total(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    from maverick.assessment import AssessmentSession, list_saved_heads, save_session

    first = AssessmentSession(type="pia", subject="First")
    second = AssessmentSession(type="pia", subject="Second")
    save_session(first)
    save_session(second)

    rows, total = list_saved_heads(limit=1)
    assert total == 2
    assert len(rows) == 1
    assert rows[0]["id"] in {first.id, second.id}
    assert "_audit_pending" not in rows[0]


def test_list_saved_tolerates_sibling_register_in_same_data_dir(tmp_path, monkeypatch):
    """packages/maverick-core/maverick/assessments.py (the governance-suite
    register, a distinct module) stores its own JSON at
    ``data_dir("assessments", "register.json")`` -- the exact directory
    ``assessment.py`` (this module) globs for saved per-subject records. Its
    filename stem "register" passes the permissive assessment-id pattern, so
    list_saved()/list_saved_heads() used to try to load it as a saved
    assessment and blow up on the identity check (no "id" field == its own
    stem). A foreign file here must be skipped, not crash the listing."""
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    from maverick.assessment import AssessmentSession, list_saved, list_saved_heads, save_session
    from maverick.paths import data_dir

    save_session(AssessmentSession(type="pia", subject="Real Subject"))

    register_path = data_dir("assessments", "register.json")
    register_path.write_text(
        json.dumps({"schema_version": 2, "revision": 1, "records": {}}),
        encoding="utf-8",
    )

    rows = list_saved()
    assert [row["subject"] for row in rows] == ["Real Subject"]

    heads, total = list_saved_heads()
    assert len(heads) == 1
    assert heads[0]["subject"] == "Real Subject"


def test_metrics_survive_the_capability_review_register(tmp_path, monkeypatch):
    """Running one capability (agent) assessment writes
    ``assessments/register.json`` next to the per-subject records. That file
    used to make ``acceptance_metrics`` and ``question_roi`` raise
    ``AssessmentStateError`` ("assessment record identity is invalid"), which
    surfaced as a 500 on the audit binder, the finance board and the question
    analytics. Drive the register through the real writer, then read the
    metrics: the real record must still be counted and nothing may raise."""
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    from maverick import assessments
    from maverick.assessment import (
        AssessmentSession,
        acceptance_metrics,
        decide_assessment,
        question_roi,
        save_session,
    )
    from maverick.paths import data_dir

    monkeypatch.setattr(
        assessments,
        "subject_surface",
        lambda kind, name: {
            "kind": "agent", "subject": name, "description": "d",
            "allow_tools": [], "deny_tools": [], "max_risk": "low",
            "allow_paths": [], "allow_hosts": [], "mcp_servers": [],
            "knowledge_sources": [], "has_human_gate": True, "steps": 1,
        },
    )
    session = AssessmentSession(type="pia", subject="Real Subject")
    save_session(session)
    decide_assessment(session.id, "approved", decided_by="dpo")

    assert assessments.refresh("agent", "calm_bot", expected_revision=0) is not None
    assert data_dir("assessments", "register.json").exists()

    assert acceptance_metrics()["decided"] == 1
    roi = question_roi("pia")
    assert roi["assessed"] == 1


def test_equal_timestamp_history_has_canonical_order_and_limit():
    from maverick.assessment import (
        AssessmentSession,
        list_saved,
        risk_trend,
        save_session,
    )

    # Save in deliberately non-lexical order.  Equal wall-clock timestamps are
    # possible on real filesystems, so neither list order nor trend truncation
    # may inherit Path.glob() enumeration order.
    for assessment_id in ("tie-c", "tie-a", "tie-b"):
        save_session(
            AssessmentSession(
                type="vendor_risk",
                subject="Tied Clock Vendor",
                id=assessment_id,
                created_at=100.0,
            )
        )

    assert [row["id"] for row in list_saved()] == ["tie-c", "tie-b", "tie-a"]
    assert [
        row["id"] for row in risk_trend("Tied Clock Vendor", "vendor_risk")
    ] == ["tie-a", "tie-b", "tie-c"]
    assert [
        row["id"]
        for row in risk_trend("Tied Clock Vendor", "vendor_risk", limit=2)
    ] == ["tie-b", "tie-c"]


def test_record_rejects_bad_answer_and_unknown_question():
    from maverick.assessment import AssessmentSession

    s = AssessmentSession(type="aira", subject="Resume screener")
    with pytest.raises(ValueError):
        s.record("aira_purpose", "maybe")
    with pytest.raises(KeyError):
        s.record("does_not_exist", "yes")


def test_assessment_session_ids_are_unique_for_rapid_creation():
    from maverick.assessment import AssessmentSession

    ids = {AssessmentSession(type="pia", subject=f"Subject {i}").id for i in range(1000)}

    assert len(ids) == 1000


def test_persistence_round_trip():
    from maverick.assessment import (
        AssessmentSession,
        list_saved,
        load_saved,
        save_session,
    )

    s = AssessmentSession(type="vendor_risk", subject="Acme Corp")
    s.record("vr_dpa", "no")
    path = save_session(s)
    assert path.exists()

    rows = list_saved()
    assert len(rows) == 1
    assert rows[0]["subject"] == "Acme Corp"
    assert rows[0]["risk_rating"] == "high"

    data = load_saved(s.id)
    assert data["type"] == "vendor_risk"
    assert data["result"]["findings"][0]["question_id"] == "vr_dpa"


def test_cli_assess_flow(tmp_path):
    from maverick.assessment import list_saved

    runner = CliRunner()
    assert runner.invoke(main, ["assess", "templates"]).exit_code == 0

    q = runner.invoke(main, ["assess", "questions", "pia"])
    assert q.exit_code == 0 and "pia_security" in q.output

    answers = tmp_path / "answers.json"
    answers.write_text(json.dumps({"vr_dpa": "no", "vr_soc2": "yes"}))
    scored = runner.invoke(
        main,
        ["assess", "score", "vendor_risk", "--subject", "Acme", "--answers", str(answers)],
    )
    assert scored.exit_code == 0
    assert "HIGH" in scored.output and "saved:" in scored.output

    lst = runner.invoke(main, ["assess", "list"])
    assert lst.exit_code == 0 and "Acme" in lst.output

    shown = runner.invoke(main, ["assess", "show", list_saved()[0]["id"]])
    assert shown.exit_code == 0 and "Acme" in shown.output


def test_load_saved_rejects_path_traversal():
    from maverick.assessment import load_saved

    # `assess show ../../etc/passwd` must not read outside the assessments dir.
    assert load_saved("../../etc/passwd") is None
    assert load_saved("../secret") is None
    assert load_saved("does-not-exist") is None


def test_save_session_is_written_private_0600():
    from maverick.assessment import AssessmentSession, save_session
    from maverick.file_lock import private_path_is_restricted

    path = save_session(AssessmentSession(type="pia", subject="Acme"))
    assert private_path_is_restricted(path, 0o600)
