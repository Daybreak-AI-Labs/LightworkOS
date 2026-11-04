"""Agent-attack hunter: sweep the audit trail for attack signals."""
from __future__ import annotations

import pytest
from click.testing import CliRunner
from maverick import threat_hunt
from maverick.audit import export
from maverick.cli import main

_EVENTS = [
    {"kind": "shield_block", "agent": "a1", "ts": 100.0, "reason": "injection"},
    {"kind": "shield_block", "agent": "a2", "ts": 200.0},
    {"kind": "egress_blocked", "agent": "a1", "ts": 150.0, "provider": "anthropic"},
    {"kind": "capability_denied", "agent": "a3", "ts": 120.0, "tool": "shell"},
    {"kind": "secret_redacted", "agent": "a1", "ts": 50.0},
    {"kind": "tool_call", "agent": "a1", "ts": 10.0},     # not an indicator
    {"kind": "goal_start", "agent": "a1", "ts": 5.0},      # not an indicator
]


def _feed(monkeypatch, events):
    monkeypatch.setattr(export, "iter_audit_events", lambda **k: iter(list(events)))


def test_hunt_aggregates_indicators_and_ignores_noise(monkeypatch):
    _feed(monkeypatch, _EVENTS)
    report = threat_hunt.hunt()

    assert report.events_scanned == 7
    assert report.risk_rating == "high"
    by = {f.kind: f for f in report.findings}
    assert "tool_call" not in by and "goal_start" not in by   # noise ignored
    assert by["shield_block"].count == 2
    assert by["shield_block"].agents == ["a1", "a2"]
    assert by["shield_block"].last_seen == 200.0
    assert by["egress_blocked"].samples[0]["provider"] == "anthropic"
    # high-severity signals sort before the low-severity redaction
    assert report.findings[0].severity == "high"
    assert report.findings[-1].kind == "secret_redacted"


def test_hunt_skips_malformed_rows_and_keeps_scanning(monkeypatch):
    _feed(monkeypatch, [
        {"kind": [], "agent": "poison", "ts": 1},
        {"kind": "egress_blocked", "agent": "a", "ts": 2.0},
    ])

    report = threat_hunt.hunt()

    assert report.events_scanned == 2
    assert report.risk_rating == "high"
    assert [f.kind for f in report.findings] == ["egress_blocked"]


def test_hunt_ignores_non_finite_timestamps(monkeypatch):
    _feed(monkeypatch, [
        {"kind": "shield_block", "agent": "poison", "ts": float("inf")},
        {"kind": "shield_block", "agent": "a", "ts": "nan"},
    ])

    report = threat_hunt.hunt()

    assert report.risk_rating == "high"
    assert report.findings[0].count == 2
    assert report.findings[0].last_seen == 0.0
    assert all("ts" not in sample for sample in report.findings[0].samples)
    assert "last ?" in threat_hunt.render_report_text(report)


def test_hunt_is_clear_with_no_signals(monkeypatch):
    _feed(monkeypatch, [{"kind": "tool_call", "agent": "a", "ts": 1.0}])
    report = threat_hunt.hunt()
    assert report.risk_rating == "clear" and report.findings == []
    assert "No attack signals" in threat_hunt.render_report_text(report)


def test_hunt_is_fail_soft_on_a_broken_log(monkeypatch):
    def _boom(**k):
        raise OSError("unreadable audit dir")
    monkeypatch.setattr(export, "iter_audit_events", _boom)
    report = threat_hunt.hunt()           # must not raise
    assert report.risk_rating == "clear"


def test_cli_hunt_reports_and_strict_gates(monkeypatch):
    _feed(monkeypatch, [{"kind": "egress_blocked", "agent": "a", "ts": 1.0}])
    runner = CliRunner()

    out = runner.invoke(main, ["hunt"])
    assert out.exit_code == 0 and "Exfiltration" in out.output

    strict = runner.invoke(main, ["hunt", "--strict"])
    assert strict.exit_code != 0


@pytest.mark.parametrize("severities,expected", [
    ([], "clear"),
    (["low"], "low"),
    (["low", "high", "medium"], "high"),
])
def test_rollup(severities, expected):
    findings = [threat_hunt.ThreatFinding("k", "t", s, 1, ["a"], 0.0) for s in severities]
    assert threat_hunt._rollup(findings) == expected


def test_one_poisoned_event_does_not_blind_the_sweep(monkeypatch):
    # A well-formed event with a hostile ts must not abort the scan and hide
    # the later attack signals.
    _feed(monkeypatch, [
        {"kind": "egress_blocked", "agent": "a", "ts": 1.0},
        {"kind": "shield_block", "agent": "b", "ts": "NOT-A-NUMBER"},
        {"kind": "capability_denied", "agent": "c", "ts": 3.0},
    ])
    kinds = {f.kind for f in threat_hunt.hunt().findings}
    assert {"egress_blocked", "shield_block", "capability_denied"} <= kinds


def test_consent_denial_is_a_signal_but_approval_is_not(monkeypatch):
    _feed(monkeypatch, [
        {"kind": "consent_result", "agent": "a", "ts": 1.0, "decision": "deny"},
        {"kind": "consent_result", "agent": "a", "ts": 2.0, "decision": "approve"},
        {"kind": "consent_result", "agent": "a", "ts": 3.0, "decision": "timeout"},
    ])
    cr = [f for f in threat_hunt.hunt().findings if f.kind == "consent_result"]
    assert len(cr) == 1 and cr[0].count == 2     # deny + timeout, not approve


def test_free_text_samples_are_truncated_and_control_stripped(monkeypatch):
    _feed(monkeypatch, [
        {"kind": "shield_block", "agent": "a", "ts": 1.0, "reason": "x\n" * 500},
    ])
    reason = threat_hunt.hunt().findings[0].samples[0]["reason"]
    assert "\n" not in reason and len(reason) <= 160
