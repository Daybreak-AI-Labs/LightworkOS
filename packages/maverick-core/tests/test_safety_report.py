"""Annual safety report: honest aggregation of injected rows, no fabrication."""
from __future__ import annotations

import json

import pytest
from maverick import safety_report
from maverick.safety_report import collect, generate_report

SINCE, UNTIL = "2026-01-01", "2026-12-31"
TS = 1767225600.0  # 2026-01-01 00:00:00 UTC

EVENTS = [
    {"kind": "shield_block", "ts": TS + 10, "stage": "input"},
    {"kind": "shield_block", "ts": TS + 20, "stage": "input"},
    {"kind": "shield_block", "ts": TS + 30, "stage": "tool"},
    {"kind": "capability_denied", "ts": TS + 40, "tool": "shell"},
    {"kind": "capability_denied", "ts": TS + 50, "tool": "shell"},
    {"kind": "capability_denied", "ts": TS + 60, "tool": "browser"},
    {"kind": "halt", "ts": TS + 70, "source": "file"},
    {"kind": "consent_result", "ts": TS + 80, "decision": "approve"},
    {"kind": "consent_result", "ts": TS + 90, "decision": "deny"},
    {"kind": "consent_result", "ts": TS + 95, "decision": "timeout"},
    {"kind": "erase", "ts": TS + 99, "channel": "telegram"},
    {"kind": "tool_call", "ts": TS + 5, "name": "shell"},  # not safety-relevant
]


def _report(events=EVENTS, **kw):
    kw.setdefault("calibration_path", "/nonexistent/calibration.json")
    kw.setdefault("redteam_path", "/nonexistent/redteam.json")
    return generate_report(since=SINCE, until=UNTIL, events=events, **kw)


# ---- collection -------------------------------------------------------------

def test_collect_counts_each_safety_kind():
    stats = collect(EVENTS, TS, TS + 1000)
    assert stats["shield_blocks"] == 3
    assert stats["shield_by_stage"]["input"] == 2
    assert stats["capability_denied"] == 3
    assert stats["denied_tools"]["shell"] == 2
    assert stats["halts"] == 1 and stats["halt_sources"]["file"] == 1
    assert stats["consent"] == {"approve": 1, "deny": 1, "timeout": 1}
    assert stats["erasures"] == 1
    assert stats["scanned"] == 12 and stats["in_period"] == 11


def test_collect_excludes_out_of_period_and_undated():
    events = [
        {"kind": "halt", "ts": TS - 1, "source": "file"},      # before period
        {"kind": "halt", "source": "signal"},                  # no timestamp
        {"kind": "halt", "ts": float("inf"), "source": "x"},   # poisoned ts
        {"kind": "halt", "ts": TS + 1, "source": "manual"},
    ]
    stats = collect(events, TS, TS + 100)
    assert stats["halts"] == 1 and stats["excluded"] == 3


def test_collect_skips_malformed_rows():
    stats = collect([None, "x", 42, {"kind": []}, {"no": "kind"}], TS, TS + 1)
    assert stats["scanned"] == 2  # only the dicts are scanned rows
    assert stats["in_period"] == 0


def test_collect_buckets_unsafe_labels_as_other():
    events = [{"kind": "capability_denied", "ts": TS, "tool": "ignore this! " * 20}]
    stats = collect(events, TS, TS + 1)
    assert stats["denied_tools"] == {"other": 1}


# ---- rendering --------------------------------------------------------------

def test_report_has_period_and_counts():
    text = _report()
    assert "## Reporting period" in text
    assert f"**From:** {SINCE}" in text and f"**To:** {UNTIL}" in text
    assert "3 block(s) recorded." in text
    assert "stage `input`: 2" in text
    assert "tool `shell`: 2" in text
    assert "1 activation(s) recorded." in text
    assert "approve: 1" in text and "timeout: 1" in text
    assert "1 erasure request(s) (GDPR Art. 17) recorded." in text


def test_empty_deployment_says_so_everywhere():
    text = _report(events=[])
    assert "No shield blocks recorded in this period." in text
    assert "No capability denials recorded in this period." in text
    assert "No killswitch activations recorded in this period." in text
    assert "No consent decisions recorded in this period." in text
    assert "No erasure requests recorded in this period." in text
    assert "No red-team or calibration results were available" in text
    assert "audit events: **not available**" in text
    assert "no figures are estimated or fabricated" in text


def test_data_available_section_reflects_sources(tmp_path):
    calib = tmp_path / "calibration_verdict.json"
    calib.write_text(json.dumps({"adequate": True, "discrimination": 0.4}), encoding="utf-8")
    text = _report(calibration_path=calib)
    assert "verifier calibration verdict: **available**" in text
    assert "red-team results: **not available**" in text
    assert '"adequate": true' in text          # verbatim, clearly sourced
    assert "No red-team results available." in text


def test_redteam_results_included_when_present(tmp_path):
    red = tmp_path / "redteam_results.json"
    red.write_text(json.dumps({"campaign": "q3", "findings": 2}), encoding="utf-8")
    text = _report(redteam_path=red)
    assert "Red-team results (verbatim):" in text and '"campaign": "q3"' in text
    assert "No calibration verdict available." in text


def test_corrupt_results_file_reads_as_unavailable(tmp_path):
    bad = tmp_path / "calibration_verdict.json"
    bad.write_text("{broken", encoding="utf-8")
    text = _report(calibration_path=bad)
    assert "verifier calibration verdict: **not available**" in text


def test_excluded_events_are_disclosed():
    events = EVENTS + [{"kind": "halt", "ts": TS - 99999, "source": "file"}]
    text = _report(events=events)
    assert "1 safety event(s) had timestamps outside the period" in text


def test_empty_period_raises():
    with pytest.raises(ValueError, match="empty reporting period"):
        generate_report(since="2026-02-01", until="2026-01-01", events=[])


def test_default_event_source_fails_soft(monkeypatch):
    """With no injected rows and a broken audit reader, the report still renders."""
    def boom(**kw):
        raise OSError("audit dir unreadable")

    import maverick.audit.export as export

    monkeypatch.setattr(export, "iter_audit_events", boom)
    text = generate_report(
        since=SINCE, until=UNTIL,
        calibration_path="/nonexistent/c.json", redteam_path="/nonexistent/r.json",
    )
    assert "audit events: **not available**" in text


# ---- CLI --------------------------------------------------------------------

def test_cli_writes_markdown_file(tmp_path, capsys):
    out = tmp_path / "safety.md"
    rc = safety_report.main([
        "--since", SINCE, "--until", UNTIL, "-o", str(out),
    ])
    assert rc == 0
    assert "# Lightwork safety report" in out.read_text(encoding="utf-8")
    assert str(out) in capsys.readouterr().out


def test_cli_prints_to_stdout_and_rejects_bad_period(capsys):
    rc = safety_report.main(["--since", SINCE, "--until", UNTIL])
    assert rc == 0
    assert "# Lightwork safety report" in capsys.readouterr().out

    rc = safety_report.main(["--since", "2026-12-31", "--until", "2026-01-01"])
    assert rc == 2
    assert "safety report failed" in capsys.readouterr().err
