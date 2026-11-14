"""Focused import fidelity, command admission, and data-boundary regressions."""
from __future__ import annotations

import json
import os
from types import SimpleNamespace

import click
import pytest
from click.testing import CliRunner
from maverick.automation_import import ir, uipath, workato
from maverick.automation_import.base import ImporterError


@pytest.mark.parametrize("complete", [False, True])
def test_schedule_trigger_redacts_its_cron_text(complete):
    secret = "sk-" + "a" * 48
    cron = "0 9 * * *\n" + secret + " " + "description " * 30
    text = ir.ImportedTrigger(kind="schedule", cron=cron).render(complete=complete)
    assert secret not in text
    assert "REDACTED" in text
    if not complete:
        assert "\n" not in text
        assert len(text) <= len("on a schedule ()") + 120
    else:
        assert "description " * 25 in text


def _response(body):
    return SimpleNamespace(content=b"{}", json=lambda: body, raise_for_status=lambda: None)


def test_workato_refuses_truncated_recipe_inventory():
    calls = []

    def request(url, **kwargs):
        calls.append(kwargs["params"]["page"])
        return _response({"items": [{"id": len(calls)}] * 100})

    with pytest.raises(ImporterError, match="10,000|page limit"):
        workato.WorkatoImporter("https://workato.example", request=request).fetch()
    assert len(calls) == 100
    assert workato.WorkatoImporter(
        "https://workato.example", request=lambda *_a, **_k: _response({"items": [{"id": 1}]})
    ).fetch() == [{"id": 1}]


@pytest.mark.parametrize("next_link", ["?$skip=1", "https://uipath.example/tenant/odata/ProcessSchedules?$skip=1"])
def test_uipath_follows_bounded_same_endpoint_pages(next_link):
    calls = []

    def request(url, **kwargs):
        calls.append(url)
        if "ProcessSchedules" not in url:
            return _response({"value": [{"Id": "release"}]})
        if "?$skip=1" in url:
            return _response({"value": [{"Id": "second"}]})
        return _response({"value": [{"Id": "first"}], "@odata.nextLink": next_link})

    rows = uipath.UiPathImporter("https://uipath.example/tenant", request=request).fetch()
    assert [row["Id"] for row in rows] == ["first", "second", "release"]
    assert len(calls) == 3


@pytest.mark.parametrize("next_link", [
    "https://other.example/tenant/odata/ProcessSchedules?$skip=1",
    "https://user@uipath.example/tenant/odata/ProcessSchedules?$skip=1",
    "https://uipath.example/other/odata/ProcessSchedules?$skip=1",
    "https://uipath.example:0/tenant/odata/ProcessSchedules?$skip=1",
    "https://[invalid/tenant/odata/ProcessSchedules?$skip=1",
    "#fragment",
    "/tenant/odata/ProcessSchedules",
])
def test_uipath_refuses_unsafe_or_cyclic_next_links_before_request(next_link):
    calls = []

    def request(url, **kwargs):
        calls.append(url)
        return _response({"value": [], "@odata.nextLink": next_link})

    with pytest.raises(ImporterError, match="pagination|page"):
        uipath.UiPathImporter("https://uipath.example/tenant", request=request).fetch()
    assert len(calls) == 1

    def unending(url, **kwargs):
        calls.append(url)
        return _response({"value": [], "@odata.nextLink": f"?$skip={len(calls)}"})

    calls.clear()
    with pytest.raises(ImporterError, match="page limit"):
        uipath.UiPathImporter("https://uipath.example/tenant", request=unending).fetch()
    assert len(calls) == 100


@pytest.mark.parametrize("stage", ["batch", "native"])
def test_import_repair_reason_reaches_dashboard_as_validation_error(monkeypatch, stage):
    from fastapi import HTTPException
    from maverick_dashboard import automation_imports as imports

    message = "n8n import needs repair: unsupported branch structure"

    def broken(*_args):
        raise ValueError(message)

    monkeypatch.setattr(imports, "authority", lambda *_a, **_k: ("tenant", "user:alice", "context"))
    monkeypatch.setattr(imports, "_template", lambda *_a: None)
    monkeypatch.setattr(imports, "flows_enabled", lambda: True)
    monkeypatch.setattr(imports, "to_flow_with_report", broken)
    automation = ir.ImportedAutomation("n8n", "id", "workflow", ir.ImportedTrigger())
    monkeypatch.setattr(imports, "get_importer", lambda _s: SimpleNamespace(translate=lambda _r: automation))
    with pytest.raises(HTTPException) as caught:
        if stage == "batch":
            imports._translated(None, {"context": "context", "source": "n8n", "as_flows": True}, [{}])
        else:
            imports.native_call(broken)
    assert caught.value.status_code == 422
    assert message in caught.value.detail


def test_schema_hints_keep_only_bounded_identifier_keys_and_clean_prior_hints():
    from maverick.flow.schema_infer import infer_shape, merge_shapes

    values = {"person@example.test": 1, "customer-123": 2, 123: 3,
              "status": 4, "account_total": 5, "x" * 129: 6}
    expected = ["account_total", "status"]
    assert infer_shape(values)["keys"] == expected
    assert infer_shape([values])["keys"] == expected
    merged = merge_shapes({"out": {"type": "object", "keys": ["person@example.test", "prior"]}},
                          {"out": infer_shape(values)})
    assert merged["out"]["keys"] == ["account_total", "prior", "status"]
    assert merge_shapes({"other": {"type": "object", "keys": list(values)}}, {})["other"]["keys"] == expected


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="OS UID database is POSIX-only")
def test_control_actor_uses_uid_database_not_environment(monkeypatch):
    import pwd

    from maverick.cli._agent_control_plane_groups import _actor

    monkeypatch.setenv("LOGNAME", "chosen-by-environment")
    monkeypatch.setenv("USER", "chosen-by-environment")
    assert _actor() == f"cli:{pwd.getpwuid(os.getuid()).pw_name}"


def test_refine_revert_requires_confirmation_and_reports_module_errors(monkeypatch):
    from maverick import harness_refine
    from maverick.cli import main

    calls = []
    monkeypatch.setattr(harness_refine, "revert", lambda *_a, **_k: calls.append(True) or True)
    refused = CliRunner().invoke(main, ["refine", "revert", "proposal"], input="n\n")
    assert refused.exit_code != 0
    assert calls == []
    accepted = CliRunner().invoke(main, ["refine", "revert", "proposal", "--yes"])
    assert accepted.exit_code == 0 and calls == [True]

    def broken(*_args, **_kwargs):
        raise harness_refine.RefineError("snapshot no longer retained")

    monkeypatch.setattr(harness_refine, "revert", broken)
    failed = CliRunner().invoke(main, ["refine", "revert", "proposal", "--yes"])
    assert failed.exit_code == 1
    assert "Error: snapshot no longer retained" in failed.output


def test_retention_override_keeps_other_configured_rules(monkeypatch):
    from maverick import config
    from maverick.audit import retention
    from maverick.cli import main

    configured = {"audit_days": 7, "episodes_days": 9}
    monkeypatch.setattr(config, "load_config", lambda: {"retention": configured})
    seen = []
    monkeypatch.setattr(retention, "enforce", lambda **kwargs: seen.append(kwargs) or {})
    result = CliRunner().invoke(main, ["retention", "enforce", "--events-days", "3", "--dry-run"])
    assert result.exit_code == 0, result.output
    assert seen == [{"config": {"audit_days": 7, "episodes_days": 9, "events_days": 3}, "dry_run": True}]
    assert configured == {"audit_days": 7, "episodes_days": 9}


def test_repl_refuses_goal_rebinding_before_receipt_or_execution(monkeypatch):
    from maverick import audit, config
    from maverick import governed_repl as repl

    monkeypatch.setattr(config, "get_repl", lambda: {
        "enable": True, "max_statements": 10, "max_output_chars": 1000,
    })
    monkeypatch.setattr(audit, "audit_event", lambda *_a, **_k: None)
    monkeypatch.setattr(repl, "_sandbox_for", lambda _p: object())
    receipts, effects = [], []
    monkeypatch.setattr(repl, "_receipt", lambda *a, **k: receipts.append(a) or True)
    monkeypatch.setattr(repl, "_run_statement", lambda *_a: effects.append(True) or ({"ok": True}, 0, 0.0))
    session = repl.open_session(goal_id=7)
    with pytest.raises(repl.ReplError, match="goal"):
        repl.execute(session, "x = 1", goal_id=8)
    assert receipts == [] and effects == []
    assert repl.session_info(session)["statements"] == 0
    assert repl.execute(session, "x = 1", goal_id=7)["ok"] is True
    assert effects == [True]
    assert [row[0] for row in receipts] == [7, 7]


def test_run_tree_strips_terminal_controls_from_display(monkeypatch):
    from maverick import session_tree
    from maverick.cli import main

    monkeypatch.setattr(session_tree, "tree", lambda _id: {
        "goal_id": 7, "status": "done", "title": "safe\x1b]0;FORGED\x07title", "children": [],
    })
    result = CliRunner().invoke(main, ["run-tree", "show", "7"])
    assert result.exit_code == 0, result.output
    assert "\x1b" not in result.output and "\x07" not in result.output
    assert "safetitle" in result.output


@pytest.mark.parametrize("value", ["x", None, 1, [1], [1, {"id": "kept"}]])
def test_import_file_envelope_requires_a_list_of_definitions(tmp_path, value, caplog):
    from maverick.cli._import_groups import _load_raws

    path = tmp_path / "export.json"
    path.write_text(json.dumps({"data": value}))
    if isinstance(value, list):
        assert _load_raws(str(path), "n8n") == [row for row in value if isinstance(row, dict)]
        omitted = sum(not isinstance(row, dict) for row in value)
        if omitted:
            assert f"Skipped {omitted} import record(s) that are not JSON objects" in caplog.text
    else:
        with pytest.raises(click.ClickException, match="array|list"):
            _load_raws(str(path), "n8n")
