"""`maverick import` CLI: clean errors, not tracebacks, on bad inputs."""
from __future__ import annotations

import json

from click.testing import CliRunner
from maverick.cli import main


def _run(args, env=None):
    return CliRunner().invoke(main, args, env={"MAVERICK_AUTOMATION_IMPORT": "1", **(env or {})})


def test_sources_lists_platforms():
    r = _run(["import", "sources"])
    assert r.exit_code == 0
    names = {s["source"] for s in json.loads(r.output)}
    assert {"n8n", "make", "zapier"} <= names


def test_gate_off_is_clean_error():
    r = _run(["import", "run", "n8n", "--from-file", "/nope.json"],
             env={"MAVERICK_AUTOMATION_IMPORT": "0"})
    assert r.exit_code != 0
    assert "automation import is off" in r.output


def test_missing_file_is_clean_error(tmp_path):
    r = _run(["import", "run", "n8n", "--from-file", str(tmp_path / "nope.json")])
    assert r.exit_code != 0
    assert "cannot read" in r.output
    assert "Traceback" not in r.output


def test_bad_json_is_clean_error(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text("{not json")
    r = _run(["import", "run", "n8n", "--from-file", str(f)])
    assert r.exit_code != 0
    assert "not valid JSON" in r.output
    assert "Traceback" not in r.output


def test_unknown_source_with_file_is_clean_error(tmp_path):
    # Regression: the --from-file path skipped source validation, so an unknown
    # source raised an uncaught ImporterError (traceback) at translate time.
    f = tmp_path / "wf.json"
    f.write_text(json.dumps({"name": "x", "nodes": [], "connections": {}}))
    r = _run(["import", "run", "totally-unknown", "--from-file", str(f)])
    assert r.exit_code != 0
    assert "unknown automation source" in r.output
    assert "Traceback" not in r.output


def test_import_from_file_dry_run(tmp_path):
    wf = {"id": "1", "name": "Flow", "active": True,
          "nodes": [{"name": "Hook", "type": "n8n-nodes-base.webhook", "parameters": {}},
                    {"name": "Do", "type": "n8n-nodes-base.set", "parameters": {}}],
          "connections": {"Hook": {"main": [[{"node": "Do"}]]}}}
    f = tmp_path / "wf.json"
    f.write_text(json.dumps(wf))
    r = _run(["import", "run", "n8n", "--from-file", str(f), "--dry-run"])
    assert r.exit_code == 0, r.output
    assert "Would import" in r.output
    assert "Traceback" not in r.output


def test_reimport_with_activate_schedules_does_not_duplicate_the_cron_job(tmp_path, monkeypatch):
    from maverick import job_queue

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / ".maverick"))
    monkeypatch.setattr(job_queue, "DEFAULT_DB", tmp_path / "jobs.db")
    wf = {"id": "7", "name": "Nightly", "active": True,
          "nodes": [{"name": "Cron", "type": "n8n-nodes-base.cron",
                     "parameters": {"cronExpression": "0 3 * * *"}},
                    {"name": "Do", "type": "n8n-nodes-base.set", "parameters": {}}],
          "connections": {"Cron": {"main": [[{"node": "Do"}]]}}}
    f = tmp_path / "wf.json"
    f.write_text(json.dumps(wf))
    args = ["import", "run", "n8n", "--from-file", str(f), "--activate-schedules", "--json"]

    first = _run(args)
    assert first.exit_code == 0, first.output
    assert json.loads(first.output)[0]["schedule"]["cron"] == "0 3 * * *"
    second = _run(args)
    assert second.exit_code == 0, second.output
    again = json.loads(second.output)[0]
    assert again["schedule"] is None
    assert any("not duplicated" in n for n in again["notes"])
    assert len(list(job_queue.JobQueue().iter_pending("start_goal"))) == 1

    # A changed automation updates the schedule this import created: the job
    # carries the import's mark, so it is known to be the import's own.
    wf["nodes"][1]["name"] = "Send the nightly digest"
    f.write_text(json.dumps(wf))
    changed = _run(args)
    assert changed.exit_code == 0, changed.output
    updated = json.loads(changed.output)[0]
    assert updated["schedule"]["updated"] is True
    assert updated["schedule"]["schedule_id"] == json.loads(first.output)[0]["schedule"]["schedule_id"]
    assert any("updated" in n for n in updated["notes"])
    jobs = list(job_queue.JobQueue().iter_pending("start_goal"))
    assert len(jobs) == 1 and "Send the nightly digest" in jobs[0].payload["text"]
    assert jobs[0].payload["imported_from"].startswith("n8n:n8n-nightly-")


def test_reimport_leaves_a_schedule_it_did_not_create_unchanged(tmp_path, monkeypatch):
    # A schedule made before imports were marked (or by hand) with the same
    # title and cron may not be the import's own, so it is never rewritten.
    from maverick import job_queue
    from maverick.automation_import import get_importer

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / ".maverick"))
    monkeypatch.setattr(job_queue, "DEFAULT_DB", tmp_path / "jobs.db")
    wf = {"id": "7", "name": "Nightly", "active": True,
          "nodes": [{"name": "Cron", "type": "n8n-nodes-base.cron",
                     "parameters": {"cronExpression": "0 3 * * *"}},
                    {"name": "Do", "type": "n8n-nodes-base.set", "parameters": {}}],
          "connections": {"Cron": {"main": [[{"node": "Do"}]]}}}
    title, _body = get_importer("n8n").translate(wf).render()
    job_queue.JobQueue().enqueue(
        "start_goal", {"text": "older text", "title": title[:200], "__cron__": "0 3 * * *"})
    f = tmp_path / "wf.json"
    f.write_text(json.dumps(wf))

    result = _run(["import", "run", "n8n", "--from-file", str(f), "--activate-schedules", "--json"])

    assert result.exit_code == 0, result.output
    assert any("different text" in n for n in json.loads(result.output)[0]["notes"])
    jobs = list(job_queue.JobQueue().iter_pending("start_goal"))
    assert len(jobs) == 1 and jobs[0].payload["text"] == "older text"


def test_two_workflows_with_one_name_and_no_id_never_overwrite_each_other(tmp_path, monkeypatch):
    # n8n names every new workflow "My workflow"; an export may carry no ids.
    from maverick import job_queue

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / ".maverick"))
    monkeypatch.setattr(job_queue, "DEFAULT_DB", tmp_path / "jobs.db")

    def workflow(cron, step):
        return {"name": "My workflow", "active": True,
                "nodes": [{"name": "Cron", "type": "n8n-nodes-base.cron", "parameters": {"cronExpression": cron}},
                          {"name": step, "type": "n8n-nodes-base.set", "parameters": {}}],
                "connections": {"Cron": {"main": [[{"node": step}]]}}}

    def schedules():
        return sorted((job.payload["__cron__"], "Send invoices" in job.payload["text"],
                       "Back up files" in job.payload["text"])
                      for job in job_queue.JobQueue().iter_pending("start_goal"))

    f = tmp_path / "wf.json"
    f.write_text(json.dumps([workflow("0 3 * * *", "Send invoices"), workflow("0 5 * * *", "Back up files")]))
    args = ["import", "run", "n8n", "--from-file", str(f), "--activate-schedules", "--json"]
    first = _run(args)
    assert first.exit_code == 0, first.output
    both = [("0 3 * * *", True, False), ("0 5 * * *", False, True)]
    assert schedules() == both
    assert all(any("same name" in note for note in item["notes"]) for item in json.loads(first.output))

    assert _run(args).exit_code == 0
    assert schedules() == both                                # a re-import swaps nothing

    # One of them changes: neither schedule is rewritten, and the note says so.
    f.write_text(json.dumps([workflow("0 3 * * *", "Send reminders"), workflow("0 5 * * *", "Back up files")]))
    changed = _run(args)
    assert changed.exit_code == 0, changed.output
    assert schedules() == both
    assert any("different text" in note for note in json.loads(changed.output)[0]["notes"])


def test_a_workflow_without_an_id_never_updates_another_imports_schedule(tmp_path, monkeypatch):
    # Imported alone in a later file, a same-named workflow with no id cannot be
    # told from the first one, so it must not be taken for a changed version of it.
    from maverick import job_queue

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / ".maverick"))
    monkeypatch.setattr(job_queue, "DEFAULT_DB", tmp_path / "jobs.db")

    def run(cron, step):
        f = tmp_path / "wf.json"
        f.write_text(json.dumps({"name": "My workflow", "active": True,
            "nodes": [{"name": "Cron", "type": "n8n-nodes-base.cron", "parameters": {"cronExpression": cron}},
                      {"name": step, "type": "n8n-nodes-base.set", "parameters": {}}],
            "connections": {"Cron": {"main": [[{"node": step}]]}}}))
        result = _run(["import", "run", "n8n", "--from-file", str(f), "--activate-schedules", "--json"])
        assert result.exit_code == 0, result.output
        return json.loads(result.output)[0]

    first = run("0 3 * * *", "Send invoices")
    assert first["schedule"] and any("no id" in note for note in first["notes"])
    second = run("0 5 * * *", "Back up files")
    assert second["schedule"] and not second["schedule"].get("updated")
    jobs = sorted((job.payload["__cron__"], "Send invoices" in job.payload["text"])
                  for job in job_queue.JobQueue().iter_pending("start_goal"))
    assert jobs == [("0 3 * * *", True), ("0 5 * * *", False)]
    assert all("imported_from" not in job.payload for job in job_queue.JobQueue().iter_pending("start_goal"))
    # The same file again adds nothing.
    assert run("0 5 * * *", "Back up files")["schedule"] is None
    assert len(list(job_queue.JobQueue().iter_pending("start_goal"))) == 2


def test_untranslatable_n8n_schedule_is_reported_not_silently_dropped(tmp_path):
    good = {"id": "1", "name": "Flow", "active": True,
            "nodes": [{"name": "Hook", "type": "n8n-nodes-base.webhook", "parameters": {}}],
            "connections": {}}
    fortnightly = {"id": "2", "name": "Fortnightly report", "active": True, "nodes": [{
        "name": "Schedule", "type": "n8n-nodes-base.scheduleTrigger",
        "parameters": {"rule": {"interval": [{"field": "weeks", "weeksInterval": 2}]}},
    }], "connections": {}}
    f = tmp_path / "wf.json"
    f.write_text(json.dumps([good, fortnightly]))
    r = _run(["import", "run", "n8n", "--from-file", str(f), "--dry-run"])
    assert r.exit_code == 0, r.output
    assert "Would import 1 automation(s)" in r.output
    assert "Not imported: Fortnightly report" in r.output
    assert "interval cannot be represented exactly by cron" in r.output
    f.write_text(json.dumps([fortnightly]))
    r = _run(["import", "run", "n8n", "--from-file", str(f), "--dry-run"])
    assert r.exit_code != 0
    assert "Not imported: Fortnightly report" in r.output
    assert "interval cannot be represented exactly by cron" in r.output


def test_not_imported_line_is_one_clean_bounded_line(tmp_path):
    fortnightly = {"id": "2", "name": "Evil\x1b]0;FORGED\x07\nname " + "x" * 200, "active": True,
                   "nodes": [{"name": "Schedule", "type": "n8n-nodes-base.scheduleTrigger",
                              "parameters": {"rule": {"interval": [{"field": "weeks", "weeksInterval": 2}]}}}],
                   "connections": {}}
    f = tmp_path / "wf.json"
    f.write_text(json.dumps([fortnightly]))
    r = _run(["import", "run", "n8n", "--from-file", str(f), "--dry-run"])
    line = next(row for row in r.output.splitlines() if row.startswith("Not imported:"))
    assert "\x1b" not in r.output and "\x07" not in r.output
    assert "Evil ]0;FORGED name" in line and "x" * 100 not in line
    assert "interval cannot be represented exactly by cron" in line
