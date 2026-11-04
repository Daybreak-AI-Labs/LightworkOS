"""Kernel functions shared by terminal commands and their dashboard buttons:
skill preview and fingerprint-bound install, the plugin lock report, record
addresses for governed connectors, picked analytics questions and the trace
naming rule."""
from __future__ import annotations

import pytest
from maverick import plugin_lock, skills
from maverick.connector_previews import dialect_for

SKILL = "---\nname: weekly-status\ntriggers:\n  - weekly status\n---\n# Steps\n\nSummarise the finished work in five bullets.\n"


def test_validate_skill_text_matches_the_file_linter(tmp_path):
    path = tmp_path / "SKILL.md"
    path.write_text(SKILL)
    assert skills.validate_skill_text(SKILL) == skills.validate_skill_file(path)


def test_preview_fetches_through_the_guarded_path_and_binds_the_install(tmp_path, monkeypatch):
    served = [SKILL]
    monkeypatch.setattr(skills, "_fetch_url_bytes", lambda url: served[0].encode())
    preview = skills.preview_skill_source("https://example.com/SKILL.md")
    assert preview.name == "weekly-status" and preview.validation.ok
    assert not list(tmp_path.glob("*.md"))
    with pytest.raises(ValueError, match="https"):
        skills.preview_skill_source("http://example.com/SKILL.md")
    with pytest.raises(ValueError):
        skills.preview_skill_source("/etc/passwd")
    served[0] = SKILL.replace("five", "ten")
    with pytest.raises(ValueError, match="changed since it was checked"):
        skills.install_skill("https://example.com/SKILL.md", skills_dir=tmp_path, trusted_local=False,
                             expected_sha256=preview.sha256)
    assert not (tmp_path / "weekly-status.md").exists()
    served[0] = SKILL
    installed = skills.install_skill("https://example.com/SKILL.md", skills_dir=tmp_path, trusted_local=False,
                                     expected_sha256=preview.sha256)
    assert installed.name == "weekly-status"


def test_lock_report_lists_matching_drifted_missing_and_unpinned(tmp_path, monkeypatch):
    installed = {"a": "1", "b": "1"}
    monkeypatch.setattr(plugin_lock, "_active_plugin_dists", lambda: dict(installed))
    monkeypatch.setattr(plugin_lock, "_dist_content_hash", lambda name: None)
    lock = tmp_path / "plugins.lock.json"
    assert plugin_lock.lock_report(lock) == {"locked": False, "ok": True, "rows": [
        {"name": "a", "pinned": None, "installed": "1", "state": "unpinned"},
        {"name": "b", "pinned": None, "installed": "1", "state": "unpinned"}]}
    plugin_lock.write_lock(lock)
    installed.update({"a": "2", "c": "1"})
    installed.pop("b")
    report = plugin_lock.lock_report(lock)
    assert {r["name"]: r["state"] for r in report["rows"]} == {"a": "drifted", "b": "missing", "c": "unpinned"}
    assert report["ok"] is plugin_lock.verify_lock(lock)["ok"] is False


def test_record_addresses_follow_each_vendor_grammar():
    sf = dialect_for("salesforce")
    path = sf.path_for("Opportunity", "006000000000001AAA")
    assert sf.target(path) == ("Opportunity", "006000000000001AAA")
    assert sf.collection(sf.path_for("Opportunity")) == "Opportunity"
    sn = dialect_for("servicenow")
    assert sn.target(sn.path_for("incident", "a" * 32)) == ("incident", "a" * 32)
    for bad in (("Opportunity", "../../x"), ("Opp/../x", ""), ("Opportunity", "short")):
        with pytest.raises(ValueError):
            sf.path_for(*bad)
    with pytest.raises(ValueError):
        dialect_for("unknown").path_for("x", "")


def test_picked_questions_never_become_sql_text():
    pytest.importorskip("duckdb")
    from maverick.duckdb_analytics import WorldAnalytics

    class _World:
        def list_goals(self, limit):
            return [type("G", (), {"id": 1, "title": "Report", "status": "done"})()]

        def list_episodes(self, goal_id, limit):
            return [type("E", (), {"cost_dollars": 2.0, "input_tokens": 3, "output_tokens": 4,
                                   "outcome": "success", "ended_at": 1_700_000_000.0})()]
    wa = WorldAnalytics(_World())
    assert wa.ask("spend", "status") == [{"group": "done", "value": 2.0}]
    assert wa.ask("tokens", "none", since=1_800_000_000.0) == []
    for metric, group in (("spend; DROP TABLE goals", "none"), ("spend", "owner")):
        with pytest.raises(ValueError):
            wa.ask(metric, group)
    with pytest.raises(TimeoutError):
        wa.query("WITH RECURSIVE t(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM t) SELECT count(*) FROM t",
                 timeout=0.2)


def test_goal_trace_path_is_the_orchestrator_naming_rule(tmp_path, monkeypatch):
    from maverick.replay.trace import goal_trace_path
    monkeypatch.delenv("MAVERICK_TRACE_DIR", raising=False)
    assert goal_trace_path(7) is None
    monkeypatch.setenv("MAVERICK_TRACE_DIR", str(tmp_path))
    assert goal_trace_path(7) == tmp_path / "goal-7.jsonl"
