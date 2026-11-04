"""Discovery Title reads conception gates and input commitments straight from
governed research runs, so they are recorded as the research happens."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

import pytest
from maverick.immune import title

# Reuse the research-run fixtures by path: several packages ship a ``tests``
# package, so a package-relative sibling import is ambiguous in the full suite.
_spec = importlib.util.spec_from_file_location(
    "_immune_research_run_fixtures", Path(__file__).with_name("test_research_runs.py"))
_rr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_rr)
TENANT, _dataset, _plan, services = _rr.TENANT, _rr._dataset, _rr._plan, _rr.services


def _dossier(**extra):
    return {"problem": {"statement": "x", "signed_off_by": "user:researcher"},
            "claims": [{"id": "c1", "elements": ["assay-design"]}],
            "verification": [{"checker": "holdout", "passed": True}],
            "coverage": {"examined": 1, "total": 1}, **extra}


def test_planning_decisions_become_framed_gates_and_inputs(services):
    registry, runs, state = services
    planned = _plan(runs, _dataset(registry, state))
    queued = runs.queue(TENANT, "user:researcher", planned["run_id"],
                        expected_revision=planned["revision"])
    run = runs.inspect(TENANT, "user:researcher", queued["run_id"])

    ev = title.research_run_evidence(run, ["assay-design"])
    assert [(g["human"], g["decision"], g["elements"]) for g in ev["gates"]] == [
        ("user:researcher", "framed", ["assay-design"])]  # queued is not conception
    plan_event = run["attempts"][0]["events"][0]
    assert ev["gates"][0]["at"] == ev["inputs_committed_at"] == plan_event["recorded_at"]
    assert ev["gates"][0]["evidence"] == plan_event["event_sha256"]
    names = [i["name"] for i in ev["inputs"]]
    assert names[0].startswith("code:") and "dataset:dataset-one@v1" in names

    # read from the governed store itself: verified
    dossier = title.add_research_runs(_dossier(), [{"run": run}], ["assay-design"], verified=True)
    assert title.problems(dossier) == []
    assert title.add_research_runs(dossier, [run], ["assay-design"],
                                   verified=True) == dossier  # idempotent
    # without the caller's element assertion, nothing is inferred
    assert title.problems(title.add_research_runs(_dossier(), [run], verified=True)) == [
        "claim element without human conception: assay-design"]
    # an idea recorded before the run's inputs were pinned is reported
    early = _dossier(priority=[{"commitment": "c", "at": plan_event["recorded_at"] - 1}])
    assert "inputs were committed after the first recorded idea" in title.problems(
        title.add_research_runs(early, [run], ["assay-design"]))


def test_an_export_with_recomputed_digests_is_reported_unverified(services):
    import hashlib

    from maverick.immune import _ledger
    registry, runs, state = services
    run = copy.deepcopy(runs.inspect(TENANT, "user:researcher",
                                     _plan(runs, _dataset(registry, state))["run_id"]))
    event = run["attempts"][0]["events"][0]
    event["actor"] = "user:mallory"
    body = {k: v for k, v in event.items() if k != "event_sha256"}
    event["event_sha256"] = hashlib.sha256(_ledger.canonical(body)).hexdigest()
    for later in run["attempts"][0]["events"][1:]:  # re-chain whatever follows
        later["previous_event_sha256"] = event["event_sha256"]
        body = {k: v for k, v in later.items() if k != "event_sha256"}
        later["event_sha256"] = event = hashlib.sha256(_ledger.canonical(body)).hexdigest()
    dossier = title.add_research_runs(_dossier(), [run], ["assay-design"])  # an export
    (gate,) = dossier["gates"]
    assert gate["human"] == "user:mallory" and gate["verified"] is False
    assert title.problems(dossier) == [
        f"conception gate rests on an unverified research export: {gate['id']}"]


def test_tampered_run_history_is_refused(services):
    registry, runs, state = services
    run = runs.inspect(TENANT, "user:researcher",
                       _plan(runs, _dataset(registry, state))["run_id"])
    forged = copy.deepcopy(run)
    forged["attempts"][0]["events"][0]["actor"] = "user:someone-else"
    with pytest.raises(ValueError, match="does not verify"):
        title.research_run_evidence(forged)
    forged = copy.deepcopy(run)
    forged["manifest"]["seed"] = 7
    with pytest.raises(ValueError, match="manifest"):
        title.research_run_evidence(forged)


def test_cli_adds_research_runs_to_a_dossier(services, tmp_path):
    from click.testing import CliRunner
    from maverick.cli import main
    registry, runs, state = services
    run = runs.inspect(TENANT, "user:researcher",
                       _plan(runs, _dataset(registry, state))["run_id"])
    d, r, out = tmp_path / "d.json", tmp_path / "r.json", tmp_path / "o.json"
    d.write_text(json.dumps(_dossier()))
    r.write_text(json.dumps({"run": run}))
    res = CliRunner().invoke(main, ["immune", "title", "research", str(d), str(r),
                                    "--element", "assay-design", "-o", str(out)])
    assert res.exit_code == 0, res.output
    assert "1 conception gate(s) added" in res.output
    check = CliRunner().invoke(main, ["immune", "title", "check", str(out)])
    assert check.exit_code == 1 and "unverified research export" in check.output


def test_a_research_gate_stripped_of_its_verified_flag_is_still_reported(services):
    registry, runs, state = services
    run = runs.inspect(TENANT, "user:researcher", _plan(runs, _dataset(registry, state))["run_id"])
    dossier = title.add_research_runs(_dossier(), [run], ["assay-design"], verified=True)
    for gate in dossier["gates"]:
        gate.pop("verified")
    assert any("unverified research export" in p for p in title.problems(dossier))
