"""saas_trigger_registry: register + match SaaS triggers (wildcards)."""
from __future__ import annotations

import json

from maverick.tools.saas_trigger_registry import saas_trigger_registry


def _run(**kw):
    return saas_trigger_registry().fn(kw)


def test_register_validates_and_dedupes():
    out = json.loads(_run(op="register", triggers=[
        {"source": "github", "event": "push", "goal": "run ci"},
        {"source": "github", "event": "push", "goal": "run ci"},  # exact dup
        {"source": "stripe", "event": "charge.failed", "goal": "alert finance"},
    ]))
    assert out["count"] == 2
    sigs = {(t["source"], t["event"], t["goal"]) for t in out["triggers"]}
    assert ("github", "push", "run ci") in sigs
    assert ("stripe", "charge.failed", "alert finance") in sigs


def test_register_rejects_incomplete_triggers():
    t = saas_trigger_registry()
    assert t.fn({"op": "register", "triggers": [{"source": "x", "event": "y"}]}).startswith(
        "ERROR"
    )
    assert t.fn({"op": "register", "triggers": [{"source": "", "event": "y", "goal": "g"}]}
                ).startswith("ERROR")
    assert t.fn({"op": "register", "triggers": []}).startswith("ERROR")


def test_match_exact():
    registry = {"triggers": [
        {"source": "github", "event": "push", "goal": "run ci"},
        {"source": "github", "event": "pull_request", "goal": "review pr"},
    ]}
    out = json.loads(_run(op="match", source="github", event="push", registry=registry))
    assert out == ["run ci"]
    none = json.loads(_run(op="match", source="github", event="delete", registry=registry))
    assert none == []


def test_match_wildcards():
    registry = [
        {"source": "*", "event": "deploy", "goal": "notify oncall"},
        {"source": "datadog", "event": "*", "goal": "triage alert"},
        {"source": "github", "event": "deploy", "goal": "tag release"},
    ]
    # source wildcard + exact-source rule both match "deploy".
    deploy = json.loads(_run(op="match", source="github", event="deploy", registry=registry))
    assert set(deploy) == {"notify oncall", "tag release"}
    # event wildcard matches any datadog event.
    dd = json.loads(_run(op="match", source="datadog", event="anything", registry=registry))
    assert dd == ["triage alert"]


def test_match_dedupes_goals_and_accepts_bare_list():
    registry = [
        {"source": "*", "event": "*", "goal": "log it"},
        {"source": "slack", "event": "message", "goal": "log it"},  # same goal
    ]
    out = json.loads(_run(op="match", source="slack", event="message", registry=registry))
    assert out == ["log it"]  # de-duplicated to one


def test_errors_and_factory_contract():
    t = saas_trigger_registry()
    assert t.fn({"op": "match", "event": "x", "registry": []}).startswith("ERROR")  # no source
    assert t.fn({"op": "match", "source": "x", "registry": []}).startswith("ERROR")  # no event
    assert t.fn({"op": "match", "source": "x", "event": "y"}).startswith("ERROR")  # no registry
    assert t.fn({"op": "nope"}).startswith("ERROR")
    assert t.name == "saas_trigger_registry"
    assert t.parallel_safe is True
