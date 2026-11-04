"""Governed Actions: typed ops + simulate-before-commit + tamper-evident lineage."""
from __future__ import annotations

import dataclasses
import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from maverick import governed_actions as ga_mod
from maverick.governed_actions import ActionError, ActionSpec, GovernedActions


def _registry(applied):
    ga = GovernedActions()
    ga.register(ActionSpec(
        name="set_status", params={"id": int, "status": str}, risk="medium",
        simulate=lambda p: f"would set {p['id']} -> {p['status']}",
        apply=lambda p: (applied.append((p["id"], p["status"])), f"set {p['id']}")[1]))
    return ga


def test_simulate_previews_without_side_effects():
    applied: list = []
    ga = _registry(applied)
    pv = ga.simulate("set_status", {"id": 1, "status": "done"})
    assert "would set 1 -> done" in pv.effect
    assert applied == []                 # simulate must NOT apply
    assert pv.requires_approval is False  # medium < default floor (high)


def test_commit_applies_and_records_lineage():
    applied: list = []
    ga = _registry(applied)
    assert ga.commit("set_status", {"id": 1, "status": "done"}) == "set 1"
    assert applied == [(1, "done")]
    assert len(ga.lineage) == 1
    assert ga.verify_lineage().startswith("VALID")


def test_typing_is_enforced():
    ga = GovernedActions()
    ga.register(ActionSpec("a", {"x": int}, apply=lambda p: "ok"))
    with pytest.raises(ActionError, match="missing"):
        ga.commit("a", {})
    with pytest.raises(ActionError, match="must be int"):
        ga.commit("a", {"x": "nope"})


def test_high_risk_requires_an_approver():
    ga = GovernedActions()
    ga.register(ActionSpec("delete", {"id": int}, risk="high", apply=lambda p: "deleted"))
    with pytest.raises(ActionError, match="requires an approver"):
        ga.commit("delete", {"id": 1})            # high-risk, no approver -> refused
    assert ga.commit("delete", {"id": 1}, approver="alice") == "deleted"
    assert ga.lineage[-1].approver == "alice"


def test_unknown_action_and_bad_risk_rejected():
    ga = GovernedActions()
    with pytest.raises(ActionError, match="unknown action"):
        ga.simulate("nope", {})
    with pytest.raises(ValueError):
        ActionSpec("a", {}, risk="nuclear")


def test_lineage_detects_tampering():
    ga = GovernedActions()
    ga.register(ActionSpec("a", {"x": int}, apply=lambda p: "ok"))
    ga.commit("a", {"x": 1})
    ga.commit("a", {"x": 2})
    assert ga.verify_lineage().startswith("VALID")
    # edit a recorded input -> the chain must break at that link
    ga.lineage[0] = dataclasses.replace(ga.lineage[0], params_json='{"x": 999}')
    assert ga.verify_lineage().startswith("BROKEN")


def test_trace_is_the_decision_lineage():
    ga = GovernedActions()
    ga.register(ActionSpec("recommend", {"q": str}, risk="low",
                           simulate=lambda p: "preview", apply=lambda p: "ANSWER"))
    ga.commit("recommend", {"q": "x"}, sources=("doc1",), skills=("skill-a",))
    t = ga.trace()
    assert t["action"] == "recommend"
    assert t["result"] == "ANSWER"
    assert t["sources"] == ["doc1"] and t["skills"] == ["skill-a"]


# -- run-path wiring: enable flag + persistent per-goal lineage -------------

def test_enabled_off_by_default_and_env_toggles(monkeypatch):
    monkeypatch.delenv("MAVERICK_GOVERNED_ACTIONS", raising=False)
    assert ga_mod.enabled() is False
    monkeypatch.setenv("MAVERICK_GOVERNED_ACTIONS", "1")
    assert ga_mod.enabled() is True
    monkeypatch.setenv("MAVERICK_GOVERNED_ACTIONS", "0")
    assert ga_mod.enabled() is False


def test_record_tool_lineage_only_traces_consequential(tmp_path):
    # read_file is low risk -> NOT traced; write_file/shell are consequential.
    ga_mod.record_tool_lineage(7, "read_file", {"path": "x"}, store_dir=tmp_path)
    assert ga_mod.load_lineage(7, store_dir=tmp_path) == []
    ga_mod.record_tool_lineage(7, "write_file", {"path": "x", "content": "y"},
                               skills=("s1",), sources=("ticket-9",),
                               actor="root", store_dir=tmp_path)
    ga_mod.record_tool_lineage(7, "shell", {"cmd": "ls"}, store_dir=tmp_path)
    links = ga_mod.load_lineage(7, store_dir=tmp_path)
    assert [link["action"] for link in links] == ["write_file", "shell"]
    assert links[0]["skills"] == ["s1"] and links[0]["sources"] == ["ticket-9"]
    assert ga_mod.verify_lineage_file(7, store_dir=tmp_path).startswith("VALID")


def test_persisted_lineage_detects_tampering(tmp_path):
    ga_mod.record_tool_lineage(1, "shell", {"cmd": "a"}, store_dir=tmp_path)
    ga_mod.record_tool_lineage(1, "shell", {"cmd": "b"}, store_dir=tmp_path)
    assert ga_mod.verify_lineage_file(1, store_dir=tmp_path).startswith("VALID")
    import json
    f = tmp_path / "1.ndjson"
    lines = f.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["params_json"] = '{"cmd": "TAMPERED"}'
    lines[0] = json.dumps(rec)
    f.write_text("\n".join(lines) + "\n")
    assert ga_mod.verify_lineage_file(1, store_dir=tmp_path).startswith("BROKEN")


def test_record_tool_lineage_is_fail_open(tmp_path):
    # A bad goal_id type must not raise (lineage never breaks a run).
    ga_mod.record_tool_lineage("not-an-int", "shell", {}, store_dir=tmp_path)  # no exception


def test_impact_of_finds_actions_that_used_a_skill_or_source(tmp_path):
    ga_mod.record_tool_lineage(10, "write_file", {"p": "a"},
                               skills=("auth-skill",), sources=("kb-1",), store_dir=tmp_path)
    ga_mod.record_tool_lineage(11, "shell", {"cmd": "x"},
                               skills=("auth-skill",), sources=("kb-2",), store_dir=tmp_path)
    ga_mod.record_tool_lineage(11, "shell", {"cmd": "y"},
                               skills=("other",), sources=("kb-2",), store_dir=tmp_path)
    # revoke auth-skill -> what did it touch? (across goals)
    hits = ga_mod.impact_of("auth-skill", kind="skill", store_dir=tmp_path)
    assert sorted(h["goal_id"] for h in hits) == [10, 11]
    assert all(h["via"] == "skill" for h in hits)
    # by source
    src = ga_mod.impact_of("kb-2", kind="source", store_dir=tmp_path)
    assert {h["goal_id"] for h in src} == {11} and len(src) == 2
    # nothing for an unused identifier
    assert ga_mod.impact_of("nope", store_dir=tmp_path) == []


def test_lineage_is_tenant_scoped(monkeypatch, tmp_path):
    # With an active tenant, lineage lives under the tenant's data dir -- one
    # tenant's audit trail must never mix with another's (matches the other
    # learned stores). Patch the tenant resolver to avoid coupling to its API.
    monkeypatch.setenv("HOME", str(tmp_path))
    tbase = tmp_path / "tenants" / "acme"
    monkeypatch.setattr("maverick.paths.current_tenant", lambda: "acme")
    monkeypatch.setattr("maverick.paths.data_dir", lambda *p: tbase.joinpath(*p))
    ga_mod.record_tool_lineage(4, "shell", {"c": "y"})
    assert ga_mod.load_lineage(4)[0]["action"] == "shell"
    assert (tbase / "lineage" / "4.ndjson").exists()
    assert not (tmp_path / ".maverick" / "lineage" / "4.ndjson").exists()  # not the flat dir


def test_lineage_caps_large_params(tmp_path):
    # A huge tool input (e.g. full file content) must not be stored verbatim.
    ga_mod.record_tool_lineage(2, "write_file", {"content": "x" * 10000}, store_dir=tmp_path)
    pj = ga_mod.load_lineage(2, store_dir=tmp_path)[0]["params_json"]
    assert pj.endswith("...(truncated)") and len(pj) < 5000


def test_lineage_redacts_non_param_audit_fields(monkeypatch, tmp_path):
    def _redact(value):
        return str(value).replace("sensitive-value", "[REDACTED]"), []

    monkeypatch.setattr("maverick.safety.secret_detector.redact", _redact)
    assert ga_mod.record_tool_lineage(
        3,
        "connector.write.commit",
        {"field": "safe"},
        effect="updated sensitive-value",
        result="remote response sensitive-value",
        sources=("ticket-sensitive-value",),
        force=True,
        strict=True,
        store_dir=tmp_path,
    )
    persisted = ga_mod.load_lineage(3, store_dir=tmp_path)[0]
    assert "sensitive-value" not in json.dumps(persisted)
    assert "[REDACTED]" in persisted["effect"]
    assert "[REDACTED]" in persisted["result"]
    assert "[REDACTED]" in persisted["sources"][0]


def test_lineage_never_persists_raw_text_when_redaction_is_unavailable(
    monkeypatch, tmp_path,
):
    def _unavailable(_value):
        raise RuntimeError("detector unavailable")

    monkeypatch.setattr("maverick.safety.secret_detector.redact", _unavailable)
    assert ga_mod.record_tool_lineage(
        5,
        "connector.write.commit",
        {"private": "never-store-this"},
        result="never-store-this",
        force=True,
        strict=True,
        store_dir=tmp_path,
    )
    raw = (tmp_path / "5.ndjson").read_text(encoding="utf-8")
    assert "never-store-this" not in raw
    assert "redaction unavailable" in raw


def test_transaction_receipts_are_hashed_with_phase_and_identity(tmp_path):
    assert ga_mod.record_tool_lineage(
        9, "salesforce.write.prepare", {"op": "post"},
        actor="user:alice", effect="would POST /accounts", approver="human",
        transaction_id="tx-1", phase="PREPARE", force=True, strict=True,
        store_dir=tmp_path,
    )
    assert ga_mod.record_tool_lineage(
        9, "salesforce.write.commit", {"op": "post"},
        actor="user:alice", effect="would POST /accounts", result="created",
        approver="human", transaction_id="tx-1", phase="COMMIT", force=True,
        strict=True, store_dir=tmp_path,
    )
    links = ga_mod.load_lineage(9, store_dir=tmp_path)
    assert [link["phase"] for link in links] == ["PREPARE", "COMMIT"]
    assert {link["transaction_id"] for link in links} == {"tx-1"}
    assert all(link["actor"] == "user:alice" for link in links)
    assert ga_mod.verify_lineage_file(9, store_dir=tmp_path).startswith("VALID: 2")


def test_concurrent_receipts_do_not_fork_or_lose_hash_chain(tmp_path):
    def _write(index: int) -> bool:
        return ga_mod.record_tool_lineage(
            12, "connector.write.prepare", {"index": index},
            transaction_id=f"tx-{index}", phase="PREPARE", force=True,
            strict=True, store_dir=tmp_path,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert all(pool.map(_write, range(32)))
    links = ga_mod.load_lineage(12, store_dir=tmp_path)
    assert len(links) == 32
    assert {link["transaction_id"] for link in links} == {
        f"tx-{index}" for index in range(32)
    }
    assert ga_mod.verify_lineage_file(12, store_dir=tmp_path).startswith("VALID: 32")


def test_strict_receipt_failure_propagates(tmp_path):
    with pytest.raises(ValueError):
        ga_mod.record_tool_lineage(
            "not-an-int", "connector.write.prepare", {}, force=True,
            strict=True, store_dir=tmp_path,
        )


def test_strict_receipt_refuses_to_extend_a_tampered_chain(tmp_path):
    assert ga_mod.record_tool_lineage(
        18, "connector.write.prepare", {"value": "original"}, force=True,
        strict=True, store_dir=tmp_path,
    )
    ledger = tmp_path / "18.ndjson"
    link = json.loads(ledger.read_text(encoding="utf-8"))
    link["params_json"] = '{"value":"tampered"}'
    ledger.write_text(json.dumps(link) + "\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="lineage is not trustworthy"):
        ga_mod.record_tool_lineage(
            18, "connector.write.commit", {"value": "original"}, force=True,
            strict=True, store_dir=tmp_path,
        )

    assert len(ledger.read_text(encoding="utf-8").splitlines()) == 1
