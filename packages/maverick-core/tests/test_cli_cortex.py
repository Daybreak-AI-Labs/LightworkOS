"""Operator CLI for Cortex, the company brain: `maverick cortex`.

The kernel had one governed recall/deposit surface over every memory source
but no way to reach it from a terminal. This pins the three commands --
``status`` (what each source holds plus the encryption/isolation posture),
``recall`` (hits grouped by source with citations, or the prompt block), and
``deposit`` (a cited chunk or a fleet lesson) -- and that every flag lands on
the kernel call unchanged. The kernel itself is covered by test_cortex.py, so
``maverick.cortex.recall/status/deposit`` are monkeypatched here; the world
model the record source needs is a throwaway ``--db`` under tmp.
"""
from __future__ import annotations

import json

import pytest
from click.testing import CliRunner
from maverick import cortex
from maverick.cli import main


@pytest.fixture
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_CORTEX", raising=False)
    return tmp_path


def _invoke(tmp_path, *args):
    return CliRunner().invoke(main, ["--db", str(tmp_path / "world.db"), *args])


def _status_payload(enabled=True):
    return {
        "enabled": enabled, "tenant": "acme",
        "sources": {
            "knowledge": {"available": True, "collections": ["finance", "policies"]},
            "skills": {"count": 12, "verified": 3},
            "lessons": {"models": 2, "lines": 7, "enabled": True},
            "record": {"entries": 41, "n_records": 41, "n_goals": 30,
                       "n_approvals": 11, "n_human_decisions": 9,
                       "departments": {"finance": 20}},
            "fleet": {"enabled": True, "agents": [{"source": "acme:bot-1"}],
                      "ingested": {"acme:bot-1": {"success": 4, "failure": 1}}},
        },
        "encryption": {"at_rest": True, "per_tenant": False},
        "isolation": {"tenant_floored": True, "pooled_across_tenants": False,
                      "note": "every source is floored to the active tenant"},
    }


def _result(query="refund policy", hits=None, denied=None, sources=cortex.SOURCES):
    hits = hits if hits is not None else [
        cortex.Hit("knowledge", "policies", "Refunds within 30 days.",
                   "policies/refunds.md", 0.91, {"collection": "policies"}),
        cortex.Hit("knowledge", "finance", "Refund reserve is 2%.",
                   "finance/reserve.md", 0.42, {"collection": "finance"}),
        cortex.Hit("lessons", "lesson", "check the refund window first",
                   "self-harness · claude-x", 0.5, {"model": "claude-x"}),
    ]
    res = cortex.Result(query=query, tenant="acme", sources=tuple(sources), hits=hits,
                        per_source={s: sum(1 for h in hits if h.source == s) for s in sources},
                        denied=dict(denied or {}), took_ms=12, audited=True)
    return res


# ---------- status ----------

def test_status_table_lists_every_source_with_counts_and_posture(_home, monkeypatch):
    seen = {}

    def _status(*, world=None):
        seen["world"] = world
        return _status_payload()

    monkeypatch.setattr(cortex, "status", _status)
    r = _invoke(_home, "cortex", "status")
    assert r.exit_code == 0, r.output
    # The record source is answered from the CLI's world model, not a second open.
    assert seen["world"] is not None
    out = r.output
    for source in cortex.SOURCES:
        assert source in out, source
    assert "2 collections" in out and "finance" in out and "policies" in out
    assert "12 skills" in out and "3 verified" in out
    assert "7 lines" in out and "2 models" in out
    assert "41 entries" in out and "9 human decisions" in out
    assert "1 agent" in out and "4 success" in out
    assert "at rest: on" in out and "per tenant: off" in out
    assert "tenant" in out and "acme" in out
    assert "pooled across tenants: no" in out


def test_status_reports_a_source_that_is_off_or_broken(_home, monkeypatch):
    payload = _status_payload()
    payload["sources"]["knowledge"] = {"available": False, "collections": []}
    payload["sources"]["fleet"] = {"enabled": False}
    payload["sources"]["lessons"] = {"models": 0, "lines": 0, "error": "store unreadable"}
    monkeypatch.setattr(cortex, "status", lambda *, world=None: payload)
    r = _invoke(_home, "cortex", "status")
    assert r.exit_code == 0, r.output
    assert "unavailable" in r.output
    assert "off" in r.output
    assert "store unreadable" in r.output


def test_status_warns_when_cortex_is_disabled(_home, monkeypatch):
    monkeypatch.setattr(cortex, "status", lambda *, world=None: _status_payload(enabled=False))
    r = _invoke(_home, "cortex", "status")
    assert r.exit_code == 0, r.output
    assert "disabled" in r.output and "[cortex] enable" in r.output


def test_status_json_is_the_kernel_payload_verbatim(_home, monkeypatch):
    monkeypatch.setattr(cortex, "status", lambda *, world=None: _status_payload())
    r = _invoke(_home, "cortex", "status", "--json")
    assert r.exit_code == 0, r.output
    assert json.loads(r.output) == _status_payload()


# ---------- recall ----------

def test_recall_groups_hits_by_source_with_citations(_home, monkeypatch):
    monkeypatch.setattr(cortex, "recall", lambda query, **kw: _result(query))
    r = _invoke(_home, "cortex", "recall", "refund policy")
    assert r.exit_code == 0, r.output
    out = r.output
    assert "refund policy" in out
    assert out.index("knowledge") < out.index("lessons")
    assert "policies/refunds.md" in out and "finance/reserve.md" in out
    assert "self-harness · claude-x" in out
    assert "Refunds within 30 days." in out
    assert "3 hits" in out and "acme" in out


def test_recall_passes_every_flag_to_the_kernel(_home, monkeypatch):
    seen = {}

    def _recall(query, **kw):
        seen["query"] = query
        seen.update(kw)
        return _result(query, hits=[], sources=("knowledge", "skills"))

    monkeypatch.setattr(cortex, "recall", _recall)
    r = _invoke(_home, "cortex", "recall", "close the books",
                "--source", "knowledge", "--source", "skills",
                "--domain", "finance", "--model", "claude-x", "--k", "3")
    assert r.exit_code == 0, r.output
    assert seen["query"] == "close the books"
    assert tuple(seen["sources"]) == ("knowledge", "skills")
    assert seen["domain"] == "finance"
    assert seen["model_id"] == "claude-x"
    assert seen["k"] == 3
    # The record source was not requested, so no world model was opened for it.
    assert seen.get("world") is None


def test_recall_hands_the_world_model_to_the_record_source(_home, monkeypatch):
    seen = {}

    def _recall(query, **kw):
        seen.update(kw)
        return _result(query, hits=[])

    monkeypatch.setattr(cortex, "recall", _recall)
    r = _invoke(_home, "cortex", "recall", "anything")
    assert r.exit_code == 0, r.output
    assert seen["world"] is not None


def test_recall_rejects_an_unknown_source(_home, monkeypatch):
    monkeypatch.setattr(cortex, "recall", lambda query, **kw: _result(query))
    r = _invoke(_home, "cortex", "recall", "x", "--source", "gossip")
    assert r.exit_code != 0
    assert "gossip" in r.output


def test_recall_reports_denied_sources_without_hiding_the_hits(_home, monkeypatch):
    denied = {"fleet": "fleet memory answers enrolled external agents"}
    monkeypatch.setattr(cortex, "recall",
                        lambda query, **kw: _result(query, denied=denied))
    r = _invoke(_home, "cortex", "recall", "refund policy")
    assert r.exit_code == 0, r.output
    assert "policies/refunds.md" in r.output
    assert "fleet" in r.output and "enrolled external agents" in r.output


def test_recall_says_so_when_nothing_matched(_home, monkeypatch):
    monkeypatch.setattr(cortex, "recall", lambda query, **kw: _result(query, hits=[]))
    r = _invoke(_home, "cortex", "recall", "nothing here")
    assert r.exit_code == 0, r.output
    assert "no hits" in r.output


def test_recall_fails_loudly_when_cortex_is_disabled(_home, monkeypatch):
    denied = {"cortex": "cortex is disabled ([cortex] enable = true)"}
    monkeypatch.setattr(cortex, "recall",
                        lambda query, **kw: _result(query, hits=[], denied=denied))
    r = _invoke(_home, "cortex", "recall", "anything")
    assert r.exit_code != 0
    assert "cortex is disabled" in r.output


def test_recall_context_prints_the_prompt_block(_home, monkeypatch):
    res = _result()
    monkeypatch.setattr(cortex, "recall", lambda query, **kw: res)
    r = _invoke(_home, "cortex", "recall", "refund policy", "--context")
    assert r.exit_code == 0, r.output
    assert r.output.strip() == res.context().strip()
    assert "[knowledge · policies/refunds.md]" in r.output


def test_recall_json_is_the_result_envelope(_home, monkeypatch):
    res = _result()
    monkeypatch.setattr(cortex, "recall", lambda query, **kw: res)
    r = _invoke(_home, "cortex", "recall", "refund policy", "--json")
    assert r.exit_code == 0, r.output
    data = json.loads(r.output)
    assert data == json.loads(json.dumps(res.to_dict()))
    assert data["per_source"]["knowledge"] == 2
    assert data["hits"][0]["citation"] == "policies/refunds.md"


# ---------- deposit ----------

def test_deposit_text_into_knowledge(_home, monkeypatch):
    seen = {}

    def _deposit(text, **kw):
        seen["text"] = text
        seen.update(kw)
        return True, "ingested"

    monkeypatch.setattr(cortex, "deposit", _deposit)
    r = _invoke(_home, "cortex", "deposit", "--collection", "policies",
                "--source", "handbook.md", "--domain", "hr",
                "Parental leave is 16 weeks.")
    assert r.exit_code == 0, r.output
    assert seen["text"] == "Parental leave is 16 weeks."
    assert seen["kind"] == "knowledge"
    assert seen["collection"] == "policies"
    assert seen["source"] == "handbook.md"
    assert seen["domain"] == "hr"
    assert "ingested" in r.output and "knowledge" in r.output


def test_deposit_reads_text_from_a_file(_home, monkeypatch, tmp_path):
    doc = tmp_path / "note.md"
    doc.write_text("Invoices are due net 30.\n", encoding="utf-8")
    seen = {}

    def _deposit(text, **kw):
        seen["text"] = text
        seen.update(kw)
        return True, "ingested"

    monkeypatch.setattr(cortex, "deposit", _deposit)
    r = _invoke(_home, "cortex", "deposit", "--file", str(doc))
    assert r.exit_code == 0, r.output
    assert seen["text"] == "Invoices are due net 30.\n"
    # No --source: the kernel attributes the chunk to the file it came from.
    assert seen["source"] == str(doc)
    assert seen["collection"] == "cortex"


def test_deposit_fleet_kind(_home, monkeypatch):
    seen = {}

    def _deposit(text, **kw):
        seen.update(kw)
        return True, "ingested"

    monkeypatch.setattr(cortex, "deposit", _deposit)
    r = _invoke(_home, "cortex", "deposit", "--kind", "fleet", "--domain", "ops",
                "always confirm the change window")
    assert r.exit_code == 0, r.output
    assert seen["kind"] == "fleet" and seen["domain"] == "ops"


def test_deposit_requires_text_or_file(_home, monkeypatch):
    monkeypatch.setattr(cortex, "deposit",
                        lambda text, **kw: pytest.fail("kernel must not be called"))
    r = _invoke(_home, "cortex", "deposit")
    assert r.exit_code != 0
    assert "TEXT or --file" in r.output


def test_deposit_refuses_both_text_and_file(_home, monkeypatch, tmp_path):
    doc = tmp_path / "note.md"
    doc.write_text("x", encoding="utf-8")
    monkeypatch.setattr(cortex, "deposit",
                        lambda text, **kw: pytest.fail("kernel must not be called"))
    r = _invoke(_home, "cortex", "deposit", "--file", str(doc), "also text")
    assert r.exit_code != 0
    assert "not both" in r.output


def test_deposit_rejects_an_unknown_kind(_home, monkeypatch):
    monkeypatch.setattr(cortex, "deposit",
                        lambda text, **kw: pytest.fail("kernel must not be called"))
    r = _invoke(_home, "cortex", "deposit", "--kind", "gossip", "text")
    assert r.exit_code != 0


def test_deposit_failure_exits_nonzero_with_the_reason(_home, monkeypatch):
    monkeypatch.setattr(cortex, "deposit",
                        lambda text, **kw: (False, "cortex is disabled ([cortex] enable = true)"))
    r = _invoke(_home, "cortex", "deposit", "some text")
    assert r.exit_code != 0
    assert "cortex is disabled" in r.output
