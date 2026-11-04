"""Learned summarizer compaction (v3): outcome ledger + bandit-lite template pick."""
from __future__ import annotations

import json
import os
import stat

import pytest
from maverick.compaction import compact_messages
from maverick.compaction.learned import (
    TEMPLATES,
    LearnedSummarizer,
    OutcomeLedger,
    classify_kind,
    reward,
)


class FixedRng:
    """Injectable PRNG: scripted ``random()`` values, fixed ``randrange`` pick."""

    def __init__(self, values: list[float], pick: int = 0):
        self._values = list(values)
        self._pick = pick

    def random(self) -> float:
        return self._values.pop(0)

    def randrange(self, n: int) -> int:
        return min(self._pick, n - 1)


def _traj(tool: str = "shell") -> list[dict]:
    msgs: list[dict] = [{"role": "user", "content": "GOAL: ship the parser. brief."}]
    for i in range(5):
        msgs.append({"role": "assistant", "content": [
            {"type": "text", "text": f"step {i}"},
            {"type": "tool_use", "id": f"t{i}", "name": tool, "input": {"q": i}},
        ]})
        msgs.append({"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": f"t{i}", "content": f"out {i}"},
        ]})
    msgs.append({"role": "user", "content": "recent question"})
    msgs.append({"role": "assistant", "content": "recent answer"})
    return msgs


class TestClassifyKind:
    def test_code(self):
        assert classify_kind(_traj("shell")[1:]) == "code"

    def test_research(self):
        assert classify_kind(_traj("web_search")[1:]) == "research"

    def test_chat_when_no_tools(self):
        msgs = [{"role": "user", "content": "hi"}, {"role": "assistant", "content": "yo"}]
        assert classify_kind(msgs) == "chat"

    def test_mixed_when_no_majority(self):
        msgs = [{"role": "assistant", "content": [
            {"type": "tool_use", "id": "1", "name": "shell", "input": {}},
            {"type": "tool_use", "id": "2", "name": "web_search", "input": {}},
        ]}]
        assert classify_kind(msgs) == "mixed"


class TestReward:
    def test_bounds(self):
        assert reward(False, 0) == 0.0
        assert reward(True, 20) == 1.0
        assert reward(True, 0) == 0.5

    def test_continuation_saturates_and_clamps(self):
        assert reward(True, 200) == 1.0
        assert reward(False, -5) == 0.0


class TestOutcomeLedger:
    def test_record_accumulates(self, tmp_path):
        led = OutcomeLedger(path=tmp_path / "ledger.json")
        led.record("code", "facts", success=True, continuation_turns=20)
        led.record("code", "facts", success=False, continuation_turns=0)
        st = led.stats("code")["facts"]
        assert st["trials"] == 2
        assert st["reward_sum"] == 1.0

    def test_file_is_owner_only_and_uses_injected_clock(self, tmp_path):
        path = tmp_path / "ledger.json"
        led = OutcomeLedger(path=path, clock=lambda: 123.0)
        led.record("code", "facts", success=True, continuation_turns=0)
        raw = json.loads(path.read_text(encoding="utf-8"))
        assert raw["code"]["facts"]["last"] == 123.0
        if os.name == "posix":
            assert stat.S_IMODE(path.stat().st_mode) == 0o600

    def test_corrupt_file_degrades_to_empty(self, tmp_path):
        path = tmp_path / "ledger.json"
        path.write_text("{not json", encoding="utf-8")
        assert OutcomeLedger(path=path).stats("code") == {}

    def test_unknown_template_not_recorded(self, tmp_path):
        led = OutcomeLedger(path=tmp_path / "ledger.json")
        led.record("code", "nope", success=True)
        assert led.stats("code") == {}

    def test_default_path_under_data_dir(self, monkeypatch, tmp_path):
        monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mvhome"))
        assert OutcomeLedger().path == tmp_path / "mvhome" / "compaction_ledger.json"

    def test_pick_untried_first_in_fixed_order(self, tmp_path):
        led = OutcomeLedger(path=tmp_path / "ledger.json")
        ids = list(TEMPLATES)
        assert led.pick_template("code", FixedRng([0.9])) == ids[0]
        led.record("code", ids[0], success=True)
        assert led.pick_template("code", FixedRng([0.9])) == ids[1]

    def test_pick_exploits_best_mean(self, tmp_path):
        led = OutcomeLedger(path=tmp_path / "ledger.json")
        led.record("code", "facts", success=False, continuation_turns=0)       # 0.0
        led.record("code", "narrative", success=True, continuation_turns=20)   # 1.0
        led.record("code", "decisions", success=True, continuation_turns=0)    # 0.5
        assert led.pick_template("code", FixedRng([0.9])) == "narrative"

    def test_pick_explores_with_injected_rng(self, tmp_path):
        led = OutcomeLedger(path=tmp_path / "ledger.json")
        for tid in TEMPLATES:
            led.record("code", tid, success=True)
        # random() below epsilon -> explore; randrange picks index 2.
        assert led.pick_template("code", FixedRng([0.05], pick=2)) == list(TEMPLATES)[2]


class TestLearnedSummarizer:
    def test_short_list_passes_through(self):
        msgs = [{"role": "user", "content": "hi"}]
        assert LearnedSummarizer(llm=None).compact(msgs) == msgs

    def test_no_llm_falls_back_to_default(self, tmp_path):
        msgs = _traj()
        ls = LearnedSummarizer(llm=None, ledger=OutcomeLedger(path=tmp_path / "l.json"))
        assert ls.compact(msgs, keep_recent=2) == compact_messages(msgs, keep_recent=2)

    def test_digest_replaces_middle_keeps_brief_and_tail(
        self, tmp_path, fake_llm, make_llm_response,
    ):
        msgs = _traj()
        fake_llm.scripted = [make_llm_response("ran 5 shell steps; parser ships")]
        ls = LearnedSummarizer(
            llm=fake_llm, ledger=OutcomeLedger(path=tmp_path / "l.json"))
        out = ls.compact(msgs, keep_recent=2)
        assert out[0] == msgs[0]
        assert out[-2:] == msgs[-2:]
        assert len(out) == 4  # brief + digest + 2-message tail
        body = out[1]["content"]
        assert '<learned-digest kind="code" template="facts"' in body
        assert "ran 5 shell steps" in body
        # The transcript went through the seam.
        assert "step 0" in fake_llm.calls[0]["messages"][0]["content"]

    def test_uses_configured_summarizer_role_model(
        self, monkeypatch, tmp_path, fake_llm, make_llm_response,
    ):
        monkeypatch.setenv("MAVERICK_MODEL_OVERRIDE_SUMMARIZER", "testprov:tiny-sum")
        fake_llm.scripted = [make_llm_response("digest")]
        ls = LearnedSummarizer(
            llm=fake_llm, ledger=OutcomeLedger(path=tmp_path / "l.json"))
        ls.compact(_traj(), keep_recent=2)
        assert fake_llm.calls[0]["model"] == "testprov:tiny-sum"

    def test_department_scope_keys_its_own_ledger_rows(
        self, tmp_path, fake_llm, make_llm_response,
    ):
        # A finance agent's compaction outcomes train finance's own
        # (scope|kind) rows; an unscoped summarizer keeps the legacy keys.
        fake_llm.scripted = [make_llm_response("scoped digest")]
        ledger = OutcomeLedger(path=tmp_path / "l.json")
        ls = LearnedSummarizer(llm=fake_llm, ledger=ledger, scope="finance_sox")
        out = ls.compact(_traj(), keep_recent=2)
        assert ls.last_pick is not None
        kind, template = ls.last_pick
        assert kind == "finance_sox|code"
        assert 'kind="finance_sox|code"' in out[1]["content"]
        ls.record_outcome(success=True, continuation_turns=1)
        assert ledger.stats("finance_sox|code")[template]["trials"] == 1
        assert ledger.stats("code") == {}

    def test_llm_error_falls_back(self, tmp_path):
        class Boom:
            def complete(self, *a, **kw):
                raise RuntimeError("api down")

        msgs = _traj()
        ls = LearnedSummarizer(llm=Boom(), ledger=OutcomeLedger(path=tmp_path / "l.json"))
        assert ls.compact(msgs, keep_recent=2) == compact_messages(msgs, keep_recent=2)

    def test_empty_digest_falls_back(self, tmp_path, fake_llm, make_llm_response):
        msgs = _traj()
        fake_llm.scripted = [make_llm_response("   ")]
        ls = LearnedSummarizer(
            llm=fake_llm, ledger=OutcomeLedger(path=tmp_path / "l.json"))
        assert ls.compact(msgs, keep_recent=2) == compact_messages(msgs, keep_recent=2)

    def test_record_outcome_scores_last_pick(self, tmp_path, fake_llm, make_llm_response):
        fake_llm.scripted = [make_llm_response("digest")]
        led = OutcomeLedger(path=tmp_path / "l.json")
        ls = LearnedSummarizer(llm=fake_llm, ledger=led)
        ls.compact(_traj(), keep_recent=2)
        assert ls.last_pick == ("code", "facts")
        ls.record_outcome(success=True, continuation_turns=20)
        st = led.stats("code")["facts"]
        assert st["trials"] == 1
        assert st["reward_sum"] == pytest.approx(1.0)

    def test_record_outcome_noop_before_any_compaction(self, tmp_path):
        led = OutcomeLedger(path=tmp_path / "l.json")
        LearnedSummarizer(llm=None, ledger=led).record_outcome(success=True)
        assert led.stats("code") == {}

    def test_ledger_scores_drive_template_choice(
        self, tmp_path, fake_llm, make_llm_response,
    ):
        led = OutcomeLedger(path=tmp_path / "l.json")
        led.record("code", "facts", success=False)
        led.record("code", "narrative", success=True, continuation_turns=20)
        led.record("code", "decisions", success=False)
        fake_llm.scripted = [make_llm_response("digest")]
        ls = LearnedSummarizer(llm=fake_llm, ledger=led, rng=FixedRng([0.9]))
        out = ls.compact(_traj(), keep_recent=2)
        assert fake_llm.calls[0]["system"] == TEMPLATES["narrative"]
        assert 'template="narrative"' in out[1]["content"]


def test_record_is_concurrency_safe(tmp_path):
    """Separate ledgers at one path (≈ separate processes) recording the same
    template must accumulate trials, not clobber: the load-modify-save is now
    flock-guarded (the discipline the docstring already promised)."""
    import threading

    from maverick.compaction.learned import OutcomeLedger

    p = tmp_path / "ledger.json"
    n, per = 8, 20

    def worker():
        led = OutcomeLedger(path=p)
        for _ in range(per):
            led.record("code", "facts", success=True, continuation_turns=5)

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    st = OutcomeLedger(path=p).stats("code").get("facts", {})
    assert int(st.get("trials", 0)) == n * per
    assert list(tmp_path.glob("*.tmp")) == []
