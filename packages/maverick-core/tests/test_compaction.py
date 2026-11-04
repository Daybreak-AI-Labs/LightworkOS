"""Long-context compaction."""
from __future__ import annotations

from maverick.compaction import (
    compact_messages,
    make_heuristic_digest,
    should_digest,
)


def _tool_turn(i: int, size: int) -> list[dict]:
    """An assistant tool_use + user tool_result pair carrying `size` chars."""
    return [
        {"role": "assistant", "content": [
            {"type": "tool_use", "id": f"t{i}", "name": "shell", "input": {}}]},
        {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": f"t{i}",
             "content": f"out{i} " + "x" * size}]},
    ]


class TestTotalCeiling:
    """max_total_bytes: the live-window overflow pass.

    The per-block pass only trims content behind keep_recent; inside the
    recent window a handful of results at the per-result cap can still carry
    ~100k tokens. Over the ceiling, the shrink extends into the recent window
    (oldest first), always sparing the first message (the brief) and the last
    (the freshest tool results the model must act on).
    """

    def _msgs(self) -> list[dict]:
        msgs = [{"role": "user", "content": "the brief"}]
        for i in range(4):
            msgs += _tool_turn(i, 10_000)
        return msgs

    def test_over_ceiling_shrinks_recent_window(self):
        msgs = self._msgs()
        out = compact_messages(
            msgs, keep_recent=8, max_tool_bytes=200, max_total_bytes=15_000)
        assert out[0] == msgs[0]              # brief intact
        assert out[-1] == msgs[-1]            # freshest tool_result intact
        # at least the oldest in-window result was digested
        assert "truncated" in out[2]["content"][0]["content"]
        total = sum(len(str(m.get("content"))) for m in out)
        assert total < sum(len(str(m.get("content"))) for m in msgs)

    def test_oldest_shrunk_first_newer_spared(self):
        msgs = self._msgs()
        # ceiling that one shrink satisfies: only turn 0's result is digested
        out = compact_messages(
            msgs, keep_recent=8, max_tool_bytes=200, max_total_bytes=32_000)
        assert "truncated" in out[2]["content"][0]["content"]
        assert out[4]["content"][0]["content"] == msgs[4]["content"][0]["content"]

    def test_under_ceiling_recent_window_untouched(self):
        msgs = self._msgs()
        out = compact_messages(
            msgs, keep_recent=8, max_tool_bytes=200, max_total_bytes=500_000)
        assert out == msgs

    def test_zero_disables_ceiling(self):
        msgs = self._msgs()
        out = compact_messages(
            msgs, keep_recent=8, max_tool_bytes=200, max_total_bytes=0)
        assert out == msgs

    def test_overflow_pass_is_idempotent(self):
        msgs = self._msgs()
        once = compact_messages(
            msgs, keep_recent=8, max_tool_bytes=200, max_total_bytes=15_000)
        twice = compact_messages(
            once, keep_recent=8, max_tool_bytes=200, max_total_bytes=15_000)
        assert twice == once

    def test_tool_use_pairing_preserved(self):
        # shrinking must never drop messages/blocks, only shrink content
        msgs = self._msgs()
        out = compact_messages(
            msgs, keep_recent=8, max_tool_bytes=200, max_total_bytes=15_000)
        assert len(out) == len(msgs)
        uses = [b["id"] for m in out for b in m["content"]
                if isinstance(m["content"], list) and isinstance(b, dict)
                and b.get("type") == "tool_use"]
        results = [b["tool_use_id"] for m in out for b in m["content"]
                   if isinstance(m["content"], list) and isinstance(b, dict)
                   and b.get("type") == "tool_result"]
        assert uses == results == [f"t{i}" for i in range(4)]


class TestCompactMessages:
    def test_short_list_passes_through(self):
        msgs = [{"role": "user", "content": "hi"}]
        out = compact_messages(msgs, keep_recent=4)
        assert out == msgs

    def test_recent_messages_untouched(self):
        """The last `keep_recent` messages must not be shrunk."""
        msgs = [
            {"role": "user", "content": "the brief"},
            {"role": "assistant", "content": "ok"},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "x",
                                          "content": "huge " * 10000}]},
            {"role": "assistant", "content": "ok2"},
            {"role": "user", "content": "recent-1"},
            {"role": "assistant", "content": "recent-2"},
        ]
        out = compact_messages(msgs, keep_recent=2, max_tool_bytes=100)
        # First (user brief) preserved.
        assert out[0] == msgs[0]
        # Recent two unchanged.
        assert out[-2:] == msgs[-2:]

    def test_old_oversized_tool_result_shrunk(self):
        big = "x" * 5000
        msgs = [
            {"role": "user", "content": "brief"},
            {"role": "user", "content": [{
                "type": "tool_result", "tool_use_id": "abc",
                "content": big,
            }]},
            {"role": "assistant", "content": "ok"},
            {"role": "user", "content": "recent"},
        ]
        out = compact_messages(msgs, keep_recent=2, max_tool_bytes=200)
        # The big tool_result is now small with a digest hint.
        shrunk = out[1]["content"][0]
        assert isinstance(shrunk, dict)
        assert "truncated" in shrunk["content"]
        assert "5000B" in shrunk["content"]
        assert len(shrunk["content"]) < 500

    def test_under_threshold_tool_result_passes_through(self):
        small = "x" * 50
        msgs = [
            {"role": "user", "content": "brief"},
            {"role": "user", "content": [{"type": "tool_result",
                                          "tool_use_id": "abc",
                                          "content": small}]},
            {"role": "assistant", "content": "a"},
            {"role": "user", "content": "b"},
            {"role": "assistant", "content": "c"},
            {"role": "user", "content": "recent"},
        ]
        out = compact_messages(msgs, keep_recent=2, max_tool_bytes=200)
        assert out[1]["content"][0]["content"] == small

    def test_text_content_string_truncated(self):
        msgs = [
            {"role": "user", "content": "brief"},
            {"role": "assistant", "content": "y" * 5000},
            {"role": "user", "content": "recent"},
            {"role": "assistant", "content": "ok"},
        ]
        out = compact_messages(msgs, keep_recent=2, max_tool_bytes=200)
        assert "truncated" in out[1]["content"]
        assert len(out[1]["content"]) < 500


class TestShouldDigest:
    def test_zero_step_no(self):
        assert should_digest(0) is False

    def test_multiples_yes(self):
        assert should_digest(10, every=10) is True
        assert should_digest(20, every=10) is True

    def test_non_multiples_no(self):
        assert should_digest(7, every=10) is False
        assert should_digest(15, every=10) is False


class TestHeuristicDigest:
    def test_includes_first_user_brief(self):
        msgs = [
            {"role": "user", "content": "Plan a trip to Lisbon."},
            {"role": "assistant", "content": [{"type": "tool_use",
                                               "id": "1", "name": "shell",
                                               "input": {"cmd": "ls"}}]},
        ]
        out = make_heuristic_digest(msgs)
        assert "Lisbon" in out
        assert "<digest>" in out
        assert "</digest>" in out

    def test_counts_tool_invocations(self):
        msgs = [
            {"role": "user", "content": "brief"},
            {"role": "assistant", "content": [
                {"type": "tool_use", "id": "1", "name": "shell", "input": {}},
                {"type": "tool_use", "id": "2", "name": "shell", "input": {}},
                {"type": "tool_use", "id": "3", "name": "read_file", "input": {}},
            ]},
        ]
        out = make_heuristic_digest(msgs)
        assert "shell(2)" in out
        assert "read_file(1)" in out

    def test_empty_messages(self):
        assert make_heuristic_digest([]) == ""
