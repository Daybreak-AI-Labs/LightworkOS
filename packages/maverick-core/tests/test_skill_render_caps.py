"""Skill overlays must be bounded before entering the system prompt.

Regression target: render_for_prompt appended full SKILL.md bodies with no
char cap — the only size limit anywhere was 256 KB at install — so three
recalled skills could inject ~190k tokens into EVERY agent's system prompt,
re-paid by each node of a swarm. The render caps bound the per-body and
combined size; deep workers recall fewer skills than the root.
"""
from __future__ import annotations

from types import SimpleNamespace

from maverick.skills import render_for_prompt


def _skill(name: str, body: str):
    # A built-in skill carries no learned runtime binding.
    return SimpleNamespace(name=name, body=body, source="builtin", _runtime_binding=None)


class TestRenderCaps:
    def test_small_bodies_untouched(self):
        out = render_for_prompt([_skill("a", "short body")])
        assert "## a" in out and "short body" in out
        assert "truncated" not in out

    def test_oversized_body_truncated_with_note(self):
        out = render_for_prompt([_skill("big", "x" * 50_000)])
        assert len(out) < 6_000
        assert "truncated" in out

    def test_total_budget_drops_lowest_relevance_tail(self):
        # skills arrive relevance-ranked; once the combined budget is spent,
        # the tail (least relevant) is dropped rather than squeezing all in
        skills = [_skill(f"s{i}", "y" * 4_000) for i in range(3)]
        out = render_for_prompt(skills, max_body_chars=4_000, max_total_chars=8_000)
        assert "## s0" in out and "## s1" in out
        assert "## s2" not in out

    def test_first_skill_always_renders(self):
        out = render_for_prompt(
            [_skill("only", "z" * 4_000)], max_body_chars=4_000, max_total_chars=100)
        assert "## only" in out

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_SKILL_RENDER_MAX_CHARS", "100")
        out = render_for_prompt([_skill("a", "w" * 500)])
        assert "truncated" in out and len(out) < 400

    def test_zero_disables_caps(self):
        body = "v" * 20_000
        out = render_for_prompt(
            [_skill("a", body)], max_body_chars=0, max_total_chars=0)
        assert body in out


class TestDepthGating:
    def test_workers_recall_fewer_skills(self, monkeypatch):
        from maverick.agent import apply_skill_overlays

        seen = {}

        def fake_relevant(brief, all_skills, max_n=3):
            seen["max_n"] = max_n
            return []

        monkeypatch.setattr("maverick.skills.relevant_skills", fake_relevant)
        monkeypatch.setattr("maverick.skills.available_skills", list)
        apply_skill_overlays("B", brief="x", use_skills=True, depth=0)
        assert seen["max_n"] == 3
        apply_skill_overlays("B", brief="x", use_skills=True, depth=2)
        assert seen["max_n"] == 1
