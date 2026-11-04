"""Embedding-based skill retrieval tests.

fastembed is an optional dep and not installed in CI, so most tests
here exercise the graceful-fallback path (relevant_skills_embed
returns None -> caller uses lexical).
"""
from __future__ import annotations

from pathlib import Path

import pytest
from maverick.skill.embeddings import (
    _cosine,
    _have_fastembed,
    _skill_to_embed_text,
    relevant_skills_embed,
)
from maverick.skills import Skill


def _mk_skill(name: str, triggers: list[str], body: str = "") -> Skill:
    return Skill(
        name=name, triggers=triggers, tools_needed=[],
        body=body or "placeholder", path=Path(f"/tmp/{name}.md"),
    )


def test_embedding_cache_is_tenant_scoped(monkeypatch, tmp_path):
    """The vector cache must follow the ACTIVE tenant, not the import-time one.

    CACHE_PATH was frozen at import, so in a long-lived multi-tenant process
    tenant B read/wrote tenant A's cache; since it's keyed by skill name and
    learned skills are tenant-scoped, B could be served A's vector. Mirrors the
    isolation stats.py already has. Regression for the import-time freeze."""
    from maverick.paths import reset_tenant, set_tenant
    from maverick.skill.embeddings import (
        CachedEmbedding,
        _cache_path,
        _load_cache,
        _save_cache,
    )

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))

    tok = set_tenant("acme")
    try:
        _save_cache({"shared": CachedEmbedding(
            name="shared", text="ACME-text", mtime=1.0, vector=[0.1, 0.2])})
        acme_path = _cache_path()
    finally:
        reset_tenant(tok)

    tok = set_tenant("globex")
    try:
        # globex sees its OWN (empty) cache, not acme's.
        assert _load_cache() == {}
        _save_cache({"shared": CachedEmbedding(
            name="shared", text="GLOBEX-text", mtime=2.0, vector=[0.9])})
        globex_path = _cache_path()
    finally:
        reset_tenant(tok)

    assert acme_path != globex_path  # separate per-tenant files

    tok = set_tenant("acme")
    try:
        # acme still reads ITS OWN vector, uncontaminated by globex.
        assert _load_cache()["shared"].text == "ACME-text"
    finally:
        reset_tenant(tok)


class TestCosine:
    def test_identical_vectors_score_one(self):
        v = [1.0, 0.0, 0.0]
        assert _cosine(v, v) == pytest.approx(1.0)

    def test_orthogonal_vectors_score_zero(self):
        assert _cosine([1.0, 0.0], [0.0, 1.0]) == 0.0

    def test_opposite_vectors_score_negative_one(self):
        assert _cosine([1.0, 0.0], [-1.0, 0.0]) == pytest.approx(-1.0)

    def test_zero_vector_returns_zero(self):
        assert _cosine([0.0, 0.0], [1.0, 1.0]) == 0.0

    def test_mismatched_lengths_return_zero(self):
        assert _cosine([1.0], [1.0, 1.0]) == 0.0


class TestEmbedText:
    def test_includes_name_and_triggers(self):
        s = _mk_skill("deploy", ["ship it", "push to prod"], "# Deploy a service")
        text = _skill_to_embed_text(s)
        assert "deploy" in text
        assert "ship it" in text
        assert "push to prod" in text
        # First body line included.
        assert "# Deploy a service" in text

    def test_empty_triggers_no_crash(self):
        s = _mk_skill("orphan", [])
        text = _skill_to_embed_text(s)
        assert "orphan" in text


class TestRelevantSkillsEmbed:
    def test_returns_none_when_fastembed_missing(self):
        if _have_fastembed():
            pytest.skip("fastembed installed; this test verifies fallback path")
        skills = [_mk_skill("a", ["do thing"])]
        assert relevant_skills_embed("do thing", skills) is None

    def test_empty_skills_returns_empty(self):
        # When fastembed is missing returns None; when installed returns [].
        # Either way, no crash.
        result = relevant_skills_embed("anything", [])
        assert result in (None, [])
