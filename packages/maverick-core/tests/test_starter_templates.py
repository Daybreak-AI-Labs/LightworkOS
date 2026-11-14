"""Personalized starter templates: profile, scorer, suggest ranking."""
from __future__ import annotations

import pytest
from maverick import starter_templates as st
from maverick.templates import Template
from maverick.world_model import WorldModel


def _world(tmp_path) -> WorldModel:
    return WorldModel(tmp_path / "world.db")


def _tpl(name: str, title: str, params: list[str] | None = None) -> Template:
    return Template(name=name, title=title, body="body", params=params or [])


def test_tokens_drop_stopwords_and_short_words():
    toks = st._tokens("Research the best AI agent for my trip")
    assert "research" in toks and "agent" in toks and "trip" in toks
    assert "the" not in toks and "for" not in toks and "ai" not in toks  # len < 3


def test_history_profile_counts_title_words(tmp_path):
    w = _world(tmp_path)
    w.create_goal("research competitor pricing", "")
    w.create_goal("research market trends", "")
    w.create_goal("draft launch email", "")
    profile = st.history_profile(w)
    assert profile["research"] == 2
    assert profile["email"] == 1


def test_score_counts_distinct_words_once():
    from collections import Counter
    p = Counter({"research": 5, "trip": 2})
    # 'research' appears in both name and title but only counts once.
    assert st.score_template("research-deep", "Deep research report", [], p) == 5
    assert st.score_template("trip-plan", "Plan a trip", ["trip"], p) == 2
    assert st.score_template("unrelated", "Tidy the garage", [], p) == 0


def test_suggest_ranks_by_history_overlap(tmp_path):
    w = _world(tmp_path)
    for _ in range(3):
        w.create_goal("research a market", "")
    w.create_goal("plan a trip to lisbon", "")
    tpls = [
        _tpl("trip-plan", "Plan a trip to {{ city }}", ["city"]),
        _tpl("research-report", "Research a topic in depth", ["topic"]),
        _tpl("email-draft", "Draft an email"),
    ]
    rows = st.suggest(w, k=3, templates=tpls)
    assert [r["name"] for r in rows] == ["research-report", "trip-plan", "email-draft"]
    assert rows[0]["score"] >= 3 and rows[0]["params"] == ["topic"]
    assert rows[2]["score"] == 0


def test_suggest_cold_start_is_alphabetical_and_k_capped(tmp_path):
    w = _world(tmp_path)  # no history at all
    tpls = [_tpl("zeta", "Z"), _tpl("alpha", "A"), _tpl("mid", "M")]
    rows = st.suggest(w, k=2, templates=tpls)
    assert [r["name"] for r in rows] == ["alpha", "mid"]


def test_suggest_owner_scopes_history(tmp_path):
    w = _world(tmp_path)
    w.create_goal("research quarterly numbers", "", owner="user:amy")
    w.create_goal("plan a trip", "", owner="user:bob")
    tpls = [_tpl("research-report", "Research a topic"), _tpl("trip-plan", "Plan a trip")]
    amy = st.suggest(w, k=1, owner="user:amy", templates=tpls)
    bob = st.suggest(w, k=1, owner="user:bob", templates=tpls)
    assert amy[0]["name"] == "research-report"
    assert bob[0]["name"] == "trip-plan"
    # An unscoped (admin) caller is ranked on all goals, not only unowned ones.
    w.create_goal("plan another trip", "", owner="user:amy")
    assert st.suggest(w, k=1, owner=None, templates=tpls)[0]["name"] == "trip-plan"


def test_suggest_reads_local_template_catalog(tmp_path, monkeypatch):
    import maverick.templates as tpl_mod
    user_dir = tmp_path / "templates"
    user_dir.mkdir()
    (user_dir / "trip-plan.md").write_text(
        "---\nowner: local\ntitle: Plan a trip to {{ city }}\nparams:\n  - city\n---\nGo.",
        encoding="utf-8",
    )
    monkeypatch.setattr(tpl_mod, "USER_TEMPLATES", user_dir)
    monkeypatch.setattr(tpl_mod, "_BUNDLED_CANDIDATES", [])
    w = _world(tmp_path)
    w.create_goal("plan a trip to porto", "")
    rows = st.suggest(w, k=5)
    assert rows[0]["name"] == "trip-plan" and rows[0]["score"] > 0


def test_user_template_path_resolves_current_tenant_at_call_time(tmp_path, monkeypatch):
    """One long-lived process must not pin tenant A's template dir at import."""
    import maverick.templates as tpl_mod
    from maverick.paths import reset_tenant, set_tenant

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    name = "tenant-isolation-probe-7391"

    token = set_tenant("acme")
    try:
        tpl_mod.save_user_template(name, title="Acme", body="acme-only")
        assert tpl_mod.load_template(name).body == "acme-only"
    finally:
        reset_tenant(token)

    token = set_tenant("globex")
    try:
        with pytest.raises(FileNotFoundError):
            tpl_mod.load_template(name)
        tpl_mod.save_user_template(name, title="Globex", body="globex-only")
        assert tpl_mod.load_template(name).body == "globex-only"
    finally:
        reset_tenant(token)

    token = set_tenant("acme")
    try:
        assert tpl_mod.load_template(name).body == "acme-only"
    finally:
        reset_tenant(token)
