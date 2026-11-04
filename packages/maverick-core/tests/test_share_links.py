"""Revocable, expiring read-only share links (schema v20). The clear token is
returned once; only its hash is stored."""
from __future__ import annotations

from maverick.world_model import WorldModel


def test_mint_and_resolve(tmp_path):
    w = WorldModel(tmp_path / "w.db")
    g = w.create_goal("forecast", domain="finance_cash13w")
    lid, token = w.create_share_link(g, created_by="user:a", ttl_seconds=3600)
    assert isinstance(lid, int) and len(token) > 20
    assert w.resolve_share_link(token) == g
    assert w.resolve_share_link("not-a-real-token") is None
    assert w.resolve_share_link("") is None


def test_clear_token_is_not_stored(tmp_path):
    # Only the SHA-256 hash hits disk -- the raw token must not appear in the DB.
    db = tmp_path / "w.db"
    w = WorldModel(db)
    g = w.create_goal("g")
    _, token = w.create_share_link(g)
    assert token.encode() not in db.read_bytes()


def test_expiry(tmp_path):
    w = WorldModel(tmp_path / "w.db")
    g = w.create_goal("g")
    _, token = w.create_share_link(g, ttl_seconds=-1)  # already past
    assert w.resolve_share_link(token) is None


def test_revoke_is_goal_scoped(tmp_path):
    w = WorldModel(tmp_path / "w.db")
    g = w.create_goal("g")
    other = w.create_goal("other")
    lid, token = w.create_share_link(g)
    assert w.revoke_share_link(lid, goal_id=other) is False   # wrong goal: no-op
    assert w.resolve_share_link(token) == g                    # still valid
    assert w.revoke_share_link(lid, goal_id=g) is True
    assert w.resolve_share_link(token) is None                 # now dead


def test_links_for_goal_lifecycle(tmp_path):
    w = WorldModel(tmp_path / "w.db")
    g = w.create_goal("g")
    live, _ = w.create_share_link(g)
    expired, _ = w.create_share_link(g, ttl_seconds=-1)
    w.create_share_link(g)
    w.revoke_share_link(live, goal_id=g)
    states = {d["id"]: (d["active"], d["revoked"], d["expired"]) for d in w.share_links_for_goal(g)}
    assert states[live] == (False, True, False)
    assert states[expired] == (False, False, True)
    assert any(s[0] for s in states.values())  # the untouched one is active
