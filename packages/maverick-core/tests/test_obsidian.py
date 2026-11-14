"""Obsidian vault tool."""
from __future__ import annotations

import pytest
from maverick.tools import obsidian as obs


def test_create_read_append_list_search(tmp_path):
    assert obs._op_create(tmp_path, "ideas/agents.md", "# Agents\nswarm notes") \
        == "created ideas/agents.md"
    assert "swarm notes" in obs._op_read(tmp_path, "ideas/agents.md")
    # create refuses to clobber
    assert "already exists" in obs._op_create(tmp_path, "ideas/agents.md", "x")
    # append (adds a newline separator)
    obs._op_append(tmp_path, "ideas/agents.md", "more")
    body = obs._op_read(tmp_path, "ideas/agents.md")
    assert body.endswith("more") and "swarm notes" in body
    # the .md suffix is added automatically
    obs._op_create(tmp_path, "todo", "buy milk")
    assert "todo.md" in obs._op_list(tmp_path)
    # search hits by name and by content
    assert "ideas/agents.md" in obs._op_search(tmp_path, "swarm")
    assert "todo.md" in obs._op_search(tmp_path, "todo")
    assert "no notes match" in obs._op_search(tmp_path, "zzz-nope")


def test_read_missing_note(tmp_path):
    assert "no such note" in obs._op_read(tmp_path, "absent.md")


def test_resolve_rejects_path_traversal(tmp_path):
    with pytest.raises(ValueError):
        obs._resolve(tmp_path, "../escape.md")
    with pytest.raises(ValueError):
        obs._resolve(tmp_path, "/etc/passwd")


def test_run_dispatch(monkeypatch, tmp_path):
    monkeypatch.setattr(obs, "_vault", lambda: tmp_path)
    assert obs._run({"op": "create", "note": "n.md", "body": "hello"}) == "created n.md"
    assert obs._run({"op": "read", "note": "n.md"}) == "hello"
    assert obs._run({"op": "search", "query": "hello"}) == "n.md"
    assert obs._run({"op": "bogus"}).startswith("ERROR: unknown op")
    assert obs._run({}).startswith("ERROR: op is required")


def test_run_without_vault_config_errors(monkeypatch):
    def _no_vault():
        raise RuntimeError("no Obsidian vault configured")
    monkeypatch.setattr(obs, "_vault", _no_vault)
    assert "no Obsidian vault configured" in obs._run({"op": "list"})


def test_factory_shape():
    t = obs.obsidian()
    assert t.name == "obsidian" and t.fn is obs._run
    assert "op" in t.input_schema["required"]


def test_search_survives_a_non_utf8_note_and_clamps_limit(monkeypatch, tmp_path):
    monkeypatch.setattr(obs, "_vault", lambda: tmp_path)
    (tmp_path / "bad.md").write_bytes(b"\xff\xfe not utf-8")
    (tmp_path / "good.md").write_text("needle", encoding="utf-8")
    assert obs._run({"op": "search", "query": "needle"}) == "good.md"
    assert obs._run({"op": "list", "limit": -1}) == "bad.md"
