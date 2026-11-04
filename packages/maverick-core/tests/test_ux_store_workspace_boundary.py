"""Shared UX state resolves each caller's tenant, without losing write locks."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from maverick import paths, ux_store


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    ux_store.reset_shared()
    yield
    ux_store.reset_shared()


def test_repeated_workspace_switch_scopes_all_ux_records():
    with paths.tenant_scope(tenant="ux-alpha"):
        first = ux_store.shared()
        first.annotate(7, 1, "Alpha private annotation", author="alice")
        first.pin("alice", 7)
        first.save_view("alice", "Private view", {"q": "Alpha query"})
        first.gallery_add(7, blurb="Alpha private blurb", curator="alice")
    with paths.tenant_scope(tenant="ux-beta"):
        other = ux_store.shared()
        assert other.annotations(7) == []
        assert other.pins("alice") == []
        assert other.views("alice") == {}
        assert other.gallery() == []
        other.annotate(7, 1, "Beta annotation", author="alice")
    with paths.tenant_scope(tenant="ux-alpha"):
        assert ux_store.shared() is first
        assert ux_store.shared().annotations(7)[0]["note"] == "Alpha private annotation"


def test_concurrent_contexts_retain_one_store_lock_per_workspace():
    barrier = Barrier(4)

    def write(index):
        workspace = "ux-alpha" if index % 2 == 0 else "ux-beta"
        with paths.tenant_scope(tenant=workspace):
            store = ux_store.shared()
            barrier.wait(timeout=10)
            store.annotate(7, index, workspace, author="alice")
            return workspace, store

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(write, range(4)))
    assert results[0][1] is results[2][1]
    assert results[1][1] is results[3][1]
    assert results[0][1] is not results[1][1]
    for workspace in ("ux-alpha", "ux-beta"):
        with paths.tenant_scope(tenant=workspace):
            rows = ux_store.shared().annotations(7)
            assert len(rows) == 2
            assert {row["note"] for row in rows} == {workspace}


def test_legacy_first_workspace_file_is_not_silently_adopted():
    # Reproduce the historical first-workspace capture: a store from A is
    # subsequently used by B, so its file cannot safely be assigned to A.
    with paths.tenant_scope(tenant="ux-alpha"):
        legacy_path = paths.data_dir("dashboard", "ux_store.json")
        captured = ux_store.UxStore(path=legacy_path)
    with paths.tenant_scope(tenant="ux-beta"):
        captured.annotate(7, 1, "Beta private annotation", author="alice")
        captured.pin("alice", 7)
        captured.save_view("alice", "Beta private view", {"q": "Beta private query"})
        captured.gallery_add(7, blurb="Beta private blurb", curator="alice")
    ux_store.reset_shared()
    with paths.tenant_scope(tenant="ux-alpha"):
        current = ux_store.shared()
        assert current.annotations(7) == []
        assert current.pins("alice") == []
        assert current.views("alice") == {}
        assert current.gallery() == []
        assert ux_store.UxStore().annotations(7) == []
        current.annotate(7, 1, "New Alpha annotation", author="alice")
        assert current.annotations(7)[0]["note"] == "New Alpha annotation"
    # Bytes remain available for deliberate custodian review, not guessed
    # ownership, destructive migration or ordinary employee publication.
    assert ux_store.UxStore(path=legacy_path).annotations(7)[0]["note"] == "Beta private annotation"
