"""Exact-owner navigation erasure retains shared and other-owner records."""
import json

import pytest
from maverick.ux_store import UxStore, ViewConflict


@pytest.fixture
def store(tmp_path):
    value = UxStore(tmp_path / "ux.json")
    value.pin("user:alice", 1)
    value.pin("user:bob", 2)
    value.save_view("user:alice", "Private filter", {"q": "private search"})
    value.save_view("user:bob", "Other filter", {"q": "other search"})
    value.annotate(1, 0, "shared trace", author="user:alice")
    value.gallery_add(1, blurb="retained curation", curator="user:alice")
    return value


def test_inventory_is_content_free_and_export_is_exact_owner(store):
    inventory = store.owned_navigation_inventory("user:alice")
    assert inventory["pin_count"] == inventory["view_count"] == 1
    assert "private search" not in json.dumps(inventory)
    assert "Private filter" not in json.dumps(inventory)
    exported = store.export_owned_navigation("user:alice")
    assert exported["pins"] == [1]
    assert exported["views"]["Private filter"]["params"]["q"] == "private search"
    assert "other search" not in json.dumps(exported) and "shared trace" not in json.dumps(exported)


def test_reviewed_erasure_preserves_every_other_owner_and_shared_record(store):
    other = store.export_owned_navigation("user:bob")
    annotations, gallery = store.annotations(1), store.gallery()
    result = store.erase_owned_navigation("user:alice", expected_version=store.owned_navigation_inventory("user:alice")["version"])
    assert result["state"] == "purged" and result["removed"] == 2
    assert store.pins("user:alice") == [] and store.views("user:alice") == {}
    assert store.export_owned_navigation("user:bob") == other
    assert store.annotations(1) == annotations and store.gallery() == gallery
    assert "trace annotations" in result["retained"]


@pytest.mark.parametrize("change", ["pin", "view"])
def test_new_pin_or_filter_invalidates_review_before_any_deletion(store, change):
    revision = store.owned_navigation_inventory("user:alice")["version"]
    if change == "pin":
        store.pin("user:alice", 3)
    else:
        store.save_view("user:alice", "New", {"q": "newer"})
    before = store.path.read_bytes()
    with pytest.raises(ViewConflict):
        store.erase_owned_navigation("user:alice", expected_version=revision)
    assert store.path.read_bytes() == before


def test_snapshot_cannot_be_reused_for_another_workspace_store(store, tmp_path):
    other = UxStore(tmp_path / "other-workspace" / "ux.json")
    other.path.parent.mkdir()
    other.path.write_bytes(store.path.read_bytes())
    with pytest.raises(ViewConflict):
        other.erase_owned_navigation("user:alice", expected_version=store.owned_navigation_inventory("user:alice")["version"])
    assert other.pins("user:alice") == [1]


def test_unreadable_or_malformed_storage_never_reports_empty_or_purged(store):
    version = store.owned_navigation_inventory("user:alice")["version"]
    store.path.write_text('{"pins":', encoding="utf-8")
    for operation in [lambda: store.owned_navigation_inventory("user:alice"),
                      lambda: store.export_owned_navigation("user:alice"),
                      lambda: store.erase_owned_navigation("user:alice", expected_version=version),
                      lambda: store.view_snapshot("user:alice")]:
        with pytest.raises(ValueError):
            operation()
    assert store.path.read_text(encoding="utf-8") == '{"pins":'


def test_write_failure_never_returns_an_erasure_confirmation(store, monkeypatch):
    version = store.owned_navigation_inventory("user:alice")["version"]
    before = store.path.read_bytes()
    def failed(_data):
        raise OSError("disk unavailable")
    monkeypatch.setattr(store, "_save", failed)
    with pytest.raises(OSError):
        store.erase_owned_navigation("user:alice", expected_version=version)
    assert store.path.read_bytes() == before


@pytest.mark.parametrize("owner", [None, "", "_anon", " user:alice"])
def test_unnamed_or_normalized_identity_cannot_address_owner_bucket(store, owner):
    with pytest.raises(ValueError):
        store.owned_navigation_inventory(owner)
