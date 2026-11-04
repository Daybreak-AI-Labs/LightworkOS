"""Tenant lifecycle / provisioning registry."""
from __future__ import annotations

import sqlite3

import pytest
from click.testing import CliRunner
from maverick.cli import main
from maverick.tenant import registry as tr


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)


def test_create_lists_and_makes_workspace(tmp_path):
    rec = tr.create_tenant("acme", plan="pro", display_name="Acme Inc", max_daily_dollars=50)
    assert rec.id == "acme" and rec.status == tr.ACTIVE and rec.plan == "pro"
    assert rec.max_daily_dollars == 50.0
    assert [t.id for t in tr.list_tenants()] == ["acme"]
    # The tenant's workspace dir was materialized under tenants/.
    assert (tmp_path / "tenants" / "acme").exists()


def test_create_defaults_to_no_cap_and_a_cap_is_an_explicit_choice():
    default = tr.create_tenant("default")
    bounded = tr.create_tenant("bounded", max_daily_dollars=5)

    assert default.max_daily_dollars == tr.DEFAULT_TENANT_DAILY_DOLLARS == 0.0
    assert bounded.max_daily_dollars == 5.0


def test_create_duplicate_rejected():
    tr.create_tenant("acme")
    with pytest.raises(ValueError) as exc:
        tr.create_tenant("acme")
    assert not isinstance(exc.value, tr.DuplicateWorkspaceName)


def test_visible_workspace_name_is_unique_even_when_paused(tmp_path):
    tr.create_tenant("acme", display_name="Acme Finance")
    tr.suspend_tenant("acme")
    with pytest.raises(tr.DuplicateWorkspaceName, match="workspace with that name"):
        tr.create_tenant("other", display_name=" acme   FINANCE ", allocate_suffix=True)
    assert not (tmp_path / "tenants" / "other").exists()
    assert [rec.id for rec in tr.list_tenants()] == ["acme"]
    assert tr.create_tenant("other", display_name="Acme Sales").display_name == "Acme Sales"


def test_unnamed_workspace_cannot_shadow_an_existing_visible_name(tmp_path):
    tr.create_tenant("first", display_name="Acme")
    with pytest.raises(tr.DuplicateWorkspaceName, match="workspace with that name"):
        tr.create_tenant("acme")
    assert not (tmp_path / "tenants" / "acme").exists()
    assert [rec.id for rec in tr.list_tenants()] == ["first"]


def test_implicit_default_workspace_name_is_reserved_before_first_roster(monkeypatch):
    monkeypatch.setenv("MAVERICK_TENANT", "implicit")
    with pytest.raises(tr.DuplicateWorkspaceName, match="workspace with that name"):
        tr.create_tenant("other", display_name="Default workspace")
    assert tr.list_tenants() == []


def test_create_rejects_casefold_namespace_alias(tmp_path):
    from maverick.paths import TenantNamespaceCollision

    tr.create_tenant("Acme")
    with pytest.raises((ValueError, TenantNamespaceCollision), match="alias"):
        tr.create_tenant("acme")
    assert [record.id for record in tr.list_tenants()] == ["Acme"]
    assert (tmp_path / "tenants" / "Acme").is_dir()


def test_create_normalizes_nfd_and_rejects_duplicate_identity():
    import unicodedata

    nfc = unicodedata.normalize("NFC", "café")
    nfd = unicodedata.normalize("NFD", "café")
    assert tr.create_tenant(nfd).id == nfc
    assert tr.get_tenant(nfd).id == nfc
    with pytest.raises(ValueError, match="already exists"):
        tr.create_tenant(nfc)


def test_deleted_namespace_claim_prevents_case_alias_reuse():
    tr.create_tenant("Acme")
    assert tr.delete_tenant("Acme", purge=True)
    with pytest.raises(ValueError, match="history|aliases namespace owned"):
        tr.create_tenant("acme")


def test_create_blank_id_rejected():
    with pytest.raises(ValueError):
        tr.create_tenant("  ")


def test_suspend_resume_flips_active_and_enforcement():
    tr.create_tenant("acme")
    assert tr.is_active("acme") is True
    tr.assert_tenant_active("acme")  # no raise

    tr.suspend_tenant("acme")
    assert tr.is_active("acme") is False
    assert tr.get_tenant("acme").status == tr.SUSPENDED
    with pytest.raises(tr.TenantSuspended):
        tr.assert_tenant_active("acme")

    tr.resume_tenant("acme")
    assert tr.is_active("acme") is True


def test_enforcement_is_noop_for_unprovisioned_and_none():
    # No registry file at all -> everything is active (opt-in).
    assert tr.is_active("never-provisioned") is True
    assert tr.is_active(None) is True
    tr.assert_tenant_active(None)  # no raise
    tr.assert_tenant_active("never-provisioned")  # no raise


def test_unknown_tenant_refused_once_registry_exists():
    tr.create_tenant("acme")
    assert tr.is_active(None) is True
    assert tr.is_active("ghost") is False
    with pytest.raises(tr.TenantSuspended):
        tr.assert_tenant_active("ghost")


def test_set_quota_and_plan():
    tr.create_tenant("acme")
    assert tr.set_quota("acme", 12.5).max_daily_dollars == 12.5
    assert tr.set_plan("acme", "enterprise").plan == "enterprise"


# ---- per-tenant feature overrides ----

def test_feature_overrides_roundtrip_and_serialization():
    tr.create_tenant("acme", plan="pro")
    # deduped + sorted, canonical shape.
    rec = tr.set_feature_overrides("acme", ["channels", "channels"], ["grpc"])
    assert rec.feature_overrides == {"add": ["channels"], "remove": ["grpc"]}
    # survives a fresh read from disk and serializes only when non-empty.
    reread = tr.get_tenant("acme")
    assert reread.feature_overrides == {"add": ["channels"], "remove": ["grpc"]}
    assert reread.to_dict()["feature_overrides"] == {
        "add": ["channels"], "remove": ["grpc"]
    }


def test_feature_overrides_default_empty_not_serialized():
    tr.create_tenant("acme")
    rec = tr.get_tenant("acme")
    assert rec.feature_overrides == {}
    assert "feature_overrides" not in rec.to_dict()


def test_feature_overrides_can_be_cleared():
    tr.create_tenant("acme")
    tr.set_feature_overrides("acme", ["channels"], [])
    tr.set_feature_overrides("acme", [], [])
    assert tr.get_tenant("acme").feature_overrides == {}


def test_feature_overrides_reject_overlap():
    tr.create_tenant("acme")
    with pytest.raises(ValueError, match="both add and remove"):
        tr.set_feature_overrides("acme", ["grpc"], ["grpc"])


def test_feature_overrides_reject_non_string_and_blank():
    tr.create_tenant("acme")
    with pytest.raises(ValueError, match="strings"):
        tr.set_feature_overrides("acme", [123], [])
    with pytest.raises(ValueError, match="non-blank"):
        tr.set_feature_overrides("acme", ["  "], [])


def test_feature_overrides_reject_over_cap():
    tr.create_tenant("acme")
    too_many = [f"department:x{i}" for i in range(tr.MAX_FEATURE_OVERRIDES + 1)]
    with pytest.raises(ValueError, match="cap"):
        tr.set_feature_overrides("acme", too_many, [])


def test_feature_overrides_unknown_tenant_raises():
    with pytest.raises(tr.UnknownTenant):
        tr.set_feature_overrides("ghost", ["core"], [])


def test_overlapping_overrides_on_disk_rejected_on_read(tmp_path):
    import json
    import os
    tr.create_tenant("acme")
    path = tmp_path / "tenant_registry.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["tenants"][0]["feature_overrides"] = {"add": ["grpc"], "remove": ["grpc"]}
    path.write_text(json.dumps(data), encoding="utf-8")
    os.chmod(path, 0o600)
    with pytest.raises(tr.TenantRegistryError):
        tr.list_tenants()


def test_mutate_unknown_tenant_raises():
    with pytest.raises(tr.UnknownTenant):
        tr.suspend_tenant("ghost")


def test_delete_without_purge_keeps_data(tmp_path):
    tr.create_tenant("acme")
    data = tmp_path / "tenants" / "acme"
    (data / "world.db").write_text("x", encoding="utf-8") if data.exists() else None
    assert tr.delete_tenant("acme") is True
    assert tr.get_tenant("acme") is None
    # Data dir survives a non-purging delete.
    assert data.exists()
    assert tr.is_active("acme") is False
    with pytest.raises(tr.TenantSuspended):
        tr.assert_tenant_active("acme")
    assert tr.delete_tenant("acme") is False  # already gone


def test_delete_with_purge_removes_data(tmp_path):
    tr.create_tenant("acme")
    data = tmp_path / "tenants" / "acme"
    (data / "world.db").write_text("x", encoding="utf-8")
    assert tr.delete_tenant("acme", purge=True) is True
    assert not data.exists()


def _is_closed(connection):
    try:
        connection.execute("SELECT 1")
    except sqlite3.ProgrammingError:
        return True
    return False


def test_purge_closes_the_tenant_federation_state_before_removing_it(tmp_path, monkeypatch):
    import shutil

    from maverick import federation

    tr.create_tenant("acme")
    state = federation._FederationState(
        tmp_path / "tenants" / "acme" / "federation" / "inbound_state.sqlite3"
    )
    with federation._STATE_FILE_GATE.shared():
        cached = state._connect()
    closed_when_removed = []
    real_rmtree = shutil.rmtree

    def checked_rmtree(path, *args, **kwargs):
        if path.name == "acme":
            closed_when_removed.append(_is_closed(cached))
        return real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(shutil, "rmtree", checked_rmtree)
    assert tr.delete_tenant("acme", purge=True) is True
    assert closed_when_removed == [True]
    assert not (tmp_path / "tenants" / "acme").exists()


def test_erasure_closes_the_tenant_federation_state_before_unlinking_it(tmp_path, monkeypatch):
    import time

    from maverick import federation

    tr.create_tenant("former")
    root = tmp_path / "tenants" / "former"
    state = federation._FederationState(root / "federation" / "inbound_state.sqlite3")
    assert state.claim_replay("scope", "sig", expires_at=time.time() + 60, now=time.time()) is False
    with federation._STATE_FILE_GATE.shared():
        cached = state._connect()
    assert tr.delete_tenant("former") is True
    review = tr.erasure_review("former")
    closed_when_unlinked = []
    real_unlink = tr._erasure_unlink

    def checked_unlink(root_, entries, check):
        assert any(entry["path"] == "federation/inbound_state.sqlite3" for entry in entries)
        closed_when_unlinked.append(_is_closed(cached))
        return real_unlink(root_, entries, check)

    monkeypatch.setattr(tr, "_erasure_unlink", checked_unlink)
    result = tr.erase_removed_tenant("former", revision=review["revision"], operation="4" * 32,
                                     actor="user:owner", context="test",
                                     previous_attempt=review["previous_attempt"])
    assert result["result"] == "confirmed" and not root.exists()
    assert closed_when_unlinked == [True]


def test_registry_round_trips_on_disk():
    tr.create_tenant("acme", plan="pro")
    tr.create_tenant("beta")
    # Fresh read from disk preserves both records, sorted.
    ids = [t.id for t in tr.list_tenants()]
    assert ids == ["acme", "beta"]
    assert tr.get_tenant("acme").plan == "pro"


@pytest.mark.parametrize(
    "content",
    [
        "[]",
        '{"tenants":[{"id":"acme","status":"suspnded"}]}',
        '{"tenants":[{"id":"acme","status":"active","max_daily_dollars":NaN}]}',
        '{"tenants":[],"tenants":[]}',
    ],
)
def test_corrupt_registry_fails_closed_and_is_not_overwritten(content, tmp_path):
    path = tmp_path / "tenant_registry.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(tr.TenantRegistryError):
        tr.list_tenants()
    assert tr.is_active("acme") is False
    with pytest.raises(tr.TenantRegistryError):
        tr.assert_tenant_active("acme")
    with pytest.raises(tr.TenantRegistryError):
        tr.create_tenant("new")
    assert path.read_text(encoding="utf-8") == content


# ---- atomic persistence + concurrency-safe roster edits ----

def test_save_is_atomic_0600_no_temp(tmp_path):
    from maverick.file_lock import private_path_is_restricted

    tr.create_tenant("acme")
    path = tmp_path / "tenant_registry.json"
    assert private_path_is_restricted(path)
    # A valid, fully-written JSON roster -- never a truncated file.
    import json
    assert "acme" in {t["id"] for t in json.loads(path.read_text())["tenants"]}
    # No stray temp droppings from the atomic write.
    assert list(tmp_path.glob("*.tmp")) == []


def test_create_tenant_provisions_private_workspace():
    from maverick.file_lock import private_path_is_restricted
    from maverick.workspace import Workspace

    tr.create_tenant("private-acme")
    root = Workspace("private-acme").root
    assert root.is_dir()
    assert private_path_is_restricted(root, 0o700)


def test_failed_workspace_provision_never_publishes_active_tenant(tmp_path):
    blocked = tmp_path / "tenants" / "blocked"
    blocked.parent.mkdir()
    blocked.write_text("not a directory", encoding="utf-8")

    # An existing path is now refused before namespace reservation. It may be
    # retained legacy data, so provisioning must not adopt it.
    with pytest.raises(ValueError, match="retained legacy data"):
        tr.create_tenant("blocked")
    assert tr.get_tenant("blocked") is None

    blocked.unlink()
    rec = tr.create_tenant("blocked")
    assert rec.active


def test_concurrent_creates_do_not_lose_tenants():
    """Each create_tenant does a load-modify-save; without the lock two
    concurrent creates both load the same roster and the second save clobbers
    the first's tenant. All N distinct tenants must survive."""
    import threading

    n = 24
    errors: list[Exception] = []

    def make(i: int):
        try:
            tr.create_tenant(f"t{i:03d}")
        except (ValueError, OSError) as e:
            errors.append(e)

    threads = [threading.Thread(target=make, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors[:3]
    assert len(tr.list_tenants()) == n


def test_concurrent_suspend_and_quota_both_apply():
    """A suspend racing a set_quota must not lose either change (last-writer
    clobber). After both, the tenant is suspended AND carries the new quota."""
    import threading

    tr.create_tenant("acme")
    barrier = threading.Barrier(2)

    def suspend():
        barrier.wait()
        tr.suspend_tenant("acme")

    def quota():
        barrier.wait()
        tr.set_quota("acme", 99.0)

    ts = [threading.Thread(target=suspend), threading.Thread(target=quota)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()

    rec = tr.get_tenant("acme")
    assert rec.status == tr.SUSPENDED
    assert rec.max_daily_dollars == 99.0


def test_erasure_removes_children_before_a_one_character_top_level_name(tmp_path):
    # The root entry '.' and a one-character top-level name share a sort depth and
    # length; the root must still be removed last or rmdir fails (ENOTEMPTY).
    tr.create_tenant("former")
    root = tmp_path / "tenants" / "former"
    (root / "x").mkdir()
    (root / "x" / "y.txt").write_text("private", encoding="utf-8")
    (root / "a").write_text("private", encoding="utf-8")
    (root / "keep" / "deep").mkdir(parents=True)
    (root / "keep" / "deep" / "z.txt").write_text("private", encoding="utf-8")
    assert tr.delete_tenant("former") is True

    review = tr.erasure_review("former")
    result = tr.erase_removed_tenant("former", revision=review["revision"], operation="1" * 32,
                                     actor="user:owner", context="test", previous_attempt=review["previous_attempt"])

    assert result["result"] == "confirmed"
    assert not root.exists()


def test_removed_workspace_with_an_active_legal_matter_is_not_erased_until_released(tmp_path, monkeypatch):
    from maverick import ediscovery
    from maverick.paths import tenant_scope

    tr.create_tenant("former")
    root = tmp_path / "tenants" / "former"
    (root / "kept.txt").write_text("held", encoding="utf-8")
    with tenant_scope(tenant="former"):
        store = ediscovery.MatterStore(ediscovery.store_path())
        matter = store.create("former", actor="auditor", values={
            "name": "Acme dispute", "custodians": ["user:cli:alice"], "record_kinds": ["goals"]})
    assert tr.delete_tenant("former") is True
    review = tr.erasure_review("former")
    with pytest.raises(tr.TenantRegistryError, match="legal hold is active"):
        tr.erase_removed_tenant("former", revision=review["revision"], operation="2" * 32,
                                actor="user:owner", context="test", previous_attempt=review["previous_attempt"])
    assert (root / "kept.txt").read_text(encoding="utf-8") == "held"

    with tenant_scope(tenant="former"):
        store.release("former", matter["id"], actor="auditor", expected_revision=1)
    review = tr.erasure_review("former")
    result = tr.erase_removed_tenant("former", revision=review["revision"], operation="3" * 32,
                                     actor="user:owner", context="test", previous_attempt=review["previous_attempt"])
    assert result["result"] == "confirmed" and not root.exists()


# ---- tenant quota: non-finite caps -----------------------------------------

@pytest.mark.parametrize("bad", ["nan", "inf", "-inf"])
def test_tenant_quota_rejects_non_finite(bad):
    from maverick.tenant import registry as tr
    tr.create_tenant("acme", max_daily_dollars=5.0)
    res = CliRunner().invoke(main, ["tenant", "quota", "acme", "--", bad])
    assert res.exit_code == 2, res.output
    assert "finite" in res.output
    assert tr.get_tenant("acme").max_daily_dollars == 5.0  # existing cap unchanged


# ---- CLI start refuses a suspended tenant ----------------------------------

def test_cli_start_refuses_suspended_tenant(monkeypatch):
    # The server path enforces assert_tenant_active, and so must the CLI start
    # path, or a suspended tenant runs goals freely. The guard
    # fires before goal creation / the kernel, so no provider key is needed.
    from maverick.tenant import registry as tr
    tr.create_tenant("acme")
    tr.suspend_tenant("acme")
    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    # A present (not necessarily valid) key gets past start's provider preflight
    # so execution reaches the tenant-active guard.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-dummy")
    res = CliRunner().invoke(main, ["start", "do something", "--sandbox", "local"])
    assert res.exit_code == 3, res.output
    assert "suspended" in res.output.lower()
