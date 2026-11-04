"""Provisioning never inherits an earlier tenant incarnation's retained state."""
from __future__ import annotations

import json
import subprocess
import sys
import unicodedata
from concurrent.futures import ThreadPoolExecutor

import pytest
from maverick import paths
from maverick.tenant import registry


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)


@pytest.mark.parametrize("purge", [False, True])
@pytest.mark.parametrize("cold", [False, True])
def test_deleted_exact_id_cannot_reopen_old_data_roles_or_credentials(tmp_path, purge, cold):
    registry.create_tenant("acme")
    root = paths.data_dir(tenant="acme")
    (root / "private.txt").write_text("old private fixture", encoding="utf-8")
    (tmp_path / "dashboard-tenant-roles.json").write_text(json.dumps({"acme": {"user:old": "admin"}}), encoding="utf-8")
    registry.delete_tenant("acme", purge=purge)
    if cold:
        paths._tenant_namespace_cache.clear()
    with pytest.raises(ValueError, match="history|used before"):
        registry.create_tenant("acme")
    assert registry.get_tenant("acme") is None
    assert not registry.is_active("acme")
    assert json.loads((tmp_path / "dashboard-tenant-roles.json").read_text())["acme"] == {"user:old": "admin"}
    if not purge:
        assert (root / "private.txt").read_text() == "old private fixture"
        # Namespace read binding is distinct from fresh provisioning; retained
        # evidence can still be addressed by an independently authorized reader.
        assert paths.bind_tenant_namespace("acme") == "acme"


@pytest.mark.parametrize("alias", ["Acme", "acme"])
def test_case_alias_and_purged_namespace_remain_reserved(alias):
    registry.create_tenant("Acme")
    registry.delete_tenant("Acme", purge=True)
    with pytest.raises(ValueError):
        registry.create_tenant(alias)


def test_unicode_equivalent_retirement_survives_cache_reset():
    nfc, nfd = "caf\u00e9", unicodedata.normalize("NFD", "caf\u00e9")
    registry.create_tenant(nfd)
    registry.delete_tenant(nfc, purge=True)
    paths._tenant_namespace_cache.clear()
    with pytest.raises(ValueError):
        registry.create_tenant(nfd)
    assert not registry.is_active(nfc)


def test_legacy_orphan_namespace_and_global_membership_are_not_adopted(tmp_path):
    directory = tmp_path / "tenants" / "legacy"
    directory.mkdir(parents=True)
    (directory / "old.txt").write_text("retained", encoding="utf-8")
    with pytest.raises(ValueError, match="legacy data"):
        registry.create_tenant("legacy")
    (tmp_path / "dashboard-tenant-roles.json").write_text('{"removed":{"user:old":"admin"}}', encoding="utf-8")
    with pytest.raises(ValueError, match="membership history"):
        registry.create_tenant("removed")
    assert (directory / "old.txt").read_text() == "retained"
    assert registry.list_tenants() == []


def test_fresh_allocation_skips_all_historical_representations(tmp_path):
    registry.create_tenant("work")
    registry.delete_tenant("work", purge=True)
    paths.bind_tenant_namespace("work-2")  # retained reservation without roster
    (tmp_path / "tenants" / "work-3").mkdir()
    (tmp_path / "dashboard-tenant-roles.json").write_text('{"WORK-4":{"user:old":"viewer"}}', encoding="utf-8")
    made = registry.create_tenant("work", allocate_suffix=True)
    assert made.id == "work-5" and registry.is_active("work-5")
    assert registry.list_tenants() == [made]


def test_interrupted_delete_cannot_leave_live_or_resumable_old_roster(monkeypatch):
    registry.create_tenant("acme")
    original = registry._save
    monkeypatch.setattr(registry, "_save", lambda records: (_ for _ in ()).throw(OSError("storage unavailable")))
    with pytest.raises(OSError):
        registry.delete_tenant("acme")
    assert registry.get_tenant("acme") is None and registry.list_tenants() == []
    assert not registry.is_active("acme")
    with pytest.raises(registry.TenantSuspended):
        registry.assert_tenant_active("acme")
    with pytest.raises(registry.UnknownTenant):
        registry.resume_tenant("acme")
    monkeypatch.setattr(registry, "_save", original)
    assert registry.delete_tenant("acme")
    with pytest.raises(ValueError):
        registry.create_tenant("acme")


def test_tombstone_survives_missing_roster_and_corrupt_tombstone_fails_closed(tmp_path):
    registry.create_tenant("acme")
    registry.delete_tenant("acme")
    (tmp_path / "tenant_registry.json").unlink()
    assert not registry.is_active("acme")
    with pytest.raises(registry.TenantSuspended):
        registry.assert_tenant_active("acme")
    registry._retirement_path("acme").write_text('{"id":"other","version":1}', encoding="utf-8")
    assert not registry.is_active("acme")
    with pytest.raises(registry.TenantRegistryError):
        registry.create_tenant("acme")


def test_concurrent_new_display_name_allocations_get_distinct_incarnations():
    with ThreadPoolExecutor(max_workers=2) as pool:
        records = list(pool.map(lambda _: registry.create_tenant("team", allocate_suffix=True), range(2)))
    assert {record.id for record in records} == {"team", "team-2"}


_CREATE_PROCESS = """
from maverick.tenant import registry
try:
    registry.create_tenant('acme')
except ValueError:
    print('refused')
else:
    print('reused')
"""


def test_new_process_cannot_reuse_a_purged_incarnation(tmp_path):
    registry.create_tenant("acme")
    registry.delete_tenant("acme", purge=True)
    result = subprocess.run([sys.executable, "-c", _CREATE_PROCESS],
                            capture_output=True, text=True, timeout=30, check=True)
    assert result.stdout.strip() == "refused"


@pytest.mark.parametrize("purge", [False, True])
def test_separate_process_create_racing_delete_never_reuses_incarnation(purge):
    registry.create_tenant("acme")
    root = paths.data_dir(tenant="acme")
    (root / "retained.txt").write_text("old private fixture", encoding="utf-8")
    # Both processes wait on stdin, ensuring their mutations contend on the
    # production cross-process registry lock rather than an in-test mutex.
    reader = subprocess.Popen([sys.executable, "-c", "input()\n" + _CREATE_PROCESS],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True)
    deleter = subprocess.Popen([sys.executable, "-c",
                               "input()\nfrom maverick.tenant import registry\n"
                               f"registry.delete_tenant('acme', purge={purge!r})\n"],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True)
    try:
        reader.stdin.write("go\n")
        reader.stdin.flush()
        deleter.stdin.write("go\n")
        deleter.stdin.flush()
        output, errors = reader.communicate(timeout=30)
        _, delete_errors = deleter.communicate(timeout=30)
        assert reader.returncode == 0, errors
        assert deleter.returncode == 0, delete_errors
        assert output.strip() == "refused"
    finally:
        for process in (reader, deleter):
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=10)
    assert registry.get_tenant("acme") is None
    assert not registry.is_active("acme")


@pytest.mark.parametrize("payload", ['{"acme":{},"acme":{}}', '{"acme":[]}', '{'])
def test_ambiguous_legacy_role_inventory_refuses_new_provisioning(tmp_path, payload):
    (tmp_path / "dashboard-tenant-roles.json").write_text(payload, encoding="utf-8")
    with pytest.raises(registry.TenantRegistryError):
        registry.create_tenant("fresh")
    assert registry.get_tenant("fresh") is None


def test_existing_active_legacy_workspace_is_readable_without_reprovisioning(tmp_path):
    # Existing roster entries keep their incarnation. Only a NEW create is
    # prohibited from adopting a directory or membership from an absent row.
    registry._save({"legacy": registry.TenantRecord("legacy")})
    root = tmp_path / "tenants" / "legacy"
    root.mkdir(parents=True)
    (root / "private.txt").write_text("retained", encoding="utf-8")
    (tmp_path / "dashboard-tenant-roles.json").write_text('{"legacy":{"user:old":"admin"}}', encoding="utf-8")
    assert registry.get_tenant("legacy").active
    assert registry.is_active("legacy")
    assert paths.data_dir(tenant="legacy") == root
    assert (root / "private.txt").read_text() == "retained"


def test_automatic_allocation_skips_casing_of_legacy_active_roster():
    registry._save({"Team": registry.TenantRecord("Team")})
    assert registry.create_tenant("team", allocate_suffix=True).id == "team-2"


@pytest.mark.parametrize("operation", ["create", "delete"])
def test_lifecycle_refuses_when_strict_cross_process_lock_is_unavailable(monkeypatch, operation):
    registry.create_tenant("existing")

    def unsupported(_path, *, strict=False):
        assert strict is True
        raise OSError("synthetic unavailable process lock")

    monkeypatch.setattr(registry, "cross_process_lock", unsupported)
    with pytest.raises(OSError, match="unavailable process lock"):
        if operation == "create":
            registry.create_tenant("fresh")
        else:
            registry.delete_tenant("existing")
    assert registry.get_tenant("fresh") is None
    assert registry.get_tenant("existing").active


def test_uncertain_create_publication_never_releases_its_reserved_name(monkeypatch):
    original = registry._save

    def failed_save(_records):
        raise OSError("synthetic publication failure")

    monkeypatch.setattr(registry, "_save", failed_save)
    with pytest.raises(OSError):
        registry.create_tenant("reserved")
    monkeypatch.setattr(registry, "_save", original)
    assert registry.get_tenant("reserved") is None
    with pytest.raises(ValueError, match="used before"):
        registry.create_tenant("reserved")
    assert registry.create_tenant("reserved", allocate_suffix=True).id == "reserved-2"


def test_fresh_creation_and_existing_active_scope_still_work(tmp_path):
    active = registry.create_tenant("fresh", display_name="New team")
    assert paths.bind_tenant_namespace("fresh") == "fresh"
    assert registry.get_tenant("fresh") == active
    registry.suspend_tenant("fresh")
    assert not registry.is_active("fresh")
    assert registry.resume_tenant("fresh").active
    assert registry.create_tenant("another").id == "another"
