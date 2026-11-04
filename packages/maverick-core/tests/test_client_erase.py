"""Per-client export + right-to-erasure. Provably complete because one
deployment = one client = one data root; fail-closed so it never targets the
shared root."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from maverick import client


@pytest.fixture(autouse=True)
def _bound(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CLIENT_ID", "acme")
    monkeypatch.setenv("MAVERICK_BACKUP_SIGNING_KEY", bytes(range(32)).hex())
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    client.reset_client_cache()
    yield
    client.reset_client_cache()


def _seed():
    import sqlite3

    from maverick.paths import data_dir
    root = data_dir()
    (root / "audit").mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(root / "world.db"))  # a real DB (export uses backup API)
    con.execute("CREATE TABLE t (v)")
    con.commit()
    con.close()
    from maverick import audit
    assert audit.record("test_client_seed", agent="test") is True
    (root / "agent_trust.json").write_text("[]")
    return root


def test_erase_removes_everything():
    root = _seed()
    res = client.erase_client()
    assert res["client_id"] == "acme" and res["removed"] >= 3
    assert not (root / "world.db").exists()
    assert not (root / "agent_trust.json").exists()
    assert not (root / "audit").exists()
    receipt, events = _receipt(res["audit_event_id"])
    assert receipt == Path(res["receipt_path"])
    assert [event["kind"] for event in events] == [
        "client_erase_requested", "client_erase_ready", "client_erased",
    ]
    assert events[-1]["status"] == "completed"
    assert events[-1]["removed"] == res["removed"]
    assert events[0]["client_root"] == "tenants/acme"
    assert events[0]["actor"].startswith("local:")


def test_erase_closes_the_client_federation_state_before_removing_it(monkeypatch):
    import sqlite3
    import time

    from maverick import federation

    root = _seed()
    state = federation._FederationState(root / "federation" / "inbound_state.sqlite3")
    assert state.claim_replay("scope", "sig", expires_at=time.time() + 60, now=time.time()) is False
    with federation._STATE_FILE_GATE.shared():
        cached = state._connect()
    closed_when_removed = []
    real_remove = client._remove_client_path

    def checked_remove(path, windows_identity):
        if path.name == "inbound_state.sqlite3":
            try:
                cached.execute("SELECT 1")
                closed_when_removed.append(False)
            except sqlite3.ProgrammingError:
                closed_when_removed.append(True)
        return real_remove(path, windows_identity)

    monkeypatch.setattr(client, "_remove_client_path", checked_remove)
    res = client.erase_client()
    assert res["removed"] >= 1
    assert closed_when_removed == [True]
    assert not (root / "federation" / "inbound_state.sqlite3").exists()


def test_erase_keep_audit():
    root = _seed()
    res = client.erase_client(keep_audit=True, actor="user:offboarding-admin")
    assert not (root / "world.db").exists()
    from maverick import audit
    events = list(audit.iter_events(audit_dir=root / "audit", all_days=True))
    assert [event["kind"] for event in events] == [
        "test_client_seed", "client_erase_requested", "client_erased",
    ]
    assert events[-1]["actor"] == "user:offboarding-admin"
    assert events[-1]["event_id"] == res["audit_event_id"]
    assert all(audit.verify_chain(path) == [] for path in audit.day_files(root / "audit"))
    _receipt(res["audit_event_id"])


def _receipt(receipt_id):
    """Verify using only the surviving artifact, after tenant keys are gone."""
    from maverick.audit import verify_chain
    from maverick.paths import maverick_home
    directory = maverick_home() / "client-erasure" / receipt_id
    path = directory / "events.ndjson"
    public_key = (directory / "verification-key.hex").read_text().strip()
    assert verify_chain(path, public_key) == []
    return path, [json.loads(line) for line in path.read_text().splitlines()]


def test_first_use_signing_leaves_no_client_key_material(monkeypatch):
    import hashlib

    from maverick import client_erasure
    from maverick.paths import data_dir
    root = data_dir()
    root.mkdir(parents=True)
    (root / "customer.txt").write_text("Client content")
    expected = {}
    original = client_erasure.ErasureReceipt.prepare

    def check_inventory(receipt, targets):
        relative = sorted(p.relative_to(root).as_posix() for p in client._erase_targets(root, keep_audit=False))
        expected.update(deletion_target_count=len(relative),
                        deletion_manifest_sha256=hashlib.sha256(json.dumps(relative).encode()).hexdigest())
        assert targets == expected
        original(receipt, targets)

    monkeypatch.setattr(client_erasure.ErasureReceipt, "prepare", check_inventory)
    res = client.erase_client()
    assert list(root.iterdir()) == []
    _, events = _receipt(res["audit_event_id"])
    assert events[-1]["status"] == "completed"
    assert events[0]["preflight_target_count"] == 1
    assert events[1]["deletion_target_count"] > events[0]["preflight_target_count"]
    for event in events[1:]:
        assert {key: event[key] for key in expected} == expected


@pytest.mark.parametrize("keep_audit", [False, True])
def test_missing_signer_refuses_before_deletion(monkeypatch, keep_audit):
    from maverick import client_erasure
    from maverick.audit import AuditRefused
    root = _seed()

    def refuse(_path):
        raise AuditRefused("required signing identity unavailable")

    monkeypatch.setattr(client_erasure, "AuditSigner", refuse)
    with pytest.raises(client.ClientErasureError, match="Nothing was erased"):
        client.erase_client(keep_audit=keep_audit)
    assert (root / "world.db").exists()
    assert (root / "agent_trust.json").exists()


def test_unconfirmed_request_refuses_before_deletion(monkeypatch):
    from maverick import client_erasure
    root = _seed()
    monkeypatch.setattr(client_erasure.AuditSigner, "write", lambda _self, _event: False)
    with pytest.raises(client.ClientErasureError, match="Nothing was erased"):
        client.erase_client()
    assert (root / "world.db").exists()


def test_unconfirmed_retained_request_refuses_before_deletion(monkeypatch):
    from maverick import audit
    root = _seed()
    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: False)
    with pytest.raises(client.ClientErasureError, match="Nothing was erased"):
        client.erase_client(keep_audit=True)
    assert (root / "world.db").exists()


def test_disabled_signed_retention_refuses_before_deletion(monkeypatch):
    from maverick import audit
    root = _seed()
    monkeypatch.setattr(audit.default_audit_log(), "_signing_enabled", False)
    with pytest.raises(client.ClientErasureError, match="Nothing was erased") as caught:
        client.erase_client(keep_audit=True)
    assert (root / "world.db").exists()
    assert "signing is disabled" in str(caught.value.__cause__)


def test_unconfirmed_prepared_inventory_refuses_before_deletion(monkeypatch):
    from maverick import client_erasure
    root = _seed()
    original = client_erasure.AuditSigner.write

    def fail_prepare(signer, event, **kwargs):
        return False if event["kind"] == "client_erase_ready" else original(signer, event, **kwargs)

    monkeypatch.setattr(client_erasure.AuditSigner, "write", fail_prepare)
    with pytest.raises(client.ClientErasureError, match="Nothing was erased") as caught:
        client.erase_client()
    assert (root / "world.db").exists()
    _, events = _receipt(caught.value.receipt_id)
    assert [event["status"] for event in events] == ["requested"]


def test_tampered_request_refuses_before_deletion(monkeypatch):
    from maverick import client_erasure
    from maverick.file_lock import atomic_read_text, atomic_write_text
    root = _seed()
    original = client_erasure.AuditSigner.write

    def corrupt_request(signer, event, **kwargs):
        result = original(signer, event, **kwargs)
        if event["kind"] == "client_erase_requested":
            row = json.loads(atomic_read_text(signer._path).splitlines()[0])
            row["actor"] = "forged operator"
            atomic_write_text(signer._path, json.dumps(row) + "\n")
        return result

    monkeypatch.setattr(client_erasure.AuditSigner, "write", corrupt_request)
    with pytest.raises(client.ClientErasureError, match="Nothing was erased"):
        client.erase_client()
    assert (root / "world.db").exists()


def test_receipt_retains_only_minimal_inventory_metadata():
    root = _seed()
    (root / "Sensitive customer name").mkdir()
    (root / "Sensitive customer name" / "private.txt").write_text("private client content")
    res = client.erase_client()
    path, events = _receipt(res["audit_event_id"])
    assert "Sensitive customer name" not in path.read_text()
    assert "private client content" not in path.read_text()
    assert len(events[0]["preflight_inventory_sha256"]) == 64
    assert events[0]["preflight_target_areas"]["(other folders)"] == 1


def _symlink_or_skip(path, target):
    try:
        path.symlink_to(target, target_is_directory=True)
    except OSError as exc:
        import os
        import subprocess
        if os.name != "nt":
            pytest.skip(f"directory symlinks unavailable on this host: {exc}")
        # A junction needs no administrator privilege on Windows and exercises
        # the same no-traversal requirement against real temporary directories.
        subprocess.run(["cmd", "/c", "mklink", "/J", str(path), str(target)],
                       check=True, capture_output=True)


def test_nested_directory_alias_is_removed_without_touching_target(tmp_path):
    root = _seed()
    outside = tmp_path / "other-client"
    outside.mkdir()
    (outside / "must-stay.txt").write_text("other client's data")
    link = root / "outside-link"
    _symlink_or_skip(link, outside)
    client.erase_client()
    assert not link.exists()
    assert (outside / "must-stay.txt").read_text() == "other client's data"


_WINDOWS_DIRECTORY = 0x10
_WINDOWS_REPARSE_POINT = 0x400


def _windows_directory_alias(monkeypatch, tmp_path, handle_attributes, *, root=None):
    """A directory symlink erased through the Windows deletion path on any OS.

    lstat reports a directory symlink as S_IFLNK with the DIRECTORY and
    REPARSE_POINT attributes, and the deletion handle reports the same attributes.
    ``handle_attributes`` is what the handle reports when deletion checks it.
    """
    import ctypes
    import types

    from maverick import client_erasure

    outside = tmp_path / "other-client"
    outside.mkdir()
    (outside / "must-stay.txt").write_text("other client's data")
    if root is None:
        root = tmp_path / "client-root"
        root.mkdir()
    link = root / "outside-link"
    _symlink_or_skip(link, outside)
    real = link.lstat()
    real_lstat = Path.lstat

    def windows_lstat(self, *args, **kwargs):
        info = real_lstat(self, *args, **kwargs)
        if self != link:
            return info
        return types.SimpleNamespace(
            st_mode=info.st_mode, st_ino=info.st_ino, st_dev=info.st_dev,
            st_nlink=info.st_nlink,
            st_file_attributes=_WINDOWS_DIRECTORY | _WINDOWS_REPARSE_POINT)

    class HandleInfo(ctypes.Structure):
        _fields_ = [("attributes", ctypes.c_uint32), ("index_high", ctypes.c_uint32),
                    ("index_low", ctypes.c_uint32), ("links", ctypes.c_uint32)]

    class Disposition(ctypes.Structure):
        _fields_ = [("delete_file", ctypes.c_bool)]

    inspections = []
    deleted = []

    def inspect_handle():
        inspections.append(None)
        return HandleInfo(attributes=handle_attributes, index_high=real.st_ino >> 32,
                          index_low=real.st_ino & 0xFFFFFFFF,
                          links=1 if len(inspections) == 1 else 0)

    def set_disposition(handle, _cls, _info, _size):
        # Delete-on-close of the opened object: the alias itself, never its target.
        # Windows removes a directory link with rmdir; unlink refuses a directory.
        deleted.append(handle)
        (os.rmdir if os.name == "nt" else os.unlink)(link)
        return True

    api = (lambda *_args: 7, lambda _handle, _ref: True, set_disposition,
           lambda _handle: True, inspect_handle, Disposition)
    monkeypatch.setattr(Path, "lstat", windows_lstat)
    monkeypatch.setattr(client_erasure, "_windows_erase_api", lambda: api)
    return link, outside, deleted


def test_windows_directory_alias_identity_matches_its_deletion_handle(monkeypatch, tmp_path):
    """Windows: lstat set S_IFLNK on a directory symlink, so S_ISDIR was False while
    the deletion handle reported FILE_ATTRIBUTE_DIRECTORY, and every directory alias
    looked changed after the signed inventory. The alias must be removed as a link,
    and the folder it points to must stay untouched."""
    from maverick import client_erasure

    link, outside, deleted = _windows_directory_alias(
        monkeypatch, tmp_path, handle_attributes=_WINDOWS_DIRECTORY | _WINDOWS_REPARSE_POINT)
    identity = client_erasure.windows_erase_target_identity(link)
    assert identity[2:] == (True, True)
    client_erasure.delete_windows_erase_target(link, identity)
    assert deleted and not os.path.lexists(link)
    assert (outside / "must-stay.txt").read_text() == "other client's data"


def test_windows_alias_replaced_by_a_real_directory_is_refused_before_deletion(monkeypatch, tmp_path):
    """The identity check still refuses a target that changed after the inventory:
    here the alias was replaced by an ordinary directory, so nothing is deleted."""
    from maverick import client_erasure

    link, outside, deleted = _windows_directory_alias(
        monkeypatch, tmp_path, handle_attributes=_WINDOWS_DIRECTORY)
    identity = client_erasure.windows_erase_target_identity(link)
    with pytest.raises(ValueError, match="changed after the signed inventory"):
        client_erasure.delete_windows_erase_target(link, identity)
    assert deleted == [] and os.path.islink(link)
    assert (outside / "must-stay.txt").read_text() == "other client's data"


def test_windows_directory_alias_erase_completes_and_keeps_its_target(monkeypatch, tmp_path):
    """A whole erase on the Windows identity path. The signed inventory and the
    removal must read the alias the same way, or the erase reports it as changed
    and never completes. The erase must complete and leave the folder it points to."""
    from maverick import client_erasure

    root = _seed()
    link, outside, deleted = _windows_directory_alias(
        monkeypatch, tmp_path, handle_attributes=_WINDOWS_DIRECTORY | _WINDOWS_REPARSE_POINT,
        root=root)
    real_remove = client._remove_client_path

    # The Windows-only steps of the erase, reproduced on this host: identities come
    # from windows_erase_target_identity and the alias goes through its handle.
    monkeypatch.setattr(client, "_windows_target_identities", lambda targets: {
        p: client_erasure.windows_erase_target_identity(p) for p in targets})

    def remove_path(path, identity):
        if path != link:
            return real_remove(path, None)
        client_erasure.delete_windows_erase_target(path, identity)
        return 1

    monkeypatch.setattr(client, "_remove_client_path", remove_path)
    res = client.erase_client()
    assert res["removed"] >= 1 and deleted
    assert not os.path.lexists(link)
    assert not (root / "world.db").exists()
    assert (outside / "must-stay.txt").read_text() == "other client's data"


@pytest.mark.parametrize("alias_area", ["client", "receipt"])
def test_redirected_folder_refuses_without_removing_outside_data(tmp_path, alias_area):
    from maverick.paths import data_dir
    outside = tmp_path / "outside-data"
    outside.mkdir()
    (outside / "must-stay.txt").write_text("outside data")
    if alias_area == "client":
        root = data_dir()
        root.parent.mkdir(exist_ok=True)
        _symlink_or_skip(root, outside)
    else:
        root = _seed()
        _symlink_or_skip(tmp_path / "client-erasure", outside)
    with pytest.raises(client.ClientErasureError, match="Nothing was erased"):
        client.erase_client()
    assert (outside / "must-stay.txt").read_text() == "outside data"
    if alias_area == "receipt":
        assert (root / "world.db").exists()


@pytest.mark.parametrize("replacement", ["junction", "ordinary_directory"])
def test_root_replaced_after_preparation_stops_without_deleting_replacement(monkeypatch, tmp_path, replacement):
    from maverick import client_erasure
    root = _seed()
    parked = tmp_path / "parked-original-client"
    outside = tmp_path / "outside-replacement"
    outside.mkdir()
    (outside / "world.db").write_text("outside data must survive")
    original = client_erasure.ErasureReceipt.prepare

    def replace_root(receipt, targets):
        original(receipt, targets)
        root.rename(parked)
        if replacement == "junction":
            _symlink_or_skip(root, outside)
        else:
            root.mkdir()
            (root / "world.db").write_text("replacement data must survive")

    monkeypatch.setattr(client_erasure.ErasureReceipt, "prepare", replace_root)
    with pytest.raises(client.ClientErasureError, match="Erasure is incomplete") as caught:
        client.erase_client()
    assert (parked / "world.db").exists()
    assert (outside / "world.db").read_text() == "outside data must survive"
    if replacement == "ordinary_directory":
        assert (root / "world.db").read_text() == "replacement data must survive"
    assert caught.value.removed == 0
    _, events = _receipt(caught.value.receipt_id)
    assert events[-1]["status"] == "incomplete"


def test_root_replaced_during_receipt_creation_refuses_before_deletion(monkeypatch, tmp_path):
    from maverick import client_erasure

    root = _seed()
    parked = tmp_path / "parked-original-client"
    original = client_erasure.ErasureReceipt.__init__

    def replace_root(receipt, home, detail):
        original(receipt, home, detail)
        root.rename(parked)
        root.mkdir()
        (root / "replacement.txt").write_text("replacement data must survive")

    monkeypatch.setattr(client_erasure.ErasureReceipt, "__init__", replace_root)
    with pytest.raises(client.ClientErasureError, match="Nothing was erased") as caught:
        client.erase_client()
    assert (parked / "world.db").exists()
    assert (root / "replacement.txt").read_text() == "replacement data must survive"
    _, events = _receipt(caught.value.receipt_id)
    assert [event["status"] for event in events] == ["requested"]


@pytest.mark.skipif(os.name != "nt", reason="Windows directory sharing prevents the junction swap")
def test_windows_parent_pin_blocks_cross_tenant_junction_swap(monkeypatch, tmp_path):
    import inspect

    root = _seed()
    other = tmp_path / "tenants" / "other-client"
    other.mkdir()
    (other / "agent_trust.json").write_text("other client's data")
    parked = tmp_path / "parked-original-client"
    original_resolve = Path.resolve
    attempted = []

    def swap_after_parent_check(path, *args, **kwargs):
        resolved = original_resolve(path, *args, **kwargs)
        caller = inspect.currentframe().f_back
        if (path == root and caller.f_code.co_name == "_erase_client_locked"
                and caller.f_locals.get("p") == root / "agent_trust.json" and not attempted):
            attempted.append(True)
            try:
                root.rename(parked)
            except OSError as exc:
                assert exc.winerror in {5, 32}  # sharing violation / access denied
            else:
                _symlink_or_skip(root, other)
        return resolved

    monkeypatch.setattr(Path, "resolve", swap_after_parent_check)
    result = client.erase_client()
    assert attempted and result["client_id"] == "acme"
    assert (other / "agent_trust.json").read_text() == "other client's data"
    assert not parked.exists()


def test_target_moved_out_of_client_root_after_preparation_is_not_claimed_erased(monkeypatch, tmp_path):
    from maverick import client_erasure
    root = _seed()
    parked = tmp_path / "still-existing-client-data.db"
    original = client_erasure.ErasureReceipt.prepare

    def move_prepared_target(receipt, targets):
        original(receipt, targets)
        (root / "world.db").rename(parked)

    monkeypatch.setattr(client_erasure.ErasureReceipt, "prepare", move_prepared_target)
    with pytest.raises(client.ClientErasureError, match="Erasure is incomplete") as caught:
        client.erase_client()
    assert parked.exists()
    _, events = _receipt(caught.value.receipt_id)
    assert events[-1]["status"] == "incomplete"


@pytest.mark.skipif(os.name != "nt", reason="Windows uses identity-bound deletion handles")
def test_windows_replaced_child_cannot_produce_completed_receipt(monkeypatch, tmp_path):
    from maverick import client_erasure

    root = _seed()
    parked = tmp_path / "still-existing-client-data.db"
    original = client_erasure.ErasureReceipt.prepare

    def replace_after_signed_inventory(receipt, targets):
        original(receipt, targets)
        (root / "world.db").rename(parked)
        (root / "world.db").write_text("replacement data")

    monkeypatch.setattr(client_erasure.ErasureReceipt, "prepare", replace_after_signed_inventory)
    with pytest.raises(client.ClientErasureError, match="Erasure is incomplete") as caught:
        client.erase_client()
    assert parked.exists()
    assert (root / "world.db").read_text() == "replacement data"
    _, events = _receipt(caught.value.receipt_id)
    assert events[-1]["status"] == "incomplete"
    assert all(event["kind"] != "client_erased" for event in events)


@pytest.mark.skipif(os.name != "nt", reason="Windows records target file IDs during preflight")
def test_windows_child_changed_during_receipt_creation_refuses_before_deletion(monkeypatch, tmp_path):
    from maverick import client_erasure

    root = _seed()
    parked = tmp_path / "still-existing-client-data.db"
    original = client_erasure.ErasureReceipt.__init__

    def replace_during_receipt(receipt, home, detail):
        original(receipt, home, detail)
        (root / "world.db").rename(parked)
        (root / "world.db").write_text("replacement data")

    monkeypatch.setattr(client_erasure.ErasureReceipt, "__init__", replace_during_receipt)
    with pytest.raises(client.ClientErasureError, match="Nothing was erased") as caught:
        client.erase_client()
    assert parked.exists()
    assert (root / "world.db").read_text() == "replacement data"
    _, events = _receipt(caught.value.receipt_id)
    assert [event["status"] for event in events] == ["requested"]


@pytest.mark.skipif(os.name != "nt", reason="Windows target handle prevents child rename")
def test_windows_target_cannot_move_while_deletion_handle_is_open(monkeypatch, tmp_path):
    import ctypes

    from maverick import client_erasure

    root = _seed()
    target = root / "world.db"
    expected_id = target.lstat().st_ino
    parked = tmp_path / "moved-client-data.db"
    original_api = client_erasure._windows_erase_api
    api = original_api()
    attempts = []

    def set_info_with_race(handle, *args):
        info = api[4]()
        assert api[1](handle, ctypes.byref(info))
        if ((info.index_high << 32) | info.index_low) == expected_id and not attempts:
            attempts.append(True)
            with pytest.raises(OSError) as caught:
                target.rename(parked)
            assert caught.value.winerror in {5, 32}
        return api[2](handle, *args)

    monkeypatch.setattr(client_erasure, "_windows_erase_api",
                        lambda: (api[0], api[1], set_info_with_race, *api[3:]))
    result = client.erase_client()
    assert attempts and result["client_id"] == "acme"
    assert not parked.exists()
    assert not target.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows exposes link count on the opened target")
def test_windows_concurrent_hardlink_cannot_produce_completed_receipt(monkeypatch, tmp_path):
    import ctypes

    from maverick import client_erasure

    root = _seed()
    target = root / "world.db"
    expected_id = target.lstat().st_ino
    outside = tmp_path / "still-existing-client-data.db"
    original_api = client_erasure._windows_erase_api
    api = original_api()
    linked = []

    def set_info_with_hardlink(handle, *args):
        info = api[4]()
        assert api[1](handle, ctypes.byref(info))
        if ((info.index_high << 32) | info.index_low) == expected_id and not linked:
            outside.hardlink_to(target)
            linked.append(True)
        return api[2](handle, *args)

    monkeypatch.setattr(client_erasure, "_windows_erase_api",
                        lambda: (api[0], api[1], set_info_with_hardlink, *api[3:]))
    with pytest.raises(client.ClientErasureError, match="Erasure is incomplete") as caught:
        client.erase_client()
    assert linked and outside.exists()
    _, events = _receipt(caught.value.receipt_id)
    assert events[-1]["status"] == "incomplete"


def _deny_world_removal(monkeypatch, root):
    if os.name == "nt":
        original = client.delete_windows_erase_target

        def deny_world(path, identity):
            if path == root / "world.db":
                raise PermissionError("file is still in use")
            return original(path, identity)

        monkeypatch.setattr(client, "delete_windows_erase_target", deny_world)
    else:
        original = Path.unlink

        def deny_world(path, *args, **kwargs):
            if path == root / "world.db":
                raise PermissionError("file is still in use")
            return original(path, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", deny_world)


@pytest.mark.parametrize("keep_audit", [False, True])
def test_partial_deletion_records_incomplete_and_raises(monkeypatch, keep_audit):
    root = _seed()
    _deny_world_removal(monkeypatch, root)
    with pytest.raises(client.ClientErasureError, match="Erasure is incomplete") as caught:
        client.erase_client(keep_audit=keep_audit)
    assert (root / "world.db").exists()
    assert not (root / "agent_trust.json").exists()
    assert caught.value.removed > 0
    _, events = _receipt(caught.value.receipt_id)
    assert events[-1]["kind"] == "client_erase_incomplete"
    assert events[-1]["status"] == "incomplete"
    assert events[-1]["failures"] > 0
    assert all(event["kind"] != "client_erased" for event in events)


def test_final_receipt_failure_never_claims_completed_erasure(monkeypatch):
    from maverick import client_erasure
    root = _seed()
    original = client_erasure.AuditSigner.write

    def fail_completion(signer, event, **kwargs):
        if event["kind"] == "client_erased":
            return False
        return original(signer, event, **kwargs)

    monkeypatch.setattr(client_erasure.AuditSigner, "write", fail_completion)
    with pytest.raises(client.ClientErasureError, match="final activity receipt could not be confirmed") as caught:
        client.erase_client()
    assert not (root / "world.db").exists()
    _, events = _receipt(caught.value.receipt_id)
    assert [event["status"] for event in events] == ["requested", "prepared"]


def test_bound_client_scope_is_restored_and_other_workspace_is_untouched():
    from maverick.paths import current_tenant, data_dir, tenant_scope
    root = _seed()
    with tenant_scope(tenant="other-workspace"):
        other = data_dir()
        other.mkdir(parents=True)
        (other / "customer.txt").write_text("other workspace")
        res = client.erase_client()
        assert current_tenant() == "other-workspace"
        assert Path(res["root"]) == root
        assert (other / "customer.txt").read_text() == "other workspace"
    assert not (root / "world.db").exists()
    _receipt(res["audit_event_id"])


def test_erase_refuses_without_binding(monkeypatch):
    monkeypatch.delenv("MAVERICK_CLIENT_ID", raising=False)
    monkeypatch.setattr(client, "_resolve", lambda: None)
    client.reset_client_cache()
    with pytest.raises(client.ClientBindingError):
        client.erase_client()


def test_erase_targets_client_subtree_only(monkeypatch, tmp_path):
    # A file directly under MAVERICK_HOME (the shared root) is NOT touched —
    # erase only wipes tenants/<client>/.
    _seed()
    shared = tmp_path / "shared.txt"
    shared.write_text("other")
    client.erase_client()
    assert shared.exists()


# ---- CLI ------------------------------------------------------------------


def _run(*args):
    from click.testing import CliRunner
    from maverick.cli import main
    return CliRunner().invoke(main, list(args))


def test_cli_erase_requires_confirm():
    _seed()
    r = _run("client", "erase")
    assert r.exit_code != 0 and "--confirm" in r.output
    from maverick.paths import data_dir
    assert (data_dir() / "world.db").exists()  # nothing erased without --confirm


def test_cli_status_and_erase_confirm():
    _seed()
    r = _run("client", "status")
    assert r.exit_code == 0 and "acme" in r.output
    r = _run("client", "erase", "--confirm")
    assert r.exit_code == 0 and "erased local data for client" in r.output
    assert "Activity receipt:" in r.output and "events.ndjson" in r.output
    from maverick.paths import data_dir
    assert not (data_dir() / "world.db").exists()


def test_cli_reports_partial_erasure_as_failure(monkeypatch):
    root = _seed()
    _deny_world_removal(monkeypatch, root)
    result = _run("client", "erase", "--confirm")
    assert result.exit_code != 0 and "Erasure is incomplete" in result.output
    assert "Activity receipt:" in result.output
    assert "erased local data for client" not in result.output


def test_cli_export():
    _seed()
    r = _run("client", "export")
    assert r.exit_code == 0 and "client export written" in r.output
