from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest
from maverick import privacy_rights_orchestration as privacy
from maverick import third_party_collaboration as collaboration
from maverick import third_party_lifecycle as lifecycle
from maverick.sqlite_initialized import InitializedFiles

posix_only = pytest.mark.skipif(os.name == "nt", reason="privacy is an ACL on Windows")


def _private(path: Path) -> Path:
    sqlite3.connect(path).close()
    path.chmod(0o600)
    return path


@posix_only
def test_a_remembered_file_stays_current_until_it_changes(tmp_path: Path) -> None:
    memo = InitializedFiles()
    path = _private(tmp_path / "store.sqlite3")
    assert not memo.current(path)
    memo.remember(path)
    assert memo.current(path)

    path.chmod(0o644)  # loosened: the next construction runs the script again
    assert not memo.current(path)
    path.chmod(0o600)
    assert not memo.current(path)  # forgotten until initialized again

    memo.remember(path)
    replacement = _private(tmp_path / "replacement.sqlite3")
    os.replace(replacement, path)
    assert not memo.current(path)

    memo.remember(path)
    os.link(path, tmp_path / "alias.sqlite3")
    assert not memo.current(path)


@posix_only
def test_a_removed_or_aliased_file_is_never_current(tmp_path: Path) -> None:
    memo = InitializedFiles()
    path = _private(tmp_path / "store.sqlite3")
    memo.remember(path)
    path.unlink()
    assert not memo.current(path)

    target = _private(tmp_path / "target.sqlite3")
    link = tmp_path / "link.sqlite3"
    link.symlink_to(target)
    memo.remember(link)
    assert not memo.current(link)


def _count_initializations(monkeypatch: pytest.MonkeyPatch, store_class) -> list[int]:
    calls: list[int] = []
    original = store_class._initialize

    def counted(self):
        calls.append(1)
        return original(self)

    monkeypatch.setattr(store_class, "_initialize", counted)
    return calls


@posix_only
def test_lifecycle_store_runs_its_schema_script_once_per_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _count_initializations(monkeypatch, lifecycle.ThirdPartyLifecycleStore)
    path = tmp_path / "lifecycle.sqlite3"
    for _ in range(3):
        store = lifecycle.ThirdPartyLifecycleStore(
            path, config_gate=lambda: None, principal_resolver=lambda: "owner",
        )
        assert store.list_templates("tenant-a") == ()
    assert len(calls) == 1

    path.unlink()  # a missing database is created and initialized again
    store = lifecycle.ThirdPartyLifecycleStore(
        path, config_gate=lambda: None, principal_resolver=lambda: "owner",
    )
    assert store.list_templates("tenant-a") == ()
    assert len(calls) == 2


@posix_only
def test_lifecycle_construction_still_runs_its_config_gate(tmp_path: Path) -> None:
    path = tmp_path / "lifecycle.sqlite3"
    lifecycle.ThirdPartyLifecycleStore(
        path, config_gate=lambda: None, principal_resolver=lambda: "owner",
    )

    def refuse() -> None:
        raise lifecycle.ThirdPartyLifecycleConfigError("disabled")

    with pytest.raises(lifecycle.ThirdPartyLifecycleConfigError):
        lifecycle.ThirdPartyLifecycleStore(
            path, config_gate=refuse, principal_resolver=lambda: "owner",
        )


@posix_only
def test_privacy_store_runs_its_schema_script_once_per_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _count_initializations(monkeypatch, privacy.PrivacyRightsOrchestrationStore)
    path = tmp_path / "privacy.sqlite3"
    for _ in range(3):
        store = privacy.PrivacyRightsOrchestrationStore(
            path,
            config_gate=lambda: None,
            principal_resolver=lambda: "owner",
            digest_key_resolver=lambda _tenant: b"k" * 32,
        )
        assert store.list_sources("tenant-a") == ()
    assert len(calls) == 1


@posix_only
def test_collaboration_store_runs_its_schema_script_once_per_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _count_initializations(monkeypatch, collaboration.ThirdPartyCollaborationStore)
    for _ in range(3):
        store = collaboration.ThirdPartyCollaborationStore(
            tmp_path / "collaboration.sqlite3",
            lifecycle_path=tmp_path / "lifecycle.sqlite3",
            config_gate=lambda: None,
            principal_resolver=lambda: "owner",
        )
        assert store.list_invitations("tenant-a")["items"] == []
    assert len(calls) == 1
