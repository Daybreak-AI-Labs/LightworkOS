"""Browser auth vault."""
from __future__ import annotations

import pytest

# cryptography ships via the audit-signing extra and is present in the test env;
# skip cleanly if it ever isn't, since the vault is gated behind that extra.
pytest.importorskip("cryptography")

from maverick.browser_auth_vault import (  # noqa: E402
    Vault,
    decrypt_entry,
    encrypt_entry,
    generate_key,
    resolve_key,
)
from maverick.file_lock import private_path_is_restricted  # noqa: E402


def test_encrypt_decrypt_roundtrip():
    key = generate_key()
    data = {"cookie": "abc123", "expires": 9999}
    token = encrypt_entry(key, data)
    assert token != str(data)  # actually encrypted
    assert decrypt_entry(key, token) == data


def test_wrong_key_fails():
    token = encrypt_entry(generate_key(), {"x": 1})
    with pytest.raises(ValueError):
        decrypt_entry(generate_key(), token)


def test_vault_store_load_list_delete(tmp_path):
    key = generate_key()
    v = Vault(key, tmp_path / "vault.json")
    v.store("github", {"session": "tok-1"})
    v.store("gitlab", {"session": "tok-2"})
    assert v.list_entries() == ["github", "gitlab"]
    assert v.load("github") == {"session": "tok-1"}
    assert v.delete("github") is True
    assert v.list_entries() == ["gitlab"]
    assert v.delete("github") is False
    assert private_path_is_restricted(tmp_path / "vault.json")


def test_load_missing_entry_raises(tmp_path):
    v = Vault(generate_key(), tmp_path / "v.json")
    with pytest.raises(KeyError):
        v.load("nope")


def test_data_file_holds_only_ciphertext(tmp_path):
    key = generate_key()
    path = tmp_path / "vault.json"
    Vault(key, path).store("acct", {"password": "hunter2"})  # pragma: allowlist secret
    raw = path.read_text(encoding="utf-8")
    assert "hunter2" not in raw  # secret never stored in cleartext


def test_resolve_key_from_env(tmp_path, monkeypatch):
    key = generate_key()
    monkeypatch.setenv("MAVERICK_VAULT_KEY", key.decode("ascii"))
    assert resolve_key(tmp_path / "key") == key


def test_resolve_key_generates_and_persists(tmp_path, monkeypatch):
    monkeypatch.delenv("MAVERICK_VAULT_KEY", raising=False)
    kf = tmp_path / "key"
    k1 = resolve_key(kf)
    assert kf.exists()
    assert private_path_is_restricted(kf)
    assert resolve_key(kf) == k1  # stable across calls


def test_resolve_existing_key_is_tightened_before_read(tmp_path, monkeypatch):
    monkeypatch.delenv("MAVERICK_VAULT_KEY", raising=False)
    kf = tmp_path / "key"
    key = generate_key()
    kf.write_bytes(key)
    kf.chmod(0o644)

    assert resolve_key(kf) == key
    assert private_path_is_restricted(kf)


def test_vault_read_modify_write_is_cross_process_serialized(tmp_path):
    import subprocess
    import sys
    import textwrap

    key = generate_key()
    path = tmp_path / "vault.json"
    start = tmp_path / "start"
    script = textwrap.dedent(
        """
        import sys
        import time
        from pathlib import Path
        from maverick.browser_auth_vault import Vault

        key, path, prefix, start = sys.argv[1:]
        deadline = time.monotonic() + 10
        while not Path(start).exists():
            if time.monotonic() >= deadline:
                raise TimeoutError("start barrier was not released")
            time.sleep(0.01)
        vault = Vault(key.encode("ascii"), path)
        for index in range(5):
            vault.store(
                f"{prefix}-{index}",
                {"token": f"value-{prefix}-{index}"},
            )
        """
    )
    workers = [
        subprocess.Popen(
            [
                sys.executable,
                "-c",
                script,
                key.decode("ascii"),
                str(path),
                str(index),
                str(start),
            ]
        )
        for index in range(4)
    ]
    start.touch()
    for worker in workers:
        assert worker.wait(timeout=30) == 0

    assert len(Vault(key, path).list_entries()) == 20


def test_a_missing_key_is_not_reminted_over_existing_entries(tmp_path, monkeypatch):
    """A default backup withholds vault/key; after restoring it elsewhere the
    first use must not seal under a fresh key beside the old entries."""
    from maverick import browser_auth_vault as bav

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("MAVERICK_VAULT_KEY", raising=False)
    assert bav._run({"op": "store", "name": "github", "data": {"cookie": "c"}}).startswith("sealed entry")
    key_file, data_file = bav._default_paths()
    key_file.unlink()
    out = bav._run({"op": "list"})
    assert out.startswith("ERROR:") and "vault key is missing" in out
    assert not key_file.exists()
    with pytest.raises(RuntimeError, match="vault key is missing"):
        resolve_key()
