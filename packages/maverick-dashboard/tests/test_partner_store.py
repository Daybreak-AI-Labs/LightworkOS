"""Encrypted, restart-safe Partner Fleet credential custody."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

_CONCURRENT_UPSERT = """
import os
import sys
import time

home, index, start = sys.argv[1:]
os.environ["HOME"] = home
os.environ["MAVERICK_HOME"] = home
os.environ.pop("MAVERICK_TENANT", None)
deadline = time.monotonic() + 20
while not os.path.exists(start):
    if time.monotonic() >= deadline:
        raise TimeoutError("concurrency start marker was not published")
    time.sleep(0.005)

from maverick.tenant import kms
from maverick_dashboard import partner_store

kms._dek_cache.clear()
partner_store.upsert_tenant(
    name=f"Tenant {index}",
    base_url=f"https://8.8.8.8/tenant-{index}",
    token=f"token-{index}",
)
"""

_READ_PARTNERS = """
import json
import os
import sys

home = sys.argv[1]
os.environ["HOME"] = home
os.environ["MAVERICK_HOME"] = home
os.environ.pop("MAVERICK_TENANT", None)
from maverick_dashboard import partner_store

print(json.dumps(partner_store.list_tenants()))
"""


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick.tenant import kms

    kms._dek_cache.clear()
    yield
    kms._dek_cache.clear()


def test_partner_registry_is_encrypted_and_plaintext_never_persists():
    from maverick_dashboard import partner_store

    partner_store.upsert_tenant(
        name="Acme Secret Fleet",
        base_url="https://8.8.8.8/acme",
        token="partner-bearer-secret",
        notes="private operator note",
    )

    persisted = partner_store._path().read_bytes()
    assert persisted.startswith(b"MVKTEN1\n")
    for plaintext in (
        b"Acme Secret Fleet",
        b"partner-bearer-secret",
        b"private operator note",
    ):
        assert plaintext not in persisted
    assert not partner_store._legacy_path().exists()
    assert not partner_store._legacy_quarantine_path().exists()
    assert partner_store.list_tenants()[0]["token"] == "partner-bearer-secret"


def test_legacy_plaintext_migrates_only_after_authenticated_roundtrip():
    from maverick_dashboard import partner_store

    legacy = partner_store._legacy_path()
    legacy.parent.mkdir(parents=True)
    legacy.write_text(
        json.dumps([
            {
                "id": "legacy-one",
                "name": "Legacy Client",
                "base_url": "https://legacy.example",
                "token": "legacy-secret",
            }
        ]),
        encoding="utf-8",
    )

    rows = partner_store.list_tenants()

    assert rows[0]["id"] == "legacy-one"
    assert partner_store._path().exists()
    assert b"legacy-secret" not in partner_store._path().read_bytes()
    assert not legacy.exists()
    assert not partner_store._legacy_quarantine_path().exists()


def test_corrupt_sealed_generation_never_falls_back_to_legacy_plaintext():
    from maverick_dashboard import partner_store

    partner_store.upsert_tenant(
        name="Authoritative", base_url="https://8.8.8.8/sealed", token="sealed-token"
    )
    partner_store._path().write_bytes(b"not-an-authenticated-envelope")
    legacy = partner_store._legacy_path()
    legacy.write_text(
        json.dumps([
            {
                "id": "stale",
                "name": "Stale plaintext",
                "base_url": "https://stale.example",
                "token": "stale-token",
            }
        ]),
        encoding="utf-8",
    )

    with pytest.raises(partner_store.PartnerStoreUnavailable, match="ciphertext"):
        partner_store.list_tenants()

    assert legacy.exists()
    assert partner_store._path().read_bytes() == b"not-an-authenticated-envelope"


def test_interrupted_plaintext_cleanup_is_quarantined_and_retried(monkeypatch):
    from maverick_dashboard import partner_store

    legacy = partner_store._legacy_path()
    pending = partner_store._legacy_quarantine_path()
    legacy.parent.mkdir(parents=True)
    legacy.write_text(
        json.dumps([
            {
                "id": "legacy-one",
                "name": "Original",
                "base_url": "https://original.example",
                "token": "original-token",
            }
        ]),
        encoding="utf-8",
    )
    real_unlink = Path.unlink
    blocked = {legacy, pending}

    def interrupted_unlink(path: Path, *args, **kwargs):
        if path in blocked:
            raise PermissionError("simulated interrupted cleanup")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", interrupted_unlink)
    with pytest.raises(partner_store.PartnerStoreUnavailable, match="quarantined"):
        partner_store.list_tenants()

    assert partner_store._path().exists()
    assert not legacy.exists()
    assert pending.exists()

    # A stale plaintext edit cannot win after ciphertext publication. Once the
    # transient cleanup problem clears, the next locked read deletes quarantine.
    pending.write_text(
        json.dumps([{"id": "attacker", "token": "replacement"}]),
        encoding="utf-8",
    )
    blocked.clear()
    rows = partner_store.list_tenants()

    assert rows[0]["id"] == "legacy-one"
    assert rows[0]["token"] == "original-token"
    assert not pending.exists()


def test_cross_process_writers_do_not_lose_partner_rows(tmp_path):
    home = tmp_path / "multiprocess-home"
    start = tmp_path / "start-workers"
    workers = 4
    processes = [
        subprocess.Popen(
            [
                sys.executable,
                "-c",
                _CONCURRENT_UPSERT,
                str(home),
                str(index),
                str(start),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for index in range(workers)
    ]
    start.write_text("go\n", encoding="utf-8")
    try:
        results = [process.communicate(timeout=30) for process in processes]
        assert [process.returncode for process in processes] == [0] * workers, [
            stderr for _stdout, stderr in results
        ]
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)

    reader = subprocess.run(
        [sys.executable, "-c", _READ_PARTNERS, str(home)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert reader.returncode == 0, reader.stderr
    rows = json.loads(reader.stdout)
    assert {row["name"] for row in rows} == {
        f"Tenant {index}" for index in range(workers)
    }
    persisted = (home / "partner" / "tenants.sealed").read_bytes()
    assert all(f"token-{index}".encode() not in persisted for index in range(workers))
