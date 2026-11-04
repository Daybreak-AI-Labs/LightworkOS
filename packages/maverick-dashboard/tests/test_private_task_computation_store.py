"""The private task check's write fence refuses a non-local world plainly."""
from __future__ import annotations

from contextlib import nullcontext
from types import SimpleNamespace

import pytest
from fastapi import HTTPException


def test_a_world_without_local_custody_is_a_plain_refusal_not_a_server_error(monkeypatch):
    # A Postgres world has no local write connection; the check must not call it
    # before the custody check and fail with AttributeError (a 500).
    from maverick_dashboard import private_task_computation_store as store

    monkeypatch.setattr(store, "authority_effect_fence", nullcontext)
    monkeypatch.setattr(store, "_world", lambda: SimpleNamespace())
    monkeypatch.setattr(store.STORE, "_backend", lambda: SimpleNamespace(kind="local"))
    with pytest.raises(HTTPException) as refused, store._writer():
        pass
    assert refused.value.status_code == 503
    assert "native local custody" in refused.value.detail
