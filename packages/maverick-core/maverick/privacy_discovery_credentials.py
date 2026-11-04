"""Tenant-private discovery credential references and sealed evidence-key generations."""

from __future__ import annotations

import json
import re
import secrets
import threading
import time

from . import connections
from .file_lock import (
    atomic_read_bytes,
    atomic_write_bytes,
    cross_process_lock,
    ensure_private_directory,
)
from .governed_operations import digest
from .paths import current_tenant_id_strict, data_dir
from .tenant.kms import seal_text_for_tenant, unseal_text_for_tenant

CONNECTION_PATTERN = r"connection:[a-z0-9][a-z0-9_-]{0,63}:[0-9a-f]{32}"
KEY_PATTERN = r"evidence-key:[a-z0-9][a-z0-9_-]{0,63}:[1-9][0-9]{0,9}"
ENV_PATTERN = r"[A-Z][A-Z0-9_]{1,127}"
_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
_LOCK = threading.Lock()


def validate_reference(value, *, evidence=False):
    pattern = KEY_PATTERN if evidence else CONNECTION_PATTERN
    if not isinstance(value, str) or not re.fullmatch(f"(?:{ENV_PATTERN}|{pattern})", value):
        raise ValueError("select a saved reference or a deployment-managed environment name")
    return value


def resolve_connection(reference, *, provider, origin):
    if not isinstance(reference, str) or not re.fullmatch(CONNECTION_PATTERN, reference):
        raise ValueError("saved connection reference is invalid")
    _, name, revision = reference.split(":")
    return connections.resolve_named(
        name, expected_revision=revision, connector=provider, origin=origin
    )


def connection_present(reference):
    if not re.fullmatch(CONNECTION_PATTERN, reference):
        return False
    _, name, revision = reference.split(":")
    record = connections.get_connection(name) if connections.enabled() else None
    return bool(
        connections.current_principal()
        and record
        and record.get("revision") == revision
        and record.get("token")
        and connections._may_use(record, connections.current_principal())
    )


def _authority():
    tenant, principal = current_tenant_id_strict(), connections.current_principal()
    if not tenant or not principal or not connections.enabled():
        raise PermissionError(
            "evidence keys require an active tenant, named principal and enabled connections"
        )
    return tenant, principal


def _path():
    return data_dir("privacy_automation", "evidence-keys.sealed")


def _load(tenant):
    try:
        result = json.loads(unseal_text_for_tenant(tenant, atomic_read_bytes(_path())))
        if (
            not isinstance(result, dict)
            or not isinstance(result.get("keys"), dict)
            or not isinstance(result.get("operations"), dict)
        ):
            raise ValueError("invalid store")
        return result
    except FileNotFoundError:
        return {"keys": {}, "operations": {}}
    except Exception:
        raise RuntimeError(
            "evidence key store cannot be authenticated; no keys were changed"
        ) from None


def _public(record):
    return {
        key: record[key]
        for key in ("name", "revision", "owner", "created_at", "updated_at", "reference")
    }


def list_keys():
    tenant, principal = _authority()
    return [
        _public(record)
        for _, record in sorted(_load(tenant)["keys"].items())
        if record["owner"] == principal
    ]


def create_or_rotate(name, *, expected_revision, idempotency_key):
    tenant, principal = _authority()
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        raise ValueError("key name must contain lowercase letters, numbers, hyphens or underscores")
    if type(expected_revision) is not int or not 0 <= expected_revision < 10**10 - 1:
        raise ValueError("key version is invalid")
    if not isinstance(idempotency_key, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}", idempotency_key
    ):
        raise ValueError("request reference is invalid")
    request_sha = digest({"name": name, "expected_revision": expected_revision, "actor": principal})
    with _LOCK, cross_process_lock(_path(), strict=True):
        state = _load(tenant)
        operation = state["operations"].get(idempotency_key)
        if operation:
            if operation["request_sha256"] != request_sha:
                raise connections.ConnectionVersionConflict(
                    "request reference was already used for another key operation"
                )
            return dict(operation["result"])
        current = state["keys"].get(name)
        if current and current["owner"] != principal:
            raise PermissionError("evidence key belongs to another principal")
        if (current or {}).get("revision", 0) != expected_revision:
            raise connections.ConnectionVersionConflict(
                "evidence key changed; reload its current version"
            )
        if len(state["operations"]) >= 10000 or (not current and len(state["keys"]) >= 1000):
            raise ValueError("evidence key registry capacity reached")
        revision, now = expected_revision + 1, time.time()
        record = {
            "name": name,
            "owner": principal,
            "revision": revision,
            "created_at": current["created_at"] if current else now,
            "updated_at": now,
            "reference": f"evidence-key:{name}:{revision}",
            "key_hex": secrets.token_hex(32),
        }
        state["keys"][name] = record
        result = _public(record)
        state["operations"][idempotency_key] = {"request_sha256": request_sha, "result": result}
        ensure_private_directory(_path().parent)
        atomic_write_bytes(
            _path(), seal_text_for_tenant(tenant, json.dumps(state, sort_keys=True)), mode=0o600
        )
        return result


def resolve_key(reference):
    tenant, principal = _authority()
    if not isinstance(reference, str) or not re.fullmatch(KEY_PATTERN, reference):
        raise ValueError("evidence key reference is invalid")
    _, name, revision = reference.split(":")
    record = _load(tenant)["keys"].get(name)
    if not record or record["owner"] != principal:
        raise PermissionError("evidence key access is unavailable or denied")
    if record["revision"] != int(revision):
        raise connections.ConnectionVersionConflict(
            "evidence key rotated; explicitly update the source to the current key version"
        )
    value = bytes.fromhex(record["key_hex"])
    if len(value) != 32:
        raise RuntimeError("evidence key store is invalid")
    return value
