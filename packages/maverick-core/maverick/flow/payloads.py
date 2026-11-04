"""Complete, bounded flow checkpoints, separate from their public previews.

Large checkpoints are immutable tenant-encrypted artifacts. The run row and
artifact are published under a short checkpoint lock (not the execution lock),
so readers see a complete generation and obsolete artifacts can be reclaimed.
Credential redaction runs before persistence, including inside ciphertext.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
from pathlib import Path
from typing import Any

from ..file_lock import _windows_extended_path
from .redact import cap, redact

SCHEMA = "lightwork.flow-data.v1"
MAX_BYTES = 16 * 1024 * 1024
MAX_ITEMS = 200_000
MAX_DEPTH = 64
PREVIEW_BYTES = 32 * 1024
_HASH = re.compile(r"[0-9a-f]{64}\Z")


class FlowPayloadError(ValueError):
    """Checkpoint unavailable: restore its artifact/key or retry from inputs."""


def _json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def prepare(data: dict, input_data: dict, continuation: dict | None = None) -> dict:
    """Validate resource limits before detection; keep every legitimate value.

    Unlike preview truncation, quota/type failures are explicit. Tuples are
    normalized to the JSON arrays they have always become after a restart.
    """
    items = 0
    size = 0

    def visit(value: Any, depth: int = 0) -> Any:
        nonlocal items, size
        items += 1
        if items > MAX_ITEMS or depth > MAX_DEPTH or size > MAX_BYTES:
            raise FlowPayloadError("flow checkpoint exceeds its item/depth/byte quota")
        if isinstance(value, str):
            if len(value) > MAX_BYTES:
                raise FlowPayloadError("flow checkpoint exceeds its byte quota")
            size += len(value.encode("utf-8"))
        elif isinstance(value, dict):
            if len(value) > MAX_ITEMS:
                raise FlowPayloadError("flow checkpoint exceeds its item quota")
            if any(not isinstance(key, str) for key in value):
                raise FlowPayloadError("flow checkpoint object keys must be strings")
            return {visit(key, depth + 1): visit(item, depth + 1)
                    for key, item in value.items()}
        elif isinstance(value, (list, tuple)):
            if len(value) > MAX_ITEMS:
                raise FlowPayloadError("flow checkpoint exceeds its item quota")
            return [visit(item, depth + 1) for item in value]
        elif value is None or type(value) in (bool, int):
            size += 16
        elif isinstance(value, float) and math.isfinite(value):
            size += 24
        else:
            raise FlowPayloadError("flow checkpoint contains an unsupported value")
        if size > MAX_BYTES:
            raise FlowPayloadError("flow checkpoint exceeds its byte quota")
        return value

    if not isinstance(data, dict) or not isinstance(input_data, dict):
        raise FlowPayloadError("flow checkpoint data must be objects")
    values = {"data": data, "input_data": input_data}
    if continuation is not None:
        if not isinstance(continuation, dict):
            raise FlowPayloadError("flow continuation must be an object")
        values["continuation"] = continuation
    normalized = visit(values)
    try:
        # Measure escaping/large integers too, before scanning the text.
        if len(_json(normalized)) > MAX_BYTES:
            raise FlowPayloadError("flow checkpoint exceeds its byte quota")
        result = redact(normalized, strict=True)
        if len(_json(result)) > MAX_BYTES:
            raise FlowPayloadError("redacted flow checkpoint exceeds its byte quota")
        return result
    except (TypeError, ValueError, RecursionError) as exc:
        if isinstance(exc, FlowPayloadError):
            raise
        raise FlowPayloadError("flow checkpoint could not be safely prepared") from exc


def preview(value: dict) -> dict:
    """Bounded, credential-redacted display projection; never execution input."""
    result = redact(cap(value))
    if len(_json(result)) > PREVIEW_BYTES:
        return {"_flow_data_preview": "Complete data is retained privately; preview exceeds 32 KiB."}
    return result


def approval_data(value: dict, card: dict | None = None) -> dict:
    """New approval cards bind full data; old complete cards retain their digest."""
    if card is not None and (card.get("inputs") or {}).get("run_data_format") != SCHEMA:
        return redact(cap(value))
    return prepare(value, {})["data"]


def _scope(row: dict) -> dict:
    from ..paths import current_tenant_id_strict

    return {"schema": SCHEMA, "tenant": current_tenant_id_strict(),
            "run_id": row["run_id"], "flow_id": row["flow_id"],
            "owner": row.get("owner", "")}


def _directory(root: Path, run_id: str) -> Path:
    # No reference can select another run's directory or a caller-provided path.
    return root / hashlib.sha256(run_id.encode("utf-8")).hexdigest()


def _io_path(path: Path) -> Path:
    # Keep stored references portable while Windows filesystem calls reach deep
    # tenant checkpoint paths beyond the legacy Win32 path limit.
    return Path(_windows_extended_path(path) if os.name == "nt" else path)


def _read_artifact(path: Path) -> bytes:
    from ..file_lock import ensure_private_directory, ensure_private_file

    io_path = _io_path(path)
    ensure_private_directory(io_path.parent)
    ensure_private_file(io_path)
    with io_path.open("rb") as source:
        blob = source.read(MAX_BYTES + 8193)
    if len(blob) > MAX_BYTES + 8192:
        raise FlowPayloadError("flow checkpoint artifact exceeds its byte quota")
    return blob


def encode(root: Path, row: dict, values: dict) -> dict:
    """Publish an immutable artifact before the referring run row is committed."""
    raw = _json(values)
    if len(raw) <= PREVIEW_BYTES and all(preview(values[k]) == values[k] for k in values):
        return {"schema": SCHEMA, "kind": "inline", "sha256": hashlib.sha256(raw).hexdigest()}
    from ..file_lock import atomic_create_bytes
    from ..tenant.kms import seal_for_tenant

    scope = _scope(row)
    try:
        clear = _json({**scope, "values": values})
        if len(clear) > MAX_BYTES + 4096:
            raise FlowPayloadError("flow checkpoint scope exceeds its byte quota")
        blob = seal_for_tenant(scope["tenant"], clear)
        digest = hashlib.sha256(blob).hexdigest()
        path = _directory(root, row["run_id"]) / (digest + ".bin")
        atomic_create_bytes(path, blob)
    except Exception as exc:
        raise FlowPayloadError("flow checkpoint could not be securely stored") from exc
    return {"schema": SCHEMA, "kind": "artifact", "sha256": digest, "bytes": len(blob)}


def _legacy_incomplete(value: Any) -> bool:
    if isinstance(value, str):
        return value == "…" or value.endswith("…[truncated]") or bool(
            re.fullmatch(r"…\[\d+ more items\]", value))
    if isinstance(value, list):
        return any(_legacy_incomplete(item) for item in value)
    if isinstance(value, dict):
        return ("_flow_data_preview" in value
                or ("…" in value and bool(re.fullmatch(r"\[\d+ more keys\]", str(value["…"]))))
                or any(_legacy_incomplete(item) for item in value.values()))
    return False


def decode(root: Path, row: dict) -> dict:
    ref = row.get("data_state")
    values = {"data": row.get("data") or {}, "input_data": row.get("input_data") or {}}
    if "continuation" in row:
        values["continuation"] = row["continuation"]
    if ref is None:
        if _legacy_incomplete(values):
            raise FlowPayloadError("legacy flow checkpoint is incomplete; restore complete inputs before retrying")
        return prepare(**values)
    if (not isinstance(ref, dict) or ref.get("schema") != SCHEMA
            or not isinstance(ref.get("sha256"), str) or not _HASH.fullmatch(ref["sha256"])):
        raise FlowPayloadError("flow checkpoint reference is invalid")
    try:
        if ref.get("kind") == "inline" and set(ref) == {"schema", "kind", "sha256"}:
            if hashlib.sha256(_json(values)).hexdigest() != ref["sha256"]:
                raise FlowPayloadError("inline flow checkpoint failed integrity checks")
        elif ref.get("kind") == "artifact" and set(ref) == {"schema", "kind", "sha256", "bytes"}:
            if type(ref["bytes"]) is not int or not 0 < ref["bytes"] <= MAX_BYTES + 8192:
                raise FlowPayloadError("flow checkpoint reference size is invalid")
            from ..tenant.kms import unseal_for_tenant

            blob = _read_artifact(_directory(root, row["run_id"]) / (ref["sha256"] + ".bin"))
            if len(blob) != ref["bytes"] or hashlib.sha256(blob).hexdigest() != ref["sha256"]:
                raise FlowPayloadError("flow checkpoint artifact failed integrity checks")
            scope = _scope(row)
            opened = json.loads(unseal_for_tenant(scope["tenant"], blob))
            if (not isinstance(opened, dict) or set(opened) != {*scope, "values"}
                    or any(opened[key] != value for key, value in scope.items())):
                raise FlowPayloadError("flow checkpoint artifact belongs to a different scope")
            values = opened["values"]
            if not isinstance(values, dict) or set(values) not in (
                {"data", "input_data"}, {"data", "input_data", "continuation"},
            ):
                raise FlowPayloadError("flow checkpoint artifact values are invalid")
        else:
            raise FlowPayloadError("flow checkpoint reference kind is invalid")
        return prepare(**values)
    except FlowPayloadError:
        raise
    except Exception as exc:
        raise FlowPayloadError("flow checkpoint unavailable; restore its artifact and tenant key before resuming") from exc


def reclaim(root: Path, run_id: str, keep: dict | None) -> None:
    """Only under the checkpoint lock; retain the currently committed artifact."""
    directory = _io_path(_directory(root, run_id))
    retained = (keep or {}).get("sha256") if (keep or {}).get("kind") == "artifact" else None
    if not directory.exists():
        return
    from ..file_lock import ensure_private_directory

    ensure_private_directory(directory)
    for path in directory.glob("*.bin"):
        if _HASH.fullmatch(path.stem) and path.stem != retained:
            path.unlink(missing_ok=True)
