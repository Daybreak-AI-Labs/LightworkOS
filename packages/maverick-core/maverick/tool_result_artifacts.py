"""Immutable screened result artifacts, scoped to tenant, principal and goal.

Private artifacts expire after seven days and cannot consume more than 256 MiB
or 128 files in a tenant. Quota exhaustion refuses publication; it never evicts
another live result or presents a preview as complete execution data.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import stat
import struct
import time

from .file_lock import (
    atomic_create_bytes,
    cross_process_lock,
    ensure_private_directory,
    open_private_read,
)
from .paths import current_tenant_id_strict, data_dir
from .tool_result_stream import MAX_RESULT_BYTES, result_bytes

SCHEMA = "lightwork.tool-result.v1"
RETENTION_SECONDS = 7 * 24 * 3600
MAX_TENANT_BYTES = 256 * 1024 * 1024
MAX_TENANT_FILES = 128
MAX_HEADER = 8192
_ID = re.compile(r"[0-9a-f]{64}\Z")


class ToolArtifactError(ValueError):
    """Complete output is unavailable; do not fabricate data from its preview."""


def _scope(goal_id, principal) -> dict:
    if goal_id is not None and (type(goal_id) is not int or goal_id < 0):
        raise ToolArtifactError("invalid tool-result goal scope")
    if principal is not None and (not isinstance(principal, str) or len(principal) > 512):
        raise ToolArtifactError("invalid tool-result owner scope")
    return {"schema": SCHEMA, "tenant": current_tenant_id_strict(),
            "goal_id": goal_id, "principal": principal or None}


def _root():
    current_tenant_id_strict()
    root = data_dir("tool_result_artifacts")
    ensure_private_directory(root)
    return root


def _inventory(root, now: float) -> tuple[int, int]:
    """Count bounded admitted files, reclaiming only expired private artifacts."""
    total = count = 0
    for scanned, path in enumerate(root.iterdir(), start=1):
        if scanned > MAX_TENANT_FILES * 2 + 16:
            raise ToolArtifactError("tool-result directory exceeds its inventory bound")
        if path.suffix != ".bin" or not _ID.fullmatch(path.stem):
            continue
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ToolArtifactError("tool-result artifact custody is invalid")
        if info.st_mtime <= now - RETENTION_SECONDS:
            # Check the actual private descriptor before removing a GC candidate.
            import os
            descriptor = open_private_read(path)
            os.close(descriptor)
            path.unlink()
            continue
        total += info.st_size
        count += 1
        if count > MAX_TENANT_FILES or total > MAX_TENANT_BYTES:
            raise ToolArtifactError("tool-result artifact store exceeds its quota")
    return total, count


def publish(text: str, *, goal_id, principal, tool: str) -> dict:
    """Persist complete redacted output only after the caller's policy screening."""
    from .safety.secret_detector import redact
    from .tenant.kms import seal_for_tenant

    scope = _scope(goal_id, principal)
    result_bytes(text)
    text, _ = redact(text)  # fail closed if redaction itself is unavailable
    size = result_bytes(text)
    now = time.time()
    payload = text.encode("utf-8")
    safe_tool, _ = redact(str(tool)[:128])
    header = {**scope, "created_at": now, "expires_at": now + RETENTION_SECONDS,
              "tool": safe_tool, "bytes": size,
              "sha256": hashlib.sha256(payload).hexdigest()}
    encoded = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    if len(encoded) > MAX_HEADER:
        raise ToolArtifactError("tool-result metadata exceeds its bound")
    blob = seal_for_tenant(scope["tenant"], struct.pack(">I", len(encoded)) + encoded + payload)
    artifact_id = hashlib.sha256(blob).hexdigest()
    root = _root()
    with cross_process_lock(root / ".quota", strict=True):
        total, count = _inventory(root, now)
        if count >= MAX_TENANT_FILES or total + len(blob) > MAX_TENANT_BYTES:
            raise ToolArtifactError("tool-result artifact quota reached; retained data was not evicted")
        atomic_create_bytes(root / f"{artifact_id}.bin", blob)
    return {"artifact_id": artifact_id, "bytes": size, "sha256": header["sha256"],
            "expires_at": header["expires_at"], "complete": True}


def read_complete(artifact_id: str, *, goal_id, principal) -> str:
    """Authenticate content and all execution scope fields before returning it."""
    import os

    from .tenant.kms import unseal_for_tenant

    if not isinstance(artifact_id, str) or not _ID.fullmatch(artifact_id):
        raise ToolArtifactError("invalid tool-result artifact reference")
    scope = _scope(goal_id, principal)
    try:
        with os.fdopen(open_private_read(_root() / f"{artifact_id}.bin"), "rb") as source:
            blob = source.read(MAX_RESULT_BYTES + MAX_HEADER + 1025)
        if len(blob) > MAX_RESULT_BYTES + MAX_HEADER + 1024 or hashlib.sha256(blob).hexdigest() != artifact_id:
            raise ToolArtifactError("tool-result artifact size or digest is invalid")
        clear = unseal_for_tenant(scope["tenant"], blob)
        if len(clear) < 4:
            raise ToolArtifactError("tool-result artifact is incomplete")
        length = struct.unpack(">I", clear[:4])[0]
        if not 1 <= length <= MAX_HEADER:
            raise ToolArtifactError("tool-result artifact metadata is invalid")
        header = json.loads(clear[4:4 + length])
        if not isinstance(header, dict) or any(header.get(key) != value for key, value in scope.items()):
            raise ToolArtifactError("tool-result artifact is unavailable for this execution scope")
        expires = header.get("expires_at")
        if type(expires) not in (float, int) or not math.isfinite(expires) or expires <= time.time():
            raise ToolArtifactError("tool-result artifact has expired")
        payload = clear[4 + length:]
        if type(header.get("bytes")) is not int or len(payload) > MAX_RESULT_BYTES or len(payload) != header.get("bytes") or hashlib.sha256(payload).hexdigest() != header.get("sha256"):
            raise ToolArtifactError("tool-result artifact content is invalid")
        return payload.decode("utf-8")
    except ToolArtifactError:
        raise
    except Exception as exc:
        raise ToolArtifactError("complete tool result is unavailable; restore its artifact or key, never use the preview as full data") from exc


def read_tool_result(*, goal_id, principal):
    """A read-only, authority-bound slice reader for model-visible references."""
    from .tools import Tool

    def run(args):
        try:
            offset, limit = args.get("offset", 0), args.get("limit", 16000)
            if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 16000:
                return "ERROR: offset must be nonnegative and limit must be between 1 and 16000 characters"
            text = read_complete(args.get("artifact_id"), goal_id=goal_id, principal=principal)
            if offset > len(text):
                return "ERROR: offset exceeds the complete result length"
            end = min(len(text), offset + limit)
            return json.dumps({"status": "complete", "offset": offset, "next_offset": end,
                               "total_chars": len(text), "has_more": end < len(text),
                               "text": text[offset:end]}, ensure_ascii=False)
        except ToolArtifactError as exc:
            return f"ERROR: {exc}"

    return Tool(name="read_tool_result", description=(
        "Read a slice of a complete screened tool-result artifact retained for this goal and identity. "
        "Use the exact artifact_id from a prior tool response; follow next_offset while has_more. "
        "Expired, missing or unauthorized results fail explicitly; never treat a preview as complete data."),
        input_schema={"type": "object", "properties": {
            "artifact_id": {"type": "string"}, "offset": {"type": "integer", "minimum": 0},
            "limit": {"type": "integer", "minimum": 1, "maximum": 16000}}, "required": ["artifact_id"]},
        fn=run, parallel_safe=False)  # recheck expiry/custody each read; do not memoize
