"""S3-backed attachment store — content-addressed keys + URL builders.

A dependency-free helper for an S3 attachment workflow: derive a stable,
content-addressed object key for a filename, and build virtual-hosted-style
S3 URLs for upload (PUT) / download (GET). This intentionally uses stdlib
only — it builds *plain* virtual-hosted URLs (no SigV4 presigning, so the
bucket/object must be reachable with the caller's own credentials or be
public); for full presigned URLs use the boto3-backed ``s3`` tool.

ops:
  - key_for(filename)     — content-addressed key (sha256 of the name +
    preserved extension).
  - put_url(bucket, key)  — virtual-hosted URL for an upload.
  - get_url(bucket, key)  — virtual-hosted URL for a download.

Read ``AWS_REGION`` for the host (default us-east-1). The URL builders and
key derivation are pure helpers tested without any network access — this
tool never makes a network call.
"""
from __future__ import annotations

import hashlib
import os
import posixpath
from typing import Any

from . import Tool


def _region() -> str:
    return os.environ.get("AWS_REGION", "us-east-1").strip() or "us-east-1"


def key_for(filename: str, prefix: str = "attachments") -> str:
    """Return a deterministic content-addressed key for ``filename``.

    The key is ``{prefix}/{sha256(filename)}{ext}`` where ``ext`` is the
    lower-cased extension of the filename (preserved so downstream tools can
    infer a content type). Deterministic: the same filename always maps to
    the same key.
    """
    name = (filename or "").strip()
    digest = hashlib.sha256(name.encode("utf-8")).hexdigest()
    ext = posixpath.splitext(name)[1].lower()
    pre = prefix.strip("/")
    return f"{pre}/{digest}{ext}" if pre else f"{digest}{ext}"


def _host(bucket: str, region: str) -> str:
    return f"{bucket}.s3.{region}.amazonaws.com"


def build_url(bucket: str, key: str, region: str) -> str:
    """Build a virtual-hosted-style S3 URL for ``bucket``/``key``."""
    # Encode each path segment but keep the '/' separators.
    from urllib.parse import quote

    safe_key = "/".join(quote(seg, safe="") for seg in key.split("/"))
    return f"https://{_host(bucket, region)}/{safe_key}"


def _slug(args: dict) -> tuple[str, str] | str:
    bucket = (args.get("bucket") or "").strip()
    key = (args.get("key") or "").strip()
    if not bucket or not key:
        return "ERROR: bucket and key are required"
    return bucket, key


def _op_key_for(args: dict) -> str:
    filename = (args.get("filename") or "").strip()
    if not filename:
        return "ERROR: key_for requires filename"
    return key_for(filename)


def _op_put_url(args: dict) -> str:
    sg = _slug(args)
    if isinstance(sg, str):
        return sg
    bucket, key = sg
    return build_url(bucket, key, _region())


def _op_get_url(args: dict) -> str:
    sg = _slug(args)
    if isinstance(sg, str):
        return sg
    bucket, key = sg
    return build_url(bucket, key, _region())


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    if not isinstance(op, str):
        return f"ERROR: unknown op {op!r}"
    return {
        "key_for": _op_key_for,
        "put_url": _op_put_url,
        "get_url": _op_get_url,
    }.get(op, lambda a: f"ERROR: unknown op {op!r}")(args)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["key_for", "put_url", "get_url"]},
        "bucket": {"type": "string"},
        "key": {"type": "string"},
        "filename": {"type": "string", "description": "Source filename (key_for)."},
    },
    "required": ["op"],
}


def s3_attachments() -> Tool:
    return Tool(
        name="s3_attachments",
        description=(
            "S3 attachment helpers (stdlib, no boto3). ops: key_for "
            "(content-addressed key from a filename), put_url / get_url "
            "(virtual-hosted-style S3 URLs for bucket+key). Plain URLs, "
            "not SigV4-presigned. AWS_REGION sets the host (default "
            "us-east-1). Use the 's3' tool for presigned URLs."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
