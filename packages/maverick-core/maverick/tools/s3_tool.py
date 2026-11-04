"""S3 tool — list/get/put/delete objects in any S3-compatible bucket.

Works against AWS S3, Cloudflare R2, MinIO, Backblaze B2, anything
that speaks the S3 API.

Auth (standard boto3 chain):
  - ``AWS_ACCESS_KEY_ID`` + ``AWS_SECRET_ACCESS_KEY``
  - or an IAM role / aws config profile

Optional ``AWS_ENDPOINT_URL`` for non-AWS providers (R2, MinIO).
Optional ``AWS_REGION``.

ops:
  - list_buckets()
  - list_objects(bucket, prefix, limit)
  - get(bucket, key)              — returns text (first 4KB) + size
  - put(bucket, key, body, confirm)
  - delete(bucket, key, confirm)
  - presign(bucket, key, expires)  — generate a temporary download URL

Mutations (put / delete) gated by confirm=true.

Requires::

    python -m pip install -e './packages/maverick-core[s3]'
"""
from __future__ import annotations

import logging
import os
from typing import Any

from . import Tool, as_bool

log = logging.getLogger(__name__)


_S3_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["list_buckets", "list_objects", "get",
                     "put", "delete", "presign"],
        },
        "bucket": {"type": "string"},
        "key": {"type": "string"},
        "prefix": {"type": "string"},
        "limit": {"type": "integer"},
        "body": {"type": "string", "description": "utf-8 text (put)."},
        "expires": {"type": "integer", "description": "Presign TTL seconds (default 3600)."},
        "confirm": {"type": "boolean"},
    },
    "required": ["op"],
}


def _client():
    import boto3
    return boto3.client(
        "s3",
        endpoint_url=os.environ.get("AWS_ENDPOINT_URL") or None,
        region_name=os.environ.get("AWS_REGION") or None,
    )


def _op_list_buckets() -> str:
    c = _client()
    r = c.list_buckets()
    buckets = r.get("Buckets") or []
    if not buckets:
        return "no buckets"
    return "\n".join(
        f"  {b['Name']}  created={b.get('CreationDate')}" for b in buckets
    )


def _op_list_objects(bucket: str, prefix: str, limit: int) -> str:
    if not bucket:
        return "ERROR: list_objects requires bucket"
    c = _client()
    kwargs: dict = {"Bucket": bucket, "MaxKeys": max(1, min(limit, 1000))}
    if prefix:
        kwargs["Prefix"] = prefix
    r = c.list_objects_v2(**kwargs)
    items = r.get("Contents") or []
    if not items:
        return f"no objects in {bucket}{(' (prefix ' + prefix + ')') if prefix else ''}"
    return "\n".join(
        f"  {it['Size']:>10}  {it['LastModified']}  {it['Key']}"
        for it in items
    )


def _op_get(bucket: str, key: str) -> str:
    if not bucket or not key:
        return "ERROR: get requires bucket and key"
    c = _client()
    r = c.get_object(Bucket=bucket, Key=key)
    body = r["Body"].read(4096)
    text = body.decode("utf-8", errors="replace")
    size = int(r.get("ContentLength") or len(body))
    return (
        f"size={size}  content_type={r.get('ContentType', '?')}\n"
        f"{text}{'... (truncated)' if size > 4096 else ''}"
    )


def _op_put(bucket: str, key: str, body: str, confirm: bool) -> str:
    if not bucket or not key:
        return "ERROR: put requires bucket and key"
    if not confirm:
        return f"DRY RUN: would put s3://{bucket}/{key} ({len(body)} bytes). " \
               "Re-run with confirm=true."
    c = _client()
    c.put_object(Bucket=bucket, Key=key, Body=body.encode("utf-8"))
    return f"put s3://{bucket}/{key} ({len(body)} bytes)"


def _op_delete(bucket: str, key: str, confirm: bool) -> str:
    if not bucket or not key:
        return "ERROR: delete requires bucket and key"
    if not confirm:
        return f"DRY RUN: would delete s3://{bucket}/{key}. Re-run with confirm=true."
    c = _client()
    c.delete_object(Bucket=bucket, Key=key)
    return f"deleted s3://{bucket}/{key}"


def _op_presign(bucket: str, key: str, expires: int) -> str:
    if not bucket or not key:
        return "ERROR: presign requires bucket and key"
    c = _client()
    url = c.generate_presigned_url(
        "get_object",
        Params={"Bucket": bucket, "Key": key},
        ExpiresIn=max(60, min(int(expires or 3600), 7 * 24 * 3600)),
    )
    return url


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import boto3  # noqa: F401
    except ImportError:
        return (
            "ERROR: boto3 not installed. "
            "Run: python -m pip install -e './packages/maverick-core[s3]'"
        )
    try:
        if op == "list_buckets":
            return _op_list_buckets()
        bucket = (args.get("bucket") or "").strip()
        key = (args.get("key") or "").strip()
        if op == "list_objects":
            return _op_list_objects(
                bucket, (args.get("prefix") or "").strip(),
                int(args.get("limit") or 100),
            )
        if op == "get":
            return _op_get(bucket, key)
        if op == "put":
            return _op_put(bucket, key, args.get("body") or "",
                            as_bool(args.get("confirm")))
        if op == "delete":
            return _op_delete(bucket, key, as_bool(args.get("confirm")))
        if op == "presign":
            return _op_presign(bucket, key, int(args.get("expires") or 3600))
    except Exception as e:
        return f"ERROR: S3 request failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def s3_tool() -> Tool:
    return Tool(
        name="s3",
        description=(
            "S3-compatible object storage. ops: list_buckets, "
            "list_objects (bucket + optional prefix), get (4KB "
            "preview), put + delete (gated by confirm=true), "
            "presign (signed download URL). AWS_ENDPOINT_URL for "
            "R2/MinIO/Backblaze. Uses standard boto3 auth chain."
        ),
        input_schema=_S3_SCHEMA,
        fn=_run,
    )
