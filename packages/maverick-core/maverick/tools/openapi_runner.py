"""OpenAPI runner — call any REST endpoint by spec.

Given an OpenAPI 3 spec (URL or local file) the agent can:
  - list the operations the API exposes,
  - look up the schema of a specific operation,
  - invoke an operation with named parameters.

Lightweight: no codegen, no client class library. We parse the spec
once (cached by path/URL), then synthesize requests on demand. JSON
specs are first-class; YAML works when ``pyyaml`` is installed.

ops:
  - list_ops(spec)                 — every {method, path, opId, summary}
  - describe(spec, op_id)          — params + request body schema
  - call(spec, op_id, params, body, base_url)
                                   — issue the request, return response

Auth is opt-in via standard headers in ``headers={...}`` on call().

This wraps tens of thousands of public + private APIs without us
writing a tool per API. Limits: no OAuth flow handling (caller
provides bearer/api-key in ``headers``); no multipart upload;
only application/json bodies.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

from . import Tool

log = logging.getLogger(__name__)


def _confine_local(source: str, workdir: Path | None) -> Path:
    """Resolve a local spec path, confined to the workspace.

    Like every other file-reading tool (fs / ocr / pdf_reader / view_image),
    ``openapi_runner`` confines local paths to the workdir, so a spec path
    cannot read an arbitrary host file (``/etc/passwd``, ``~/.ssh/id_rsa``).
    An absolute path is allowed only when it resolves INSIDE the workspace —
    so loading a spec by absolute path (a tested feature) keeps working for
    in-workspace files, while a path escape raises. ``~`` is expanded first so
    ``~/.ssh/...`` can't sneak past via expansion inside the workdir.
    """
    base = (workdir or Path.cwd()).resolve()
    p = Path(os.path.expanduser(source))
    p = p.resolve() if p.is_absolute() else (base / p).resolve()
    try:
        p.relative_to(base)
    except ValueError as e:
        raise RuntimeError(
            f"refusing to read spec outside the workspace: {source}"
        ) from e
    return p


_OAS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["list_ops", "describe", "call"]},
        "spec": {
            "type": "string",
            "description": "Spec source: URL (http(s)://) or local file path.",
        },
        "op_id": {"type": "string", "description": "operationId from the spec."},
        "params": {
            "type": "object",
            "description": "Named values for path/query parameters.",
        },
        "body": {
            "description": "Request body (JSON-serializable) for POST/PUT/PATCH.",
        },
        "headers": {
            "type": "object",
            "description": "Extra HTTP headers (auth tokens etc.).",
        },
        "base_url": {
            "type": "string",
            "description": "Override the spec's servers[0].url.",
        },
    },
    "required": ["op", "spec"],
}


_spec_lock = threading.Lock()
_spec_cache: dict[Any, dict] = {}
_SPEC_CACHE_MAX_ENTRIES = 32

# Hard byte ceilings on model/user-supplied HTTP bodies. ``safe_client`` only
# validates the host -- it does not bound the response size, so ``r.text``
# would buffer an unbounded (multi-GB / endless) body into memory before we
# ever parse or truncate it. Mirror ``http_fetch._stream_fetch``: read at most
# this many bytes off the wire, then stop. Specs are larger than call replies
# (the call result is sliced to 3000 chars anyway), so give specs more room.
# Both are env-overridable for the rare legitimately-huge spec.
# Also settings ([tools] openapi_spec_max_bytes / openapi_call_max_bytes) read
# once at startup; the environment still wins (and still fails loudly when it
# is not a number, as before).
def _limit_setting(env: str, key: str, default: int) -> int:
    from ..env_setting import env_or_config

    raw = os.getenv(env)
    if raw:
        return int(raw)
    try:
        return int(env_or_config(env, "tools", key) or default)
    except ValueError:
        return default


_SPEC_MAX_BYTES = _limit_setting("MAVERICK_OPENAPI_SPEC_MAX_BYTES", "openapi_spec_max_bytes",
                                 10_000_000)
_CALL_MAX_BYTES = _limit_setting("MAVERICK_OPENAPI_CALL_MAX_BYTES", "openapi_call_max_bytes",
                                 1_000_000)


def _stream_text(client: Any, method: str, url: str, max_bytes: int,
                 **req_kwargs: Any) -> str:
    """Stream a response with a hard byte ceiling, returning decoded text.

    ``safe_client`` pins the host but does not cap the body; without this a
    spec/endpoint URL pointing at an endless body exhausts memory. Read at
    most ``max_bytes`` off the wire (mirrors ``http_fetch._stream_fetch``),
    then stop. The buffered bytes are decoded with the response encoding.
    """
    with client.stream(method, url, **req_kwargs) as resp:
        resp.raise_for_status()
        encoding = resp.encoding
        buf = bytearray()
        for chunk in resp.iter_bytes():
            buf += chunk
            if len(buf) >= max_bytes:
                break
        raw = bytes(buf[:max_bytes])
    try:
        return raw.decode(encoding or "utf-8", errors="replace")
    except (LookupError, UnicodeDecodeError):
        return raw.decode("utf-8", errors="replace")


def _load_spec(source: str, workdir: Path | None = None) -> dict:
    is_url = source.startswith(("http://", "https://"))
    # Confine local reads to the workspace BEFORE the cache lookup so a
    # path escape can't slip through a warm cache (and is rejected even if the
    # same bad path was attempted before).
    local_path = None if is_url else _confine_local(source, workdir)
    # Cache local specs by their confined, resolved path rather than the raw
    # user-provided string. Otherwise separate sandboxes using the same
    # relative name (for example, ``spec.json``) can share a process-global
    # cache entry across workdirs. URL specs remain keyed by URL.
    # A local spec is keyed by its size and mtime too, so an edited file is
    # re-read rather than served stale for the life of the process.
    if is_url:
        cache_key: Any = source
    else:
        stat = os.stat(local_path)
        if stat.st_size > _SPEC_MAX_BYTES:
            raise RuntimeError(f"spec exceeds {_SPEC_MAX_BYTES} bytes")
        cache_key = (str(local_path), stat.st_mtime_ns, stat.st_size)
    with _spec_lock:
        cached = _spec_cache.get(cache_key)
    if cached is not None:
        if is_url:
            # The cache is process-wide: the caller's own egress policy must
            # still allow the host, or a spec fetched for one tenant would be
            # served to a tenant that may not reach it.
            from ..egress_guard import _check
            _check(source)
        return cached
    if is_url:
        from ._ssrf import safe_client
        # safe_client validates the host and pins the connection to the
        # resolved public IP (closes the DNS-rebinding TOCTOU).
        with safe_client(source, timeout=30.0) as client:
            text = _stream_text(client, "GET", source, _SPEC_MAX_BYTES)
    else:
        with open(local_path, encoding="utf-8") as f:
            text = f.read(_SPEC_MAX_BYTES + 1)
        if len(text) > _SPEC_MAX_BYTES:
            raise RuntimeError(f"spec exceeds {_SPEC_MAX_BYTES} bytes")
    # Try JSON first; fall back to YAML.
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        try:
            import yaml
        except ImportError as e:
            raise RuntimeError(
                "Spec is YAML and pyyaml not installed. "
                "Install pyyaml or convert to JSON."
            ) from e
        data = yaml.safe_load(text)
    if not isinstance(data, dict) or "paths" not in data:
        raise RuntimeError("OpenAPI spec missing 'paths'")
    with _spec_lock:
        while len(_spec_cache) >= _SPEC_CACHE_MAX_ENTRIES:
            _spec_cache.pop(next(iter(_spec_cache)))
        _spec_cache[cache_key] = data
    return data


def _walk_ops(spec: dict):
    paths = spec.get("paths") or {}
    methods = ("get", "post", "put", "patch", "delete", "options", "head")
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method in methods:
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            yield method.upper(), path, op


def _resolve_ref(spec: dict, node: Any, _seen: frozenset[str] = frozenset()) -> Any:
    """Resolve an internal JSON Reference (``{"$ref": "#/..."}``) within ``spec``.

    Returns the referenced object (following a chain transitively), or the node
    unchanged when it isn't a ``$ref``, points outside the document, is
    unresolvable, or would cycle. Never raises -- ref problems must not break
    describe/call; an unresolved external ref just shows/sends as-is.
    """
    if not isinstance(node, dict):
        return node
    ref = node.get("$ref")
    if not isinstance(ref, str) or not ref.startswith("#/") or ref in _seen:
        return node
    target: Any = spec
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")  # JSON-pointer unescape
        if isinstance(target, dict) and part in target:
            target = target[part]
        else:
            return node  # unresolvable pointer: leave the node as-is
    return _resolve_ref(spec, target, _seen | {ref})


def _merged_parameters(spec: dict, path_item: dict, op: dict) -> list[dict]:
    """Effective parameters for an operation: path-item-level + operation-level,
    each ``$ref``-resolved, keyed by (name, location) with operation-level
    overriding path-level (per the OpenAPI spec).
    """
    merged: dict[tuple, dict] = {}
    for source in (path_item.get("parameters") or [], op.get("parameters") or []):
        for raw in source:
            p = _resolve_ref(spec, raw)
            if isinstance(p, dict):
                merged[(p.get("name"), p.get("in"))] = p
    return list(merged.values())


def _op_list(spec_src: str, workdir: Path | None = None) -> str:
    spec = _load_spec(spec_src, workdir)
    rows: list[str] = []
    for method, path, op in _walk_ops(spec):
        op_id = op.get("operationId") or f"{method.lower()}_{path}"
        summary = (op.get("summary") or "").strip()
        rows.append(
            f"  {method:>6}  {path:<40}  {op_id}  — {summary[:60]}"
        )
    if not rows:
        return "no operations"
    return "\n".join(rows)


def _find_op(spec: dict, op_id: str) -> tuple[str, str, dict] | None:
    for method, path, op in _walk_ops(spec):
        # Match the id list_ops shows, including the synthetic one it prints
        # for an operation without an operationId.
        if (op.get("operationId") or f"{method.lower()}_{path}") == op_id:
            return method, path, op
    return None


def _op_describe(spec_src: str, op_id: str, workdir: Path | None = None) -> str:
    spec = _load_spec(spec_src, workdir)
    found = _find_op(spec, op_id)
    if not found:
        return f"op {op_id!r} not found"
    method, path, op = found
    path_item = (spec.get("paths") or {}).get(path) or {}
    lines = [f"{method} {path}",
             f"  summary: {op.get('summary', '')}"]
    for p in _merged_parameters(spec, path_item, op):
        loc = p.get("in", "?")
        name = p.get("name", "?")
        required = "*" if p.get("required") else ""
        schema = _resolve_ref(spec, p.get("schema") or {}).get("type", "?")
        lines.append(f"  param ({loc}): {name}{required} : {schema}")
    body = _resolve_ref(spec, op.get("requestBody") or {})
    if body:
        content = (body.get("content") or {}).get("application/json") or {}
        schema = _resolve_ref(spec, content.get("schema") or {})
        lines.append("  body (application/json): " + json.dumps(schema, default=str)[:400])
    return "\n".join(lines)


def _resolve_base(spec: dict, override: str) -> str:
    if override:
        return override.rstrip("/")
    servers = spec.get("servers") or []
    if servers and isinstance(servers[0], dict):
        return str(servers[0].get("url", "")).rstrip("/")
    return ""


def _safe_failure_detail(value: Any) -> str:
    """Secret-scrub and bound untrusted HTTP/spec failure detail."""
    try:
        raw = value if isinstance(value, str) else json.dumps(value, default=str)
        from ..safety.secret_detector import redact

        scrubbed, _ = redact(raw)
        return scrubbed[:500]
    except Exception:  # pragma: no cover -- error reporting must fail closed
        return "request failed (details unavailable)"


def _op_call(
    spec_src: str,
    op_id: str,
    params: dict | None,
    body: Any,
    headers: dict | None,
    base_url: str,
    workdir: Path | None = None,
) -> str:
    spec = _load_spec(spec_src, workdir)
    found = _find_op(spec, op_id)
    if not found:
        return f"op {op_id!r} not found"
    method, path, op = found
    params = params or {}
    # Substitute path params from `params`.
    used: set[str] = set()
    out_path = path
    path_item = (spec.get("paths") or {}).get(path) or {}
    for p in _merged_parameters(spec, path_item, op):
        if p.get("in") == "path":
            name = p.get("name", "")
            if name in params:
                out_path = out_path.replace("{" + name + "}", str(params[name]))
                used.add(name)
            elif p.get("required"):
                return f"ERROR: required path param {name!r} not provided"
    # Remaining params -> query.
    query = {k: v for k, v in params.items() if k not in used}
    base = _resolve_base(spec, base_url)
    url = (base or "") + out_path
    if not url.startswith(("http://", "https://")):
        return "ERROR: no base URL and op has no absolute servers[0]"
    req_kwargs = {
        "headers": headers or {},
        "params": query,
    }
    if body is not None and method in {"POST", "PUT", "PATCH"}:
        req_kwargs["json"] = body
    from ._ssrf import safe_client
    # Validate + pin the connection to the resolved public IP so a rebinding
    # resolver can't redirect the call to an internal/metadata address.
    with safe_client(url, timeout=60.0) as client:
        with client.stream(method, url, **req_kwargs) as r:
            status_code = r.status_code
            encoding = r.encoding
            buf = bytearray()
            for chunk in r.iter_bytes():
                buf += chunk
                # Read a little past the 3000-char display slice, then stop --
                # no point buffering an unbounded body we'll truncate anyway.
                if len(buf) >= _CALL_MAX_BYTES:
                    break
            raw = bytes(buf[:_CALL_MAX_BYTES])
    try:
        text = raw.decode(encoding or "utf-8", errors="replace")
    except (LookupError, UnicodeDecodeError):
        text = raw.decode("utf-8", errors="replace")
    if status_code >= 400:
        # A failed write is not a successful tool result. Prefixing ERROR lets
        # governed_actions mark the post-effect state INDETERMINATE instead of
        # committing a false success, and never returns an echoed credential.
        return f"ERROR: HTTP {status_code}: upstream request failed"
    truncated = text[:3000] + (" ... (truncated)" if len(text) > 3000 else "")
    return f"HTTP {status_code}\n{truncated}"


def _run(args: dict[str, Any], workdir: Path | None = None) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    spec_src = (args.get("spec") or "").strip()
    if not spec_src:
        return "ERROR: spec is required (URL or local path)"
    try:
        if op == "list_ops":
            return _op_list(spec_src, workdir)
        if op == "describe":
            op_id = (args.get("op_id") or "").strip()
            if not op_id:
                return "ERROR: describe requires op_id"
            return _op_describe(spec_src, op_id, workdir)
        if op == "call":
            try:
                import httpx  # noqa: F401
            except ImportError:
                return "ERROR: httpx not installed. Run: python -m pip install -e './packages/maverick-core[issue-trackers]'"
            op_id = (args.get("op_id") or "").strip()
            if not op_id:
                return "ERROR: call requires op_id"
            return _op_call(
                spec_src, op_id,
                args.get("params") if isinstance(args.get("params"), dict) else None,
                args.get("body"),
                args.get("headers") if isinstance(args.get("headers"), dict) else None,
                (args.get("base_url") or "").strip(),
                workdir,
            )
    except RuntimeError as e:
        return f"ERROR: {_safe_failure_detail(str(e))}"
    except Exception as e:
        from ._ssrf import BlockedHost
        if isinstance(e, BlockedHost):
            return (
                "ERROR: refusing to fetch (blocked host): "
                f"{_safe_failure_detail(str(e))}"
            )
        return f"ERROR: openapi request failed ({type(e).__name__[:120]})"
    return f"ERROR: unknown op {op!r}"


def openapi_runner(sandbox: Any = None) -> Tool:
    # Thread the sandbox workdir so local spec reads are confined to the
    # workspace (URL specs are unaffected). None -> falls back to cwd-confine.
    workdir = None
    wd = getattr(sandbox, "workdir", None)
    if wd is not None:
        workdir = Path(wd)

    def _fn(args: dict[str, Any]) -> str:
        return _run(args, workdir)

    return Tool(
        name="openapi_runner",
        description=(
            "Call any REST API by OpenAPI 3 spec. ops: list_ops "
            "(enumerate operationIds), describe (params + body "
            "schema for one op), call (issue the request, returns "
            "HTTP status + body). Auth tokens go in headers. "
            "Spec URL is cached for the process."
        ),
        input_schema=_OAS_SCHEMA,
        fn=_fn,
    )
