"""Governed Streamable-HTTP sidecar for external MCP clients.

The normal :mod:`maverick_mcp` server exposes Lightwork-owned tools.  This
module is deliberately a different boundary: it exposes an *operator-curated*
allow-list of upstream MCP tools to external clients such as Claude Desktop,
Cursor, Claude Code, and a vendor gateway.  It never discovers or forwards an
arbitrary upstream tool.  Every ``tools/call`` is rechecked immediately before
egress against the caller's trust entry, the current kill switch, a narrowed
capability, compiled policy, input Shield, an egress allow-list, and a durable
per-principal call budget.

The sidecar is a deployable Streamable HTTP request/response subset.  It serves
its own ``initialize`` and ``tools/list`` responses from the reviewed manifest,
and proxies only approved ``tools/call`` requests.  It intentionally does not
pretend that a static manifest proves an upstream's safety or availability.
Provider pilots and authorization-code OAuth callbacks remain deployment work;
the non-interactive runtime supports OAuth 2.1 client credentials through the
existing ``maverick.mcp_oauth`` implementation.

Config (all capability-changing settings are explicit)::

    [mcp_sidecar]
    enable = true
    upstream_url = "https://mcp.example.com/mcp"
    upstream_token_env = "UPSTREAM_MCP_TOKEN"  # optional
    require_shield = true
    max_calls_per_window = 1000
    budget_window_seconds = 3600

    [mcp_sidecar.tools.search]
    risk = "low"
    description = "Reviewed search endpoint"
    input_schema = { type = "object" }
    obligation_tags = ["inventory-reviewed"]

The configured upstream URL is not model-controlled.  Even so, it is pinned
to HTTPS (except loopback development) and checked again through Lightwork's
enterprise egress boundary before every network call.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

try:  # Optional HTTP extra; the pure sidecar boundary remains importable without it.
    from starlette.requests import Request as _HTTPRequest
except ImportError:  # pragma: no cover - exercised in package-minimal installs
    _HTTPRequest = Any

SIDECAR_SCHEMA = "lightwork.governed-mcp-sidecar.v1"
_BUDGET_SCHEMA = "lightwork.governed-mcp-sidecar-budget.v1"
_MAX_CONFIG_TOOLS = 512
_MAX_HEADERS = 32
_MAX_BODY_BYTES = 256 * 1024
_MAX_RESPONSE_BYTES = 1024 * 1024
_MAX_SCHEMA_BYTES = 64 * 1024
_MAX_DESCRIPTION_CHARS = 4_000
_MAX_OBLIGATION_TAGS = 64
_TOOL_RE = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
_ENV_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
_TAG_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}\Z")
_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host",
    "content-length", "authorization", "cookie", "mcp-session-id",
    "mcp-protocol-version",
})
_RISK_LEVELS = frozenset({"low", "medium", "high"})


class SidecarError(RuntimeError):
    """Base error safe to return from a sidecar boundary."""


class SidecarConfigError(SidecarError, ValueError):
    """The reviewed sidecar configuration is malformed or incomplete."""


class SidecarUpstreamError(SidecarError):
    """The upstream MCP server could not produce a bounded valid reply."""


@dataclass(frozen=True)
class SidecarTool:
    """One explicitly reviewed upstream tool binding.

    ``governed_action`` is derived, not supplied by the upstream or an external
    caller.  This prevents a manifest from laundering an arbitrary external
    tool through the name of a lower-risk local tool.
    """

    name: str
    risk: str = "high"
    description: str = ""
    input_schema: dict[str, Any] | None = None
    obligation_tags: tuple[str, ...] = ()

    @property
    def governed_action(self) -> str:
        return f"mcp_sidecar__{self.name}"

    @classmethod
    def from_config(cls, name: object, raw: object) -> SidecarTool:
        if not isinstance(name, str) or not _TOOL_RE.fullmatch(name) or "__" in name:
            raise SidecarConfigError(
                "mcp_sidecar tool names must match [A-Za-z0-9_.-], be <=128 "
                "characters, and not contain '__'"
            )
        if not isinstance(raw, Mapping):
            raise SidecarConfigError(f"mcp_sidecar.tools.{name} must be a table")
        allowed = {"risk", "description", "input_schema", "obligation_tags"}
        unknown = set(raw) - allowed
        if unknown:
            raise SidecarConfigError(
                f"mcp_sidecar.tools.{name} has unknown keys: "
                f"{', '.join(sorted(str(key) for key in unknown))}"
            )
        risk = str(raw.get("risk", "high")).strip().lower()
        if risk not in _RISK_LEVELS:
            raise SidecarConfigError(
                f"mcp_sidecar.tools.{name}.risk must be low, medium, or high"
            )
        description = str(raw.get("description") or "")
        if len(description) > _MAX_DESCRIPTION_CHARS:
            raise SidecarConfigError(
                f"mcp_sidecar.tools.{name}.description exceeds "
                f"{_MAX_DESCRIPTION_CHARS} characters"
            )
        schema = raw.get("input_schema")
        if schema is None:
            schema = {"type": "object", "properties": {}}
        if not isinstance(schema, dict):
            raise SidecarConfigError(
                f"mcp_sidecar.tools.{name}.input_schema must be an object"
            )
        try:
            encoded_schema = _canonical(schema)
        except SidecarError as exc:
            raise SidecarConfigError(
                f"mcp_sidecar.tools.{name}.input_schema must be JSON-compatible"
            ) from exc
        if len(encoded_schema) > _MAX_SCHEMA_BYTES:
            raise SidecarConfigError(
                f"mcp_sidecar.tools.{name}.input_schema exceeds "
                f"{_MAX_SCHEMA_BYTES} bytes"
            )
        raw_tags = raw.get("obligation_tags", [])
        if not isinstance(raw_tags, list) or len(raw_tags) > _MAX_OBLIGATION_TAGS:
            raise SidecarConfigError(
                f"mcp_sidecar.tools.{name}.obligation_tags must be a bounded list"
            )
        tags: list[str] = []
        for tag in raw_tags:
            if not isinstance(tag, str) or not _TAG_RE.fullmatch(tag):
                raise SidecarConfigError(
                    f"mcp_sidecar.tools.{name}.obligation_tags contains an invalid tag"
                )
            if tag not in tags:
                tags.append(tag)
        return cls(
            name=name,
            risk=risk,
            description=description,
            input_schema=dict(schema),
            obligation_tags=tuple(tags),
        )

    def tool_spec(self) -> dict[str, Any]:
        """The local, Shield-reviewed manifest advertised to the client."""

        return {
            "name": self.name,
            "description": self.description or "Reviewed governed MCP tool",
            "inputSchema": dict(self.input_schema or {}),
        }


@dataclass(frozen=True)
class SidecarConfig:
    """Validated configuration for one governed sidecar instance."""

    enable: bool = False
    upstream_url: str = ""
    upstream_token_env: str = ""
    oauth: dict[str, Any] | None = None
    upstream_headers: tuple[tuple[str, str], ...] = ()
    tools: tuple[SidecarTool, ...] = ()
    require_shield: bool = True
    max_body_bytes: int = _MAX_BODY_BYTES
    max_calls_per_window: int = 0
    budget_window_seconds: int = 3_600
    principal_max_calls: tuple[tuple[str, int], ...] = ()
    allowed_origins: tuple[str, ...] = ()
    listen_host: str = "127.0.0.1"
    listen_port: int = 8787

    @classmethod
    def from_mapping(cls, raw: object) -> SidecarConfig:  # noqa: C901 - strict boundary validation is intentionally linear
        if raw is None:
            raw = {}
        if not isinstance(raw, Mapping):
            raise SidecarConfigError("mcp_sidecar must be a table")
        allowed = {
            "enable", "upstream_url", "upstream_token_env", "oauth",
            "upstream_headers", "tools", "require_shield", "max_body_bytes",
            "max_calls_per_window", "budget_window_seconds",
            "principal_max_calls", "allowed_origins", "listen_host",
            "listen_port",
        }
        unknown = set(raw) - allowed
        if unknown:
            raise SidecarConfigError(
                "mcp_sidecar has unknown keys: "
                + ", ".join(sorted(str(key) for key in unknown))
            )
        enable = raw.get("enable", False)
        if not isinstance(enable, bool):
            raise SidecarConfigError("mcp_sidecar.enable must be a boolean")
        if not enable:
            return cls(enable=False)
        upstream_url = str(raw.get("upstream_url") or "").strip()
        _validate_upstream_url(upstream_url)
        token_env = str(raw.get("upstream_token_env") or "").strip()
        if token_env and not _ENV_RE.fullmatch(token_env):
            raise SidecarConfigError(
                "mcp_sidecar.upstream_token_env must be an environment variable name"
            )
        oauth = raw.get("oauth")
        if oauth is not None and not isinstance(oauth, Mapping):
            raise SidecarConfigError("mcp_sidecar.oauth must be a table")
        if token_env and oauth:
            raise SidecarConfigError(
                "configure upstream_token_env or oauth, not both"
            )
        if oauth:
            _validate_sidecar_oauth(dict(oauth))
        headers_raw = raw.get("upstream_headers", {})
        if not isinstance(headers_raw, Mapping) or len(headers_raw) > _MAX_HEADERS:
            raise SidecarConfigError(
                "mcp_sidecar.upstream_headers must be a bounded string table"
            )
        headers: list[tuple[str, str]] = []
        for key, value in headers_raw.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise SidecarConfigError(
                    "mcp_sidecar.upstream_headers must be a string table"
                )
            norm = key.strip().lower()
            if not norm or norm in _HOP_BY_HOP or "\r" in key or "\n" in key:
                raise SidecarConfigError(
                    "mcp_sidecar.upstream_headers cannot override authentication, "
                    "MCP transport, or hop-by-hop headers"
                )
            if "\r" in value or "\n" in value or len(value) > 4_096:
                raise SidecarConfigError("mcp_sidecar upstream header is invalid")
            headers.append((key.strip(), value))
        tools_raw = raw.get("tools", {})
        if not isinstance(tools_raw, Mapping) or not tools_raw:
            raise SidecarConfigError(
                "mcp_sidecar.tools must be a non-empty reviewed tool table"
            )
        if len(tools_raw) > _MAX_CONFIG_TOOLS:
            raise SidecarConfigError(
                f"mcp_sidecar.tools may contain at most {_MAX_CONFIG_TOOLS} entries"
            )
        tools = tuple(
            SidecarTool.from_config(name, entry)
            for name, entry in sorted(tools_raw.items(), key=lambda item: str(item[0]))
        )
        require_shield = raw.get("require_shield", True)
        if not isinstance(require_shield, bool):
            raise SidecarConfigError("mcp_sidecar.require_shield must be a boolean")
        max_body = _bounded_int(
            raw.get("max_body_bytes", _MAX_BODY_BYTES),
            "mcp_sidecar.max_body_bytes", 4_096, _MAX_BODY_BYTES,
        )
        max_calls = _bounded_int(
            raw.get("max_calls_per_window", 0),
            "mcp_sidecar.max_calls_per_window", 0, 1_000_000,
        )
        window = _bounded_int(
            raw.get("budget_window_seconds", 3_600),
            "mcp_sidecar.budget_window_seconds", 60, 31_622_400,
        )
        principal_raw = raw.get("principal_max_calls", {})
        if not isinstance(principal_raw, Mapping) or len(principal_raw) > _MAX_CONFIG_TOOLS:
            raise SidecarConfigError(
                "mcp_sidecar.principal_max_calls must be a bounded integer table"
            )
        principal_max: list[tuple[str, int]] = []
        for principal, limit in sorted(principal_raw.items(), key=lambda item: str(item[0])):
            if not isinstance(principal, str) or not principal or len(principal) > 512:
                raise SidecarConfigError("mcp_sidecar principal budget key is invalid")
            principal_max.append((
                principal,
                _bounded_int(
                    limit,
                    f"mcp_sidecar.principal_max_calls.{principal}",
                    0,
                    1_000_000,
                ),
            ))
        origins_raw = raw.get("allowed_origins", [])
        if not isinstance(origins_raw, list) or len(origins_raw) > _MAX_HEADERS:
            raise SidecarConfigError("mcp_sidecar.allowed_origins must be a bounded list")
        origins: list[str] = []
        for origin in origins_raw:
            normalized = _validated_origin(origin)
            if normalized not in origins:
                origins.append(normalized)
        host = str(raw.get("listen_host", "127.0.0.1")).strip()
        if not host or len(host) > 255 or any(ch in host for ch in "\r\n/\\"):
            raise SidecarConfigError("mcp_sidecar.listen_host is invalid")
        port = _bounded_int(
            raw.get("listen_port", 8787),
            "mcp_sidecar.listen_port", 1, 65_535,
        )
        return cls(
            enable=True,
            upstream_url=upstream_url,
            upstream_token_env=token_env,
            oauth=dict(oauth) if oauth else None,
            upstream_headers=tuple(headers),
            tools=tools,
            require_shield=require_shield,
            max_body_bytes=max_body,
            max_calls_per_window=max_calls,
            budget_window_seconds=window,
            principal_max_calls=tuple(principal_max),
            allowed_origins=tuple(origins),
            listen_host=host,
            listen_port=port,
        )

    @property
    def tools_by_name(self) -> dict[str, SidecarTool]:
        return {tool.name: tool for tool in self.tools}

    def max_calls_for(self, principal: str) -> int:
        overrides = dict(self.principal_max_calls)
        return int(overrides.get(principal, self.max_calls_per_window))


@dataclass(frozen=True)
class GateDecision:
    """A normalized decision from an injected or production enforcement gate."""

    allowed: bool
    rule: str
    reason: str
    capability: Any | None = None
    requires_human: bool = False
    profiles: tuple[str, ...] | None = ()


@dataclass(frozen=True)
class BudgetDecision:
    allowed: bool
    rule: str
    reason: str
    remaining: int | None = None


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise SidecarError("sidecar payload must be finite JSON-compatible data") from exc


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _bounded_int(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise SidecarConfigError(f"{label} must be an integer between {minimum} and {maximum}")
    return int(value)


def _loopback_host(host: str | None) -> bool:
    return (host or "").lower() in {"localhost", "127.0.0.1", "::1"}


def _validate_upstream_url(value: str) -> None:
    if not value or len(value) > 2_048 or "\r" in value or "\n" in value:
        raise SidecarConfigError("mcp_sidecar.upstream_url is invalid")
    parsed = urlparse(value)
    if not parsed.netloc or parsed.scheme not in {"https", "http"}:
        raise SidecarConfigError("mcp_sidecar.upstream_url must be an http(s) URL")
    if parsed.username or parsed.password or parsed.fragment:
        raise SidecarConfigError(
            "mcp_sidecar.upstream_url must not contain credentials or a fragment"
        )
    if parsed.scheme != "https" and not _loopback_host(parsed.hostname):
        raise SidecarConfigError(
            "mcp_sidecar.upstream_url must use https outside loopback development"
        )


def _validate_sidecar_oauth(raw: dict[str, Any]) -> None:
    from maverick.mcp_oauth import OAuthConfig

    try:
        cfg = OAuthConfig.from_dict(raw)
    except (TypeError, ValueError) as exc:
        raise SidecarConfigError("mcp_sidecar.oauth is invalid") from exc
    if cfg.grant_type != "client_credentials":
        raise SidecarConfigError(
            "the non-interactive sidecar supports OAuth client_credentials; "
            "complete authorization-code PKCE through the managed MCP client first"
        )


def _validated_origin(value: object) -> str:
    if not isinstance(value, str) or len(value) > 1_024:
        raise SidecarConfigError("mcp_sidecar allowed origin is invalid")
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise SidecarConfigError("mcp_sidecar allowed origin must be an http(s) origin")
    if parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
        raise SidecarConfigError("mcp_sidecar allowed origin must not include a path")
    return f"{parsed.scheme}://{parsed.netloc}"


def _origin_allowed(origin: str | None, config: SidecarConfig) -> bool:
    if not origin:
        return True
    try:
        normalized = _validated_origin(origin)
    except SidecarConfigError:
        return False
    parsed = urlparse(normalized)
    return _loopback_host(parsed.hostname) or normalized in set(config.allowed_origins)


class SidecarCallBudget:
    """Durable fixed-window call budget, keyed by a principal digest.

    This is intentionally independent of :class:`maverick.budget.Budget`:
    MCP calls have no reliable model-token price, and charging them through the
    LLM accounting path would make a request-count ceiling look like money.
    Reservation happens *before* egress and is deliberately not refunded on an
    ambiguous network error, so retries cannot evade the configured ceiling.
    """

    def __init__(
        self,
        config: SidecarConfig,
        *,
        path: Path | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._config = config
        self._path = path
        self._clock = clock or time.time

    def _state_path(self) -> Path:
        if self._path is not None:
            return self._path
        from maverick.paths import data_dir

        return data_dir("mcp_sidecar", "call_budget.json")

    def reserve(self, principal: str) -> BudgetDecision:
        limit = self._config.max_calls_for(principal)
        if limit <= 0:
            return BudgetDecision(True, "budget_disabled", "no call budget configured")
        now = float(self._clock())
        if not now > 0:
            return BudgetDecision(False, "budget_authority", "call budget clock is unavailable")
        path = self._state_path()
        try:
            from maverick.file_lock import (
                atomic_read_text,
                atomic_write_text,
                cross_process_lock,
                ensure_private_directory,
                ensure_private_file,
            )

            ensure_private_directory(path.parent)
            with cross_process_lock(path, strict=True):
                state: dict[str, Any] = {"schema": _BUDGET_SCHEMA, "rows": {}}
                if path.exists():
                    ensure_private_file(path)
                    raw = atomic_read_text(path)
                    if len(raw.encode("utf-8")) > _MAX_RESPONSE_BYTES:
                        raise ValueError("budget ledger exceeds its byte bound")
                    state = json.loads(raw)
                if (
                    not isinstance(state, dict)
                    or state.get("schema") != _BUDGET_SCHEMA
                    or not isinstance(state.get("rows"), dict)
                ):
                    raise ValueError("budget ledger is malformed")
                key = _sha256(principal.encode("utf-8"))
                rows = state["rows"]
                row = rows.get(key, {})
                if not isinstance(row, dict):
                    raise ValueError("budget ledger row is malformed")
                started = row.get("window_started")
                count = row.get("count")
                if (
                    isinstance(started, bool)
                    or not isinstance(started, (int, float))
                    or isinstance(count, bool)
                    or not isinstance(count, int)
                    or count < 0
                    or now - float(started) >= self._config.budget_window_seconds
                    or now < float(started)
                ):
                    started, count = now, 0
                if count >= limit:
                    return BudgetDecision(
                        False,
                        "budget_exhausted",
                        "the governed MCP call budget is exhausted for this principal",
                        remaining=0,
                    )
                count += 1
                rows[key] = {"window_started": float(started), "count": count}
                atomic_write_text(
                    path,
                    json.dumps(state, sort_keys=True, separators=(",", ":")),
                    mode=0o600,
                )
                return BudgetDecision(
                    True,
                    "budget_reserved",
                    "call budget reserved",
                    remaining=max(0, limit - count),
                )
        except Exception:
            return BudgetDecision(
                False,
                "budget_authority",
                "call budget authority is unavailable; egress is denied",
            )


class HttpMCPUpstream:
    """A deliberately small, no-redirect Streamable HTTP MCP caller."""

    def __init__(self, config: SidecarConfig, *, client: Any | None = None) -> None:
        self._config = config
        self._client = client
        self._oauth_provider: Any | None = None

    def _authorization(self) -> str | None:
        if self._config.oauth:
            if self._oauth_provider is None:
                from maverick.mcp_oauth import OAuthConfig, OAuthTokenProvider

                self._oauth_provider = OAuthTokenProvider(
                    OAuthConfig.from_dict(self._config.oauth)
                )
            return f"Bearer {self._oauth_provider.token()}"
        if self._config.upstream_token_env:
            token = os.environ.get(self._config.upstream_token_env, "")
            if not token:
                raise SidecarUpstreamError("upstream credential is unavailable")
            return f"Bearer {token}"
        return None

    def call(self, tool: SidecarTool, arguments: Mapping[str, Any], request_id: Any) -> dict[str, Any]:
        """Call the exact reviewed upstream tool and validate the RPC envelope."""

        try:
            from maverick.enterprise import enterprise_egress_denial

            denied = enterprise_egress_denial(
                self._config.upstream_url, tool=tool.governed_action
            )
        except Exception as exc:
            raise SidecarUpstreamError("egress authority is unavailable") from exc
        if denied:
            raise SidecarUpstreamError("upstream MCP egress is denied by policy")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": "lightwork-governed-mcp-sidecar/1",
            **dict(self._config.upstream_headers),
        }
        authorization = self._authorization()
        if authorization:
            headers["Authorization"] = authorization
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": tool.name, "arguments": dict(arguments)},
        }
        try:
            if self._client is None:
                import httpx

                with httpx.stream(
                    "POST", self._config.upstream_url,
                    json=payload,
                    headers=headers,
                    timeout=30.0,
                    follow_redirects=False,
                ) as response:
                    return self._read_response(response, request_id)
            else:
                response = self._client.post(
                    self._config.upstream_url,
                    json=payload,
                    headers=headers,
                    timeout=30.0,
                    follow_redirects=False,
                )
        except SidecarUpstreamError:
            raise
        except Exception as exc:
            raise SidecarUpstreamError("upstream MCP request failed") from exc
        return self._read_response(response, request_id)

    @staticmethod
    def _read_response(response: Any, request_id: Any) -> dict[str, Any]:
        """Read one bounded response; never retry a possibly completed call."""
        if not 200 <= int(getattr(response, "status_code", 502)) < 300:
            raise SidecarUpstreamError("upstream MCP returned an HTTP error")
        headers = getattr(response, "headers", {})
        is_sse = headers.get("content-type", "").split(";", 1)[0].strip().lower() == "text/event-stream"
        chunks = (response.iter_bytes(chunk_size=65536) if hasattr(response, "iter_bytes")
                  else [getattr(response, "content", b"") or b""])
        raw = bytearray()
        if is_sse:
            return _read_sse_response(chunks, request_id)
        for chunk in chunks:
            if not isinstance(chunk, (bytes, bytearray)) or len(raw) + len(chunk) > _MAX_RESPONSE_BYTES:
                raise SidecarUpstreamError("upstream MCP response exceeds the byte cap")
            raw.extend(chunk)
        try:
            message = json.loads(bytes(raw).decode("utf-8"))
        except (UnicodeError, ValueError) as exc:
            raise SidecarUpstreamError("upstream MCP returned invalid JSON") from exc
        return _validated_upstream_response(message, request_id)


def _validated_upstream_response(message: Any, request_id: Any) -> dict[str, Any]:
    if (not isinstance(message, dict) or message.get("jsonrpc") != "2.0"
            or type(message.get("id")) is not type(request_id) or message.get("id") != request_id
            or ("result" in message) == ("error" in message)):
        raise SidecarUpstreamError("upstream MCP response envelope is invalid")
    return message


def _read_sse_response(chunks, request_id: Any) -> dict[str, Any]:
    """Decode SSE incrementally through the matching final JSON-RPC frame."""
    import codecs
    from itertools import chain

    decoder = codecs.getincrementaldecoder("utf-8")()
    pending, data, total = "", [], 0
    try:
        for chunk in chain(chunks, [None]):
            finished = chunk is None
            if finished:
                pending += decoder.decode(b"", final=True)
            else:
                if not isinstance(chunk, (bytes, bytearray)) or total + len(chunk) > _MAX_RESPONSE_BYTES:
                    raise SidecarUpstreamError("upstream MCP response exceeds the byte cap")
                total += len(chunk)
                pending += decoder.decode(chunk)
            while True:
                boundary = re.search(r"\r\n|\r|\n", pending)
                if boundary is None or (not finished and boundary.group() == "\r" and boundary.end() == len(pending)):
                    break  # A split CRLF must remain one line ending.
                line, pending = pending[:boundary.start()], pending[boundary.end():]
                if line:
                    if line.startswith("data:"):
                        value = line[5:]
                        data.append(value.removeprefix(" "))
                    continue
                if not data:
                    continue
                message = json.loads("\n".join(data))
                data = []
                if (isinstance(message, dict) and message.get("jsonrpc") == "2.0"
                        and "id" not in message and isinstance(message.get("method"), str)):
                    continue  # Progress notifications are not the call result.
                return _validated_upstream_response(message, request_id)
    except (UnicodeError, ValueError) as exc:
        raise SidecarUpstreamError("upstream MCP returned invalid SSE") from exc
    raise SidecarUpstreamError("upstream MCP stream ended without a complete matching response")


class GovernedMCPGateway:
    """The decision chain that fronts a reviewed upstream MCP manifest.

    Injection points make the security boundary fully testable without a
    running IdP, Shield, audit signer, or upstream server.  Production defaults
    call the corresponding Lightwork authorities and fail closed when one is
    unavailable.
    """

    def __init__(
        self,
        config: SidecarConfig,
        *,
        upstream: Any | None = None,
        trust_decider: Callable[[str, str, str], GateDecision] | None = None,
        policy_decider: Callable[[str, str, Any], GateDecision] | None = None,
        halt_checker: Callable[[], None] | None = None,
        egress_checker: Callable[[str, str], None] | None = None,
        shield_factory: Callable[[], Any | None] | None = None,
        budget: Any | None = None,
        auditor: Callable[..., bool] | None = None,
        token_resolver: Callable[[str], str | None] | None = None,
    ) -> None:
        if not isinstance(config, SidecarConfig):
            raise TypeError("config must be a SidecarConfig")
        self.config = config
        self._tools = config.tools_by_name
        self._upstream = upstream or HttpMCPUpstream(config)
        self._trust_decider = trust_decider or _default_trust_decider
        self._policy_decider = policy_decider or _default_policy_decider
        self._halt_checker = halt_checker or _default_halt_checker
        self._egress_checker = egress_checker or _default_egress_checker
        self._shield_factory = shield_factory or _default_shield_factory
        self._budget = budget or SidecarCallBudget(config)
        self._auditor = auditor or _default_auditor
        self._token_resolver = token_resolver or _default_token_resolver

    def authenticate(self, bearer: str) -> str | None:
        """Resolve a sidecar client only through its active per-agent MCP key."""

        try:
            return self._token_resolver(str(bearer or ""))
        except Exception:
            return None

    def handle_rpc(self, principal: str, request: object) -> dict[str, Any] | None:  # noqa: C901 - JSON-RPC boundary stays linear and auditable
        """Process one client JSON-RPC message without exposing raw bodies to logs."""

        if not self.config.enable:
            return _rpc_error(_request_id(request), -32000, "governed MCP sidecar is disabled", "disabled")
        if not isinstance(principal, str) or not principal or len(principal) > 512:
            return _rpc_error(_request_id(request), -32600, "sidecar principal is invalid", "principal")
        if not isinstance(request, Mapping) or request.get("jsonrpc") != "2.0":
            return _rpc_error(_request_id(request), -32600, "invalid JSON-RPC request", "request")
        request_id = _request_id(request)
        method = request.get("method")
        if not isinstance(method, str):
            return _rpc_error(request_id, -32600, "JSON-RPC method is invalid", "method")
        params = request.get("params", {})
        if params is None:
            params = {}
        if not isinstance(params, Mapping):
            return _rpc_error(request_id, -32602, "JSON-RPC params must be an object", "params")
        if method == "initialize":
            return _rpc_result(request_id, {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "lightwork-governed-mcp-sidecar", "version": "0.1.0"},
            })
        if method == "notifications/initialized":
            return None
        if method == "tools/list":
            return _rpc_result(request_id, {"tools": [tool.tool_spec() for tool in self.config.tools]})
        if method != "tools/call":
            return _rpc_error(request_id, -32601, "MCP method is not implemented by this sidecar", "method")
        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(tool_name, str) or not _TOOL_RE.fullmatch(tool_name):
            return _rpc_error(request_id, -32602, "tool name is invalid", "tool_name")
        tool = self._tools.get(tool_name)
        if tool is None:
            self._audit_denial(principal, tool_name, "unbound_tool", "tool is not in the reviewed sidecar manifest")
            return _rpc_error(request_id, -32001, "tool is not in the reviewed sidecar manifest", "unbound_tool")
        if not isinstance(arguments, Mapping):
            return _rpc_error(request_id, -32602, "tool arguments must be an object", "arguments")
        try:
            arg_bytes = _canonical(dict(arguments))
        except SidecarError:
            return _rpc_error(request_id, -32602, "tool arguments must be JSON-compatible", "arguments")
        if len(arg_bytes) > self.config.max_body_bytes:
            return _rpc_error(request_id, -32602, "tool arguments exceed the sidecar byte cap", "arguments_size")
        arg_digest = _sha256(arg_bytes)
        admission = self._authorize(principal, tool, arg_bytes, arg_digest)
        if not admission.allowed:
            return _rpc_error(request_id, -32010, admission.reason, admission.rule)
        try:
            reservation = self._budget.reserve(principal)
        except Exception:
            reservation = BudgetDecision(False, "budget_authority", "call budget authority is unavailable; egress is denied")
        if not isinstance(reservation, BudgetDecision) or not reservation.allowed:
            rule = reservation.rule if isinstance(reservation, BudgetDecision) else "budget_authority"
            reason = reservation.reason if isinstance(reservation, BudgetDecision) else "call budget authority is unavailable; egress is denied"
            self._audit_denial(principal, tool.governed_action, rule, reason, arg_digest=arg_digest)
            return _rpc_error(request_id, -32010, reason, rule)
        # Re-run every live authority as close as possible to egress.  The
        # durable budget reservation is intentionally conservative if a later
        # recheck blocks or the upstream result is ambiguous.
        admission = self._authorize(principal, tool, arg_bytes, arg_digest)
        if not admission.allowed:
            return _rpc_error(request_id, -32010, admission.reason, admission.rule)
        try:
            tags = _obligation_tags(
                tool, admission, tool.governed_action, tool.risk
            )
            written = self._audit(
                "screened",
                principal=principal,
                tool=tool,
                allowed=True,
                rule="allow",
                reason="sidecar admission passed",
                arg_digest=arg_digest,
                tags=tags,
                budget_remaining=reservation.remaining,
            )
            if written is not True:
                return _rpc_error(
                    request_id,
                    -32010,
                    "admission evidence could not be recorded; upstream was not called",
                    "audit_unavailable",
                )
        except Exception:
            return _rpc_error(
                request_id,
                -32010,
                "admission evidence authority is unavailable; upstream was not called",
                "audit_unavailable",
            )
        try:
            upstream_message = self._upstream.call(tool, dict(arguments), request_id)
        except SidecarUpstreamError as exc:
            self._audit_terminal(principal, tool, "failed", arg_digest, str(exc))
            return _rpc_error(request_id, -32020, str(exc), "upstream")
        except Exception:
            self._audit_terminal(principal, tool, "failed", arg_digest, "upstream MCP request failed")
            return _rpc_error(request_id, -32020, "upstream MCP request failed", "upstream")
        if not isinstance(upstream_message, Mapping):
            self._audit_terminal(principal, tool, "failed", arg_digest, "upstream MCP response is invalid")
            return _rpc_error(request_id, -32020, "upstream MCP response is invalid", "upstream")
        response_decision = self._screen_upstream_reply(upstream_message)
        if response_decision is not None:
            self._audit_terminal(principal, tool, "blocked_response", arg_digest, response_decision.reason)
            return _rpc_error(request_id, -32021, response_decision.reason, response_decision.rule)
        try:
            written = self._audit_terminal(principal, tool, "executed", arg_digest, "upstream response returned")
        except Exception:
            written = False
        if written is not True:
            return _rpc_error(
                request_id,
                -32022,
                "upstream may have completed but terminal evidence could not be recorded",
                "terminal_audit_unavailable",
            )
        # Preserve the upstream's MCP result/error while binding it to the
        # caller's original JSON-RPC id.  No upstream metadata is trusted for
        # sidecar policy, logging, identity, or follow-on egress.
        if "result" in upstream_message:
            return _rpc_result(request_id, upstream_message["result"])
        return _rpc_error(request_id, -32020, "upstream MCP tool returned an error", "upstream_tool")

    def _authorize(
        self, principal: str, tool: SidecarTool, arg_bytes: bytes, arg_digest: str,
    ) -> GateDecision:
        try:
            self._halt_checker()
        except Exception:
            decision = GateDecision(False, "halted", "kill-switch authority is active or unavailable")
            self._audit_denial(principal, tool.governed_action, decision.rule, decision.reason, arg_digest=arg_digest)
            return decision
        try:
            trust = self._trust_decider(principal, tool.governed_action, tool.risk)
        except Exception:
            trust = GateDecision(False, "trust_authority", "trust authority is unavailable; egress is denied")
        if not isinstance(trust, GateDecision) or not trust.allowed:
            decision = trust if isinstance(trust, GateDecision) else GateDecision(
                False, "trust_authority", "trust authority is unavailable; egress is denied"
            )
            self._audit_denial(principal, tool.governed_action, decision.rule, decision.reason, arg_digest=arg_digest)
            return decision
        try:
            policy = self._policy_decider(tool.governed_action, tool.risk, trust.capability)
        except Exception:
            policy = GateDecision(False, "policy_authority", "compiled policy authority is unavailable; egress is denied")
        if not isinstance(policy, GateDecision) or not policy.allowed:
            decision = policy if isinstance(policy, GateDecision) else GateDecision(
                False, "policy_authority", "compiled policy authority is unavailable; egress is denied"
            )
            rule = "human_approval_required" if decision.requires_human else decision.rule
            self._audit_denial(principal, tool.governed_action, rule, decision.reason, arg_digest=arg_digest)
            return GateDecision(False, rule, decision.reason, capability=trust.capability, profiles=decision.profiles)
        scanned = self._scan_payload(arg_bytes)
        if scanned is not None:
            self._audit_denial(principal, tool.governed_action, scanned.rule, scanned.reason, arg_digest=arg_digest)
            return scanned
        try:
            self._egress_checker(self.config.upstream_url, tool.governed_action)
        except Exception:
            decision = GateDecision(False, "egress_denied", "upstream MCP egress is denied or unavailable")
            self._audit_denial(principal, tool.governed_action, decision.rule, decision.reason, arg_digest=arg_digest)
            return decision
        return GateDecision(
            True,
            "allow",
            "sidecar admission passed",
            capability=trust.capability,
            profiles=policy.profiles,
        )

    def _scan_payload(self, payload: bytes) -> GateDecision | None:
        try:
            text = payload.decode("utf-8")
            from maverick.memory_guard import injection_markers
            from maverick.safety.secret_detector import redact

            redacted, _matches = redact(text)
            if redacted != text:
                return GateDecision(False, "secret_detected", "tool payload contains a secret-shaped value")
            if injection_markers(text):
                return GateDecision(False, "injection", "tool payload was blocked by the injection screen")
        except Exception:
            return GateDecision(False, "screen_authority", "input screening authority is unavailable")
        try:
            shield = self._shield_factory()
        except Exception:
            shield = None
            if self.config.require_shield:
                return GateDecision(False, "shield_unavailable", "Shield is unavailable; egress is denied")
        if shield is None:
            if self.config.require_shield:
                return GateDecision(False, "shield_unavailable", "Shield is unavailable; egress is denied")
            return None
        try:
            verdict = shield.scan_input(text)
            if bool(getattr(verdict, "blocked", False)) or getattr(verdict, "allowed", True) is False:
                return GateDecision(False, "shield", "tool payload was blocked by Shield")
        except Exception:
            return GateDecision(False, "shield_unavailable", "Shield is unavailable; egress is denied")
        return None

    def _screen_upstream_reply(self, payload: Mapping[str, Any]) -> GateDecision | None:
        try:
            raw = _canonical(dict(payload))
        except SidecarError:
            return GateDecision(False, "upstream_response", "upstream MCP response is invalid")
        if len(raw) > _MAX_RESPONSE_BYTES:
            return GateDecision(False, "upstream_response", "upstream MCP response exceeds the byte cap")
        # The response is untrusted tool output.  It is not written to the audit
        # row and must not be used as sidecar control data.  Scan it before it
        # returns to a client that may put it in a model context.
        return self._scan_payload(raw)

    def _audit_denial(
        self, principal: str, action: str, rule: str, reason: str, *, arg_digest: str = "",
    ) -> None:
        try:
            tool = self._tools.get(action.removeprefix("mcp_sidecar__"))
            self._audit(
                "screened",
                principal=principal,
                tool=tool,
                allowed=False,
                rule=rule,
                reason=reason,
                arg_digest=arg_digest,
                tags={},
                budget_remaining=None,
            )
        except Exception:
            # A failed denial record cannot make a denied request execute.
            pass

    def _audit_terminal(
        self, principal: str, tool: SidecarTool, outcome: str, arg_digest: str, detail: str,
    ) -> bool:
        return self._audit(
            "terminal",
            principal=principal,
            tool=tool,
            allowed=outcome == "executed",
            rule=outcome,
            reason=detail,
            arg_digest=arg_digest,
            tags={},
            budget_remaining=None,
        )

    def _audit(
        self,
        phase: str,
        *,
        principal: str,
        tool: SidecarTool | None,
        allowed: bool,
        rule: str,
        reason: str,
        arg_digest: str,
        tags: Mapping[str, Any],
        budget_remaining: int | None,
    ) -> bool:
        action = tool.governed_action if tool is not None else "mcp_sidecar__unbound"
        payload = {
            "external_agent": principal,
            "tool": action,
            "upstream_tool": tool.name if tool is not None else "",
            "allowed": bool(allowed),
            "rule": str(rule)[:128],
            "reason": str(reason)[:512],
            "request_sha256": arg_digest,
            "sidecar_schema": SIDECAR_SCHEMA,
        }
        if budget_remaining is not None:
            payload["budget_remaining"] = int(budget_remaining)
        payload.update(dict(tags))
        return bool(self._auditor(phase, **payload))


def _default_token_resolver(bearer: str) -> str | None:
    from maverick.agent_trust import agent_for_token

    agent = agent_for_token(bearer, "mcp")
    return agent.id if agent is not None else None


def _default_halt_checker() -> None:
    from maverick.killswitch import check

    check(force_refresh=True, fail_closed=True)


def _default_trust_decider(principal: str, action: str, risk: str) -> GateDecision:
    from maverick.agent_trust import decide_inbound

    decision = decide_inbound(
        principal,
        requested_tools=[action],
        max_risk=risk,
        enforced=True,
    )
    return GateDecision(
        allowed=bool(decision.allowed),
        rule=str(decision.rule),
        reason=str(decision.reason),
        capability=decision.capability,
    )


def _default_policy_decider(action: str, risk: str, capability: Any) -> GateDecision:
    # Resolve policy and compiler once in this decision.  Applying the exact
    # compiled deny-set to the trust capability is the attenuation leg: a
    # compliance profile can only remove authority, never broaden it.
    from maverick.governance import Policy, evaluate
    from maverick.regulatory_compiler import compile_obligations

    policy = Policy.from_config()
    profiles = tuple(policy.compliance_profiles)
    compiled = compile_obligations(profiles)
    attenuated = capability
    if capability is not None and compiled.deny_tools:
        attenuated = capability.attenuate(deny=compiled.deny_tools)
    verdict = evaluate(action, risk=risk, capability=attenuated, policy=policy)
    return GateDecision(
        allowed=bool(verdict.allowed),
        rule=str(verdict.rule),
        reason=str(verdict.reason),
        capability=attenuated,
        requires_human=bool(verdict.needs_human),
        profiles=profiles,
    )


def _default_egress_checker(url: str, action: str) -> None:
    parsed = urlparse(url)
    if not parsed.hostname:
        raise SidecarError("upstream MCP egress is denied or unavailable")
    from maverick.enterprise import enterprise_egress_denial

    denied = enterprise_egress_denial(url, tool=action)
    if denied:
        raise SidecarError("upstream MCP egress is denied or unavailable")


def _default_shield_factory() -> Any | None:
    try:
        from maverick_shield import Shield

        return Shield.from_config()
    except ImportError:
        return None


def _default_auditor(phase: str, **payload: Any) -> bool:
    from maverick.audit import EventKind, audit_event

    if phase == "terminal":
        return audit_event(
            EventKind.EXTERNAL_ACTION_EXECUTED,
            agent="mcp_sidecar",
            connector="mcp_sidecar",
            op="call",
            outcome=payload.pop("rule", "failed"),
            **payload,
        )
    return audit_event(EventKind.EXTERNAL_ACTION_SCREENED, agent="mcp_sidecar", **payload)


def _obligation_tags(
    tool: SidecarTool, decision: GateDecision, action: str, risk: str,
) -> dict[str, Any]:
    """Return only exact-profile compiler evidence; never relabel a decision."""

    tags: dict[str, Any] = {}
    if tool.obligation_tags:
        tags["declared_obligation_tags"] = list(tool.obligation_tags)
    if decision.profiles is None:
        tags["obligation_evidence_error"] = "policy profile provenance is unavailable"
        return tags
    try:
        from maverick.regulatory_compiler import compile_obligations

        compiled = compile_obligations(decision.profiles)
        checked = sorted({
            obligation.id
            for obligation in compiled.obligations
            if obligation.covers(action, risk)
        })
        if checked:
            tags["obligations_checked"] = checked
        tags["compliance_profiles"] = list(decision.profiles)
    except Exception:
        tags["obligation_evidence_error"] = "compiled obligation evidence is unavailable"
    return tags


def _request_id(value: object) -> Any:
    if isinstance(value, Mapping):
        request_id = value.get("id")
        if request_id is None or isinstance(request_id, (str, int, float)) and not isinstance(request_id, bool):
            return request_id
    return None


def _rpc_result(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _rpc_error(request_id: Any, code: int, message: str, rule: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": int(code), "message": str(message), "data": {"rule": str(rule)}},
    }


def config_from_current() -> SidecarConfig:
    """Load the explicit sidecar knob from the normal Lightwork config."""

    try:
        from maverick.config import config_source_errors, load_config

        raw = load_config()
        if config_source_errors():
            raise SidecarConfigError("sidecar policy source is unavailable")
    except SidecarConfigError:
        raise
    except Exception as exc:
        raise SidecarConfigError("sidecar policy source is unavailable") from exc
    return SidecarConfig.from_mapping((raw or {}).get("mcp_sidecar", {}))


def build_gateway_from_config(*, upstream: Any | None = None) -> GovernedMCPGateway:
    config = config_from_current()
    if not config.enable:
        raise SidecarConfigError("mcp_sidecar is disabled; set [mcp_sidecar] enable = true")
    return GovernedMCPGateway(config, upstream=upstream)


def build_app(gateway: GovernedMCPGateway):
    """Build the authenticated Streamable HTTP app for a gateway instance."""

    try:
        from fastapi import FastAPI, Response
        from fastapi.responses import JSONResponse
    except ImportError as exc:  # pragma: no cover - installation diagnostic
        raise RuntimeError(
            "governed MCP sidecar requires maverick-mcp-server[http]"
        ) from exc
    if not isinstance(gateway, GovernedMCPGateway):
        raise TypeError("gateway must be a GovernedMCPGateway")
    app = FastAPI(title="Lightwork governed MCP sidecar", version="0.1.0")

    @app.post("/mcp")
    async def mcp(request: _HTTPRequest):
        if not _origin_allowed(request.headers.get("origin"), gateway.config):
            return JSONResponse(_rpc_error(None, -32000, "cross-origin request denied", "origin"), status_code=403)
        authorization = request.headers.get("authorization", "")
        prefix = "Bearer "
        if not authorization.startswith(prefix):
            return JSONResponse(_rpc_error(None, -32000, "sidecar bearer required", "authentication"), status_code=401)
        principal = gateway.authenticate(authorization[len(prefix):].strip())
        if principal is None:
            return JSONResponse(_rpc_error(None, -32000, "sidecar bearer denied", "authentication"), status_code=401)
        body = await request.body()
        if len(body) > gateway.config.max_body_bytes:
            return JSONResponse(_rpc_error(None, -32600, "request exceeds sidecar byte cap", "request_size"), status_code=413)
        try:
            message = json.loads(body.decode("utf-8"))
        except (UnicodeError, ValueError):
            return JSONResponse(_rpc_error(None, -32700, "invalid JSON", "json"), status_code=400)
        result = await asyncio.to_thread(gateway.handle_rpc, principal, message)
        if result is None:
            return Response(status_code=204)
        return JSONResponse(result)

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok", "transport": "governed-mcp-sidecar"}

    return app


def main(argv: list[str] | None = None) -> int:  # pragma: no cover - process shell
    del argv
    gateway = build_gateway_from_config()
    try:
        import uvicorn
    except ImportError as exc:
        raise RuntimeError(
            "governed MCP sidecar requires maverick-mcp-server[http]"
        ) from exc
    uvicorn.run(build_app(gateway), host=gateway.config.listen_host, port=gateway.config.listen_port)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = [
    "BudgetDecision",
    "GateDecision",
    "GovernedMCPGateway",
    "HttpMCPUpstream",
    "SIDECAR_SCHEMA",
    "SidecarCallBudget",
    "SidecarConfig",
    "SidecarConfigError",
    "SidecarError",
    "SidecarTool",
    "SidecarUpstreamError",
    "build_app",
    "build_gateway_from_config",
    "config_from_current",
    "main",
]
