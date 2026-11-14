"""Generic authenticated-REST connector factory.

Most enterprise SaaS exposes a token-authed JSON REST API with the same shape:
a base URL, a bearer/basic/custom-header token, GET to read, POST/PUT/PATCH/
DELETE to write. ``make_rest_tool`` turns that shape into a Lightwork ``Tool``
so the long tail of connectors is a one-line spec instead of a hand-written
module — while keeping the house rules: explicit-env auth (no ambient creds),
``confirm=true`` gating on every write, ``ERROR:``-prefixed failures, and a
lazy ``httpx`` import.

The agent supplies the API ``path`` (the description carries the base URL +
auth env + a couple of example paths), so one factory covers every endpoint of
a service without hard-coding entities.
"""
from __future__ import annotations

import base64
import copy
import fnmatch
import json
import os
import re
from typing import Any
from urllib.parse import unquote, urlsplit

from ..connector_attempts import CONTROL_ERRORS
from . import Tool, as_bool

_WRITE_OPS = {"post", "put", "patch", "delete"}
_GQL_MUTATION_TOKEN = re.compile(r"(?<![A-Za-z0-9_])mutation(?![A-Za-z0-9_])")
_ENV_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
_RESPONSE_LIMIT = 4000
_RESPONSE_FORMAT = {
    "type": "string", "enum": ["body", "metadata"], "default": "body",
    "description": "metadata includes HTTP status and ETag for a reviewed If-Match update. Large responses are explicitly truncated; request smaller pages.",
}


class _ConnectorConfigError(RuntimeError):
    """A configuration failure whose public detail is safe to return.

    Arbitrary ``RuntimeError`` text at the connector boundary may contain an
    active credential reflected by an HTTP client or provider.  This narrower
    type carries only validated environment-variable identifiers or one of the
    fixed policy explanations below, so operators keep actionable remediation
    without reopening that value-disclosure path.
    """

    def __init__(self, *env_names: str, reason: str = "missing"):
        if reason == "scoped_connection":
            message = (
                "connector requires a principal-authorized saved connection in "
                "authenticated enterprise execution; ambient environment "
                "credentials are not permitted"
            )
        elif reason == "ambient_extra_header":
            message = (
                "ambient extra-header credentials are unavailable in "
                "authenticated enterprise execution"
            )
        elif (
            reason == "missing"
            and env_names
            and len(env_names) <= 4
            and all(
                isinstance(name, str) and _ENV_IDENTIFIER.fullmatch(name)
                for name in env_names
            )
        ):
            message = f"connector requires {' + '.join(env_names)}"
        else:
            # Never reflect an invalid/developer-controlled identifier.
            message = "connector configuration is incomplete"
        super().__init__(message)


def _capability_egress_denial(url: str, args: dict[str, Any], *, name: str) -> str | None:
    """Apply an active capability host scope to REST connector base URLs."""
    raw_allow_hosts = args.get("_capability_allow_hosts") if isinstance(args, dict) else None
    if not raw_allow_hosts:
        return None
    try:
        host = urlsplit(url).hostname
    except ValueError:
        host = None
    if not host:
        return None
    host_l = host.lower().rstrip(".")
    for pat in raw_allow_hosts:
        pat_l = str(pat).lower().rstrip(".")
        if fnmatch.fnmatchcase(host_l, pat_l):
            return None
    return f"capability policy denies host {host!r} for tool {name!r}"


def _connection_fallback(name: str) -> tuple[str, str] | None:
    """An authorized dashboard-created credential for ``name``, if present.

    Standard/local calls use this as an env fallback. Authenticated enterprise
    calls require it and never borrow ambient process credentials.
    """
    try:
        from maverick import connections
        return connections.resolve(name)
    except Exception:  # pragma: no cover -- a connection read never breaks a tool
        return None


def _requires_scoped_connection() -> bool:
    """Whether ambient process credentials are forbidden for this request."""
    try:
        from maverick import connections
        from maverick.enterprise import enterprise_enabled

        from ..template_connections import active
        return active() or bool(enterprise_enabled() and connections.current_principal())
    except Exception:  # pragma: no cover -- an unknown policy forbids ambient credentials
        return True


def _credential_config(
    name: str,
    base_url_env: str,
    token_env: str,
    *,
    default_base_url: str = "",
) -> tuple[str, str]:
    """Resolve a credential without crossing principal authorization scopes.

    Standard/operator execution retains the legacy per-field env precedence.
    Authenticated enterprise execution may use only a saved connection that
    admits the current principal; operator-global env credentials are ambient
    authority and therefore unavailable to tenant users and agents.
    """
    conn = _connection_fallback(name)
    if _requires_scoped_connection():
        base = (str(conn[0]).strip().rstrip("/") if conn else "") or default_base_url
        tok = str(conn[1]).strip() if conn else ""
        if not base or not tok:
            raise _ConnectorConfigError(reason="scoped_connection")
        return base, tok

    base = (
        os.environ.get(base_url_env, "").strip().rstrip("/")
        or default_base_url
    )
    tok = os.environ.get(token_env, "").strip()
    if (not base or not tok) and conn:
        base = base or str(conn[0]).rstrip("/")
        tok = tok or conn[1]
    if not base or not tok:
        missing = tuple(
            env_name
            for value, env_name in ((base, base_url_env), (tok, token_env))
            if not value
        )
        raise _ConnectorConfigError(*missing)
    return base, tok


def _env_config(name: str, base_url_env: str, token_env: str) -> tuple[str, str]:
    """Resolve ``(base_url, token)`` under the active credential policy."""
    return _credential_config(name, base_url_env, token_env)


def _build_auth_headers(
    tok: str, *, basic: bool, token_header: str, scheme: str,
    extra_headers_env: dict[str, str] | None,
) -> dict[str, str]:
    """Auth + content headers for a connector. Handles bearer/custom-scheme,
    HTTP basic, and APIM-style extra-header creds -- shared by REST and GraphQL
    so a GraphQL service needing basic/extra-header auth works like REST."""
    h = {"Accept": "application/json", "Content-Type": "application/json"}
    if basic:
        raw = tok if ":" in tok else f"{tok}:x"
        h["Authorization"] = "Basic " + base64.b64encode(raw.encode()).decode("ascii")
    else:
        h[token_header] = f"{scheme} {tok}".strip()
    for hdr, env_name in (extra_headers_env or {}).items():
        val = os.environ.get(env_name, "").strip()
        if val:
            if _requires_scoped_connection():
                raise _ConnectorConfigError(reason="ambient_extra_header")
            h[hdr] = val
    return h

_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["get", "post", "put", "patch", "delete"]},
        "path": {"type": "string", "description": "API path beginning with /..."},
        "params": {"type": "object", "description": "query params (get)."},
        "body": {"type": "object", "description": "JSON body (write ops)."},
        "response_format": _RESPONSE_FORMAT,
        "if_match": {
            "type": "string",
            "maxLength": 512,
            "description": (
                "Current remote ETag/revision for PUT, PATCH, or DELETE. "
                "Sent as If-Match when available; without it, a fresh human "
                "approval must acknowledge that newer remote work could be overwritten."
            ),
        },
        "confirm": {"type": "boolean", "description": "required for write ops."},
    },
    "required": ["op", "path"],
    "x-lightwork-conditional-revision": {
        "field": "if_match",
        "header": "If-Match",
        "operations": ["put", "patch", "delete"],
    },
}

_READ_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["get"], "description": "read-only: get."},
        "path": {"type": "string", "description": "API path beginning with /..."},
        "params": {"type": "object", "description": "query params."},
        "response_format": _RESPONSE_FORMAT,
    },
    "required": ["path"],
}


def _rest_validate(
    args: dict[str, Any],
    *,
    name: str,
    read_only: bool,
    read_prefixes: tuple[str, ...],
    read_path_allowed,
    norm,
) -> tuple[str, str] | str:
    """Validate op/path/confirm. Returns ``(op, path)`` or an ``ERROR/DRY RUN`` string."""
    # Coerce to str first: a malformed non-string op/path (e.g. the model emits
    # an int or a list) must yield an ``ERROR:`` string, never raise into the
    # agent loop -- ``(123).strip()`` would AttributeError otherwise.
    op = str(args.get("op") or ("get" if read_only else "")).strip().lower()
    if read_only and op != "get":
        return f"ERROR: {name} is read-only -- only GET is permitted from this seat."
    if op not in ("get", "post", "put", "patch", "delete"):
        return f"ERROR: op must be get/post/put/patch/delete (got {op!r})"
    path = str(args.get("path") or "").strip()
    if not path:
        return "ERROR: path is required"
    if args.get("response_format", "body") not in ("body", "metadata"):
        return "ERROR: response_format must be body or metadata"
    for field in ("params", "body"):
        if field in args and not isinstance(args[field], dict):
            return f"ERROR: {field} must be a JSON object"
    if read_only and not read_path_allowed(path):
        allowed = ", ".join(read_prefixes) or "(none)"
        return f"ERROR: {name} read path is not allowed. Allowed prefixes: {allowed}"
    if op in {"put", "patch", "delete"}:
        if_match = args.get("if_match")
        if not isinstance(if_match, str) or not if_match.strip():
            from ..governed_tools import approved_without_revision

            if not approved_without_revision(name, args):
                return (
                    f"ERROR: {op.upper()} requires the current remote ETag/revision "
                    "or a fresh human approval without concurrency protection"
                )
        elif (
            if_match.strip() == "*"
            or len(if_match) > 512
            or "\r" in if_match
            or "\n" in if_match
        ):
            return "ERROR: if_match must be a single ETag/revision value"
    try:
        import httpx  # noqa: F401
    except ImportError:
        return "ERROR: httpx not installed. Run: python -m pip install -e './packages/maverick-core[issue-trackers]'"
    if op in _WRITE_OPS and not as_bool(args.get("confirm")):
        return f"DRY RUN: would {op.upper()} {norm(path)}. Re-run with confirm=true."
    return op, path


def _rest_response(response, data: Any, args: dict[str, Any], token: str) -> str:
    """Preserve small legacy bodies; never pass a cut JSON document as complete."""
    rendered = json.dumps(data, default=str)
    metadata = args.get("response_format") == "metadata" or response.status_code == 202
    if not metadata and len(rendered) <= _RESPONSE_LIMIT:
        return rendered
    headers = {}
    omitted_headers = []
    # Deliberately exclude cookies, authorization, arbitrary headers and URLs
    # carrying signed query strings. ETags provide the existing If-Match input.
    for name in ("etag", "last-modified", "retry-after"):
        value = getattr(response, "headers", {}).get(name)
        if (isinstance(value, str) and len(value) <= 512
                and not any(ord(c) < 32 or ord(c) == 127 for c in value)
                and not (token and token in value)):
            # Count the encoded size too: three 512-character non-ASCII
            # headers can exceed the entire envelope before any preview fits.
            if len(json.dumps(value)) <= 514:
                headers[name] = value
            else:
                omitted_headers.append(name)
    payload = {"status_code": response.status_code, "headers": headers,
               "truncated": False, "body": data}
    if omitted_headers:
        payload["omitted_headers"] = omitted_headers
    if response.status_code == 202:
        payload["pending"] = True
        payload["note"] = "Accepted for processing; completion has not been verified."
    result = json.dumps(payload, default=str)
    if len(result) <= _RESPONSE_LIMIT:
        return result
    del payload["body"]
    payload.update(truncated=True, response_chars=len(rendered),
                   note="Partial response only; request smaller pages before drawing conclusions.",
                   preview=rendered[:_RESPONSE_LIMIT])
    result = json.dumps(payload)
    while len(result) > _RESPONSE_LIMIT:
        payload["preview"] = payload["preview"][:max(0, len(payload["preview"]) - (len(result) - _RESPONSE_LIMIT))]
        result = json.dumps(payload)
    return result


def _execute_connector_http(method, url, request_headers, *, params, body, args,
                            token, operation, label):
    """One physical HTTP attempt; metadata survives the public string preview."""
    import httpx

    from ..connector_attempts import (
        ConnectorAttempt,
        ConnectorDeadlineExceeded,
        ConnectorResponseLimit,
        ConnectorResult,
        current_invocation,
        retry_after_seconds,
    )
    from ._bounded_http import AttemptDeadline, parse_json_bounded, read_bounded
    from ._ssrf import BlockedHost, safe_client

    invocation = current_invocation()
    # Freeze auth/target/input identity across retries, retaining only a digest.
    # A changed credential or request must start a new reviewed invocation.
    invocation.bind_request(operation, {"url": url, "headers": request_headers,
                                        "params": params, "body": body, "args": args})
    attempt, expires = invocation.begin_attempt()
    deadline = AttemptDeadline(invocation, expires)
    dispatched = False
    status = None

    def outcome(text, error_class=None, retry_after=None, unknown=False):
        if unknown:
            text = ("INDETERMINATE: connector request may have executed; reconcile "
                    "before retrying. "
                    f"request_id={invocation.request_id}; attempt={attempt}")
        return ConnectorResult(text, ConnectorAttempt(
            request_id=invocation.request_id, attempt=attempt, operation=operation,
            status_code=status, error_class=error_class, retry_after=retry_after,
            dispatch_may_have_happened=dispatched, outcome_unknown=unknown))

    try:
        request_headers = {"Accept-Encoding": "identity", **request_headers}
        with safe_client(url, timeout=deadline.remaining(), attempt_deadline=deadline) as client:
            deadline.remaining()
            dispatched = True
            with client.stream(method, url, headers=request_headers,
                               params=params, json=body) as response:
                status = response.status_code
                if status >= 300:
                    klass = ("rate_limit" if status == 429 else "server_5xx" if status >= 500
                             else "auth" if status in {401, 403} else "upstream_rejected")
                    detail = ("redirect or conditional response; no completed result returned"
                              if 300 <= status < 400 else "upstream request failed")
                    return outcome(f"ERROR: {label} ({status}): {detail}", klass,
                                   retry_after_seconds(response.headers.get("retry-after")),
                                   unknown=operation != "safe_read" and status >= 500)
                raw = read_bounded(response, invocation.limits, deadline)
                try:
                    data = parse_json_bounded(raw, invocation.limits, deadline)
                except ConnectorResponseLimit:
                    raise
                except (ValueError, UnicodeError):
                    content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                    # Any 2xx with an empty body completed; only GraphQL must carry data.
                    no_content = not raw and 200 <= status < 300 and label != "graphql"
                    if not no_content and (label == "graphql" or content_type == "application/json"
                                           or content_type.endswith("+json")):
                        return outcome(f"ERROR: {label} ({status}): invalid upstream response",
                                       "malformed_response", unknown=operation != "safe_read")
                    try:
                        data = raw.decode(response.encoding or "utf-8", errors="replace")
                    except LookupError:
                        data = raw.decode("utf-8", errors="replace")
                if label == "graphql":
                    if not isinstance(data, dict) or data.get("errors"):
                        return outcome(f"ERROR: graphql ({status}): upstream request failed",
                                       "graphql_error", unknown=operation == "mutation")
                    if "data" not in data:
                        return outcome(f"ERROR: graphql ({status}): invalid upstream response",
                                       "malformed_response", unknown=operation != "safe_read")
                    data = data["data"]
                return outcome(_rest_response(response, data, args, token))
    except CONTROL_ERRORS:
        raise
    except BlockedHost:
        return outcome("ERROR: blocked host (SSRF guard)", "blocked_host")
    except (ConnectorResponseLimit, ConnectorDeadlineExceeded) as exc:
        invocation.check()
        kind = "response_limit" if isinstance(exc, ConnectorResponseLimit) else "deadline"
        return outcome(f"ERROR: connector {kind}; no complete response was admitted",
                       kind, unknown=dispatched and operation != "safe_read")
    except (httpx.ConnectError, httpx.ConnectTimeout):
        # The connection was never established, so no request bytes left.
        invocation.check()
        dispatched = False
        return outcome(f"ERROR: {label} request failed (could not connect)",
                       "transient_network")
    except (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError):
        invocation.check()
        return outcome(f"ERROR: {label} request failed (transport failure)",
                       "transient_network", unknown=dispatched and operation != "safe_read")
    except RuntimeError:
        invocation.check()
        return outcome("ERROR: connector configuration or request failed (RuntimeError)",
                       "invalid_response", unknown=dispatched and operation != "safe_read")
    except Exception:
        invocation.check()
        return outcome(f"ERROR: {label} request failed (invalid response or transport failure)",
                       "invalid_response", unknown=dispatched and operation != "safe_read")


def _rest_execute(
    op: str,
    path: str,
    args: dict[str, Any],
    *,
    name: str,
    config,
    headers,
    norm,
    query_auth: str | None = None,
) -> str:
    """Perform the authenticated REST request and render the response."""
    params = args.get("params") if isinstance(args.get("params"), dict) else None
    body = args.get("body") if isinstance(args.get("body"), dict) else None
    try:
        base, tok = config()
        # Query-param auth: the credential rides a query param (e.g. FRED's
        # ``api_key``, Census's ``key``) rather than a header. Caller-supplied
        # params cannot replace it: the configured credential always wins.
        if query_auth and tok:
            params = {**(params or {}), query_auth: tok}
        url = f"{base}{norm(path)}"
        # Enterprise mode: a connector POSTs agent-supplied content to a
        # third-party SaaS host -- hold it to the egress boundary too.
        if deny := _capability_egress_denial(url, args, name=name):
            return f"ERROR: {deny}"
        from ..enterprise import enterprise_egress_denial
        deny = enterprise_egress_denial(url, tool=name)
        if deny:
            return f"ERROR: {deny}"
        # Route through the SSRF-safe client: resolve the host ONCE and pin the
        # connection to that validated public IP, so DNS-rebinding can't point
        # the configured connector host at an internal/metadata address
        # (169.254.169.254, 127.0.0.1) after the egress check above. The bearer
        # token rides this request, so an unpinned fetch could exfil it. Redirects
        # stay off (safe_client default) -- only ``url`` passed the gate. On-prem
        # connectors opt in via MAVERICK_FETCH_ALLOW_PRIVATE=1.
        request_headers = headers(tok)
        if_match = args.get("if_match")
        if isinstance(if_match, str) and if_match.strip():
            request_headers["If-Match"] = if_match.strip()
        return _execute_connector_http(
            op.upper(), url, request_headers, params=params or None, body=body,
            args=args, token=tok, operation="safe_read" if op == "get" else "mutation", label=op)
    except CONTROL_ERRORS:
        raise
    except _ConnectorConfigError as e:
        return f"ERROR: {e}"
    except RuntimeError:
        return "ERROR: connector configuration or request failed (RuntimeError)"
    except Exception as e:  # noqa: BLE001
        return f"ERROR: {name} request failed ({type(e).__name__[:120]})"


def make_rest_tool(
    *,
    name: str,
    base_url_env: str,
    token_env: str,
    description: str,
    token_header: str = "Authorization",
    scheme: str = "Bearer",
    basic: bool = False,
    read_only: bool = False,
    allowed_read_paths: tuple[str, ...] | None = None,
    extra_headers_env: dict[str, str] | None = None,
    keyless: bool = False,
    query_auth: str | None = None,
    default_base_url: str | None = None,
) -> Tool:
    """Build a thin authenticated-REST ``Tool``.

    Auth modes:
      - ``basic=True``  -> ``Authorization: Basic b64(token)`` (token is
        ``user:pass``; a bare token is treated as ``token:x``, the API-key
        convention used by Freshdesk / Greenhouse / Lever / BambooHR).
      - ``keyless=True`` -> no credential is sent at all (public data APIs:
        SEC EDGAR, the Federal Register, weather.gov, World Bank). Only the
        base URL is required; ``token_env`` is ignored.
      - ``query_auth="<param>"`` -> the credential rides a query parameter of
        that name instead of a header (FRED ``api_key``, Census ``key``,
        EIA ``api_key``). The key still comes from ``token_env``, never the
        prompt, so it is not exposed to the model.
      - else ``{token_header}: {scheme} {token}`` (``scheme=""`` sends the raw
        token, e.g. Tableau's ``X-Tableau-Auth``).

    ``default_base_url`` supplies a fixed public host so a keyless/public-data
    connector works with zero config; an operator can still override it by
    setting ``base_url_env``.

    ``extra_headers_env`` maps additional header names to env-var names for
    APIs that need a second credential alongside the token (Azure-APIM-style
    gateways, e.g. CCH Axcess's ``Ocp-Apim-Subscription-Key``). A header is
    sent only when its env var is set; required ones are listed in the
    connector's description so a missing key fails loudly at the API.

    ``read_only=True`` exposes GET only -- a low-risk read seat (write ops are
    refused), so a read-only agent/pack can pull data without a write-capable
    tool. The connector's writes are simply unreachable from this seat.

    ``allowed_read_paths`` optionally narrows a read-only connector to known-safe
    API resource prefixes. This is intended for credentialed finance APIs where
    GET-only is not, by itself, an adequate data-access boundary.
    """

    def _config() -> tuple[str, str]:
        if not keyless:
            return _credential_config(
                name, base_url_env, token_env,
                default_base_url=default_base_url or "",
            )
        base = (os.environ.get(base_url_env, "").strip().rstrip("/")
                or (default_base_url or ""))
        if not base:
            raise _ConnectorConfigError(base_url_env)
        return base, ""

    def _headers(tok: str) -> dict[str, str]:
        if keyless or query_auth:
            # No auth header: the credential is either absent (public) or
            # carried on the query string (query_auth), handled in _rest_execute.
            return {"Accept": "application/json", "Content-Type": "application/json"}
        return _build_auth_headers(
            tok, basic=basic, token_header=token_header, scheme=scheme,
            extra_headers_env=extra_headers_env,
        )

    def _norm(path: str) -> str:
        p = path.strip()
        return p if p.startswith("/") else "/" + p

    read_prefixes = tuple(_norm(p) for p in (allowed_read_paths or ()))

    def _request_path(path: str) -> str | None:
        # Keep endpoint authorization independent from query strings. Agents may
        # pass query params separately via ``params``; embedding a query in path
        # must not help bypass or broaden endpoint checks. Percent-decode before
        # checking segments so encoded dot-segment traversal cannot pass the
        # allowlist and be normalized by the HTTP stack or upstream service.
        # A leading "//" would be parsed as a network location (dropping the
        # first segment from the checked path) while the request is still
        # sent to "<base>//...", so the check and the request would disagree.
        normalized = _norm(path)
        if normalized.startswith("//"):
            return None
        parsed = urlsplit(normalized)
        request_path = unquote(parsed.path or "/")
        # "..;" is treated as ".." by upstreams that strip path parameters.
        if any(segment.split(";", 1)[0] in (".", "..") for segment in request_path.split("/")):
            return None
        return request_path

    def _read_path_allowed(path: str) -> bool:
        if not read_prefixes:
            return True
        request_path = _request_path(path)
        if request_path is None:
            return False
        return any(
            request_path == prefix or request_path.startswith(f"{prefix}/")
            for prefix in read_prefixes
        )

    def _run(args: dict[str, Any]) -> str:
        try:
            args = copy.deepcopy(args)
        except Exception:
            return "ERROR: connector arguments cannot be frozen safely"
        validated = _rest_validate(
            args,
            name=name,
            read_only=read_only,
            read_prefixes=read_prefixes,
            read_path_allowed=_read_path_allowed,
            norm=_norm,
        )
        if isinstance(validated, str):
            return validated
        op, path = validated
        return _rest_execute(
            op, path, args,
            name=name,
            config=_config,
            headers=_headers,
            norm=_norm,
            query_auth=query_auth,
        )

    return Tool(name=name, description=description,
                input_schema=_READ_SCHEMA if read_only else _SCHEMA, fn=_run)


def _is_gql_name_char(ch: str) -> bool:
    return ch == "_" or ch.isalnum()


def _skip_gql_ignored(text: str, pos: int) -> int:
    while pos < len(text):
        ch = text[pos]
        # GraphQL permits a leading UTF-8 BOM as ignored input. Python's
        # ``isspace`` does not include U+FEFF, so handle it explicitly or a
        # BOM-prefixed mutation is misclassified as a read.
        if ch.isspace() or ch in {",", "\ufeff"}:
            pos += 1
            continue
        if ch == "#":
            newline = text.find("\n", pos)
            if newline == -1:
                return len(text)
            pos = newline + 1
            continue
        break
    return pos


def _gql_word_at(text: str, pos: int, word: str) -> bool:
    end = pos + len(word)
    return (
        text[pos:end].lower() == word
        and (pos == 0 or not _is_gql_name_char(text[pos - 1]))
        and (end == len(text) or not _is_gql_name_char(text[end]))
    )


def _skip_gql_string(text: str, pos: int) -> int:
    if text.startswith('"""', pos):
        search = pos + 3
        while True:
            end = text.find('"""', search)
            if end == -1:
                return len(text)
            # GraphQL block strings spell an embedded triple quote as \""".
            # Only an even number of immediately preceding backslashes closes
            # the block. A naive find stops early and can hide a later mutation
            # inside what governance incorrectly thinks is ignored syntax.
            slashes = 0
            cursor = end - 1
            while cursor >= pos and text[cursor] == "\\":
                slashes += 1
                cursor -= 1
            if slashes % 2 == 0:
                return end + 3
            search = end + 3

    pos += 1
    while pos < len(text):
        ch = text[pos]
        if ch == "\\":
            pos += 2
        elif ch == '"':
            return pos + 1
        else:
            pos += 1
    return pos


def _skip_gql_braced(text: str, pos: int) -> int:
    depth = 0
    while pos < len(text):
        pos = _skip_gql_ignored(text, pos)
        if pos >= len(text):
            return pos
        ch = text[pos]
        if ch == '"':
            pos = _skip_gql_string(text, pos)
        elif ch == "{":
            depth += 1
            pos += 1
        elif ch == "}":
            depth -= 1
            pos += 1
            if depth <= 0:
                return pos
        else:
            pos += 1
    return pos


def _skip_gql_definition(text: str, pos: int) -> int:
    paren_depth = 0
    while pos < len(text):
        pos = _skip_gql_ignored(text, pos)
        if pos >= len(text):
            return pos
        ch = text[pos]
        if ch == '"':
            pos = _skip_gql_string(text, pos)
            continue
        if ch == "(":
            paren_depth += 1
        elif ch == ")" and paren_depth:
            paren_depth -= 1
        elif ch == "{":
            if paren_depth == 0:
                return _skip_gql_braced(text, pos)
            pos = _skip_gql_braced(text, pos)
            continue
        pos += 1
    return pos


def _graphql_has_mutation(text: str) -> bool:
    """Return whether a GraphQL document contains a mutation operation."""
    # Security floor: GraphQL's operation keyword is a literal name token and
    # cannot be escaped. Conservatively flag it anywhere, even in a comment or
    # string (a harmless false positive), so parser edge cases can never turn a
    # real mutation into a read. The structural walk below preserves existing
    # behavior for ordinary documents and remains defense in depth.
    if _GQL_MUTATION_TOKEN.search(text):
        return True
    pos = 0
    while True:
        pos = _skip_gql_ignored(text, pos)
        while pos < len(text) and text[pos] == "(":
            pos = _skip_gql_ignored(text, pos + 1)
        if pos >= len(text):
            return False
        if _gql_word_at(text, pos, "mutation"):
            return True
        if _gql_word_at(text, pos, "query") or _gql_word_at(text, pos, "subscription"):
            pos = _skip_gql_definition(text, pos)
            continue
        if _gql_word_at(text, pos, "fragment") or text[pos] == "{":
            pos = _skip_gql_definition(text, pos)
            continue
        return False

_GQL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["query"]},
        "query": {"type": "string", "description": "GraphQL query or mutation."},
        "variables": {"type": "object"},
        "response_format": _RESPONSE_FORMAT,
        "confirm": {"type": "boolean", "description": "required for mutations."},
    },
    "required": ["op", "query"],
}


def make_graphql_tool(
    *,
    name: str,
    base_url_env: str,
    token_env: str,
    description: str,
    token_header: str = "Authorization",
    scheme: str = "Bearer",
    basic: bool = False,
    extra_headers_env: dict[str, str] | None = None,
) -> Tool:
    """Build a GraphQL connector (single POST endpoint). Mutations are
    confirm-gated; queries run."""

    def _config() -> tuple[str, str]:
        return _env_config(name, base_url_env, token_env)

    def _run(args: dict[str, Any]) -> str:
        try:
            args = copy.deepcopy(args)
        except Exception:
            return "ERROR: connector arguments cannot be frozen safely"
        # Coerce to str: a non-string query must ERROR, not raise (see _rest_validate).
        q = str(args.get("query") or "").strip()
        if not q:
            return "ERROR: query is required"
        if "variables" in args and not isinstance(args["variables"], dict):
            return "ERROR: variables must be a JSON object"
        if args.get("response_format", "body") not in ("body", "metadata"):
            return "ERROR: response_format must be body or metadata"
        try:
            import httpx  # noqa: F401
        except ImportError:
            return "ERROR: httpx not installed. Run: python -m pip install -e './packages/maverick-core[issue-trackers]'"
        mutation = _graphql_has_mutation(q)
        if mutation and not as_bool(args.get("confirm")):
            return "DRY RUN: GraphQL mutation. Re-run with confirm=true."
        variables = args.get("variables") if isinstance(args.get("variables"), dict) else {}
        try:
            base, tok = _config()
            if deny := _capability_egress_denial(base, args, name=name):
                return f"ERROR: {deny}"
            # Enterprise mode: a GraphQL connector POSTs agent-supplied query +
            # variables to a third-party host -- hold it to the egress boundary
            # too (the REST factory already does this).
            from ..enterprise import enterprise_egress_denial
            deny = enterprise_egress_denial(base, tool=name)
            if deny:
                return f"ERROR: {deny}"
            # Same SSRF-safe path as the REST branch: pin the host IP and keep
            # redirects off (the old httpx.post relied on httpx's default and had
            # no IP-pinning), so the bearer token can't be redirected/rebound to
            # an internal address. On-prem opts in via MAVERICK_FETCH_ALLOW_PRIVATE=1.
            headers = _build_auth_headers(
                tok, basic=basic, token_header=token_header, scheme=scheme,
                extra_headers_env=extra_headers_env,
            )
            return _execute_connector_http(
                "POST", base, headers, params=None, body={"query": q, "variables": variables},
                args=args, token=tok, operation="mutation" if mutation else "unverified",
                label="graphql")
        except CONTROL_ERRORS:
            raise
        except _ConnectorConfigError as e:
            return f"ERROR: {e}"
        except RuntimeError:
            return "ERROR: connector configuration or request failed (RuntimeError)"
        except Exception as e:  # noqa: BLE001
            return f"ERROR: {name} request failed ({type(e).__name__[:120]})"

    return Tool(name=name, description=description, input_schema=_GQL_SCHEMA, fn=_run)

