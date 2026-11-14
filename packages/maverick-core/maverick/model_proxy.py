"""Out-of-process model proxy.

The agent process holds the provider API keys it uses to call models. If that
process is prompt-injected or otherwise compromised, those keys are in reach.
This is the mitigation: run a tiny proxy **in a separate process** that holds
the key, and point the provider's ``base_url`` at it. The agent sends requests
with no usable credential; the proxy strips whatever the agent sent, injects
the real key, and forwards to the upstream. The key never lives in the agent's
address space.

It is also the natural central chokepoint for egress control: the proxy only
forwards to its single configured ``upstream`` host (an SSRF guard — a
compromised agent can't aim it at an arbitrary URL), and is the one place to
add per-call rate/audit policy later.

The security-critical part is :func:`build_request` (drop the client's auth +
hop-by-hop headers, inject the proxy's key in the upstream's scheme, refuse a
host outside the allow-set) — pure and exhaustively tested. The HTTP listener
(:func:`serve`, ``python -m maverick.model_proxy``) owns an asyncio HTTP/1.1
listener and an HTTPX upstream connection pool.

Config: ``[model_proxy]`` (``upstream`` / ``listen`` / ``auth_style`` /
``client_token`` / ``allowed_routes``) with the key from the proxy's **own**
environment (``MAVERICK_PROXY_KEY``) so it is never in the agent's config. The
listener requires a client bearer token (``MAVERICK_PROXY_CLIENT_TOKEN``) and
only forwards model-inference routes by default, so a reachable local service is
not a general provider-key oracle. The listener streams bounded upstream bytes
with backpressure and owns cancellation/cleanup on disconnect. Synchronous
forward/handle helpers remain bounded buffered compatibility adapters.
"""
from __future__ import annotations

import hmac
import logging
import math
import os
from dataclasses import dataclass
from urllib.parse import urlparse

from .config import load_config

log = logging.getLogger(__name__)

# Headers that are connection-specific and must NOT be forwarded, plus the
# client-supplied credential headers the proxy replaces with its own.
_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
})
_AUTH_HEADERS = frozenset({"authorization", "x-api-key", "api-key", "x-maverick-proxy-token"})

DEFAULT_PORT = 8765
DEFAULT_ALLOWED_ROUTES = frozenset({
    # Anthropic Messages API (+ token counting).
    "POST /v1/messages",
    "POST /v1/messages/count_tokens",
    # OpenAI / OpenAI-compatible inference APIs.
    "POST /v1/chat/completions",
    "POST /v1/responses",
    "POST /v1/completions",
    "POST /v1/embeddings",
})
_PROXY_TOKEN_HEADER = "x-maverick-proxy-token"


@dataclass(frozen=True)
class ProxyConfig:
    upstream: str
    api_key: str
    listen_host: str = "127.0.0.1"
    listen_port: int = DEFAULT_PORT
    auth_style: str = "bearer"          # "bearer" | "x-api-key"
    allow_hosts: frozenset[str] = frozenset()  # empty == {upstream host}
    # Shared secret clients must present to the proxy. It is intentionally not
    # the provider key; use it as the agent-side provider api_key/base credential.
    client_token: str = ""
    # "METHOD /path" specs. Empty means the safe model-inference defaults above.
    allowed_routes: frozenset[str] = frozenset()
    max_request_bytes: int = 8 * 1024 * 1024
    max_response_bytes: int = 64 * 1024 * 1024
    total_seconds: float = 600.0
    max_connections: int = 64

    def __post_init__(self):
        object.__setattr__(self, "allow_hosts", frozenset(self.allow_hosts))
        object.__setattr__(self, "allowed_routes", frozenset(self.allowed_routes))
        for field in ("max_request_bytes", "max_response_bytes", "max_connections"):
            value = getattr(self, field)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"model_proxy.{field} must be a positive integer")
        if isinstance(self.total_seconds, bool) or not math.isfinite(self.total_seconds) or self.total_seconds <= 0:
            raise ValueError("model_proxy.total_seconds must be finite and positive")

    def allowed(self) -> frozenset[str]:
        if self.allow_hosts:
            return self.allow_hosts
        host = urlparse(self.upstream).hostname
        return frozenset({host}) if host else frozenset()


def config_from_env() -> ProxyConfig | None:
    """Build the proxy config (``[model_proxy]`` + ``MAVERICK_PROXY_*``).

    Returns None when not configured (no upstream) — the caller reports it.
    The key is read from the proxy process's env, never from agent config.
    """
    upstream = os.environ.get("MAVERICK_PROXY_UPSTREAM", "").strip()
    key = os.environ.get("MAVERICK_PROXY_KEY", "").strip()
    listen = os.environ.get("MAVERICK_PROXY_LISTEN", "").strip()
    auth_style = os.environ.get("MAVERICK_PROXY_AUTH_STYLE", "").strip().lower()
    client_token = os.environ.get("MAVERICK_PROXY_CLIENT_TOKEN", "").strip()
    allowed_routes = _parse_allowed_routes(
        os.environ.get("MAVERICK_PROXY_ALLOWED_ROUTES", "")
    )
    cfg = {}
    try:
        cfg = (load_config() or {}).get("model_proxy") or {}
        if not isinstance(cfg, dict):
            cfg = {}
        listen = listen or str(cfg.get("listen") or "").strip()
        if not upstream or not auth_style or not client_token or not allowed_routes:
            upstream = upstream or str(cfg.get("upstream") or "").strip()
            auth_style = auth_style or str(cfg.get("auth_style") or "").strip().lower()
            client_token = client_token or str(cfg.get("client_token") or "").strip()
            if not allowed_routes:
                allowed_routes = _parse_allowed_routes(cfg.get("allowed_routes") or ())
    except Exception:  # pragma: no cover -- absent config never blocks startup
        pass
    if not upstream:
        return None
    host, port = _split_listen(listen)
    return ProxyConfig(
        upstream=upstream,
        api_key=key,
        listen_host=host,
        listen_port=port,
        auth_style=auth_style if auth_style in ("bearer", "x-api-key") else "bearer",
        client_token=client_token,
        allowed_routes=allowed_routes,
        **{
            name: cast(os.environ.get(f"MAVERICK_PROXY_{name.upper()}", cfg.get(name, default)))
            for name, cast, default in (
                ("max_request_bytes", int, 8 * 1024 * 1024),
                ("max_response_bytes", int, 64 * 1024 * 1024),
                ("total_seconds", float, 600.0),
                ("max_connections", int, 64),
            )
        },
    )


def _parse_allowed_routes(value) -> frozenset[str]:
    if not value:
        return frozenset()
    if isinstance(value, str):
        raw = value.replace("\n", ",").split(",")
    else:
        raw = value
    routes = set()
    for item in raw:
        route = str(item or "").strip()
        if not route:
            continue
        parts = route.split(None, 1)
        if len(parts) != 2:
            continue
        method, path = parts[0].upper(), parts[1].strip()
        if not path.startswith("/"):
            path = f"/{path}"
        routes.add(f"{method} {path}")
    return frozenset(routes)


def _configured_routes(config: ProxyConfig) -> frozenset[str]:
    return config.allowed_routes or DEFAULT_ALLOWED_ROUTES


def route_allowed(config: ProxyConfig, method: str, path: str) -> bool:
    # Origin-form only: "//host/..." parses as a network location (its path
    # alone would be checked), and dot, backslash or percent-encoded separator
    # segments can climb out of the configured upstream base path.
    if not path.startswith("/"):
        path = "/" + path  # the in-process handler receives relative paths
    route_path = path.split("?", 1)[0]
    lowered = route_path.lower()
    if (route_path.startswith("//") or "\\" in route_path
            or any(token in lowered for token in ("%2e", "%2f", "%5c"))
            or any(seg in (".", "..") for seg in route_path.split("/"))):
        return False
    clean_path = urlparse(path).path or "/"
    if not clean_path.startswith("/"):
        clean_path = f"/{clean_path}"
    return f"{method.upper()} {clean_path}" in _configured_routes(config)


def authenticate(config: ProxyConfig, headers: dict[str, str]) -> bool:
    if not config.client_token:
        return False
    lowered = {k.lower(): v for k, v in headers.items()}
    bearer = lowered.get("authorization", "").strip()
    # Compare as bytes: hmac.compare_digest raises TypeError on a str with any
    # non-ASCII char, and both header values here are attacker-controlled.
    if hmac.compare_digest(
        bearer.encode(), f"Bearer {config.client_token}".encode()
    ):
        return True
    return hmac.compare_digest(
        lowered.get(_PROXY_TOKEN_HEADER, "").strip().encode(),
        config.client_token.encode(),
    )


def _split_listen(listen: str) -> tuple[str, int]:
    if not listen:
        return "127.0.0.1", DEFAULT_PORT
    if ":" in listen:
        host, _, port = listen.rpartition(":")
        try:
            return (host or "127.0.0.1"), int(port)
        except ValueError:
            return "127.0.0.1", DEFAULT_PORT
    return listen, DEFAULT_PORT


def build_request(config: ProxyConfig, path: str,
                  headers: dict[str, str]) -> tuple[str, dict[str, str]]:
    """Transform a client request into the upstream request.

    Drops the client's auth + hop-by-hop headers and injects the proxy's key in
    the upstream's expected scheme. Raises ``ValueError`` if the resolved host
    is outside the allow-set (SSRF guard). Returns ``(url, headers)``.
    """
    url = config.upstream.rstrip("/") + "/" + path.lstrip("/")
    host = urlparse(url).hostname
    allowed = config.allowed()
    if host not in allowed:
        raise ValueError(f"upstream host {host!r} not in allow-set {sorted(allowed)}")
    out = strip_response_headers(headers)
    if config.auth_style == "x-api-key":
        out["x-api-key"] = config.api_key
    else:
        out["Authorization"] = f"Bearer {config.api_key}"
    return url, out


def strip_response_headers(headers: dict[str, str]) -> dict[str, str]:
    nominated = {
        token.strip().lower()
        for key, value in headers.items() if key.lower() == "connection"
        for token in value.split(",")
    }
    blocked = _HOP_BY_HOP | _AUTH_HEADERS | nominated
    return {key: value for key, value in headers.items() if key.lower() not in blocked}


def forward(config: ProxyConfig, method: str, path: str,
            headers: dict[str, str], body: bytes, *,
            client=None, timeout: float = 600.0) -> tuple[int, dict[str, str], bytes]:
    """Forward a request upstream with the proxy's key. Returns
    ``(status, headers, body)``. Response is buffered."""
    url, fwd_headers = build_request(config, path, headers)
    if len(body) > config.max_request_bytes:
        raise ValueError("proxy request body limit exceeded")
    if client is not None:
        # Explicit legacy buffered adapter for existing embedders/test clients.
        from .governed_http import admit_client_request

        admit_client_request(client, url)
        resp = client.request(method, url, headers=fwd_headers, content=body or b"",
                              timeout=min(timeout, config.total_seconds))
        if len(resp.content) > config.max_response_bytes:
            raise RuntimeError("proxy upstream body limit exceeded")
        return resp.status_code, strip_response_headers(dict(resp.headers)), resp.content
    import asyncio

    import httpx

    from .model_proxy_stream import forward_stream
    from .owned_process import run_sync

    async def buffered():
        async with httpx.AsyncClient(follow_redirects=False, trust_env=False) as owned:
            async with forward_stream(config, owned, method, path, headers, body) as response:
                status, response_headers, chunks = response
                output = bytearray()
                async for chunk in chunks:
                    if len(output) + len(chunk) > config.max_response_bytes:
                        raise RuntimeError("proxy upstream body limit exceeded")
                    output.extend(chunk)
                return status, response_headers, bytes(output)

    async def bounded():
        return await asyncio.wait_for(buffered(), min(timeout, config.total_seconds))

    return run_sync(bounded)


def handle(config: ProxyConfig, method: str, path: str,
           headers: dict[str, str], body: bytes, *,
           client=None) -> tuple[int, dict[str, str], bytes]:
    """Whole request handling: forward, or a clean error response. Never raises
    into the listener."""
    if not authenticate(config, headers):
        return 401, {"Content-Type": "text/plain"}, b"proxy authentication required"
    if not route_allowed(config, method, path):
        return 403, {"Content-Type": "text/plain"}, b"model proxy route not allowed"
    if len(body) > config.max_request_bytes:
        return 413, {"Content-Type": "text/plain"}, b"proxy request body limit exceeded"
    from .secrets import scrub
    try:
        return forward(config, method, path, headers, body, client=client)
    except ValueError as e:  # blocked host / bad request
        return 403, {"Content-Type": "text/plain"}, scrub(str(e)).encode("utf-8")
    except Exception as e:  # pragma: no cover -- upstream/network error
        # The upstream exception (httpx URL/error detail) is returned to the
        # proxy client and logged; scrub it so a credential-shaped string in a
        # URL/error can't leak into either sink.
        safe = scrub(str(e))
        log.warning("model proxy forward failed: %s", safe)
        return 502, {"Content-Type": "text/plain"}, f"proxy error: {safe}".encode()


def serve(config: ProxyConfig) -> None:  # pragma: no cover -- CLI lifecycle
    import asyncio

    from .model_proxy_stream import ProxyServer

    async def run():
        server = await ProxyServer(config).start()
        log.info("model proxy listening on %s:%d", config.listen_host, config.listen_port)
        await server.serve_forever()

    asyncio.run(run())


def main(argv: list[str] | None = None) -> int:  # pragma: no cover -- CLI shell
    import argparse
    p = argparse.ArgumentParser(
        prog="maverick.model_proxy",
        description="Out-of-process model proxy (holds the key the agent doesn't).")
    p.add_argument("--check", action="store_true",
                   help="validate config and exit without listening")
    args = p.parse_args(argv)
    config = config_from_env()
    if config is None:
        print("ERROR: no upstream configured "
              "(MAVERICK_PROXY_UPSTREAM or [model_proxy] upstream)")
        return 1
    if not config.client_token:
        print("ERROR: MAVERICK_PROXY_CLIENT_TOKEN or [model_proxy] client_token "
              "is required")
        return 1
    if not config.api_key:
        print("WARNING: MAVERICK_PROXY_KEY is empty; forwarded requests will be "
              "unauthenticated upstream")
    if args.check:
        print(f"OK: {config.listen_host}:{config.listen_port} -> {config.upstream} "
              f"(auth={config.auth_style})")
        return 0
    serve(config)
    return 0


__all__ = ["ProxyConfig", "config_from_env", "build_request", "forward",
           "handle", "serve", "authenticate", "route_allowed"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
