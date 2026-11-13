"""Generate the cross-language parity fixture for the Go model proxy.

Python's ``maverick.model_proxy`` is the source of truth. This script drives a
battery of inputs through the real Python functions and serializes the
decisions to ``testdata/parity.json``; ``parity_test.go`` then asserts the Go
port produces byte-identical results. Re-run after changing either side:

    python3 go/model-proxy/gen_parity.py

so the two implementations can never silently drift.
"""
from __future__ import annotations

import json
from pathlib import Path

from maverick import model_proxy as mp


def _cfg(**kw) -> mp.ProxyConfig:
    base = dict(
        upstream="https://api.anthropic.com",
        # Templated placeholders (`<...>`): obviously-fake fixtures, and the angle
        # brackets keep detect-secrets' KeywordDetector from flagging them.
        api_key="<upstream-key>",
        auth_style="bearer",
        client_token="<client-token>",
        allowed_routes=frozenset(),
    )
    base.update(kw)
    if isinstance(base.get("allowed_routes"), (list, tuple)):
        base["allowed_routes"] = frozenset(base["allowed_routes"])
    if "allow_hosts" in base and isinstance(base["allow_hosts"], (list, tuple)):
        base["allow_hosts"] = frozenset(base["allow_hosts"])
    return mp.ProxyConfig(**base)


def _cfg_json(c: mp.ProxyConfig) -> dict:
    return {
        "upstream": c.upstream,
        "api_key": c.api_key,
        "auth_style": c.auth_style,
        "client_token": c.client_token,
        "allowed_routes": sorted(c.allowed_routes),
        "allow_hosts": sorted(c.allow_hosts),
    }


# --- batteries --------------------------------------------------------------

_OPENAI = "https://api.openai.com"

_BUILD_CASES = [
    (_cfg(), "/v1/messages", {"x-maverick-proxy-token": "<client-token>",
                              "Connection": "x-private", "x-private": "drop-me"}),
    (_cfg(), "/v1/messages", {"Authorization": "Bearer <client-token>", "X-Custom": "v"}),
    (_cfg(), "v1/messages", {"x-api-key": "client-sent", "Content-Type": "application/json"}),
    (_cfg(auth_style="x-api-key"), "/v1/messages",
     {"authorization": "Bearer x", "api-key": "y", "Accept": "application/json"}),
    (_cfg(), "/v1/messages",
     {"Connection": "keep-alive", "Transfer-Encoding": "chunked", "Host": "evil",
      "Content-Length": "10", "TE": "trailers", "Keep-Alive": "1", "Upgrade": "h2"}),
    (_cfg(upstream=_OPENAI), "/v1/chat/completions", {"Authorization": "Bearer c"}),
    # An absolute URL remains a path on the configured upstream.
    (_cfg(), "https://evil.example.com/v1/messages", {"Authorization": "Bearer c"}),
    # SSRF: exclude the configured upstream from the allow-set -> error.
    (_cfg(allow_hosts=["api.openai.com", "api.example.com"]), "/v1/messages", {}),
    # A hostless upstream uses Python's None in the error message.
    (_cfg(upstream="invalid", allow_hosts=["api.openai.com"]), "/v1/messages", {}),
    (_cfg(allow_hosts=["api.anthropic.com", "api.openai.com"]), "/v1/messages",
     {"Authorization": "Bearer c"}),
    (_cfg(), "/", {}),
]

_AUTH_CASES = [
    (_cfg(), {"Authorization": "Bearer <client-token>"}),
    (_cfg(), {"authorization": "Bearer <client-token>"}),
    (_cfg(), {"Authorization": "Bearer WRONG"}),
    (_cfg(), {"x-maverick-proxy-token": "<client-token>"}),
    (_cfg(), {"X-Maverick-Proxy-Token": "<client-token>"}),
    (_cfg(), {"x-maverick-proxy-token": "nope"}),
    (_cfg(), {}),
    (_cfg(), {"Authorization": "Bearer <client-token> "}),  # trailing space stripped
    (_cfg(client_token=""), {"Authorization": "Bearer "}),  # no token -> deny
]

_ROUTE_CASES = [
    (_cfg(), "POST", "/v1/messages"),
    (_cfg(), "post", "/v1/messages"),
    (_cfg(), "POST", "/v1/messages?beta=true"),
    (_cfg(), "POST", "/v1/messages?url=https%3A%2F%2Fexample.com"),
    (_cfg(), "GET", "/v1/messages"),
    (_cfg(), "POST", "/v1/unknown"),
    (_cfg(), "POST", "v1/messages"),
    (_cfg(), "POST", "/v1/chat/completions"),
    (_cfg(allowed_routes=["GET /healthz", "POST /v1/foo"]), "GET", "/healthz"),
    (_cfg(allowed_routes=["GET /healthz"]), "POST", "/v1/messages"),
    (_cfg(), "POST", "/"),
    # Percent-encoded path must NOT match the decoded route: Python's
    # urlparse(path).path never decodes, so "/%76%31/messages" stays literal
    # and is rejected. Pins the Go port to EscapedPath() (not the decoded
    # u.Path), closing an allow-list divergence.
    (_cfg(), "POST", "//attacker/v1/messages"),
    (_cfg(), "POST", "//../v1/messages"),
    (_cfg(), "POST", "/v1/../v1/messages"),
    (_cfg(), "POST", "/v1/%2e%2e/v1/messages"),
    (_cfg(), "POST", "/v1%2fmessages"),
    (_cfg(), "POST", "/v1\\messages"),
    (_cfg(), "POST", "/%76%31/messages"),
]

_PARSE_CASES = [
    "POST /v1/messages, GET /healthz",
    "POST /v1/messages\nGET /healthz",
    "  post   /v1/messages  ,  GET healthz  ",
    "garbage",
    "",
    "POST /a, , GET /b",
    "DELETE",
]


def main() -> None:
    out = {
        "build_request": [],
        "authenticate": [],
        "route_allowed": [],
        "parse_allowed_routes": [],
    }

    for config, path, headers in _BUILD_CASES:
        entry = {"config": _cfg_json(config), "path": path, "headers": headers}
        try:
            url, fwd = mp.build_request(config, path, headers)
            entry["result"] = {"url": url, "headers": fwd}
        except ValueError as e:
            entry["result"] = {"error": str(e)}
        out["build_request"].append(entry)

    for config, headers in _AUTH_CASES:
        out["authenticate"].append({
            "config": _cfg_json(config), "headers": headers,
            "result": mp.authenticate(config, headers),
        })

    for config, method, path in _ROUTE_CASES:
        out["route_allowed"].append({
            "config": _cfg_json(config), "method": method, "path": path,
            "result": mp.route_allowed(config, method, path),
        })

    for value in _PARSE_CASES:
        out["parse_allowed_routes"].append({
            "value": value,
            "result": sorted(mp._parse_allowed_routes(value)),
        })

    dest = Path(__file__).parent / "testdata" / "parity.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {dest} "
          f"({sum(len(v) for v in out.values())} cases across {len(out)} functions)")


if __name__ == "__main__":
    main()
