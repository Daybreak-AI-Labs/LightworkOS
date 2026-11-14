"""Live model discovery: the model ids each configured provider key can reach.

The dashboard's model pickers used to offer only a hand-maintained catalog. A
saved key usually reaches more, and newer, models than any list shipped with
the code, so this module asks each provider's own model-list endpoint through
the SSRF-safe client, keeps only well-formed ids, and caches the answer under
the data home so page loads stay offline. Discovery never changes what a role
resolves to; it only widens what the settings page can offer. Switch it off
with ``[models] discovery = false`` or ``MAVERICK_MODEL_DISCOVERY=0``.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
import uuid
from collections.abc import Callable, Iterable
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit

DISCOVERY_TIMEOUT_SECONDS = 8.0
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_MODELS_PER_PROVIDER = 500
MAX_PAGES = 8
MAX_DETAIL_CHARS = 200
DEFAULT_TTL_MINUTES = 60
PRICE_REFRESH_RETRY_SECONDS = 60
CACHE_SCHEMA = "lightwork.model-discovery.v2"
ANTHROPIC_VERSION = "2023-06-01"

# provider -> (default endpoint, response style). Vendors with an OpenAI-shaped
# ``GET /models`` share the "openai" style. A configured ``base_url`` replaces
# the default host: the OpenAI-shaped SDK bases already end in ``/v1`` and take
# ``/models``; the Anthropic SDK base is the origin and takes ``/v1/models``.
LIST_ENDPOINTS: dict[str, tuple[str, str]] = {
    "anthropic": ("https://api.anthropic.com/v1/models", "anthropic"),
    "openai": ("https://api.openai.com/v1/models", "openai"),
    "gemini": ("https://generativelanguage.googleapis.com/v1beta/models", "gemini"),
    "openrouter": ("https://openrouter.ai/api/v1/models", "openai"),
    "moonshot": ("https://api.moonshot.ai/v1/models", "openai"),
    "deepseek": ("https://api.deepseek.com/v1/models", "openai"),
    "xai": ("https://api.x.ai/v1/models", "openai"),
}
# Self-hosted endpoints: the configured base URL plus a fixed path.
LOCAL_LIST_PATHS: dict[str, tuple[str, str]] = {
    "ollama": ("api/tags", "ollama"),
    "vllm": ("models", "openai"),
    "tgi": ("models", "openai"),
    "openai_compatible": ("models", "openai"),
}
UNSUPPORTED: dict[str, str] = {
    "azure": "Azure OpenAI lists deployments through the management plane, not the "
             "data-plane key; pick from the catalog or type a deployment name.",
    "bedrock": "Bedrock lists foundation models through AWS IAM, not a data-plane key; "
               "pick from the catalog or type a model id.",
    "vertex": "Vertex AI model lists need Google Cloud sign-in, not a data-plane key, "
              "and this client does not list them; type the model id exactly as shown "
              "in the Vertex AI Model Garden.",
    "codex_cli": "Codex CLI serves whatever the signed-in ChatGPT plan offers; pick "
                 "from the catalog or type a model id.",
}
DISCOVERABLE = tuple(LIST_ENDPOINTS) + tuple(LOCAL_LIST_PATHS)

_VALID_MODEL = re.compile(r"^[A-Za-z0-9_.:/-]{1,128}$")
_VALID_PROVIDER = re.compile(r"^[a-z][a-z0-9_]{1,31}$")
_VALID_TOKEN = re.compile(r"^[A-Za-z0-9_.:/=+-]{1,512}$")
_STATUSES = frozenset({"live", "unavailable", "unsupported", "unconfigured", "disabled"})
_LOOPBACK = frozenset({"127.0.0.1", "::1"})

Fetch = Callable[..., tuple[int, bytes]]


def _canonical(provider: str) -> str:
    from .providers import _canonical as canonical
    return canonical(provider)


def spec_for(provider: str, model_id: str) -> str:
    """The picker/resolver spec: bare for anthropic, ``provider:id`` otherwise."""
    name = _canonical(provider)
    return model_id if name == "anthropic" else f"{name}:{model_id}"


def discovery_enabled() -> bool:
    """``[models] discovery`` (default on), overridden by ``MAVERICK_MODEL_DISCOVERY``.

    Off while a config source is unreadable: it may hold ``discovery = false``,
    and discovery sends the provider key to the provider's model listing."""
    env = os.environ.get("MAVERICK_MODEL_DISCOVERY", "").strip().lower()
    if env:
        return env in {"1", "true", "yes", "on"}
    from .config import config_source_errors
    if config_source_errors(include_tenant=True):
        return False
    value = _models_table().get("discovery")
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() not in {"0", "false", "no", "off"}
    return True


def discovery_ttl_minutes() -> int:
    """How long a discovered list counts as fresh (``[models] discovery_ttl_minutes``)."""
    value = _models_table().get("discovery_ttl_minutes")
    try:
        minutes = int(value)
    except (TypeError, ValueError):
        return DEFAULT_TTL_MINUTES
    return max(1, min(minutes, 24 * 60))


def _models_table() -> dict:
    try:
        from . import config
        table = (config.load_config() or {}).get("models")
    except Exception:
        return {}
    return table if isinstance(table, dict) else {}


def _provider_material(provider: str) -> dict[str, Any]:
    """Configured flag, effective key and base URL for one provider (never logged)."""
    from .config import PROVIDER_KEY_ENV_MAP, get_provider_config, provider_configuration_state
    try:
        state = provider_configuration_state(provider)
    except ValueError:
        return {"configured": False, "api_key": "", "base_url": ""}
    try:
        table = get_provider_config(provider) or {}
    except Exception:
        table = {}
    key = table.get("api_key") if isinstance(table, dict) else None
    key = key.strip() if isinstance(key, str) else ""
    if not key:
        for env_name in PROVIDER_KEY_ENV_MAP.get(provider, ()):
            value = os.environ.get(env_name, "").strip()
            if value:
                key = value
                break
    return {
        "configured": bool(state.get("configured")),
        "api_key": key,
        "base_url": str(state.get("base_url") or "").strip(),
    }


def _append_path(base_url: str, suffix: str) -> str:
    parsed = urlsplit(base_url.strip())
    path = parsed.path.rstrip("/") + "/" + suffix.lstrip("/")
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def _request_plan(provider: str, key: str, base_url: str) -> tuple[str, str, dict[str, str], bool]:
    """The (url, style, headers, allow_loopback) for one provider's model list."""
    if provider in LOCAL_LIST_PATHS:
        suffix, style = LOCAL_LIST_PATHS[provider]
        if provider == "ollama":
            base = (base_url or "http://127.0.0.1:11434").rstrip("/").removesuffix("/v1")
            url = _append_path(base, suffix)
        elif base_url:
            if provider in {"vllm", "tgi"} and not base_url.rstrip("/").endswith("/v1"):
                base_url = base_url.rstrip("/") + "/v1"
            url = _append_path(base_url, suffix)
        else:
            raise ValueError("no base URL is configured for this self-hosted provider")
        headers = {"Authorization": f"Bearer {key}"} if key else {}
        return _localhost_to_loopback(url), style, headers, True
    default_url, style = LIST_ENDPOINTS[provider]
    if base_url:
        if provider == "anthropic":
            url = _append_path(base_url, "v1/models")
        else:
            # A custom base for an OpenAI-shaped vendor is the SDK base (ends in
            # /v1, or /v1beta/openai/ for Gemini's compatibility endpoint).
            url, style = _append_path(base_url, "models"), "openai"
    else:
        url = default_url
    if not key:
        raise ValueError("no effective provider key is configured")
    if provider == "anthropic":
        headers = {"x-api-key": key, "anthropic-version": ANTHROPIC_VERSION}
    elif style == "gemini":
        headers = {"x-goog-api-key": key}
    else:
        headers = {"Authorization": f"Bearer {key}"}
    if urlsplit(url).scheme != "https":
        raise ValueError("the provider endpoint is not HTTPS")
    return url, style, headers, False


def _localhost_to_loopback(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.hostname == "localhost":
        netloc = "127.0.0.1" + (f":{parsed.port}" if parsed.port else "")
        return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, ""))
    return url


def _page_url(url: str, style: str, token: str | None) -> str:
    if token is None:
        return url
    parameter = {"anthropic": "after_id", "gemini": "pageToken"}.get(style)
    if parameter is None:
        return url
    return url + ("&" if "?" in url else "?") + parameter + "=" + quote(token, safe="")


def _ids(candidates: Iterable[object]) -> list[str]:
    valid = {c.strip() for c in candidates if isinstance(c, str) and _VALID_MODEL.fullmatch(c.strip())}
    return sorted(valid)


def _zero_price(value: object) -> bool:
    """True when a provider-advertised price field is exactly zero."""
    if isinstance(value, bool):
        return False
    if isinstance(value, Decimal):
        return value.is_finite() and value == 0
    if isinstance(value, (int, float)):
        return value == 0
    if isinstance(value, str):
        try:
            return Decimal(value.strip()) == 0
        except InvalidOperation:
            return False
    return False


def parse_free_models(style: str, payload: object) -> list[str]:
    """Model ids whose prompt, completion and other advertised fees are all zero.

    OpenRouter's ``GET /api/v1/models`` carries a ``pricing`` object per row; a
    rows without both token prices, or with any non-zero or unreadable additional
    price, cannot supply a zero-price quote. Discovery accepts this evidence only
    from the official endpoint; other request options may have separate charges.
    """
    if style != "openai" or not isinstance(payload, dict):
        return []
    rows = payload.get("data")
    if not isinstance(rows, list):
        return []
    free = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        pricing = row.get("pricing")
        if not isinstance(pricing, dict):
            continue
        if (_zero_price(pricing.get("prompt")) and _zero_price(pricing.get("completion"))
                and all(_zero_price(value) for field, value in pricing.items() if field not in {"prompt", "completion"})):
            free.append(row.get("id"))
    return _ids(free)


def parse_models(style: str, payload: object) -> tuple[list[str], str | None]:
    """Model ids (sorted, unique, well-formed) and the next page token, if any."""
    if not isinstance(payload, dict):
        raise ValueError("model list is not an object")
    token: str | None = None
    if style in {"openai", "anthropic"}:
        rows = payload.get("data")
        if not isinstance(rows, list):
            raise ValueError("model list has no data rows")
        ids = _ids(row.get("id") for row in rows if isinstance(row, dict))
        if style == "anthropic" and payload.get("has_more") is True:
            last = payload.get("last_id")
            if isinstance(last, str) and _VALID_TOKEN.fullmatch(last):
                token = last
        return ids, token
    if style == "gemini":
        rows = payload.get("models")
        if not isinstance(rows, list):
            raise ValueError("model list has no models")
        names = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            name = row.get("name")
            if not isinstance(name, str) or not name.startswith("models/"):
                continue
            methods = row.get("supportedGenerationMethods")
            if isinstance(methods, list) and "generateContent" not in methods:
                continue
            names.append(name[len("models/"):])
        next_token = payload.get("nextPageToken")
        if isinstance(next_token, str) and _VALID_TOKEN.fullmatch(next_token):
            token = next_token
        return _ids(names), token
    if style == "ollama":
        rows = payload.get("models")
        if not isinstance(rows, list):
            raise ValueError("model list has no models")
        return _ids((row.get("name") or row.get("model")) for row in rows if isinstance(row, dict)), None
    raise ValueError("unknown model list style")


def _fetch(url: str, headers: dict[str, str], *, allow_loopback: bool) -> tuple[int, bytes]:
    """One bounded GET through the SSRF-safe pinned client (loopback only for local providers)."""
    from .tools import _ssrf

    def run() -> tuple[int, bytes]:
        with _ssrf.safe_client(url, timeout=DISCOVERY_TIMEOUT_SECONDS) as client:
            with client.stream("GET", url, headers=headers) as response:
                status = int(response.status_code)
                total = 0
                chunks: list[bytes] = []
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > MAX_RESPONSE_BYTES:
                        raise ValueError("model list exceeds the response size limit")
                    chunks.append(chunk)
                return status, b"".join(chunks)

    host = (urlsplit(url).hostname or "").strip()
    if allow_loopback and host in _LOOPBACK:
        with _ssrf.allow_private_hosts((host,)):
            return run()
    return run()


def _entry(
    provider: str,
    status: str,
    models: list[str],
    detail: str,
    fetched_at: float | None,
    free_models: list[str] | None = None,
    capabilities: dict | None = None,
) -> dict[str, Any]:
    return {
        "provider": provider,
        "status": status,
        "models": list(models),
        # Ids the provider's own listing priced at $0 (OpenRouter today); the
        # budget prices those at zero instead of refusing them as unpriced.
        "free_models": list(free_models or []),
        "capabilities": capabilities or {},
        "detail": detail[:MAX_DETAIL_CHARS],
        "fetched_at": fetched_at,
    }


def _official_openrouter_listing(url: str) -> bool:
    parsed = urlsplit(url)
    return (parsed.scheme == "https" and parsed.hostname == "openrouter.ai"
            and parsed.port in (None, 443) and parsed.path == "/api/v1/models"
            and not parsed.query and not parsed.fragment and parsed.username is None)


def discover(provider: str, *, fetch: Fetch | None = None, material: dict[str, Any] | None = None) -> dict[str, Any]:
    """Ask one provider which models its configured key can reach (no cache)."""
    name = _canonical(provider)
    fetch = fetch or _fetch
    if name in UNSUPPORTED:
        return _entry(name, "unsupported", [], UNSUPPORTED[name], None)
    if name not in DISCOVERABLE:
        return _entry(name, "unsupported", [], "this provider has no model-list endpoint; pick from the catalog or type a model id", None)
    if not discovery_enabled():
        return _entry(name, "disabled", [], "model discovery is switched off ([models] discovery or MAVERICK_MODEL_DISCOVERY)", None)
    material = material if material is not None else _provider_material(name)
    if not material["configured"]:
        return _entry(name, "unconfigured", [], "no key or endpoint is configured for this provider", None)
    now = time.time()
    try:
        url, style, headers, allow_loopback = _request_plan(name, material["api_key"], material["base_url"])
    except ValueError as exc:
        return _entry(name, "unavailable", [], str(exc), now)
    try:
        from .tools._ssrf import BlockedHost
    except Exception:  # pragma: no cover - guard import only fails without httpx
        class BlockedHost(Exception):  # type: ignore[no-redef]
            pass
    models: list[str] = []
    free: list[str] = []
    capabilities: dict = {}
    seen: set[str] = set()
    token: str | None = None
    try:
        for _page in range(MAX_PAGES):
            status, body = fetch(_page_url(url, style, token), headers, allow_loopback=allow_loopback)
            if not 200 <= int(status) < 300:
                return _entry(name, "unavailable", [], f"provider returned HTTP {int(status)} for the model list", now)
            payload = json.loads(body.decode("utf-8"), parse_float=Decimal)
            ids, token = parse_models(style, payload)
            from .model_guidance import parse_capabilities
            capabilities.update(parse_capabilities(style, payload))
            if name == "openrouter" and _official_openrouter_listing(url):
                free.extend(parse_free_models(style, payload))
            if name == "gemini":
                ids = [i.removeprefix("models/") for i in ids]
            for model_id in ids:
                if model_id not in seen:
                    seen.add(model_id)
                    models.append(model_id)
            if token is None:
                break
        else:
            return _entry(name, "unavailable", [], "the model list did not end within the page limit", now)
    except BlockedHost:
        return _entry(name, "unavailable", [], "provider endpoint is blocked by the egress policy", now)
    except (ValueError, TypeError, UnicodeDecodeError):
        return _entry(name, "unavailable", [], "provider returned an unreadable model list", now)
    except Exception as exc:
        return _entry(name, "unavailable", [], f"model list request failed ({type(exc).__name__})", now)
    models = sorted(models)[:MAX_MODELS_PER_PROVIDER]
    kept = set(models)
    return _entry(
        name,
        "live",
        models,
        f"{len(models)} models reachable with the configured key",
        now,
        free_models=[m for m in _ids(free) if m in kept],
        capabilities={m: capabilities[m] for m in kept if m in capabilities},
    )


def cache_path() -> Path:
    from .paths import data_dir
    return data_dir("cache", "model-discovery.json")


def _material_binding(provider: str, material: dict[str, Any] | None = None) -> str:
    """Opaque binding to this provider's effective connection, never its key."""
    material = material if material is not None else _provider_material(provider)
    return hashlib.sha256(json.dumps(
        [provider, material["configured"], material["api_key"], material["base_url"]],
        separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")).hexdigest()


def _load_cache(path: Path | None = None) -> dict[str, dict[str, Any]]:
    path = path or cache_path()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    providers = raw.get("providers") if isinstance(raw, dict) and raw.get("schema") == CACHE_SCHEMA else None
    if not isinstance(providers, dict):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for name, row in providers.items():
        if not (isinstance(name, str) and _VALID_PROVIDER.fullmatch(name) and isinstance(row, dict)):
            continue
        binding = _material_binding(name)
        if row.get("material_binding") != binding:
            continue
        status = row.get("status")
        if status not in _STATUSES:
            continue
        fetched_at = row.get("fetched_at")
        fetched = float(fetched_at) if isinstance(fetched_at, (int, float)) and not isinstance(fetched_at, bool) and math.isfinite(fetched_at) else None
        models = row.get("models") if isinstance(row.get("models"), list) else []
        free = row.get("free_models") if isinstance(row.get("free_models"), list) else []
        detail = row.get("detail") if isinstance(row.get("detail"), str) else ""
        from .model_guidance import clean_capabilities
        raw_caps = row.get("capabilities")
        capabilities = {m: clean_capabilities(raw_caps.get(m)) for m in _ids(models)} if isinstance(raw_caps, dict) else {}
        out[name] = _entry(name, status, _ids(models), detail, fetched,
                           free_models=[m for m in _ids(free) if m in _ids(models)], capabilities=capabilities)
        out[name]["material_binding"] = binding
        out[name]["refresh_token"] = row.get("refresh_token") if isinstance(row.get("refresh_token"), str) and re.fullmatch(r"[a-f0-9]{32}", row["refresh_token"]) else ""
        attempted = row.get("last_attempt_at")
        out[name]["last_attempt_at"] = attempted if isinstance(attempted, (int, float)) and not isinstance(attempted, bool) and math.isfinite(attempted) else None
    return out


def _write_cache(entries: dict[str, dict[str, Any]], *, path: Path | None = None, effect_guard=None) -> None:
    from . import file_lock
    path = path or cache_path()
    file_lock.ensure_private_directory(path.parent)
    payload = {"schema": CACHE_SCHEMA, "providers": entries}
    file_lock.atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True), effect_guard=effect_guard)


def refresh(providers: Iterable[str] | None = None) -> dict[str, dict[str, Any]]:
    """Discover the given providers (default: every configured one) and cache the result."""
    if providers is None:
        names = [p for p in DISCOVERABLE if _provider_material(p)["configured"]]
    else:
        names = list(dict.fromkeys(_canonical(p) for p in providers))
    if not names:
        return {}
    from .file_lock import cross_process_lock

    path = cache_path()
    materials = {name: _provider_material(name) for name in names}
    bindings = {name: _material_binding(name, material) for name, material in materials.items()}

    def current_connection() -> None:
        if cache_path() != path or any(_material_binding(name) != binding for name, binding in bindings.items()):
            raise ValueError("The AI connection changed during the check. Refresh its model list again.")

    # Reserve the latest request durably, without relying on clock resolution or
    # holding the cache lock over provider I/O. Existing evidence stays intact.
    reservations = {name: uuid.uuid4().hex for name in names}
    with cross_process_lock(path, strict=True):
        current_connection()
        entries = _load_cache(path)
        for name in names:
            previous = entries.get(name) or _entry(name, "unavailable", [], "A model-list check is in progress.", None)
            previous.update(refresh_token=reservations[name], material_binding=bindings[name])
            entries[name] = previous
        _write_cache(entries, path=path, effect_guard=current_connection)

    fresh = {name: discover(name, material=materials[name]) for name in names}
    current_connection()
    with cross_process_lock(path, strict=True):
        current_connection()
        entries = _load_cache(path)
        for name, row in fresh.items():
            previous = entries.get(name, {})
            attempted = row["fetched_at"]
            if previous.get("refresh_token") != reservations[name]:
                fresh[name] = previous or _entry(name, "unavailable", [], "A newer check replaced this request.", None)
                continue
            if row["status"] == "unavailable" and previous.get("models"):
                row.update(models=previous["models"], capabilities=previous["capabilities"],
                           fetched_at=previous["fetched_at"], free_models=[])
            row.update(material_binding=bindings[name], last_attempt_at=attempted,
                       refresh_token=reservations[name])
        entries.update(fresh)
        _write_cache(entries, path=path, effect_guard=current_connection)
    return fresh


def refresh_for_price(*, provider: str = "openrouter", model: str) -> None:
    """Check expired/missing pricing evidence before a new physical AI request.

    Only the configured discovery option permits this bounded metadata request.
    Never call this from token accounting. Failed recent attempts have a finite
    cooldown, and same-provider callers share one check without locking other
    providers' cache reads or updates. This does not grant spending permission.
    """
    from .file_lock import cross_process_lock

    name = _canonical(provider)
    if name != "openrouter" or not _VALID_MODEL.fullmatch(model) or not discovery_enabled():
        return
    material = _provider_material(name)
    if not material["configured"]:
        return
    path, binding = cache_path(), _material_binding(name, material)

    def needs_check() -> bool:
        if cache_path() != path or _material_binding(name) != binding:
            raise ValueError("The AI connection changed during the check. Refresh its model list again.")
        row = snapshot().get(name, {})
        if row.get("status") == "live" and not row.get("stale", True):
            return False
        attempted = row.get("last_attempt_at")
        return attempted is None or not 0 <= time.time() - attempted < PRICE_REFRESH_RETRY_SECONDS

    if needs_check():
        with cross_process_lock(path.with_name("model-discovery-openrouter-price"), strict=True):
            if needs_check():
                refresh([name])


def snapshot() -> dict[str, dict[str, Any]]:
    """Cached discovery entries with a ``stale`` flag; never touches the network."""
    limit = discovery_ttl_minutes() * 60
    now = time.time()
    out = {}
    for name, entry in _load_cache().items():
        fetched = entry.get("fetched_at")
        entry["stale"] = entry["status"] != "live" or fetched is None or not 0 <= now - fetched <= limit
        out[name] = entry
    return out


def reachable(provider: str) -> list[str]:
    """Model ids the cached discovery says this provider's key can reach."""
    entry = snapshot().get(_canonical(provider))
    return list(entry["models"]) if entry and entry["status"] == "live" and not entry["stale"] else []


def free_models(provider: str) -> list[str]:
    """Model ids the cached discovery says ``provider`` advertises at $0.

    A current, connection-bound, fresh successful listing is required. Previous
    model choices can remain visible after failure, but cannot supply $0 pricing
    authority. This read never refreshes the provider or sends a paid request.
    """
    entry = snapshot().get(_canonical(provider))
    if not entry or entry["status"] != "live" or entry["stale"]:
        return []
    return [m for m in entry.get("free_models") or [] if isinstance(m, str)]
