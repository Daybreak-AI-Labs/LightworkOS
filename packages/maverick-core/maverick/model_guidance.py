"""Read-only picker evidence; never changes runtime routing or billing rates."""
from __future__ import annotations

from datetime import date, datetime, timezone


def enabled() -> bool:
    from .config import load_config
    return (load_config().get("models") or {}).get("guidance", True) is not False


def clean_capabilities(value: object) -> dict:
    """Keep only bounded, typed provider evidence; absence means unknown."""
    if not isinstance(value, dict):
        return {}
    out = {key: value[key] for key in ("tools", "vision") if isinstance(value.get(key), bool)}
    for key in ("context_tokens", "output_tokens"):
        number = value.get(key)
        if isinstance(number, int) and not isinstance(number, bool) and 0 < number <= 1_000_000_000:
            out[key] = number
    return out


def parse_capabilities(style: str, payload: object) -> dict[str, dict]:
    """Read optional fields from the existing bounded model-list response."""
    if not isinstance(payload, dict):
        return {}
    rows = payload.get("models" if style in {"gemini", "ollama"} else "data")
    if not isinstance(rows, list):
        return {}
    out = {}
    for row in rows[:500]:
        if not isinstance(row, dict):
            continue
        ident = row.get("id") or row.get("name") or row.get("model")
        if not isinstance(ident, str) or len(ident) > 160:
            continue
        if style == "gemini":
            ident = ident.removeprefix("models/")
        caps = {"context_tokens": row.get("context_length", row.get("inputTokenLimit")),
                "output_tokens": row.get("outputTokenLimit")}
        for key, source in (("tools", "supports_tools"), ("vision", "supports_vision")):
            if isinstance(row.get(source), bool):
                caps[key] = row[source]
        parameters = row.get("supported_parameters")
        if isinstance(parameters, list) and "tools" in parameters:
            caps["tools"] = True
        architecture = row.get("architecture")
        modalities = architecture.get("input_modalities") if isinstance(architecture, dict) else None
        if isinstance(modalities, list) and "image" in modalities:
            caps["vision"] = True
        out[ident] = clean_capabilities(caps)
    return out


def describe(spec: str, *, provider: str, capability: object = None,
             fetched_at: object = None, stale: bool = True) -> dict:
    from .budget import UnpricedModelError, _lookup_price_quote

    result = clean_capabilities(capability)
    result.update({"self_hosted": provider in {"ollama", "vllm", "tgi"},
                   "capability_source": "Provider model list" if result else "Unknown",
                   "capability_stale": stale, "price": None})
    if isinstance(fetched_at, (int, float)) and not isinstance(fetched_at, bool):
        try:
            result["fetched_at"] = datetime.fromtimestamp(fetched_at, timezone.utc).isoformat()
        except (ValueError, OverflowError, OSError):
            pass
    # Match the *live dispatch gate*, not a planning-only quote for a model
    # spelled similarly on another provider. A price shown here must actually
    # let a task start under the current workspace policy.
    try:
        quote = _lookup_price_quote(spec)
    except UnpricedModelError:
        quote = None
    if quote is not None:
        today = datetime.now(timezone.utc).date()
        result["price"] = {"input": quote.input_per_mtok, "output": quote.output_per_mtok,
                           "currency": quote.currency, "source": quote.source,
                           "as_of": quote.as_of, "fetched_at": quote.fetched_at,
                           "verified": quote.verified, "basis": quote.pricing_basis,
                           "applicability": quote.applicability,
                           "operator_approved": quote.rate_card_version == "operator-ceiling-v1",
                           "stale": (today - date.fromisoformat(quote.as_of)).days > 30,
                           "expired": bool(quote.valid_until and today > date.fromisoformat(quote.valid_until))}
    return result
