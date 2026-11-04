"""Model cost tiers -- a manager-legible band per model: low / medium / high /
very_high.

The router already reasons in capability tiers (cheap/base/premium) and dollar
ceilings; this is the *human* framing on top: which models cost a little vs a
lot, so an operator can look at a specialist and say "this doesn't need a Very
High model." The band is DERIVED from an explicit estimate-only lookup on the
versioned pricing provider, and it is OVERRIDABLE per model via
``[model_cost_tiers]`` in config for a deployment that prices its own
endpoints (a local model is "low" no matter what the base weights would cost
hosted).

Pure + read-only here; the dashboard's settings store persists an override.
"""
from __future__ import annotations

BANDS: tuple[str, ...] = ("low", "medium", "high", "very_high")
BAND_LABELS = {"low": "Low", "medium": "Medium", "high": "High",
               "very_high": "Very High"}

# Output-weighted blended rate ($/Mtok): real usage is output-heavy, so the
# band tracks what a call actually costs, not the headline input rate.
_INPUT_WEIGHT = 0.2
_OUTPUT_WEIGHT = 0.8
# Thresholds on the blended rate. Calibrated against the shipped price table:
# Opus ($5/$25 -> 21) very_high; Sonnet ($3/$15 -> 12.6) high; Haiku
# ($1/$5 -> 4.2) medium; sub-$2 open models low.
_THRESHOLDS = ((18.0, "very_high"), (8.0, "high"), (2.5, "medium"))


def blended_rate(model: str) -> float | None:
    """The output-weighted $/Mtok for a model, or None if its price is
    unknown (an unpriced local/custom endpoint)."""
    from .budget import _lookup_price_quote

    quote = _lookup_price_quote(model, estimate_only=True)
    if quote.source.endswith("unknown-model-estimate"):
        return None
    inp, out = quote.rates
    return _INPUT_WEIGHT * float(inp) + _OUTPUT_WEIGHT * float(out)


def _derived_band(model: str) -> str:
    rate = blended_rate(model)
    if rate is None:
        # No price on file: an unpriced endpoint is almost always a
        # self-hosted/local model, which is cheap to run at scale -> low.
        return "low"
    for floor, band in _THRESHOLDS:
        if rate >= floor:
            return band
    return "low"


def _overrides() -> dict:
    try:
        from .config import load_config
        raw = (load_config() or {}).get("model_cost_tiers") or {}
        return {str(k): str(v).lower() for k, v in raw.items()
                if str(v).lower() in BANDS}
    except Exception:  # pragma: no cover -- config read never breaks a band
        return {}


def band_for(model: str) -> str:
    """The cost band for a model: an explicit ``[model_cost_tiers]`` override
    wins, else the price-derived band."""
    if not model:
        return "medium"
    ov = _overrides()
    return ov.get(model) or ov.get(model.split(":", 1)[-1]) or _derived_band(model)


def band_detail(model: str) -> dict:
    """Band + label + the rate and whether it was operator-set -- what a
    manager UI renders next to a model."""
    model = model or ""
    ov = _overrides()
    overridden = bool(model) and (model in ov or model.split(":", 1)[-1] in ov)
    band = band_for(model)
    return {"model": model, "band": band, "label": BAND_LABELS[band],
            "blended_rate": blended_rate(model) if model else None,
            "overridden": overridden}


def catalog() -> list[dict]:
    """Every priced model with its band -- the settable cost-tier table."""
    from .llm import MODEL_PRICING_PROVIDER

    # Most expensive band first (Very High → Low), then priciest within a band.
    return sorted((band_detail(m) for m in MODEL_PRICING_PROVIDER.rates),
                  key=lambda d: (-BANDS.index(d["band"]), -(d["blended_rate"] or 0)))


__all__ = ["BANDS", "BAND_LABELS", "blended_rate", "band_for", "band_detail",
           "catalog"]
