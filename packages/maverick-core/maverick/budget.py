"""Budget tracking. Long-horizon agents need hard caps.

Cost correctness:
  - record_tokens() takes the actual model id (default falls back to
    Sonnet rate for back-compat), so an Opus orchestrator call is billed
    at the Opus rate and max_dollars caps real spend.
  - Cache tokens are priced separately. Anthropic charges 0.1x for
    cache reads and 1.25x for cache writes, so they are not folded into
    ``input_tokens`` at full price.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import threading
import time
from collections.abc import Callable
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field

from .config_contracts import BOOLEAN_SETTINGS
from .pricing import (
    ModelPrice,
    UnverifiedRateError,
    assert_price_evidenced,
    load_pricing_evidence_pack,
)
from .runtime_overrides import budget_override

log = logging.getLogger(__name__)


class BudgetExceeded(Exception):
    pass


class UsageAccountingError(RuntimeError):
    """A provider reported malformed usage accounting -- a missing, non-finite
    or negative token count -- for a call that was already paid for.

    Fail closed: the spend cannot be billed against the cap, so the run stops.
    Deliberately NOT a :class:`BudgetExceeded` subclass:
    reporting a broken gateway as "budget exceeded" sent operators to raise
    ``max_dollars`` instead of fixing the gateway, hid the real cause from the
    dashboard and CLI, and made provider failover treat it as a budget control
    signal. It is still non-retryable (another model cannot repair a gateway's
    accounting), and it counts as a provider failure for the circuit breaker.
    """


class UnpricedModelError(BudgetExceeded):
    """Raised when billing lacks a verified, provenance-carrying model rate.

    Subclassing ``BudgetExceeded`` preserves the existing hard-stop behavior at
    every spend boundary. Planning code can explicitly request estimate-only
    pricing from :func:`_lookup_price`; live accounting cannot silently do so.
    """


@dataclass(frozen=True, slots=True)
class TokenCharge:
    """The cost and price evidence attributable to one token-meter update."""

    dollars: float
    pricing_evidence: dict[str, object]


# Fallback price (Sonnet 4.6 list, no cache discount) in $/Mtok.
# Used only by the explicit estimate-only fallback for an unknown model.
_FALLBACK_PRICE_IN = 3.0
_FALLBACK_PRICE_OUT = 15.0
_TOKEN_OPERATION = re.compile(r"[0-9a-f]{64}\Z")
_MAX_TOKEN_OPERATIONS = 5000
_ATTEMPT_PRICE: ContextVar[Callable[[object, str | None], ModelPrice] | None] = ContextVar(
    "maverick_attempt_price", default=None,
)


@contextmanager
def _attempt_price_scope(resolve: Callable[[object, str | None], ModelPrice]):
    """Use the exact native physical attempt's price while its adapter meters."""
    token = _ATTEMPT_PRICE.set(resolve)
    try:
        yield
    finally:
        _ATTEMPT_PRICE.reset(token)

# Model ids already warned about (estimate-priced); warn once each, not per call.
_UNPRICED_WARNED: set[str] = set()
_ESTIMATE_MODE_WARNED = False
_TRUTHY = {"1", "true", "yes", "on"}
_FALSY = {"0", "false", "no", "off"}


def _billing_strict() -> bool:
    """Whether live accounting requires a verified rate.

    Billing is fail-closed by default. The environment override has precedence,
    followed by an explicitly configured ``[budget] strict_pricing`` boolean.
    ``false`` is retained as a legacy opt-in to estimate-only accounting for
    custom gateways; malformed values fail closed.
    """

    raw = os.environ.get("MAVERICK_BILLING_STRICT")
    if raw is not None and raw.strip():
        norm = raw.strip().lower()
        if norm in _TRUTHY:
            return True
        if norm in _FALSY:
            return False
        log.warning(
            "MAVERICK_BILLING_STRICT must be true/false; failing closed "
            "with strict pricing"
        )
        return True
    try:
        from .config import get_budget_overrides

        budget = get_budget_overrides() or {}
    except Exception as exc:  # fail closed: config outage cannot weaken billing
        log.warning("pricing config unavailable; failing closed: %s", exc)
        return True
    if "strict_pricing" not in budget:
        return BOOLEAN_SETTINGS["budget.strict_pricing"].default
    value = budget.get("strict_pricing")
    if isinstance(value, bool):
        return value
    log.warning(
        "budget.strict_pricing must be true or false; failing closed with "
        "strict pricing"
    )
    return True


def _resolve_estimate_only(value: bool | None) -> bool:
    """Resolve an explicit lookup mode or the deployment billing policy."""

    global _ESTIMATE_MODE_WARNED
    if value is not None:
        return bool(value)
    estimate_only = not _billing_strict()
    if estimate_only and not _ESTIMATE_MODE_WARNED:
        _ESTIMATE_MODE_WARNED = True
        log.warning(
            "budget.strict_pricing=false enables legacy estimate-only "
            "accounting: provisional rates may affect dollar totals; every "
            "such rate is labeled unverified in Budget.pricing_evidence and "
            "must not be used for invoices or chargebacks"
        )
    return estimate_only


def _coerce_count(v: object) -> int:
    """Coerce a usage count to a non-negative int, failing closed on bad data.

    Providers occasionally return ``None`` in ``usage`` on streaming refusals;
    that remains a zero count for backwards-compatible null-safety. Non-finite,
    unparseable, or negative counts are invalid accounting data. Raise
    :class:`UsageAccountingError` so the run stops instead of silently
    recording a paid call as $0 and bypassing later budget checks -- and so
    the stop is reported as a provider fault, not a cap breach.
    """
    if v is None:
        return 0
    try:
        if isinstance(v, float) and not math.isfinite(v):
            raise ValueError("non-finite")
        n = int(v or 0)
    except (TypeError, ValueError, OverflowError) as exc:
        raise UsageAccountingError(f"invalid token usage count: {v!r}") from exc
    if n < 0:
        raise UsageAccountingError(f"invalid token usage count: negative value {n}")
    return n


def _nonnegative_finite(value: object, label: str) -> float:
    """Return a finite, non-negative accounting value or stop the run.

    ``nan`` is especially dangerous here: every comparison with it is false,
    so accepting it can permanently disable a dollar cap.  Booleans are
    rejected even though Python otherwise treats them as integers.
    """

    if isinstance(value, bool):
        raise BudgetExceeded(f"invalid {label}: {value!r}")
    try:
        normalized = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise BudgetExceeded(f"invalid {label}: {value!r}") from exc
    if not math.isfinite(normalized) or normalized < 0:
        raise BudgetExceeded(f"invalid {label}: {value!r}")
    return normalized


def _nonnegative_integer(value: object, label: str) -> int:
    """Validate a stored counter without rounding or string coercion."""

    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise BudgetExceeded(f"invalid {label}: {value!r}")
    return value


def _token_operation_id(value: object | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _TOKEN_OPERATION.fullmatch(value):
        raise BudgetExceeded("invalid token metering operation id")
    return value


def _token_request_digest(value: dict[str, object]) -> str:
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise BudgetExceeded("invalid token metering request") from exc
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _validate_token_operations(value: object) -> dict[str, dict[str, object]]:
    if not isinstance(value, dict) or len(value) > _MAX_TOKEN_OPERATIONS:
        raise BudgetExceeded("invalid token metering operation state")
    for operation, row in value.items():
        if not isinstance(operation, str) or not _TOKEN_OPERATION.fullmatch(operation):
            raise BudgetExceeded("invalid token metering operation state")
        if not isinstance(row, dict) or set(row) != {
            "request", "dollars", "pricing_evidence", "failure",
        }:
            raise BudgetExceeded("invalid token metering operation state")
        if not isinstance(row["request"], str) or not _TOKEN_OPERATION.fullmatch(row["request"]):
            raise BudgetExceeded("invalid token metering operation state")
        _nonnegative_finite(row["dollars"], "stored token charge")
        evidence = row["pricing_evidence"]
        if not isinstance(evidence, dict):
            raise BudgetExceeded("invalid token metering operation state")
        try:
            encoded = json.dumps(evidence, sort_keys=True, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise BudgetExceeded("invalid token metering operation state") from exc
        if len(encoded.encode("utf-8")) > 64 * 1024:
            raise BudgetExceeded("invalid token metering operation state")
        failure = row["failure"]
        if failure is not None and (
            not isinstance(failure, str) or not failure or len(failure) > 2000
        ):
            raise BudgetExceeded("invalid token metering operation state")
    return value

# Anthropic cache multipliers (over the list input price).
# Two TTLs: 5m default (1.25x write surcharge) and 1h (2.0x write surcharge).
# Prior code collapsed all writes to 1.25x; long-TTL writes were
# under-billed by ~40%.
_CACHE_READ_MULT = 0.1     # Anthropic: 90% discount on cache reads (both TTLs)
_CACHE_WRITE_MULT_5M = 1.25
_CACHE_WRITE_MULT_1H = 2.0

# OpenAI / o-series / gpt-5 automatic prompt cache discounts cache reads ~50%
# (0.5x), NOT 90% like Anthropic. Billing those reads at 0.1x under-counted
# cached-input cost ~5x for every non-Anthropic provider with cache hits.
# Callers pass the provider-appropriate multiplier; default stays Anthropic's.
CACHE_READ_MULT_OPENAI = 0.5


def _cache_write_mult_from_ttl(ttl: str | None) -> float:
    """Map Anthropic cache TTL string to the write surcharge multiplier.

    Strip + lowercase before matching so trailing
    whitespace ("1h ") or case variants ("1H") don't silently downgrade
    to the 5m rate. Also: anything >= 5m duration is billed at 2.0x to
    match Anthropic's published surcharge tiers (the SDK accepts more
    TTL strings than the original 3-value whitelist).
    """
    if not ttl:
        return _CACHE_WRITE_MULT_5M
    norm = ttl.strip().lower()
    # Known 1h-tier aliases.
    if norm in ("1h", "60m", "3600s", "1hour", "1 hour"):
        return _CACHE_WRITE_MULT_1H
    # Parse duration suffixes — anything > 5m bills at 1h rate.
    try:
        if norm.endswith("h"):
            return _CACHE_WRITE_MULT_1H if float(norm[:-1]) >= 1 else _CACHE_WRITE_MULT_5M
        if norm.endswith("m"):
            return _CACHE_WRITE_MULT_1H if float(norm[:-1]) > 5 else _CACHE_WRITE_MULT_5M
        if norm.endswith("s"):
            return _CACHE_WRITE_MULT_1H if float(norm[:-1]) > 300 else _CACHE_WRITE_MULT_5M
    except ValueError:
        pass
    return _CACHE_WRITE_MULT_5M


def _tracked_policy_price(
    model_id: str,
    rates: tuple[float, float],
    *,
    evidence_id: str,
) -> ModelPrice:
    """Build and verify a quote from a tracked non-vendor metering policy."""

    evidence_pack = load_pricing_evidence_pack()
    evidence = evidence_pack.entries[evidence_id]
    quote = ModelPrice(
        model_id=model_id,
        input_per_mtok=rates[0],
        output_per_mtok=rates[1],
        source=evidence.source_url,
        as_of=evidence.as_of,
        fetched_at=evidence.retrieved_at,
        currency=evidence.currency,
        confidence=evidence.confidence,
        verified=evidence.verified,
        rate_card_version=evidence_pack.rate_card_version,
        evidence_id=evidence_id,
        pricing_basis=evidence.pricing_basis,
        applicability=evidence.applicability,
    )
    assert_price_evidenced(quote, evidence_pack)
    return quote


def _estimate_policy_price(
    model_id: str,
    rates: tuple[float, float],
    *,
    source: str,
    confidence: float,
    version: str,
    evidence_id: str,
    pricing_basis: str,
    applicability: str,
) -> ModelPrice:
    """Build a clearly provisional quote for a compatibility estimate."""

    return ModelPrice(
        model_id=model_id,
        input_per_mtok=rates[0],
        output_per_mtok=rates[1],
        source=source,
        as_of="2026-07-29",
        fetched_at="2026-07-29T16:00:00Z",
        currency="USD",
        confidence=confidence,
        verified=False,
        rate_card_version=version,
        evidence_id=evidence_id,
        pricing_basis=pricing_basis,
        applicability=applicability,
    )


_BEDROCK_INFERENCE_PROFILE_PREFIXES = ("global.", "us.", "eu.", "jp.", "apac.", "au.")
_BEDROCK_VERSION_SUFFIX = re.compile(r"-v\d+(?::\d+)?$")
_BEDROCK_DATE_SUFFIX = re.compile(r"-\d{8}$")


def bedrock_rate_card_model_id(model_id: str | None) -> str | None:
    """The Claude API catalogue id behind a Bedrock model id, or ``None``.

    ``anthropic.claude-opus-5`` -> ``claude-opus-5``;
    ``us.anthropic.claude-sonnet-4-5-20250929-v1:0`` -> ``claude-sonnet-4-5``;
    ``global.anthropic.claude-opus-4-6-v1`` -> ``claude-opus-4-6``. Accepts a
    ``bedrock:`` spec prefix. Non-Anthropic Bedrock ids map to ``None``.
    """
    mid = (model_id or "").strip()
    mid = mid.removeprefix("bedrock:")
    for prefix in _BEDROCK_INFERENCE_PROFILE_PREFIXES:
        if mid.startswith(prefix):
            mid = mid[len(prefix):]
            break
    if not mid.startswith("anthropic."):
        return None
    mid = mid[len("anthropic."):]
    mid = _BEDROCK_VERSION_SUFFIX.sub("", mid)
    mid = _BEDROCK_DATE_SUFFIX.sub("", mid)
    return mid or None


def _bedrock_estimate_quote(
    requested: str,
    canonical: str,
    *,
    estimate_only: bool,
) -> ModelPrice | None:
    """Estimate-only quote for a Bedrock model id from the Claude API list rate
    of the model behind it.

    AWS invoices Bedrock at its own rates (regional endpoints carry a 10%
    premium over global), which are not in the verified rate card, so this is
    never a bill: strict accounting raises with the remedy, and planning gets
    a clearly provisional estimate.
    """
    from .llm import model_price_quote

    try:
        base = model_price_quote(canonical, estimate_only=True)
    except UnverifiedRateError:
        base = None
    if base is None:
        return None
    if not estimate_only:
        raise UnpricedModelError(
            f"no verified USD price for Bedrock model {requested!r}: AWS invoices "
            "Bedrock usage at its own rates (regional endpoints carry a 10% premium "
            "over global), which are not in Lightwork's rate card. Planning "
            f"estimates use the Claude API list rate for {canonical!r}; to account "
            "live usage at that estimate set [budget] strict_pricing=false."
        )
    if requested not in _UNPRICED_WARNED:
        _UNPRICED_WARNED.add(requested)
        log.warning(
            "estimate-only accounting for Bedrock model %r uses the Claude API "
            "list rate for %r ($%.2f/$%.2f per Mtok); AWS invoices are "
            "authoritative and this must not be used for billing",
            requested, canonical, base.rates[0], base.rates[1],
        )
    return _estimate_policy_price(
        requested,
        base.rates,
        source="maverick://pricing-policy/bedrock-anthropic-list-estimate",
        confidence=0.6,
        version="bedrock-anthropic-list-estimate-v1",
        evidence_id="bedrock-anthropic-list-estimate-v1",
        pricing_basis=(
            f"Claude API list rate for {canonical} applied to the Bedrock model "
            "id; AWS invoices are authoritative"
        ),
        applicability=(
            "Estimate-only; assumes the Bedrock global endpoint (regional "
            "endpoints carry a 10% premium)"
        ),
    )


def vertex_rate_card_model_id(model_id: str | None) -> str | None:
    """The Claude API catalogue id behind a Vertex AI Claude model id, or ``None``.

    ``vertex:claude-haiku-4-5@20251001`` -> ``claude-haiku-4-5``. Vertex AI
    serves Claude under ``name@version`` ids; any other publisher's model maps
    to ``None``, so strict accounting refuses it as before.
    """
    mid = (model_id or "").strip().removeprefix("vertex:").strip()
    if not mid.startswith("claude-"):
        return None
    return mid.split("@", 1)[0] or None


def _vertex_estimate_quote(
    requested: str,
    canonical: str,
    *,
    estimate_only: bool,
) -> ModelPrice | None:
    """Estimate-only quote for a Vertex AI Claude model id from the Claude API
    list rate of the model behind it.

    Google Cloud invoices Vertex AI usage at its own rates, which are not in
    the verified rate card (the regional and global endpoint tariffs are not
    verified here), so this is never a bill: strict accounting raises with the
    remedy, and planning gets a clearly provisional estimate.
    """
    from .llm import model_price_quote

    try:
        base = model_price_quote(canonical, estimate_only=True)
    except UnverifiedRateError:
        base = None
    if base is None:
        return None
    if not estimate_only:
        raise UnpricedModelError(
            f"no verified USD price for Vertex AI model {requested!r}: Google Cloud "
            "invoices Vertex AI usage at its own rates, which are not in Lightwork's "
            f"rate card. Planning estimates use the Claude API list rate for {canonical!r}; "
            "to account live usage at that estimate set [budget] strict_pricing=false."
        )
    if requested not in _UNPRICED_WARNED:
        _UNPRICED_WARNED.add(requested)
        log.warning(
            "estimate-only accounting for Vertex AI model %r uses the Claude API "
            "list rate for %r ($%.2f/$%.2f per Mtok); Google Cloud invoices are "
            "authoritative and this must not be used for billing",
            requested, canonical, base.rates[0], base.rates[1],
        )
    return _estimate_policy_price(
        requested,
        base.rates,
        source="maverick://pricing-policy/vertex-anthropic-list-estimate",
        confidence=0.6,
        version="vertex-anthropic-list-estimate-v1",
        evidence_id="vertex-anthropic-list-estimate-v1",
        pricing_basis=(
            f"Claude API list rate for {canonical} applied to the Vertex AI model "
            "id; Google Cloud invoices are authoritative"
        ),
        applicability=(
            "Estimate-only; Vertex AI regional and global endpoint tariffs are not verified"
        ),
    )


def _openrouter_advertised_free(model_id: str) -> bool:
    """Whether OpenRouter's own listing, as cached by model discovery, prices
    ``model_id`` at $0 for both prompt and completion. Any cache trouble prices
    nothing: the strict path then refuses as before."""
    try:
        from .model_discovery import free_models

        return model_id in free_models("openrouter")
    except Exception:  # discovery cache problems never invent a price
        return False


def _bare_model_proxy_estimate(
    requested: str, rates: tuple[float, float], *, has_source: bool,
) -> ModelPrice:
    """Label a direct-vendor tuple as a planning proxy for another route."""
    policy = "bare-model-proxy-estimate" if has_source else "legacy-tuple-estimate"
    if requested not in _UNPRICED_WARNED:
        _UNPRICED_WARNED.add(requested)
        log.warning(
            "estimate-only accounting is using an unverified proxy rate "
            "for %r; not suitable for invoices or chargebacks", requested,
        )
    return _estimate_policy_price(
        requested, (float(rates[0]), float(rates[1])),
        source=f"maverick://pricing-policy/{policy}",
        confidence=0.25,
        version=f"{policy}-v1",
        evidence_id=f"{policy}-v1",
        pricing_basis="Unverified direct-vendor rate used as a planning proxy",
        applicability="Estimate only; the selected route may charge a different tariff",
    )


def _lookup_price_quote(  # noqa: C901 - ordered evidence and policy precedence
    model: str | None,
    *,
    estimate_only: bool | None = None,
) -> ModelPrice:
    """Resolve a model rate with its provenance and verification evidence.

    Billing-grade lookup is the default and fails closed for a missing or
    provisional rate. ``estimate_only=True`` opts one planning call into
    estimates; an explicitly configured legacy ``strict_pricing=false`` opts
    live accounting into the same warning-labelled compatibility path.
    """

    from .llm import MODEL_PRICES, MODEL_SONNET, model_price_quote

    estimate_only = _resolve_estimate_only(estimate_only)
    requested = model or MODEL_SONNET
    operator_cache: list[ModelPrice | None] = []

    def operator_quote() -> ModelPrice | None:
        # Most catalog routes have tracked first-party rates. Read the shared
        # override only when that evidence is absent or provisional.
        if not operator_cache:
            operator_cache.append(_operator_rate_quote(requested))
        return operator_cache[0]

    if requested.startswith("embedding:"):
        from .embedding_prices import quote_for_budget

        return quote_for_budget(requested)

    # Codex CLI is subscription-metered rather than API-token-metered. This is
    # an explicit, verified accounting policy and must win before a bare model
    # id (such as gpt-5.5) resolves to the paid OpenAI API rate.
    if requested.startswith("codex_cli:"):
        return _tracked_policy_price(
            requested,
            (0.0, 0.0),
            evidence_id="codex-cli-subscription-policy-2026-07-29",
        )

    keys = [requested]
    bare = requested.split(":", 1)[1] if ":" in requested else requested
    # A bare row can price a qualified route only if its evidence names that
    # route's own provider. Model spelling alone says nothing about the bill:
    # OpenRouter, Azure and Bedrock can serve the same model at other tariffs.
    evidence_prefix = {
        "anthropic": "anthropic-", "openai": "openai-", "gemini": "google-",
        "moonshot": "moonshot-", "deepseek": "deepseek-", "xai": "xai-",
        "openrouter": "openrouter-",
    }.get(requested.split(":", 1)[0])
    if bare != requested and evidence_prefix is not None:
        bare_quote = model_price_quote(bare, estimate_only=True)
        if bare_quote is not None and bare_quote.evidence_id.startswith(evidence_prefix):
            keys.append(bare)

    for key in keys:
        try:
            quote = model_price_quote(key, estimate_only=estimate_only)
        except UnverifiedRateError as exc:
            approved = operator_quote()
            if approved is not None:
                return approved
            raise UnpricedModelError(
                f"{exc}. A legacy/custom gateway may explicitly set "
                "[budget] strict_pricing=false for warning-labelled "
                "estimate-only accounting."
            ) from exc
        legacy = MODEL_PRICES.get(key)
        if quote is not None and (legacy is None or legacy == quote.rates):
            if not quote.verified:
                approved = operator_quote()
                if approved is not None:
                    return approved
            if quote.currency != "USD":
                raise UnpricedModelError(
                    f"price for {requested!r} is in {quote.currency}; "
                    "Budget dollars requires a verified USD rate"
                )
            if not quote.verified and requested not in _UNPRICED_WARNED:
                _UNPRICED_WARNED.add(requested)
                log.warning(
                    "estimate-only accounting is using unverified rate for "
                    "%r (source=%s, as_of=%s, confidence=%.2f); not suitable "
                    "for invoices or chargebacks",
                    requested,
                    quote.source,
                    quote.as_of,
                    quote.confidence,
                )
            return quote
        if legacy is not None:
            approved = operator_quote()
            if approved is not None:
                return approved
            # A runtime override of the compatibility tuple map carries no
            # source or verification evidence. Preserve it for planning, but
            # never let it become a bill merely because two floats exist.
            if not estimate_only:
                raise UnpricedModelError(
                    f"price for {requested!r} exists only in the metadata-free "
                    "MODEL_PRICES compatibility view; billing requires a "
                    "verified ModelPrice"
                )
            estimate_quote = _estimate_policy_price(
                requested,
                (float(legacy[0]), float(legacy[1])),
                source="maverick://pricing-policy/legacy-tuple-estimate",
                confidence=0.25,
                version="legacy-tuple-estimate-v1",
                evidence_id="legacy-tuple-estimate-v1",
                pricing_basis="Unverified integration-supplied USD per 1M token estimate",
                applicability=(
                    "Estimate-only compatibility override; no tracked "
                    "source evidence"
                ),
            )
            if requested not in _UNPRICED_WARNED:
                _UNPRICED_WARNED.add(requested)
                log.warning(
                    "estimate-only accounting is using metadata-free rate "
                    "for %r (source=%s, confidence=%.2f); not suitable for "
                    "invoices or chargebacks",
                    requested,
                    estimate_quote.source,
                    estimate_quote.confidence,
                )
            return estimate_quote

    approved = operator_quote()
    if approved is not None:
        return approved

    # Bedrock model ids: a provisional estimate from the Claude API
    # list rate of the model behind the id; never a bill under strict pricing.
    bedrock_canonical = bedrock_rate_card_model_id(bare)
    if bedrock_canonical is not None:
        quote = _bedrock_estimate_quote(
            requested, bedrock_canonical, estimate_only=estimate_only,
        )
        if quote is not None:
            return quote

    # Vertex AI Claude ids (name@version), same policy: the explicit ``vertex:``
    # prefix is required so a bare id is never priced as a Vertex route.
    if requested.startswith("vertex:"):
        vertex_canonical = vertex_rate_card_model_id(requested)
        if vertex_canonical is not None:
            quote = _vertex_estimate_quote(
                requested, vertex_canonical, estimate_only=estimate_only,
            )
            if quote is not None:
                return quote

    # Unknown self-hosted ids incur no metered API-token charge. This does not
    # claim infrastructure is free; the source makes the accounting scope
    # explicit and auditable.
    provider = requested.split(":", 1)[0] if ":" in requested else requested
    if ":" in requested and provider in ("ollama", "vllm", "tgi"):
        return _tracked_policy_price(
            requested,
            (0.0, 0.0),
            evidence_id="self-hosted-api-metering-policy-2026-07-29",
        )

    # OpenRouter publishes a per-model price list; a model it lists at $0 for
    # prompt and completion incurs no metered charge. The discovery cache holds
    # that list as fetched with the operator's own key, so the $0 rate is the
    # provider's published one, not an estimate, and strict pricing honours it.
    if ":" in requested and provider == "openrouter" and _openrouter_advertised_free(bare):
        return _tracked_policy_price(
            requested,
            (0.0, 0.0),
            evidence_id="openrouter-advertised-free-tier-policy-2026-09-16",
        )

    # Explicit planning mode may use a bare tuple as a proxy, but the direct
    # vendor's rate is never evidence for billing through another gateway.
    if estimate_only and bare != requested and bare in MODEL_PRICES:
        return _bare_model_proxy_estimate(
            requested, MODEL_PRICES[bare],
            has_source=model_price_quote(bare, estimate_only=True) is not None,
        )

    if not estimate_only:
        raise UnpricedModelError(
            f"no verified USD price for model {requested!r}; refusing to bill "
            "at an estimate. Add a sourced ModelPrice to the versioned rate "
            "card. Planning code may explicitly request estimate_only=True; "
            "a legacy/custom gateway may explicitly set "
            "[budget] strict_pricing=false for warning-labelled estimates."
        )

    if requested not in _UNPRICED_WARNED:
        _UNPRICED_WARNED.add(requested)
        log.warning(
            "no verified price for model %r; estimate-only calculation is "
            "using the Sonnet fallback ($%.2f/$%.2f per Mtok); this rate must "
            "not be used for billing",
            requested,
            _FALLBACK_PRICE_IN,
            _FALLBACK_PRICE_OUT,
        )
    return _estimate_policy_price(
        requested,
        (_FALLBACK_PRICE_IN, _FALLBACK_PRICE_OUT),
        source="maverick://pricing-policy/unknown-model-estimate",
        confidence=0.1,
        version="unknown-model-estimate-v1",
        evidence_id="unknown-model-estimate-v1",
        pricing_basis="Unverified Sonnet-rate planning fallback",
        applicability=(
            "Estimate-only unknown-model fallback; no vendor-specific "
            "pricing evidence"
        ),
    )


def _operator_rate_quote(model: str) -> ModelPrice | None:
    """Use only a current, exact-route operator ceiling for spend admission."""
    from datetime import date, datetime, timezone

    from .llm import _parse_spec
    from .runtime_overrides import model_rate_overrides

    provider, model_id = _parse_spec(model)
    route = f"{provider}:{model_id}"
    rate = model_rate_overrides().get(route)
    if rate is None or date.fromisoformat(rate["valid_until"]) < datetime.now(timezone.utc).date():
        return None
    approved_at = rate["approved_at"]
    evidence_id = "operator-ceiling-" + hashlib.sha256(
        json.dumps({"model": route, **rate}, sort_keys=True, separators=(",", ":"))
        .encode("utf-8")
    ).hexdigest()
    return ModelPrice(
        model_id=model,
        input_per_mtok=rate["input_per_mtok"],
        output_per_mtok=rate["output_per_mtok"],
        source=rate["source"],
        as_of=rate["as_of"],
        fetched_at=approved_at,
        currency="USD",
        confidence=0.0,
        verified=False,
        rate_card_version="operator-ceiling-v1",
        evidence_id=evidence_id,
        pricing_basis="Administrator-approved USD ceiling per million tokens",
        applicability=(
            "Spend-limit estimate for this exact model route. Provider invoices "
            "remain authoritative; cached input is conservatively charged at "
            "the full input rate; do not use for chargebacks or invoices."
        ),
        valid_until=rate["valid_until"],
    )


def _lookup_price(
    model: str | None,
    *,
    estimate_only: bool | None = None,
) -> tuple[float, float]:
    """Return ``(input, output)`` rates while enforcing the requested use."""

    return _lookup_price_quote(model, estimate_only=estimate_only).rates


@dataclass
class Budget:
    max_input_tokens: int | None = None
    max_output_tokens: int | None = None
    max_dollars: float | None = None
    max_wall_seconds: float | None = None
    max_tool_calls: int | None = None

    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    dollars: float = 0.0
    tool_calls: int = 0
    started_at: float = field(default_factory=time.time)
    # Model -> immutable rate-card evidence used by this budget. Kept out of
    # ``__init__`` because callers must not inject provenance independently of
    # the pricing provider.
    pricing_evidence: dict[str, dict[str, object]] = field(
        default_factory=dict,
        init=False,
        repr=False,
    )

    # Legacy defaults; only used when ``model`` isn't passed.
    price_in_per_mtok: float = _FALLBACK_PRICE_IN
    price_out_per_mtok: float = _FALLBACK_PRICE_OUT

    def record_tokens(
        self,
        in_tok: int,
        out_tok: int,
        *,
        model: str | None = None,
        cache_read_tok: int = 0,
        cache_write_tok: int = 0,
        cache_write_ttl: str | None = None,
        cache_read_mult: float | None = None,
        cache_write_5m_tok: int = 0,
        cache_write_1h_tok: int = 0,
        operation_id: str | None = None,
    ) -> TokenCharge:
        """Add usage from one LLM call.

        ``in_tok`` is the number of input tokens billed at full rate
        (i.e. excludes the cache_read_tok and cache_write_tok counts).
        ``cache_read_tok`` is billed at ``cache_read_mult`` x the input rate
        (default 0.1x for Anthropic; pass ``CACHE_READ_MULT_OPENAI`` =0.5 for
        OpenAI/o-series/gpt-5 auto-cache). ``cache_write_tok`` at 1.25x (5m TTL)
        or 2.0x (1h TTL) — pass ``cache_write_ttl="1h"`` for a 1h breakpoint.

        A single request's cache writes can straddle BOTH TTL tiers at
        once (e.g. a 1h system/tools breakpoint plus a 5m messages
        breakpoint) -- Anthropic's response then reports
        ``usage.cache_creation.ephemeral_5m_input_tokens`` /
        ``ephemeral_1h_input_tokens`` as the real per-tier split, which is
        NOT recoverable from the flat ``cache_write_tok`` + one
        ``cache_write_ttl`` arguments (that combination
        bills every write in the call at a single multiplier, e.g. the whole
        thing at the 1h 2.0x rate when only part of it wrote at 1h). Pass
        ``cache_write_5m_tok``/``cache_write_1h_tok`` when the caller has the
        real split; they take over both the token counter and the dollar
        computation, and ``cache_write_tok``/``cache_write_ttl`` are ignored.
        Leave them at 0 (the default) to keep the prior single-bucket
        behavior for callers that only have one combined count (other
        providers, or an SDK response without the split field).

        ``None`` usage counts coerce to zero — Anthropic
        occasionally returns ``None`` in ``usage`` on streaming refusals; the
        prior code raised ``TypeError`` and the instance counted as $0 spent.
        Non-finite, unparseable, or negative counts now fail closed with
        ``BudgetExceeded`` instead of silently recording a paid call as zero.

        Cache reads/writes accumulate in separate
        counters so ``max_input_tokens`` reflects the BILLABLE input
        budget (non-cached only). Caching is a discount, so heavy
        caching should let you DO more work within the same input cap.
        """
        in_tok = _coerce_count(in_tok)
        out_tok = _coerce_count(out_tok)
        cache_read_tok = _coerce_count(cache_read_tok)
        cache_write_tok = _coerce_count(cache_write_tok)
        cache_write_5m_tok = _coerce_count(cache_write_5m_tok)
        cache_write_1h_tok = _coerce_count(cache_write_1h_tok)
        operation = _token_operation_id(operation_id)
        if model is not None and (
            not isinstance(model, str) or not model or len(model) > 512
        ):
            raise BudgetExceeded("invalid model identifier")
        if cache_write_ttl is not None and (
            not isinstance(cache_write_ttl, str) or len(cache_write_ttl) > 64
        ):
            raise BudgetExceeded("invalid cache write TTL")
        resolve_attempt = _ATTEMPT_PRICE.get()
        admitted_quote = resolve_attempt(self, model) if resolve_attempt is not None else None
        split_cache_write = bool(cache_write_5m_tok or cache_write_1h_tok)
        if split_cache_write:
            cache_write_tok = cache_write_5m_tok + cache_write_1h_tok
        # Make the accumulator atomic so a
        # future parallel best-of-N (or multi-agent swarm where two
        # agents share a Budget) can't lose updates. `+=` on float is
        # NOT atomic in CPython under threads — we'd silently undercount.
        # check() runs INSIDE the lock too — TOCTOU
        # otherwise lets two threads both pass check() with state that
        # the OTHER thread has already invalidated. check() does no I/O
        # and elapsed() is reentrant-safe, so holding the lock through
        # it is fine.
        # Compute one attributable charge before updating the shared total.
        # Returning it avoids deriving a call's cost from before/after snapshots
        # that can include another thread's direct Budget update.
        read_mult = _nonnegative_finite(
            _CACHE_READ_MULT if cache_read_mult is None else cache_read_mult,
            "cache read multiplier",
        )
        request = _token_request_digest({
            "in_tok": in_tok,
            "out_tok": out_tok,
            "model": model,
            "cache_read_tok": cache_read_tok,
            "cache_write_tok": cache_write_tok,
            "cache_write_ttl": cache_write_ttl,
            "cache_read_mult": read_mult,
            "cache_write_5m_tok": cache_write_5m_tok,
            "cache_write_1h_tok": cache_write_1h_tok,
        })

        with self._lock:
            self._validate_integrity()
            if operation is not None and operation in self._token_operations:
                prior = self._token_operations[operation]
                if prior["request"] != request:
                    raise BudgetExceeded(
                        "token metering operation belongs to different usage"
                    )
                replayed = TokenCharge(
                    _nonnegative_finite(prior["dollars"], "stored token charge"),
                    dict(prior["pricing_evidence"]),
                )
                if prior["failure"] is not None:
                    failure = BudgetExceeded(str(prior["failure"]))
                    failure.pricing_evidence = dict(replayed.pricing_evidence)
                    failure.token_charge = replayed
                    raise failure
                return replayed
            if operation is not None and len(self._token_operations) >= _MAX_TOKEN_OPERATIONS:
                raise BudgetExceeded("token metering operation capacity reached")
            # Resolve inside the operation lock. Two concurrent exact retries
            # must not both miss the receipt and mutate the same counters.
            quote = admitted_quote if admitted_quote is not None else _lookup_price_quote(model)
            in_rate, out_rate = quote.rates
            pricing_evidence = quote.metadata()
            # A private gateway's cache discount is unknown. Provider adapter
            # defaults (OpenAI 0.5x, Anthropic 0.1x) cannot silently reduce an
            # operator-entered spending ceiling; charge cached input at full
            # input rate unless a tracked provider rate establishes a discount.
            effective_read_mult = (max(read_mult, 1.0)
                                   if quote.rate_card_version == "operator-ceiling-v1"
                                   else read_mult)
            call_dollars = (in_tok / 1_000_000) * in_rate
            call_dollars += (cache_read_tok / 1_000_000) * in_rate * effective_read_mult
            if split_cache_write:
                call_dollars += (
                    (cache_write_5m_tok / 1_000_000) * in_rate
                    * _CACHE_WRITE_MULT_5M
                )
                call_dollars += (
                    (cache_write_1h_tok / 1_000_000) * in_rate
                    * _CACHE_WRITE_MULT_1H
                )
            else:
                write_mult = _cache_write_mult_from_ttl(cache_write_ttl)
                call_dollars += (
                    (cache_write_tok / 1_000_000) * in_rate * write_mult
                )
            call_dollars += (out_tok / 1_000_000) * out_rate
            call_dollars = _nonnegative_finite(call_dollars, "token charge")
            charge = TokenCharge(call_dollars, dict(pricing_evidence))
            self.input_tokens += in_tok
            self.cache_read_tokens += cache_read_tok
            self.cache_write_tokens += cache_write_tok
            self.output_tokens += out_tok

            self.pricing_evidence[quote.model_id] = dict(pricing_evidence)
            self.dollars += call_dollars
            failure = None
            try:
                self.check()
            except BudgetExceeded as exc:
                # A caller that durably records the already-incurred overrun
                # still needs the exact price evidence used by this mutation.
                exc.pricing_evidence = dict(pricing_evidence)
                exc.token_charge = charge
                failure = exc
            if operation is not None:
                self._token_operations[operation] = {
                    "request": request,
                    "dollars": call_dollars,
                    "pricing_evidence": dict(pricing_evidence),
                    "failure": None if failure is None else str(failure),
                }
            if failure is not None:
                raise failure
        return charge

    def record_tool_call(self) -> None:
        with self._lock:
            self._validate_integrity()
            self.tool_calls += 1
            self.check()

    def absorb(self, other: Budget) -> None:
        """Roll another Budget's consumption into this one atomically and
        enforce caps.

        Used when a child/attempt runs on its own Budget (e.g. best-of-N)
        and its spend must count against the parent cap. Replaces the raw
        ``self.dollars += other.dollars`` roll-up, which bypassed both the
        lock (lost updates under concurrency) and ``check()`` (so the
        parent silently busted its cap across attempts).
        """
        other._validate_integrity()
        with self._lock:
            self._validate_integrity()
            from .tenant.provider_admission import merge_budget
            merge_budget(self, other)
            self.input_tokens += other.input_tokens
            self.output_tokens += other.output_tokens
            self.cache_read_tokens += other.cache_read_tokens
            self.cache_write_tokens += other.cache_write_tokens
            self.dollars += other.dollars
            self.tool_calls += other.tool_calls
            self.pricing_evidence.update(other.pricing_evidence)
            self.check()

    def elapsed(self) -> float:
        # Use monotonic so NTP clock-skew doesn't bypass the wall
        # cap. `started_at` is captured in __post_init__ for monotonic.
        try:
            return time.monotonic() - self._started_monotonic
        except AttributeError:
            # Legacy path: dataclass instance created before __post_init__
            # extension landed. Fall back to wall clock.
            return time.time() - self.started_at

    def remaining_wall(self) -> float:
        """Seconds left before the wall-clock cap (<= 0 means already over).

        Lets a caller bound an in-flight async await (e.g. an LLM generation)
        so the wall cap is HARD — interrupting a long generation — rather than
        only checked at turn boundaries."""
        return (self.max_wall_seconds - self.elapsed()
                if self.max_wall_seconds is not None else math.inf)

    def __post_init__(self) -> None:
        self._started_monotonic = time.monotonic()
        # Per-instance lock for atomic counter updates.
        self._lock = threading.Lock()
        # Dollar cost of in-flight calls, held by reserve() until release().
        # Lets concurrent sub-agents sharing one budget account for each
        # other's pending spend instead of all passing the same check and
        # then collectively overshooting the cap.
        self._reserved = 0.0
        # Operation receipts make a durable/pickled Budget idempotent across an
        # outcome-ledger append failure and exact retry.
        self._token_operations: dict[str, dict[str, object]] = {}
        # A non-finite cap (nan/inf) silently disables enforcement: every
        # `self.dollars > nan` comparison in check() is False, so the cap
        # never trips. TOML 1.0 has native nan/inf and `--max-dollars inf`
        # parses, so a cap could arrive non-finite from config or a flag.
        # Coerce any non-finite dollar/wall/token cap back to a safe default
        # rather than run uncapped. (Budget caps are not optional.)
        for _field, _default in (
            ("max_dollars", 5.0),
            ("max_wall_seconds", 3600.0),
            ("max_input_tokens", 1_000_000),
            ("max_output_tokens", 200_000),
        ):
            _v = getattr(self, _field)
            if _v is None:
                continue
            try:
                if not math.isfinite(float(_v)):
                    setattr(self, _field, _default)
            except (TypeError, ValueError):
                setattr(self, _field, _default)

    def __getstate__(self):
        """threading.Lock is unpicklable. Drop the
        non-picklable transient fields so a Budget can survive being
        sent to a multiprocessing worker (and the monotonic clock is
        per-process — reset on unpickle to avoid bogus elapsed math)."""
        with self._lock:
            self._validate_integrity()
            state = self.__dict__.copy()
            state.pop("_lock", None)
            # Preserve consumed wall time across process boundaries.
            # Monotonic baselines are process-local, so serialize elapsed
            # duration and reconstruct a compatible baseline on restore.
            state["_elapsed_at_pickle"] = self.elapsed()
            state.pop("_started_monotonic", None)
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        self.__dict__.setdefault("_token_operations", {})
        self._lock = threading.Lock()
        elapsed = _nonnegative_finite(
            self.__dict__.pop("_elapsed_at_pickle", 0.0) or 0.0,
            "serialized elapsed time",
        )
        self._started_monotonic = time.monotonic() - elapsed
        self._validate_integrity()

    def _validate_integrity(self) -> None:
        """Fail closed when live or restored accounting state is malformed."""

        for field_name in (
            "input_tokens",
            "output_tokens",
            "cache_read_tokens",
            "cache_write_tokens",
            "tool_calls",
        ):
            _nonnegative_integer(getattr(self, field_name), field_name.replace("_", " "))
        for field_name in ("max_input_tokens", "max_output_tokens", "max_tool_calls"):
            if getattr(self, field_name) is not None:
                _nonnegative_integer(getattr(self, field_name), field_name.replace("_", " "))
        for field_name in ("dollars",):
            _nonnegative_finite(getattr(self, field_name), field_name.replace("_", " "))
        for field_name in ("max_dollars", "max_wall_seconds"):
            if getattr(self, field_name) is not None:
                _nonnegative_finite(getattr(self, field_name), field_name.replace("_", " "))
        _nonnegative_finite(getattr(self, "_reserved", 0.0), "reserved dollars")
        _validate_token_operations(getattr(self, "_token_operations", {}))

    def check(self) -> None:
        self._validate_integrity()
        if self.max_input_tokens is not None and self.input_tokens > self.max_input_tokens:
            raise BudgetExceeded(f"input tokens {self.input_tokens} > {self.max_input_tokens}")
        if self.max_output_tokens is not None and self.output_tokens > self.max_output_tokens:
            raise BudgetExceeded(f"output tokens {self.output_tokens} > {self.max_output_tokens}")
        if self.max_dollars is not None and self.dollars > self.max_dollars:
            raise BudgetExceeded(f"${self.dollars:.2f} > ${self.max_dollars:.2f}")
        if self.max_tool_calls is not None and self.tool_calls > self.max_tool_calls:
            raise BudgetExceeded(f"tool calls {self.tool_calls} > {self.max_tool_calls}")
        elapsed = _nonnegative_finite(self.elapsed(), "elapsed wall time")
        if self.max_wall_seconds is not None and elapsed >= self.max_wall_seconds:
            raise BudgetExceeded(
                f"wall time {elapsed:.0f}s >= {self.max_wall_seconds:.0f}s"
            )

    def check_projected(self, est_cost: float) -> None:
        """Raise BEFORE a call whose estimated cost would push spend over the
        dollar cap.

        ``check()`` only fires once ``dollars`` ALREADY exceeds the cap, so a
        single huge-context call -- or several concurrent sub-agent calls on a
        shared budget -- can blow far past ``max_dollars`` before the next check
        trips (observed: a $2.50 cap reached $6.81 with parallel Opus/Sonnet
        researchers on 200k-token contexts). Gating each dispatch on its
        projected cost bounds the overshoot to roughly the in-flight set.
        """
        est = _nonnegative_finite(est_cost, "projected call cost")
        if est == 0:
            return
        with self._lock:
            self._validate_integrity()
            projected = self.dollars + getattr(self, "_reserved", 0.0) + est
            if self.max_dollars is not None and projected > self.max_dollars:
                raise BudgetExceeded(
                    f"projected ${projected:.2f} > ${self.max_dollars:.2f} "
                    f"(spent ${self.dollars:.2f} + est ${est:.2f} for this call)"
                )

    def reserve(self, est_cost: float) -> float:
        """Atomically hold ``est_cost`` against the cap for an in-flight call;
        return the amount held (0.0 if non-positive). Raises ``BudgetExceeded``
        if spent + already-held + est would exceed the dollar cap -- so N
        concurrent sub-agent calls on a shared budget can't each pass an
        individual check and then collectively blow past it (a $2.50 cap hit
        $6+ with a wide parallel fan-out). Pair every successful reserve() with
        a release() in a ``finally``.
        """
        est = _nonnegative_finite(est_cost, "projected call cost")
        if est == 0.0:
            return 0.0
        with self._lock:
            self._validate_integrity()
            held = getattr(self, "_reserved", 0.0)
            projected = self.dollars + held + est
            if self.max_dollars is not None and projected > self.max_dollars:
                raise BudgetExceeded(
                    f"projected ${projected:.2f} > ${self.max_dollars:.2f} "
                    f"(spent ${self.dollars:.2f} + in-flight ${held:.2f} "
                    f"+ est ${est:.2f} for this call)"
                )
            self._reserved = held + est
            return est

    def release(self, held: float) -> None:
        """Release a hold taken by reserve(). Safe to call with 0.0."""
        amount = _nonnegative_finite(held, "released reservation")
        if amount == 0:
            return
        with self._lock:
            self._validate_integrity()
            self._reserved = max(0.0, getattr(self, "_reserved", 0.0) - amount)

    def cache_hit_rate(self) -> float:
        """Fraction of prompt-input tokens served from cache this run, across
        ALL providers (Anthropic ephemeral, OpenAI/Gemini auto-cache).

        ``cache_read / (cache_read + billable_input)`` — the consolidated
        signal there was no single cross-provider view of before (each
        provider's cache was its own ledger). 0.0 when nothing was sent."""
        seen = self.input_tokens + self.cache_read_tokens
        return (self.cache_read_tokens / seen) if seen else 0.0

    def cache_stats(self) -> dict:
        """Read-only cross-provider cache accounting for this run."""
        return {
            "cache_read_tokens": self.cache_read_tokens,
            "cache_write_tokens": self.cache_write_tokens,
            "billable_input_tokens": self.input_tokens,
            "hit_rate": self.cache_hit_rate(),
        }

    def pricing_snapshot(self) -> dict[str, dict[str, object]]:
        """Copy of the rate provenance supporting this Budget's dollar total."""

        with self._lock:
            return {
                model_id: dict(evidence)
                for model_id, evidence in self.pricing_evidence.items()
            }

    def summary(self) -> str:
        return (
            f"tokens in={self.input_tokens} out={self.output_tokens} "
            f"cache_read={self.cache_read_tokens} hit_rate={self.cache_hit_rate():.0%} "
            f"$={self.dollars:.3f} tools={self.tool_calls} wall={self.elapsed():.0f}s"
        )


_BUDGET_KEY_TYPES = {
    "max_input_tokens": int,
    "max_output_tokens": int,
    "max_dollars": float,
    "max_wall_seconds": float,
    "max_tool_calls": int,
}


def _configured_task_limits(cfg: dict) -> dict:
    limits = {}
    for key, caster in _BUDGET_KEY_TYPES.items():
        if cfg.get(key) is None:
            continue
        try:
            if isinstance(cfg[key], bool):
                raise ValueError("boolean limit")
            cast = caster(cfg[key])
            if not math.isfinite(cast) or cast < 0:
                raise ValueError("invalid limit")
            limits[key] = cast
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError(f"budget.{key} must be a finite non-negative limit") from exc
    return limits


def resolve_budget_caps(*, defaults: dict | None = None,
                        task_class: str | None = None, **overrides) -> dict:
    """Resolve the configured caps without reserving anything.

    The precedence :func:`budget_from_config` documents, stopped before the
    organization preflight and physical-call admission, so a caller can learn the
    deployment's ceiling (for example the largest per-attempt limit the
    dashboard may accept) without holding tenant allowance for a run that has
    not started.
    """
    kwargs: dict = {}
    # Lowest precedence: a learned per-task-class default cap (opt-in). Seeds
    # max_dollars so `defaults`/config/overrides below still win if they set it.
    if task_class:
        try:
            from .self_tuning_budget import suggested_max_dollars
            learned = suggested_max_dollars(task_class)
            if learned is not None:
                kwargs["max_dollars"] = float(learned)
        except Exception:  # pragma: no cover -- self-tuning never blocks a run
            pass
    if defaults:
        for key, val in defaults.items():
            if key in _BUDGET_KEY_TYPES and val is not None:
                kwargs[key] = val
    try:
        from .config import config_source_errors, get_budget_overrides
        cfg = get_budget_overrides() or {}
        if config_source_errors():
            raise ValueError("task budget configuration is unavailable")
    except Exception as exc:
        raise ValueError("task budget configuration is unavailable") from exc
    from .runtime_overrides import task_limits_override

    enabled = task_limits_override()
    if enabled is None:
        enabled = cfg.get("task_limits_enabled", True)
    if type(enabled) is not bool:
        raise ValueError("budget.task_limits_enabled must be true or false")
    if not enabled:
        kwargs.clear()
    if enabled:
        kwargs.update(_configured_task_limits(cfg))
    # Dashboard-set spend cap (settings page; lives in runtime-overrides.toml,
    # never config.toml). A live UI choice sits above [budget] config, below an
    # explicit per-call override / env flag.
    dash_cap = budget_override()
    if enabled and dash_cap is not None:
        kwargs["max_dollars"] = dash_cap
    # Env override for the documented MAVERICK_BUDGET_DOLLARS. The cookbooks
    # use `MAVERICK_BUDGET_DOLLARS=0.5 maverick start ...` to cap a single
    # invocation, but nothing read it -- so the cap silently did nothing and
    # users ran at the default. Sits above [budget] config, below an explicit
    # CLI override (--max-dollars). Malformed / non-finite -> keep prior layer.
    env_dollars = os.environ.get("MAVERICK_BUDGET_DOLLARS")
    if env_dollars:
        try:
            cast = float(env_dollars)
            if not math.isfinite(cast) or cast < 0:
                raise ValueError("invalid limit")
            kwargs["max_dollars"] = cast
        except (TypeError, ValueError) as exc:
            raise ValueError("MAVERICK_BUDGET_DOLLARS must be a finite non-negative limit") from exc
    for key, val in overrides.items():
        if val is not None and key in _BUDGET_KEY_TYPES:
            kwargs[key] = val
    _clamp_to_containment(kwargs)
    return kwargs


def _clamp_to_containment(kwargs: dict) -> None:
    """Containment mode caps every task's running time; it never raises one."""
    from .containment import active_profile

    profile = active_profile()
    if profile is None:
        return
    cap = float(profile.max_wall_seconds)
    current = kwargs.get("max_wall_seconds")
    if current is None or float(current) > cap:
        kwargs["max_wall_seconds"] = cap


def budget_from_config(*, defaults: dict | None = None,
                       task_class: str | None = None, **overrides) -> Budget:
    """Build a Budget that honors the ``[budget]`` section of config.toml.

    Precedence, lowest to highest:
      learned **self-tuning** suggestion for ``task_class`` (opt-in; only when
      that class has enough history) < ``defaults`` (a caller's own fallback,
      e.g. the background runner's conservative caps) < the ``[budget]`` config
      section < explicit ``overrides`` (e.g. a CLI ``--max-dollars`` flag). A
      ``None`` value in either ``defaults`` or ``overrides`` is treated as
      "unset", so a caller can pass an optional flag straight through.

    The self-tuning layer is the *lowest* precedence: it only fills
    ``max_dollars`` when nothing more explicit set it, so an operator's
    configured cap always wins. Off by default (``[budget] self_tuning``).

    ``config.get_budget_overrides()`` already existed but was never wired,
    so the ``[budget]`` section had no effect on any run. This is the single
    funnel that fixes that; malformed explicit values fail before the run.
    """
    kwargs = resolve_budget_caps(
        defaults=defaults, task_class=task_class, **overrides
    )
    reservation_id, refusal = _clamp_to_tenant_remainder(kwargs)
    budget = Budget(**kwargs)
    if not refusal:
        from .tenant.provider_admission import initialize_budget
        initialize_budget(budget)
    if reservation_id:
        # Handle so the run can release the tenant hold when it records its
        # actual spend: ``quotas.record_usage(..., reservation_id=b._tenant_reservation_id)``.
        budget._tenant_reservation_id = reservation_id
    if refusal:
        # The tenant allowance is exhausted (or unreadable). Carry the reason
        # without changing the task's own limits, so the run gate refuses
        # cleanly BEFORE the goal starts instead of admitting a run that dies
        # on its first model call with "budget exceeded".
        budget._tenant_refusal = refusal
    return budget


def _clamp_to_tenant_remainder(kwargs: dict) -> tuple[str | None, str | None]:
    """Preflight organization policy without allocating an arbitrary task cap.

    Per-physical-call durable admission enforces the aggregate ceiling. Merely
    constructing an uncapped or capped Budget consumes no organization funds.
    Explicit task limits remain independent, including an uncapped None value.
    """
    del kwargs  # compatibility signature; organization policy never rewrites task limits
    try:
        from .paths import current_tenant_id_strict
        from .tenant.registry import tenant_over_quota
        tenant = current_tenant_id_strict()
        return None, tenant_over_quota(tenant) if tenant else None
    except Exception as exc:
        log.error("tenant budget policy unavailable: %s", exc)
        return None, f"tenant budget policy unavailable: {exc}"
