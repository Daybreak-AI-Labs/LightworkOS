"""Versioned, provenance-carrying model pricing contracts.

The pricing layer deliberately distinguishes two uses:

``billing``
    A rate may affect a spend cap, chargeback, or invoice.  Only a rate whose
    source has been verified may be returned.

``estimate``
    A planning-only projection.  Provisional rates may be returned, but the
    caller must opt in explicitly.

This module contains no vendor rates. :mod:`maverick.llm` owns the built-in
rate card and exposes its legacy ``MODEL_PRICES`` tuple mapping as a
compatibility view. Billing and routing code use the provider here so the
metadata cannot be accidentally discarded at the trust boundary.
"""
from __future__ import annotations

import json
import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from datetime import date, datetime, timezone
from enum import Enum
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType


class PriceUse(str, Enum):
    """The trust level required by a pricing lookup."""

    BILLING = "billing"
    ESTIMATE = "estimate"


class PricingError(ValueError):
    """Base class for invalid or unusable pricing data."""


class UnverifiedRateError(PricingError):
    """A provisional rate was requested for billing-grade use."""


@dataclass(frozen=True, slots=True)
class ModelPrice:
    """One immutable price quote and the evidence needed to trust it.

    Rates are denominated per million tokens.  ``as_of`` is the date the price
    is stated to apply; ``fetched_at`` is when its source was captured.
    ``confidence`` is a bounded 0..1 assessment, separate from the hard
    ``verified`` gate: a high-confidence estimate is still not billable.
    """

    model_id: str
    input_per_mtok: float
    output_per_mtok: float
    source: str
    as_of: str
    fetched_at: str
    currency: str
    confidence: float
    verified: bool
    rate_card_version: str
    evidence_id: str
    pricing_basis: str
    applicability: str
    valid_until: str | None = None

    def __post_init__(self) -> None:
        if not self.model_id.strip():
            raise PricingError("model_id must be non-empty")
        for name in ("input_per_mtok", "output_per_mtok"):
            value = float(getattr(self, name))
            if not math.isfinite(value) or value < 0:
                raise PricingError(f"{name} must be finite and non-negative")
        if not self.source.strip():
            raise PricingError("price source must be non-empty")
        try:
            date.fromisoformat(self.as_of)
        except (TypeError, ValueError) as exc:
            raise PricingError("as_of must be an ISO-8601 date") from exc
        _validate_expiry(self.as_of, self.valid_until)
        try:
            fetched = datetime.fromisoformat(self.fetched_at.replace("Z", "+00:00"))
        except (AttributeError, TypeError, ValueError) as exc:
            raise PricingError("fetched_at must be an ISO-8601 datetime") from exc
        if fetched.tzinfo is None:
            raise PricingError("fetched_at must include a timezone")
        if len(self.currency) != 3 or self.currency != self.currency.upper():
            raise PricingError("currency must be an uppercase ISO-4217 code")
        if not math.isfinite(self.confidence) or not 0.0 <= self.confidence <= 1.0:
            raise PricingError("confidence must be between 0 and 1")
        if not isinstance(self.verified, bool):
            raise PricingError("verified must be a boolean")
        if not self.rate_card_version.strip():
            raise PricingError("rate_card_version must be non-empty")
        if not self.evidence_id.strip():
            raise PricingError("evidence_id must be non-empty")
        if not self.pricing_basis.strip():
            raise PricingError("pricing_basis must be non-empty")
        if not self.applicability.strip():
            raise PricingError("applicability must be non-empty")

    @property
    def rates(self) -> tuple[float, float]:
        return self.input_per_mtok, self.output_per_mtok

    def metadata(self) -> dict[str, object]:
        """A JSON-safe evidence record suitable for budget receipts."""

        return asdict(self)


@dataclass(frozen=True, slots=True)
class RateEvidence:
    """One tracked source capture supporting one or more rate-card rows."""

    evidence_id: str
    source_url: str
    retrieved_at: str
    as_of: str
    currency: str
    confidence: float
    verified: bool
    pricing_basis: str
    applicability: str
    rates: Mapping[str, tuple[float, float]]
    model_pattern: str | None = None
    pattern_rates: tuple[float, float] | None = None
    valid_until: str | None = None

    def supports(self, quote: ModelPrice) -> bool:
        if quote.evidence_id != self.evidence_id:
            return False
        expected = self.rates.get(quote.model_id)
        if expected is None and self.model_pattern and self.pattern_rates is not None:
            if re.fullmatch(self.model_pattern, quote.model_id):
                expected = self.pattern_rates
        if expected is None:
            return False
        return (
            quote.rates == expected
            and quote.source == self.source_url
            and quote.fetched_at == self.retrieved_at
            and quote.as_of == self.as_of
            and quote.currency == self.currency
            and math.isclose(quote.confidence, self.confidence, abs_tol=1e-12)
            and quote.verified is self.verified
            and quote.pricing_basis == self.pricing_basis
            and quote.applicability == self.applicability
            and quote.valid_until == self.valid_until
        )


@dataclass(frozen=True, slots=True)
class PricingEvidencePack:
    schema_version: int
    rate_card_version: str
    entries: Mapping[str, RateEvidence]


def _validate_expiry(as_of: str, valid_until: str | None) -> None:
    if valid_until is None:
        return
    try:
        expires = date.fromisoformat(valid_until)
    except (TypeError, ValueError) as exc:
        raise PricingError("valid_until must be an ISO-8601 date") from exc
    if expires < date.fromisoformat(as_of):
        raise PricingError("valid_until must not precede as_of")


def _parse_evidence_entry(raw: object) -> RateEvidence:
    if not isinstance(raw, dict):
        raise PricingError("pricing evidence entry must be an object")
    raw_rates = raw.get("rates", {})
    if not isinstance(raw_rates, dict):
        raise PricingError("pricing evidence rates must be an object")
    rates: dict[str, tuple[float, float]] = {}
    for model_id, pair in raw_rates.items():
        if (
            not isinstance(model_id, str)
            or not isinstance(pair, list)
            or len(pair) != 2
        ):
            raise PricingError("pricing evidence rate must be [input, output]")
        try:
            parsed_pair = (float(pair[0]), float(pair[1]))
        except (TypeError, ValueError) as exc:
            raise PricingError(
                "pricing evidence rates must be numeric"
            ) from exc
        if any(not math.isfinite(value) or value < 0 for value in parsed_pair):
            raise PricingError(
                "pricing evidence rates must be finite and non-negative"
            )
        rates[model_id] = parsed_pair
    pattern_rates_raw = raw.get("pattern_rates")
    pattern_rates = None
    if pattern_rates_raw is not None:
        if not isinstance(pattern_rates_raw, list) or len(pattern_rates_raw) != 2:
            raise PricingError("pricing evidence pattern_rates must have two values")
        try:
            pattern_rates = (
                float(pattern_rates_raw[0]),
                float(pattern_rates_raw[1]),
            )
        except (TypeError, ValueError) as exc:
            raise PricingError(
                "pricing evidence pattern_rates must be numeric"
            ) from exc
        if any(not math.isfinite(value) or value < 0 for value in pattern_rates):
            raise PricingError(
                "pricing evidence pattern_rates must be finite and non-negative"
            )
    verified = raw.get("verified")
    if not isinstance(verified, bool):
        raise PricingError("pricing evidence verified must be a boolean")
    try:
        entry = RateEvidence(
            evidence_id=str(raw["evidence_id"]),
            source_url=str(raw["source_url"]),
            retrieved_at=str(raw["retrieved_at"]),
            as_of=str(raw["as_of"]),
            currency=str(raw["currency"]),
            confidence=float(raw["confidence"]),
            verified=verified,
            pricing_basis=str(raw["pricing_basis"]),
            applicability=str(raw["applicability"]),
            rates=MappingProxyType(rates),
            model_pattern=(
                str(raw["model_pattern"]) if raw.get("model_pattern") else None
            ),
            pattern_rates=pattern_rates,
            valid_until=raw.get("valid_until"),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise PricingError("malformed pricing evidence entry") from exc
    # Reuse ModelPrice's date/currency/confidence validation with an arbitrary
    # supported model/rate. Evidence with no exact or patterned rates is inert.
    if not entry.evidence_id or not entry.source_url:
        raise PricingError("pricing evidence id/source must be non-empty")
    if not entry.rates and not (entry.model_pattern and entry.pattern_rates):
        raise PricingError("pricing evidence entry has no supported rates")
    try:
        date.fromisoformat(entry.as_of)
        fetched = datetime.fromisoformat(entry.retrieved_at.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError) as exc:
        raise PricingError("pricing evidence dates must be ISO-8601") from exc
    if fetched.tzinfo is None:
        raise PricingError("pricing evidence retrieved_at needs a timezone")
    _validate_expiry(entry.as_of, entry.valid_until)
    if len(entry.currency) != 3 or entry.currency != entry.currency.upper():
        raise PricingError("pricing evidence currency must be ISO-4217")
    if (
        not math.isfinite(entry.confidence)
        or not 0.0 <= entry.confidence <= 1.0
    ):
        raise PricingError("pricing evidence confidence must be between 0 and 1")
    return entry


@lru_cache(maxsize=1)
def load_pricing_evidence_pack() -> PricingEvidencePack:
    """Load and validate the tracked evidence data shipped with the wheel."""

    # Namespace-package resources may resolve another distribution's empty
    # maverick directory in an editable install. Anchor data to this module.
    path = Path(__file__).resolve().parent / "data/pricing-rate-card-2026-07-29.json"
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PricingError("pricing evidence pack is unavailable or corrupt") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("entries"), list):
        raise PricingError("pricing evidence pack has an invalid root")
    entries: dict[str, RateEvidence] = {}
    for raw_entry in raw["entries"]:
        entry = _parse_evidence_entry(raw_entry)
        if entry.evidence_id in entries:
            raise PricingError(f"duplicate pricing evidence id: {entry.evidence_id}")
        entries[entry.evidence_id] = entry
    try:
        schema_version = int(raw["schema_version"])
        version = str(raw["rate_card_version"])
    except (KeyError, TypeError, ValueError) as exc:
        raise PricingError("pricing evidence pack metadata is invalid") from exc
    if schema_version != 1 or not version:
        raise PricingError("unsupported pricing evidence pack version")
    return PricingEvidencePack(
        schema_version=schema_version,
        rate_card_version=version,
        entries=MappingProxyType(entries),
    )


def assert_price_evidenced(
    quote: ModelPrice,
    evidence_pack: PricingEvidencePack,
) -> None:
    """Fail closed unless a quote exactly matches its tracked evidence row."""

    evidence = evidence_pack.entries.get(quote.evidence_id)
    if evidence is None or not evidence.supports(quote):
        raise PricingError(
            f"price for {quote.model_id!r} does not match tracked evidence "
            f"{quote.evidence_id!r}"
        )


class VersionedPricingProvider:
    """An immutable rate-card snapshot with a billing-grade verification gate."""

    def __init__(
        self,
        version: str,
        rates: Iterable[ModelPrice],
        *,
        evidence_pack: PricingEvidencePack | None = None,
    ) -> None:
        if not version.strip():
            raise PricingError("rate-card version must be non-empty")
        if evidence_pack is not None and evidence_pack.rate_card_version != version:
            raise PricingError(
                "pricing evidence pack and rate-card versions do not match"
            )
        by_model: dict[str, ModelPrice] = {}
        for rate in rates:
            if rate.rate_card_version != version:
                raise PricingError(
                    f"{rate.model_id!r} belongs to rate card "
                    f"{rate.rate_card_version!r}, expected {version!r}"
                )
            if rate.model_id in by_model:
                raise PricingError(f"duplicate model price: {rate.model_id!r}")
            if evidence_pack is not None:
                assert_price_evidenced(rate, evidence_pack)
            elif rate.verified:
                raise PricingError(
                    f"verified price for {rate.model_id!r} has no evidence pack"
                )
            by_model[rate.model_id] = rate
        self._version = version
        self._rates: Mapping[str, ModelPrice] = MappingProxyType(by_model)

    @property
    def version(self) -> str:
        return self._version

    @property
    def rates(self) -> Mapping[str, ModelPrice]:
        return self._rates

    def quote(
        self,
        model_id: str,
        *,
        use: PriceUse = PriceUse.BILLING,
    ) -> ModelPrice | None:
        """Return a quote, refusing provisional data for billing by default."""

        try:
            use = PriceUse(use)
        except ValueError as exc:
            raise PricingError(f"unsupported pricing use: {use!r}") from exc
        rate = self._rates.get(model_id)
        if rate is None:
            return None
        if (use is PriceUse.BILLING and rate.valid_until is not None
                and datetime.now(timezone.utc).date() > date.fromisoformat(rate.valid_until)):
            raise UnverifiedRateError(
                f"rate for {model_id!r} expired on {rate.valid_until}; refresh reviewed pricing before billing"
            )
        if use is PriceUse.BILLING and not rate.verified:
            raise UnverifiedRateError(
                f"rate for {model_id!r} is unverified "
                f"(source={rate.source!r}, as_of={rate.as_of}); "
                "it may only be used with PriceUse.ESTIMATE"
            )
        return rate


__all__ = [
    "ModelPrice",
    "PriceUse",
    "PricingEvidencePack",
    "PricingError",
    "RateEvidence",
    "UnverifiedRateError",
    "VersionedPricingProvider",
    "assert_price_evidenced",
    "load_pricing_evidence_pack",
]
