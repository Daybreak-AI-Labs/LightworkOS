"""Reviewed standard-price contracts for direct, text-only embedding calls.

Prices and input limits were read from the linked first-party pages on
2026-11-02 (unchanged from the 2026-10-01 capture). The expiry is Lightwork's freshness policy, not a vendor promise.
These quotes exclude tax, credits, discounts and account-specific agreements;
they meter documented input usage at the captured standard list rate. They do
not establish an absolute vendor-invoice maximum or live-service qualification.

The per-item context limit is a conservative bound on *accepted* input only
when the native transport disables truncation and verifies returned usage.
No character/byte estimate or chat-model price is substituted. The caller must
also bind the exact native adapter, request, endpoint and model to its review.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone
from types import MappingProxyType

from .pricing import (
    ModelPrice,
    PricingError,
    PricingEvidencePack,
    RateEvidence,
    VersionedPricingProvider,
)

RATE_CARD_VERSION = "embedding-direct-text-2026-11-02.1"
_AS_OF = "2026-11-02"
_FETCHED_AT = "2026-11-02T16:11:35Z"
_VALID_UNTIL = "2026-12-02"
_VOYAGE_PRICING = "https://docs.voyageai.com/docs/pricing"
_VOYAGE_LIMITS = "https://docs.voyageai.com/docs/embeddings"
_OPENAI_LIMITS = (
    "https://developers.openai.com/api/reference/resources/embeddings/methods/create"
)
_BASIS = "Standard direct text embedding input tokens; USD per million tokens"
_SCOPE = (
    "Direct synchronous text-only endpoint at captured standard list price; "
    "excludes tax, credits, discounts, custom agreements, images and Batch API. "
    "The validity deadline is Lightwork's review policy, not vendor rate protection."
)


def _utc_today() -> date:
    return datetime.now(timezone.utc).date()


@dataclass(frozen=True, slots=True)
class EmbeddingPriceContract:
    """Immutable exact-route rate and accepted-input contract."""

    provider: str
    model: str
    endpoint: str
    adapter: str
    quote: ModelPrice
    max_input_tokens_per_item: int
    max_batch_inputs: int
    max_batch_tokens: int | None
    limit_source: str
    truncation_parameter: str | None
    truncation_value: bool | str | None
    usage_path: tuple[str, ...]
    input_types: tuple[str | None, ...] = (None,)

    def require_current(self) -> None:
        current = _utc_today()
        if current < date.fromisoformat(self.quote.as_of):
            raise PricingError("Embedding pricing capture is in the future.")
        if (self.quote.valid_until is None
                or current > date.fromisoformat(self.quote.valid_until)):
            raise PricingError("Embedding pricing evidence expired; refresh the reviewed contract.")

    def token_ceiling(self, item_count: int) -> int:
        """Upper bound for one accepted batch, not an invoice guarantee."""
        self.require_current()
        if type(item_count) is not int or not 0 <= item_count <= self.max_batch_inputs:
            raise PricingError("Embedding batch size is outside the reviewed input limit.")
        ceiling = item_count * self.max_input_tokens_per_item
        return min(ceiling, self.max_batch_tokens) if self.max_batch_tokens else ceiling

    def metadata(self) -> dict[str, object]:
        """Serializable evidence for the exact preview and durable receipt."""
        return {
            "provider": self.provider,
            "model": self.model,
            "endpoint": self.endpoint,
            "adapter": self.adapter,
            "quote": self.quote.metadata(),
            "max_input_tokens_per_item": self.max_input_tokens_per_item,
            "max_batch_inputs": self.max_batch_inputs,
            "max_batch_tokens": self.max_batch_tokens,
            "limit_source": self.limit_source,
            "truncation_parameter": self.truncation_parameter,
            "truncation_value": self.truncation_value,
            "usage_path": list(self.usage_path),
            "input_types": list(self.input_types),
            "bound_basis": "Accepted input context limit per item; truncation disabled",
            "invoice_qualified": False,
        }


def _evidence(provider: str, model: str, rate: float, source: str) -> RateEvidence:
    return RateEvidence(
        evidence_id=f"embedding-{provider}-{model}-{_AS_OF}",
        source_url=source,
        retrieved_at=_FETCHED_AT,
        as_of=_AS_OF,
        currency="USD",
        confidence=1.0,
        verified=True,
        pricing_basis=_BASIS,
        applicability=_SCOPE,
        rates=MappingProxyType({f"embedding:{provider}:{model}": (rate, 0.0)}),
        valid_until=_VALID_UNTIL,
    )


def _quote(evidence: RateEvidence) -> ModelPrice:
    model_id, rates = next(iter(evidence.rates.items()))
    return ModelPrice(
        model_id=model_id,
        input_per_mtok=rates[0],
        output_per_mtok=rates[1],
        source=evidence.source_url,
        as_of=evidence.as_of,
        fetched_at=evidence.retrieved_at,
        currency=evidence.currency,
        confidence=evidence.confidence,
        verified=evidence.verified,
        rate_card_version=RATE_CARD_VERSION,
        evidence_id=evidence.evidence_id,
        pricing_basis=evidence.pricing_basis,
        applicability=evidence.applicability,
        valid_until=evidence.valid_until,
    )


# Voyage documents literal per-item limits but uses abbreviated aggregate
# limits (120K/320K/1M), and omits the aggregate for voyage-3/-lite. Reserve
# the full per-item bound rather than interpret those aggregate abbreviations.
_VOYAGE_ROWS = (
    ("voyage-3", 0.06, 32_000, None),
    ("voyage-3-lite", 0.02, 32_000, None),
    ("voyage-3-large", 0.18, 32_000, None),
    ("voyage-3.5", 0.06, 32_000, None),
    ("voyage-3.5-lite", 0.02, 32_000, None),
    ("voyage-4", 0.06, 32_000, None),
    ("voyage-4-lite", 0.02, 32_000, None),
    ("voyage-4-large", 0.12, 32_000, None),
    ("voyage-code-3", 0.18, 32_000, None),
    ("voyage-finance-2", 0.12, 32_000, None),
    ("voyage-law-2", 0.12, 16_000, None),
    ("voyage-multilingual-2", 0.12, 32_000, None),
)
_OPENAI_ROWS = (
    ("text-embedding-3-small", 0.02),
    ("text-embedding-3-large", 0.13),
    ("text-embedding-ada-002", 0.10),
)


def _build_contracts():
    contracts = []
    evidence_rows = []
    for model, rate, context_limit, batch_limit in _VOYAGE_ROWS:
        evidence = _evidence("voyage", model, rate, _VOYAGE_PRICING)
        evidence_rows.append(evidence)
        contracts.append(EmbeddingPriceContract(
            "voyage", model, "https://api.voyageai.com/v1",
            "maverick_knowledge.embed.HostedEmbedder", _quote(evidence),
            context_limit, 1000, batch_limit, _VOYAGE_LIMITS,
            "truncation", False, ("usage", "total_tokens"),
        ))
    for model, rate in _OPENAI_ROWS:
        source = f"https://developers.openai.com/api/docs/models/{model}"
        evidence = _evidence("openai", model, rate, source)
        evidence_rows.append(evidence)
        contracts.append(EmbeddingPriceContract(
            "openai", model, "https://api.openai.com/v1",
            "maverick_knowledge.embed.HostedEmbedder", _quote(evidence),
            8192, 2048, 300_000, _OPENAI_LIMITS,
            None, None, ("usage", "prompt_tokens"),
        ))
    pack = PricingEvidencePack(
        schema_version=1, rate_card_version=RATE_CARD_VERSION,
        entries=MappingProxyType({row.evidence_id: row for row in evidence_rows}),
    )
    pricing = VersionedPricingProvider(
        RATE_CARD_VERSION, (row.quote for row in contracts), evidence_pack=pack,
    )
    return MappingProxyType({(row.provider, row.model): row for row in contracts}), pricing


_CONTRACTS, _PRICING = _build_contracts()


def resolve_embedding_contract(
    provider: str, model: str, endpoint: str, *, input_type: str | None = None,
) -> EmbeddingPriceContract:
    """Resolve exact documented combinations; never infer a provider by substring."""
    if not all(type(value) is str for value in (provider, model, endpoint)):
        raise PricingError("Embedding provider, model and endpoint must be explicit.")
    contract = _CONTRACTS.get((provider, model))
    if contract is None:
        raise PricingError(
            "No reviewed standard embedding price and input contract for this model; "
            "obtain current official rate evidence or a separately verified agreement."
        )
    if endpoint.rstrip("/") != contract.endpoint or input_type not in contract.input_types:
        raise PricingError("Embedding endpoint or input mode is outside the reviewed contract.")
    contract.require_current()
    return contract


def quote_for_budget(model_id: str) -> ModelPrice:
    """Resolve only explicit embedding namespaces, including the freshness gate."""
    if type(model_id) is not str or not model_id.startswith("embedding:"):
        raise PricingError("An exact namespaced embedding price is required.")
    # The provider has already validated exact source agreement at import.
    # Use this module's single UTC freshness gate for both admission and billing.
    quote = _PRICING.rates.get(model_id)
    if quote is None:
        raise PricingError("No reviewed price for this namespaced embedding model.")
    _, provider, model = model_id.split(":", 2)
    _CONTRACTS[(provider, model)].require_current()
    return quote


__all__ = [
    "EmbeddingPriceContract", "RATE_CARD_VERSION", "quote_for_budget",
    "resolve_embedding_contract",
]
