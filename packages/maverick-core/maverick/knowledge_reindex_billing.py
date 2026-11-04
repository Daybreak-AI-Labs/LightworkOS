"""One admitted hosted embedding batch; never retry an ambiguous physical call."""
from __future__ import annotations

import time

from . import provider_cost_cap as cap
from .budget import BudgetExceeded, UsageAccountingError


def contract_for(embedder):
    from maverick_knowledge.embed import CohereEmbedder, HostedEmbedder

    from .embedding_prices import resolve_embedding_contract

    if type(embedder) not in {HostedEmbedder, CohereEmbedder}:
        raise ValueError("This adapter has no verified per-request price and usage ceiling. Choose a supported standard endpoint in Knowledge settings.")
    provider = "cohere" if type(embedder) is CohereEmbedder else embedder.provider
    return resolve_embedding_contract(provider, embedder.model, embedder.base_url,
                                      input_type=getattr(embedder, "input_type", None))


def _usage(body, contract):
    if not isinstance(body, dict):
        raise UsageAccountingError("The provider returned no usable usage receipt.")
    try:
        count = body
        for field in contract.usage_path:
            count = count[field]
    except (KeyError, TypeError) as exc:
        raise UsageAccountingError("The provider omitted billed input usage.") from exc
    if type(count) is not int or not 0 <= count <= 2**53 - 1:
        raise UsageAccountingError("The provider reported invalid billed input usage.")
    if contract.provider == "openai" and (type(body["usage"].get("total_tokens")) is not int or body["usage"]["total_tokens"] != count):
        raise UsageAccountingError("The provider's input and total embedding usage disagree.")
    return count


def _vectors(body, provider, count):
    if provider == "cohere":
        # One vector per passage, like the indexed providers below: a short or
        # malformed batch fails here, not after every later batch was paid for.
        vectors = (body.get("embeddings") or {}).get("float") if isinstance(body, dict) else None
        if (not isinstance(vectors, list) or len(vectors) != count
                or any(not isinstance(row, list) or not row for row in vectors)):
            raise ValueError("The provider returned an incomplete embedding set.")
        return vectors
    data = body["data"]
    if (not isinstance(data, list) or len(data) != count
            or any(not isinstance(row, dict) or type(row.get("index")) is not int for row in data)
            or {row["index"] for row in data} != set(range(count))):
        raise ValueError("The provider returned an incomplete or ambiguous embedding order.")
    return [row["embedding"] for row in sorted(data, key=lambda row: row["index"])]


def dispatch(embedder, texts, *, contract, budget, request_id, operation_id,
             attempt_no, deadline, before_dispatch, accounted):
    """Reserve before transport; record native usage even if vectors are invalid.

    A failure retains the provider/organization hold. A caller may persist a
    successful batch only after both accounting authorities acknowledge it.
    """
    if not texts or any(not isinstance(text, str) or not text for text in texts):
        raise ValueError("Empty passages cannot be sent to a paid embedding service.")
    current = contract_for(embedder)
    if current.metadata() != contract.metadata():
        raise ValueError("The reviewed embedding price or request contract changed.")
    ceiling = contract.token_ceiling(len(texts))
    projected = ceiling * contract.quote.input_per_mtok / 1_000_000
    # The provider authority also consults personal/workspace limits using this
    # cumulative budget. Reserve locally afterwards to avoid counting this
    # batch twice during native admission.
    budget.check_projected(projected)
    held = 0.0
    hold = None
    dispatched = False
    settlement_started = False
    try:
        hold = cap.reserve(
            contract.provider, projected, request_id=request_id,
            operation_id=operation_id, category="other", parent_category="other",
            attempt_no=attempt_no, service=f"embeddings:{embedder.model}",
            organization_budget=budget,
        )
        if hold is None:
            raise cap.ProviderAccountingUnavailable
        held = budget.reserve(projected)
        reference = cap.reservation_reference(hold)
        before_dispatch(reference, projected)
        remaining = deadline - time.time()
        if remaining <= 0:
            raise BudgetExceeded("The reviewed rebuild time limit was reached.")
        budget.check()
        dispatched = True
        body = embedder._bounded_response(texts, timeout=min(60.0, remaining))
        if (not isinstance(body, dict)
                or body.get("model", None if contract.provider == "openai" else embedder.model) != embedder.model):
            raise UsageAccountingError("The provider returned a different or unidentifiable embedding model.")
        tokens = _usage(body, contract)
        failure = None
        try:
            charge = budget.record_tokens(tokens, 0, model=contract.quote.model_id)
        except BudgetExceeded as exc:
            charge = getattr(exc, "token_charge", None)
            if charge is None:
                raise
            failure = exc
        settlement_started = True
        snapshot = cap.settle(hold, charge.dollars, cost_basis="observed",
                              pricing_evidence=charge.pricing_evidence, attempt_state="succeeded")
        _acknowledge_usage(budget)
        accounted(charge.dollars, tokens, snapshot.reference)
        if tokens > ceiling:
            raise UsageAccountingError("The provider exceeded its reviewed input-usage contract; no further batch will be sent.")
        if failure is not None:
            raise failure
        return _vectors(body, contract.provider, len(texts))
    except BaseException:
        if hold is not None and not settlement_started:
            # Before transport zero is known; after transport failure is NOT free.
            cap.settle(hold, None if dispatched else 0.0,
                       **({} if dispatched else {"cost_basis": "observed", "pricing_evidence": contract.quote.metadata()}),
                       attempt_state="failed")
        raise
    finally:
        budget.release(held)


def _acknowledge_usage(budget):
    from .quotas import record_usage
    from .spending_limits import mark_recorded
    from .tenant.provider_admission import acknowledge_budget, prepare_budget

    principal = budget._organization_principal
    scope = budget._organization_scope
    dollars = prepare_budget(budget, principal, scope, budget.dollars)
    if not record_usage(principal, dollars, budget.input_tokens, 0, settlement_id=scope):
        raise cap.ProviderAccountingUnavailable
    acknowledge_budget(budget, principal, scope)
    mark_recorded(budget)
