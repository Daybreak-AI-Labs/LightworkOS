"""No transport or provider calls: exact sourced embedding price admission."""
import json
from dataclasses import FrozenInstanceError
from datetime import date, timedelta

import pytest
from maverick import embedding_prices as prices
from maverick.pricing import PricingError

# The reviewed capture's own dates, so a refreshed capture needs no test edit.
CAPTURED = date.fromisoformat(prices._AS_OF)
EXPIRES = date.fromisoformat(prices._VALID_UNTIL)


@pytest.fixture(autouse=True)
def captured_day(monkeypatch):
    monkeypatch.setattr(prices, "_utc_today", lambda: CAPTURED)


def test_default_voyage_price_is_namespaced_and_keeps_full_context_bound():
    contract = prices.resolve_embedding_contract("voyage", "voyage-3", "https://api.voyageai.com/v1/")
    assert contract.quote.rates == (0.06, 0.0)
    assert contract.quote.model_id == "embedding:voyage:voyage-3"
    assert contract.token_ceiling(12) == 384_000
    assert contract.truncation_parameter == "truncation"
    assert contract.truncation_value is False
    assert contract.usage_path == ("usage", "total_tokens")
    assert prices.quote_for_budget(contract.quote.model_id) == contract.quote
    evidence = json.loads(json.dumps(contract.metadata()))
    assert evidence["quote"]["verified"] is True
    assert evidence["quote"]["valid_until"] == prices._VALID_UNTIL
    assert CAPTURED < EXPIRES <= CAPTURED + timedelta(days=31)
    assert evidence["invoice_qualified"] is False


@pytest.mark.parametrize("model,rate", [
    ("text-embedding-3-small", 0.02), ("text-embedding-3-large", 0.13),
    ("text-embedding-ada-002", 0.10),
])
def test_openai_exact_models_use_input_limits_and_request_aggregate(model, rate):
    contract = prices.resolve_embedding_contract("openai", model, "https://api.openai.com/v1")
    assert contract.quote.rates == (rate, 0.0)
    assert contract.token_ceiling(1) == 8192
    assert contract.token_ceiling(40) == 300_000
    assert contract.usage_path == ("usage", "prompt_tokens")


@pytest.mark.parametrize("endpoint", [
    "http://api.voyageai.com/v1", "https://api.voyageai.com.example.test/v1",
    "https://api.voyageai.com@other.test/v1", "https://api.voyageai.com/v1?proxy=1",
    "https://api.voyageai.com/v1#fragment", "https://api.voyageai.com:444/v1",
    "https://proxy.example.test/v1", "https://api.openai.com/v1",
])
def test_official_rate_never_applies_to_an_alternate_endpoint(endpoint):
    with pytest.raises(PricingError, match="endpoint"):
        prices.resolve_embedding_contract("voyage", "voyage-3", endpoint)


def test_unsupported_models_modes_and_bare_quotes_are_not_guessed():
    for provider, model, endpoint in [
        ("voyage", "voyage-new", "https://api.voyageai.com/v1"),
        ("cohere", "embed-v4.0", "https://api.cohere.com/v2"),
        ("openai", "gpt-4o", "https://api.openai.com/v1"),
    ]:
        with pytest.raises(PricingError, match="No reviewed"):
            prices.resolve_embedding_contract(provider, model, endpoint)
    with pytest.raises(PricingError, match="input mode"):
        prices.resolve_embedding_contract("voyage", "voyage-3", "https://api.voyageai.com/v1", input_type="document")
    for model in ["voyage-3", "openai:text-embedding-3-small", "embedding:cohere:embed-v4.0"]:
        with pytest.raises(PricingError):
            prices.quote_for_budget(model)


def test_contract_is_frozen_and_metadata_cannot_change_the_quote():
    contract = prices.resolve_embedding_contract("voyage", "voyage-3", "https://api.voyageai.com/v1")
    with pytest.raises(FrozenInstanceError):
        contract.max_input_tokens_per_item = 1
    metadata = contract.metadata()
    metadata["quote"]["input_per_mtok"] = 0
    assert contract.quote.input_per_mtok == 0.06


@pytest.mark.parametrize("count", [-1, True, 1.5, "2", 1001])
def test_batch_bound_rejects_invalid_counts(count):
    contract = prices.resolve_embedding_contract("voyage", "voyage-3", "https://api.voyageai.com/v1")
    with pytest.raises(PricingError, match="batch size"):
        contract.token_ceiling(count)


@pytest.mark.parametrize("day", [CAPTURED - timedelta(days=1), EXPIRES + timedelta(days=1)])
def test_stale_or_future_evidence_cannot_admit_or_meter(day, monkeypatch):
    contract = prices.resolve_embedding_contract("voyage", "voyage-3", "https://api.voyageai.com/v1")
    monkeypatch.setattr(prices, "_utc_today", lambda: day)
    with pytest.raises(PricingError):
        prices.resolve_embedding_contract("voyage", "voyage-3", "https://api.voyageai.com/v1")
    with pytest.raises(PricingError):
        prices.quote_for_budget(contract.quote.model_id)
    with pytest.raises(PricingError):
        contract.token_ceiling(1)
