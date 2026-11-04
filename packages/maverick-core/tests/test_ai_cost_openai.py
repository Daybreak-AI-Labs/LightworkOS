from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from maverick.ai_cost_collectors import (
    AICostCollectorConfigError,
    AICostCollectorLimitError,
    AICostCollectorNoData,
    AICostCollectorProtocolError,
    AICostCollectorTransportError,
    CollectorLimits,
)
from maverick.ai_cost_openai import (
    OPENAI_COSTS_DOCUMENTATION_URL,
    OPENAI_COSTS_ENDPOINT,
    OPENAI_MODEL_ATTRIBUTION_UNSUPPORTED,
    OPENAI_USAGE_DOCUMENTATION_URL,
    OpenAIOrganizationCostCollector,
)
from maverick.ai_cost_roi import BillingProvider, CollectionRequest


def _stamp(day: int) -> int:
    return int(datetime(2026, 1, day, tzinfo=timezone.utc).timestamp())


REQUEST = CollectionRequest(
    period_start="2026-01-01T00:00:00Z",
    period_end="2026-01-03T00:00:00Z",
)
CLOCK = float(_stamp(4))


def _result(
    *,
    value: object = 0.06,
    currency: str = "usd",
    line_item: str | None = "Text models",
    project_id: str | None = "proj-sensitive-one",
    quantity: object | None = 1500.5,
    quantity_unit: str | None = "1000_tokens",
    **extra: Any,
) -> dict[str, Any]:
    return {
        "object": "organization.costs.result",
        "amount": {"value": value, "currency": currency},
        "line_item": line_item,
        "project_id": project_id,
        "api_key_id": None,
        "quantity": quantity,
        "quantity_unit": quantity_unit,
        **extra,
    }


def _bucket(day: int, results: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    return {
        "object": "bucket",
        "start_time": _stamp(day),
        "end_time": _stamp(day + 1),
        "results": results,
        **extra,
    }


def _page(
    buckets: list[dict[str, Any]],
    *,
    has_more: bool = False,
    next_page: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    return {
        "object": "page",
        "data": buckets,
        "has_more": has_more,
        "next_page": next_page,
        **extra,
    }


@dataclass(frozen=True)
class FakeResponse:
    status_code: int
    headers: Mapping[str, str]
    body: bytes
    url: str = ""


def _response(payload: Any, *, status: int = 200, url: str = "") -> FakeResponse:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return FakeResponse(
        status_code=status,
        headers={
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
        },
        body=body,
        url=url,
    )


class FakeTransport:
    def __init__(
        self,
        responses: list[FakeResponse] | None = None,
        *,
        error: Exception | None = None,
    ) -> None:
        self.responses = list(responses or [])
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        timeout: float,
        allow_redirects: bool,
        max_response_bytes: int,
    ) -> FakeResponse:
        self.calls.append(
            {
                "url": url,
                "headers": dict(headers),
                "timeout": timeout,
                "allow_redirects": allow_redirects,
                "max_response_bytes": max_response_bytes,
            }
        )
        if self.error is not None:
            raise self.error
        response = self.responses.pop(0)
        return response if response.url else replace(response, url=url)


def _collector(transport: FakeTransport, **kwargs: Any) -> OpenAIOrganizationCostCollector:
    clock = kwargs.pop("clock", lambda: CLOCK)
    return OpenAIOrganizationCostCollector(
        organization_ref="org-sensitive-primary",
        enabled=True,
        transport=transport,
        clock=clock,
        **kwargs,
    )


def test_collects_complete_paginated_window_and_pseudonymizes_identifiers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "sk-admin-must-never-persist"
    monkeypatch.setenv("OPENAI_ADMIN_KEY", secret)
    first = _page(
        [_bucket(1, [_result()])],
        has_more=True,
        next_page="page_AAAA-safe/opaque=",
    )
    second = _page(
        [
            _bucket(
                2,
                [
                    _result(
                        value=1.25,
                        currency="eur",
                        project_id="proj-sensitive-two",
                        quantity=None,
                        quantity_unit=None,
                    )
                ],
            )
        ]
    )
    transport = FakeTransport([_response(first), _response(second)])
    collector = _collector(transport)

    collection = collector.collect(REQUEST)

    assert collection.provider is BillingProvider.OPENAI
    assert collection.source_account_id.startswith("OPENAI-ORG-")
    assert len(collection.records) == 2
    usd = next(record for record in collection.records if record.currency == "USD")
    eur = next(record for record in collection.records if record.currency == "EUR")
    assert usd.cost == "0.06"
    assert usd.usage[0].quantity == "1500.5"
    assert usd.usage[0].unit == "1000_tokens"
    assert OPENAI_MODEL_ATTRIBUTION_UNSUPPORTED in usd.service
    assert usd.resource_id.startswith("OPENAI-PROJECT-")
    assert eur.cost == "1.25"
    assert eur.usage[0].metric == "provider-reported-cost; quantity-unsupported"
    assert eur.usage[0].quantity == "1.25"
    assert eur.usage[0].unit == "EUR"
    assert collection.manifest_citation.uri == OPENAI_COSTS_ENDPOINT

    first_query = parse_qs(urlsplit(transport.calls[0]["url"]).query)
    second_query = parse_qs(urlsplit(transport.calls[1]["url"]).query)
    assert first_query == {
        "start_time": [str(_stamp(1))],
        "end_time": [str(_stamp(3))],
        "bucket_width": ["1d"],
        "limit": ["180"],
        "group_by": ["project_id", "line_item"],
    }
    assert second_query["page"] == ["page_AAAA-safe/opaque="]
    assert transport.calls[0]["allow_redirects"] is False
    assert transport.calls[0]["headers"]["Authorization"] == f"Bearer {secret}"
    serialized = repr(collection)
    for sensitive in (
        secret,
        "org-sensitive-primary",
        "proj-sensitive-one",
        "proj-sensitive-two",
    ):
        assert sensitive not in serialized
        assert sensitive not in collection.manifest_citation.sha256
    assert secret not in repr(collector.__dict__)

    replay = _collector(
        FakeTransport([_response(first), _response(second)]),
        clock=lambda: CLOCK + 3600,
    ).collect(REQUEST)
    assert replay.batch_id == collection.batch_id
    assert replay.manifest_citation.sha256 == collection.manifest_citation.sha256
    assert [row.payload_sha256 for row in replay.records] == [
        row.payload_sha256 for row in collection.records
    ]


def test_official_source_constants_name_costs_and_usage_references() -> None:
    assert OPENAI_COSTS_DOCUMENTATION_URL.endswith("/usage/methods/costs")
    assert OPENAI_USAGE_DOCUMENTATION_URL.endswith("/usage/methods/completions")
    assert OPENAI_COSTS_ENDPOINT == "https://api.openai.com/v1/organization/costs"


def test_disabled_missing_secret_and_bad_secret_reference_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    disabled = OpenAIOrganizationCostCollector(
        organization_ref="primary",
        transport=FakeTransport([]),
    )
    with pytest.raises(AICostCollectorConfigError, match="disabled"):
        disabled.collect(REQUEST)

    monkeypatch.delenv("OPENAI_ADMIN_KEY", raising=False)
    with pytest.raises(AICostCollectorConfigError, match="OPENAI_ADMIN_KEY"):
        _collector(FakeTransport([])).collect(REQUEST)

    with pytest.raises(AICostCollectorConfigError, match="environment secret"):
        OpenAIOrganizationCostCollector(
            organization_ref="primary",
            admin_key_env="https://evil.example/key",
        )


def test_pagination_cursor_cycle_and_page_cap_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_ADMIN_KEY", "admin")
    repeating = _response(
        _page(
            [_bucket(1, [_result()])],
            has_more=True,
            next_page="same-cursor",
        )
    )
    cycle = _collector(FakeTransport([repeating, repeating]))
    with pytest.raises(AICostCollectorProtocolError, match="cursor cycle"):
        cycle.collect(REQUEST)

    limited = _collector(
        FakeTransport([repeating]),
        limits=CollectorLimits(page_cap=1),
    )
    with pytest.raises(AICostCollectorLimitError, match="page cap.*partial"):
        limited.collect(REQUEST)


def test_record_and_total_byte_caps_reject_partial_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_ADMIN_KEY", "admin")
    two_rows = _page(
        [
            _bucket(
                1,
                [_result(), _result(value=0.07, project_id="proj-other")],
            ),
            _bucket(2, []),
        ]
    )
    bounded = _collector(
        FakeTransport([_response(two_rows)]),
        limits=CollectorLimits(record_cap=1),
    )
    with pytest.raises(AICostCollectorLimitError, match="record cap.*partial"):
        bounded.collect(REQUEST)

    page_one = _response(
        _page([_bucket(1, [_result()])], has_more=True, next_page="next")
    )
    page_two = _response(_page([_bucket(2, [_result(value=1)])]))
    largest_page = max(len(page_one.body), len(page_two.body))
    total_bounded = _collector(
        FakeTransport([page_one, page_two]),
        response_byte_cap=largest_page + 8,
        total_byte_cap=largest_page + 32,
    )
    with pytest.raises(AICostCollectorLimitError, match="total byte cap.*partial"):
        total_bounded.collect(REQUEST)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda page: page.update(object="wrong"), "page object"),
        (lambda page: page["data"][0].update(object="wrong"), "bucket object"),
        (
            lambda page: page["data"][0]["results"][0].pop("amount"),
            "amount must be an object",
        ),
        (
            lambda page: page["data"][0]["results"][0]["amount"].update(
                currency="USD"
            ),
            "lowercase ISO-4217",
        ),
        (
            lambda page: page["data"][0]["results"][0].update(quantity_unit=None),
            "both be present or null",
        ),
        (
            lambda page: page["data"][0]["results"][0].update(api_key_id="key-secret"),
            "unrequested API-key",
        ),
        (
            lambda page: page["data"][0]["results"][0].update(quantity_unit="widgets"),
            "documented allowlist",
        ),
    ],
)
def test_malformed_provider_shapes_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    mutate: Any,
    message: str,
) -> None:
    monkeypatch.setenv("OPENAI_ADMIN_KEY", "admin")
    page = _page([_bucket(1, [_result()]), _bucket(2, [])])
    mutate(page)
    with pytest.raises(AICostCollectorProtocolError, match=message):
        _collector(FakeTransport([_response(page)])).collect(REQUEST)


@pytest.mark.parametrize(
    "body",
    [
        b'{"object":"page","object":"page"}',
        b'{"object":"page","data":NaN}',
        b"\xff\xfe",
    ],
)
def test_duplicate_nonfinite_or_non_utf8_json_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    body: bytes,
) -> None:
    monkeypatch.setenv("OPENAI_ADMIN_KEY", "admin")
    response = FakeResponse(
        200,
        {"Content-Type": "application/json", "Content-Length": str(len(body))},
        body,
    )
    with pytest.raises(AICostCollectorProtocolError):
        _collector(FakeTransport([response])).collect(REQUEST)


def test_oversize_body_and_content_length_fail_before_admission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_ADMIN_KEY", "admin")
    body = b"{" + (b" " * 255) + b"}"
    oversized = FakeResponse(
        200,
        {"Content-Type": "application/json", "Content-Length": str(len(body))},
        body,
    )
    with pytest.raises(AICostCollectorLimitError, match="byte bound"):
        _collector(
            FakeTransport([oversized]),
            response_byte_cap=128,
            total_byte_cap=128,
        ).collect(REQUEST)

    declared = FakeResponse(
        200,
        {"Content-Type": "application/json", "Content-Length": "999"},
        b"{}",
    )
    with pytest.raises(AICostCollectorLimitError, match="byte bound"):
        _collector(
            FakeTransport([declared]),
            response_byte_cap=128,
            total_byte_cap=128,
        ).collect(REQUEST)


@pytest.mark.parametrize(
    "response",
    [
        FakeResponse(
            302,
            {"Location": "https://evil.example/steal"},
            b"",
        ),
        _response(
            _page([_bucket(1, [_result()]), _bucket(2, [])]),
            url="https://evil.example/v1/organization/costs",
        ),
        _response(
            _page([_bucket(1, [_result()]), _bucket(2, [])]),
            url="https://api.openai.com/v1/models",
        ),
    ],
)
def test_redirect_or_ssrf_authority_change_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    response: FakeResponse,
) -> None:
    monkeypatch.setenv("OPENAI_ADMIN_KEY", "admin")
    with pytest.raises(AICostCollectorProtocolError, match="redirect|authority|host or path"):
        _collector(FakeTransport([response])).collect(REQUEST)


def test_rate_limit_and_transport_errors_are_sanitized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "secret-inside-provider-error"
    monkeypatch.setenv("OPENAI_ADMIN_KEY", "admin")
    rate_limited = FakeResponse(
        429,
        {"Content-Type": "application/json"},
        json.dumps({"error": secret}).encode(),
    )
    with pytest.raises(AICostCollectorTransportError, match="rate limited") as caught:
        _collector(FakeTransport([rate_limited])).collect(REQUEST)
    assert secret not in str(caught.value)

    with pytest.raises(AICostCollectorTransportError, match="timed out") as timed_out:
        _collector(FakeTransport(error=TimeoutError(secret))).collect(REQUEST)
    assert secret not in str(timed_out.value)
    assert timed_out.value.__cause__ is None


def test_partial_markers_missing_buckets_and_future_days_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_ADMIN_KEY", "admin")
    marked = _page(
        [_bucket(1, [_result()]), _bucket(2, [])],
        partial=True,
    )
    with pytest.raises(AICostCollectorProtocolError, match="marked partial"):
        _collector(FakeTransport([_response(marked)])).collect(REQUEST)

    missing = _page([_bucket(1, [_result()])])
    with pytest.raises(AICostCollectorProtocolError, match="complete requested period"):
        _collector(FakeTransport([_response(missing)])).collect(REQUEST)

    future = CollectionRequest(
        period_start="2026-01-03T00:00:00Z",
        period_end="2026-01-05T00:00:00Z",
    )
    with pytest.raises(AICostCollectorProtocolError, match="incomplete UTC day"):
        _collector(FakeTransport([])).collect(future)


def test_complete_empty_window_is_not_misrepresented_as_zero_cost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_ADMIN_KEY", "admin")
    complete_empty = _page([_bucket(1, []), _bucket(2, [])])
    with pytest.raises(AICostCollectorNoData, match="no billable cost rows"):
        _collector(FakeTransport([_response(complete_empty)])).collect(REQUEST)


def test_content_type_encoding_and_terminal_cursor_are_strict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_ADMIN_KEY", "admin")
    payload = _page([_bucket(1, [_result()]), _bucket(2, [])])
    wrong_type = _response(payload)
    wrong_type = replace(wrong_type, headers={"Content-Type": "text/html"})
    with pytest.raises(AICostCollectorProtocolError, match="application/json"):
        _collector(FakeTransport([wrong_type])).collect(REQUEST)

    compressed = _response(payload)
    compressed = replace(
        compressed,
        headers={"Content-Type": "application/json", "Content-Encoding": "gzip"},
    )
    with pytest.raises(AICostCollectorProtocolError, match="content encoding"):
        _collector(FakeTransport([compressed])).collect(REQUEST)

    terminal_cursor = _page(
        [_bucket(1, [_result()]), _bucket(2, [])],
        next_page="unexpected",
    )
    with pytest.raises(AICostCollectorProtocolError, match="terminal page"):
        _collector(FakeTransport([_response(terminal_cursor)])).collect(REQUEST)


def test_page_size_period_and_decimal_bounds_are_enforced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_ADMIN_KEY", "admin")
    transport = FakeTransport(
        [_response(_page([_bucket(1, [_result()]), _bucket(2, [])]))]
    )
    _collector(
        transport,
        limits=CollectorLimits(page_size=1_000),
    ).collect(REQUEST)
    assert parse_qs(urlsplit(transport.calls[0]["url"]).query)["limit"] == ["180"]

    too_long = CollectionRequest(
        period_start="2026-01-01T00:00:00Z",
        period_end="2026-01-03T00:00:00Z",
    )
    with pytest.raises(AICostCollectorLimitError, match="between 1 and 1 days"):
        _collector(
            FakeTransport([]),
            limits=CollectorLimits(max_period_days=1),
        ).collect(too_long)

    nonfinite = _page([_bucket(1, [_result(value="Infinity")]), _bucket(2, [])])
    with pytest.raises(AICostCollectorProtocolError, match="decimal bound"):
        _collector(FakeTransport([_response(nonfinite)])).collect(REQUEST)
