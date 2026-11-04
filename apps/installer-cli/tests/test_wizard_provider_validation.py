"""Provider credential probes arm egress before their one SDK attempt."""

from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace
from typing import Any

from maverick import egress_guard
from maverick_installer import wizard


def test_anthropic_validation_arms_egress_before_one_shot(monkeypatch) -> None:
    events: list[str] = []
    fake = ModuleType("anthropic")

    class AuthenticationError(Exception):
        pass

    class Client:
        def __init__(self, **kwargs: Any) -> None:
            events.append("client")
            assert kwargs == {
                "api_key": "test-key",  # pragma: allowlist secret
                "timeout": 5.0,
                "max_retries": 0,
            }
            self.models = SimpleNamespace(list=self._list)

        @staticmethod
        def _list(*, limit: int) -> list[object]:
            events.append("request")
            assert limit == 1
            return [object()]

    fake.Anthropic = Client  # type: ignore[attr-defined]
    fake.AuthenticationError = AuthenticationError  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "anthropic", fake)
    monkeypatch.setattr(
        egress_guard,
        "install",
        lambda: events.append("guard") or True,
    )

    assert wizard._validate_anthropic_key("test-key") == (True, "validated")
    assert events == ["guard", "client", "request"]


def test_openai_validation_arms_egress_before_one_shot(monkeypatch) -> None:
    events: list[str] = []
    fake = ModuleType("openai")

    class AuthenticationError(Exception):
        pass

    class Client:
        def __init__(self, **kwargs: Any) -> None:
            events.append("client")
            assert kwargs == {
                "api_key": "test-key",  # pragma: allowlist secret
                "timeout": 5.0,
                "max_retries": 0,
            }
            self.models = SimpleNamespace(list=self._list)

        @staticmethod
        def _list() -> SimpleNamespace:
            events.append("request")
            return SimpleNamespace(data=[object()])

    fake.OpenAI = Client  # type: ignore[attr-defined]
    fake.AuthenticationError = AuthenticationError  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "openai", fake)
    monkeypatch.setattr(
        egress_guard,
        "install",
        lambda: events.append("guard") or True,
    )

    assert wizard._validate_openai_key("test-key") == (True, "validated")
    assert events == ["guard", "client", "request"]


def test_validation_refuses_network_when_egress_guard_cannot_arm(monkeypatch) -> None:
    fake = ModuleType("anthropic")

    class UnexpectedClient:
        def __init__(self, **_kwargs: Any) -> None:
            raise AssertionError("provider client must not be constructed")

    fake.Anthropic = UnexpectedClient  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "anthropic", fake)
    monkeypatch.setattr(egress_guard, "install", lambda: False)

    ok, message = wizard._validate_anthropic_key("test-key")

    assert ok is True
    assert message == (
        "validation skipped: egress guard unavailable (guard did not report active)"
    )
