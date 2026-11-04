"""Sentry performance tab: opt-in init + trace_span feeding Sentry
transactions/spans. sentry_sdk is faked; no network."""
from __future__ import annotations

import contextlib
import sys
from unittest.mock import MagicMock

import maverick.observability as obs


def _reset(monkeypatch):
    monkeypatch.setattr(obs, "_initialized", False)
    monkeypatch.setattr(obs, "_tracer", None)
    monkeypatch.setattr(obs, "_sentry", None)
    obs._metrics.clear()


def _fake_sentry(monkeypatch, *, active_transaction=None):
    sdk = MagicMock(name="sentry_sdk")
    scope = MagicMock()
    scope.transaction = active_transaction
    sdk.get_current_scope.return_value = scope

    @contextlib.contextmanager
    def _txn(**kw):
        span = MagicMock(name="txn")
        span.kwargs = kw
        yield span

    @contextlib.contextmanager
    def _span(**kw):
        span = MagicMock(name="span")
        span.kwargs = kw
        yield span

    sdk.start_transaction = MagicMock(side_effect=lambda **kw: _txn(**kw))
    sdk.start_span = MagicMock(side_effect=lambda **kw: _span(**kw))
    monkeypatch.setitem(sys.modules, "sentry_sdk", sdk)
    return sdk


def test_off_by_default(monkeypatch):
    _reset(monkeypatch)
    monkeypatch.delenv("MAVERICK_SENTRY_DSN", raising=False)
    import maverick.config as config_mod
    monkeypatch.setattr(config_mod, "load_config", dict)
    with obs.trace_span("episode") as span:
        assert span is None
    assert obs._sentry is None


def test_init_with_dsn_and_sample_rate(monkeypatch):
    _reset(monkeypatch)
    sdk = _fake_sentry(monkeypatch)
    monkeypatch.setenv("MAVERICK_SENTRY_DSN", "https://k@o0.ingest.sentry.io/1")
    monkeypatch.setenv("MAVERICK_SENTRY_TRACES_SAMPLE_RATE", "0.5")
    monkeypatch.delenv("MAVERICK_OTEL_EXPORTER", raising=False)
    with obs.trace_span("episode"):
        pass
    sdk.init.assert_called_once()
    kw = sdk.init.call_args.kwargs
    assert kw["dsn"].startswith("https://k@")
    assert kw["traces_sample_rate"] == 0.5
    assert kw["send_default_pii"] is False
    assert obs.is_enabled()


def test_root_span_opens_transaction(monkeypatch):
    _reset(monkeypatch)
    sdk = _fake_sentry(monkeypatch, active_transaction=None)
    monkeypatch.setenv("MAVERICK_SENTRY_DSN", "https://k@o0.ingest.sentry.io/1")
    monkeypatch.delenv("MAVERICK_OTEL_EXPORTER", raising=False)
    with obs.trace_span("goal.run", attributes={"goal_id": 7}):
        pass
    sdk.start_transaction.assert_called_once_with(name="goal.run", op="maverick")
    assert not sdk.start_span.called


def test_nested_span_inside_transaction(monkeypatch):
    _reset(monkeypatch)
    sdk = _fake_sentry(monkeypatch, active_transaction=MagicMock(name="active"))
    monkeypatch.setenv("MAVERICK_SENTRY_DSN", "https://k@o0.ingest.sentry.io/1")
    monkeypatch.delenv("MAVERICK_OTEL_EXPORTER", raising=False)
    with obs.trace_span("tool.fs"):
        pass
    sdk.start_span.assert_called_once_with(op="tool.fs")
    assert not sdk.start_transaction.called


def test_missing_sdk_logs_and_degrades(monkeypatch, caplog):
    _reset(monkeypatch)
    monkeypatch.setitem(sys.modules, "sentry_sdk", None)
    monkeypatch.setenv("MAVERICK_SENTRY_DSN", "https://k@o0.ingest.sentry.io/1")
    monkeypatch.delenv("MAVERICK_OTEL_EXPORTER", raising=False)
    with obs.trace_span("episode") as span:
        assert span is None  # no tracer, no sentry -- but no crash
    assert obs._sentry is None


def test_bad_sample_rate_falls_back(monkeypatch):
    _reset(monkeypatch)
    sdk = _fake_sentry(monkeypatch)
    monkeypatch.setenv("MAVERICK_SENTRY_DSN", "https://k@o0.ingest.sentry.io/1")
    monkeypatch.setenv("MAVERICK_SENTRY_TRACES_SAMPLE_RATE", "banana")
    monkeypatch.delenv("MAVERICK_OTEL_EXPORTER", raising=False)
    with obs.trace_span("x"):
        pass
    assert sdk.init.call_args.kwargs["traces_sample_rate"] == 0.1
