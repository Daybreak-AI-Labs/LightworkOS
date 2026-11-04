"""Self-hosted relay reference.

Pure logic + injected transport: no server, no network, no agent. Fakes stand
in for the sync handler, the /webhook/start starter, and the outbound delivery
seam; an injected clock drives the deadline logic deterministically.
"""
from __future__ import annotations

import hashlib
import hmac
import json

import pytest
from maverick.relay_reference import (
    DEFAULT_LONG_TASK_PATTERN,
    Relay,
    RelayConfig,
    RequestKind,
    build_start_request,
    classify_request,
    sign_body,
)


def _cfg(**kw) -> RelayConfig:
    base = {"deadline_seconds": 30.0, "start_url": "http://relay/webhook/start",
            "secondary_channel": "telegram", "require_inbound_auth": False}
    base.update(kw)
    return RelayConfig(**base)


class _Recorder:
    """Captures calls to the injected starter/deliver seams."""

    def __init__(self):
        self.started = []
        self.delivered = []

    def starter(self, url, payload, *, secret=None):
        self.started.append({"url": url, "payload": payload, "secret": secret})
        return {"run_id": "run-123"}

    def deliver(self, channel, result, *, context=None):
        self.delivered.append({"channel": channel, "result": result, "context": context})
        return True


class TestClassify:
    def test_quick_query_is_quick(self):
        assert classify_request("what's the weather in Paris?", _cfg()) is RequestKind.QUICK

    def test_long_task_verbs_are_ack_then_run(self):
        for msg in ["write a blog post about ducks", "research the market", "deploy the service",
                    "build me an app", "refactor this module"]:
            assert classify_request(msg, _cfg()) is RequestKind.ACK_THEN_RUN, msg

    def test_empty_message_is_quick(self):
        assert classify_request("", _cfg()) is RequestKind.QUICK
        assert classify_request("   ", _cfg()) is RequestKind.QUICK

    def test_pattern_is_case_insensitive(self):
        assert classify_request("RESEARCH the topic", _cfg()) is RequestKind.ACK_THEN_RUN

    def test_custom_pattern_overrides_default(self):
        cfg = _cfg(long_task_pattern=r"\bsummon\b")
        assert classify_request("summon the swarm", cfg) is RequestKind.ACK_THEN_RUN
        # default trigger words no longer fire under the custom pattern
        assert classify_request("write a poem", cfg) is RequestKind.QUICK

    def test_default_classify_without_config(self):
        assert classify_request("write code") is RequestKind.ACK_THEN_RUN
        assert classify_request("hi there") is RequestKind.QUICK

    def test_default_pattern_is_documented_constant(self):
        assert _cfg().long_task_pattern == DEFAULT_LONG_TASK_PATTERN


class TestInboundAuth:
    def test_default_relay_rejects_unauthenticated_requests_before_starting(self):
        rec = _Recorder()
        relay = Relay(RelayConfig(), sync_handler=lambda t: "should not run",
                      starter=rec.starter, deliver=rec.deliver)
        resp = relay.handle("research competitor pricing", context={"source": "device"})
        assert resp.error == "unauthorized inbound relay request"
        assert resp.started is False
        assert rec.started == []

    def test_configured_token_allows_background_start(self):
        rec = _Recorder()
        relay = Relay(_cfg(require_inbound_auth=True, inbound_auth_token="device-token"),
                      sync_handler=lambda t: "x", starter=rec.starter, deliver=rec.deliver)
        resp = relay.handle("research competitor pricing", auth_token="device-token")
        assert resp.kind is RequestKind.ACK_THEN_RUN
        assert resp.started is True
        assert len(rec.started) == 1

    def test_wrong_token_rejects_before_quick_handler(self):
        rec = _Recorder()
        relay = Relay(_cfg(require_inbound_auth=True, inbound_auth_token="device-token"),
                      sync_handler=lambda t: "should not run", starter=rec.starter, deliver=rec.deliver)
        resp = relay.handle("what time is it?", auth_token="wrong")
        assert resp.error == "unauthorized inbound relay request"
        assert rec.started == []

class TestQuickPath:
    def test_quick_answer_returned_within_deadline(self):
        rec = _Recorder()
        relay = Relay(_cfg(), sync_handler=lambda t: f"answer to: {t}",
                      starter=rec.starter, deliver=rec.deliver)
        resp = relay.handle("what is 2+2?")
        assert resp.kind is RequestKind.QUICK
        assert resp.immediate == "answer to: what is 2+2?"
        assert resp.started is False
        assert rec.started == []  # no background run for a quick query

    def test_quick_path_overrunning_deadline_downgrades(self):
        # An injected clock that jumps past the deadline during the sync call.
        clock = iter([0.0, 100.0])  # start=0, end=100 -> 100s > 30s deadline
        rec = _Recorder()
        relay = Relay(_cfg(deadline_seconds=30.0), sync_handler=lambda t: "slow answer",
                      starter=rec.starter, deliver=rec.deliver, now=lambda: next(clock))
        resp = relay.handle("a short question")  # classified quick, but runs long
        assert resp.kind is RequestKind.ACK_THEN_RUN
        assert resp.started is True
        assert resp.meta["downgrade_reason"] == "deadline exceeded on sync path"
        assert len(rec.started) == 1

    def test_quick_handler_exception_falls_open_to_ack(self):
        def boom(_t):
            raise RuntimeError("agent down")
        rec = _Recorder()
        relay = Relay(_cfg(), sync_handler=boom, starter=rec.starter, deliver=rec.deliver)
        resp = relay.handle("quick question")
        assert resp.kind is RequestKind.ACK_THEN_RUN
        assert resp.started is True
        assert "sync handler error" in resp.meta["downgrade_reason"]

    def test_quick_records_elapsed(self):
        clock = iter([0.0, 1.5])
        rec = _Recorder()
        relay = Relay(_cfg(), sync_handler=lambda t: "ok", starter=rec.starter,
                      deliver=rec.deliver, now=lambda: next(clock))
        resp = relay.handle("ping")
        assert resp.meta["elapsed_seconds"] == 1.5


class TestAckThenRun:
    def test_long_task_acks_immediately_and_starts(self):
        rec = _Recorder()
        relay = Relay(_cfg(), sync_handler=lambda t: "should not be called",
                      starter=rec.starter, deliver=rec.deliver)
        resp = relay.handle("write a detailed report on ducks", context={"source": "device"})
        assert resp.kind is RequestKind.ACK_THEN_RUN
        assert "telegram" in resp.immediate
        assert resp.started is True
        assert resp.meta["run_id"] == "run-123"
        # forwarded to /webhook/start with the goal + delivery target + context
        assert len(rec.started) == 1
        sent = rec.started[0]
        assert sent["url"] == "http://relay/webhook/start"
        assert sent["payload"]["goal"] == "write a detailed report on ducks"
        assert sent["payload"]["deliver_to"] == "telegram"
        assert sent["payload"]["source"] == "device"

    def test_start_failure_still_acks_fail_open(self):
        def bad_starter(url, payload, *, secret=None):
            raise ConnectionError("start endpoint unreachable")
        rec = _Recorder()
        relay = Relay(_cfg(), sync_handler=lambda t: "x", starter=bad_starter, deliver=rec.deliver)
        resp = relay.handle("research quantum gravity")
        assert resp.kind is RequestKind.ACK_THEN_RUN
        assert resp.immediate  # device still got an ack
        assert resp.started is False
        assert "start failed" in resp.error

    def test_secret_is_passed_to_starter(self):
        rec = _Recorder()
        relay = Relay(_cfg(hmac_secret="topsecret"), sync_handler=lambda t: "x",
                      starter=rec.starter, deliver=rec.deliver)
        relay.handle("deploy the thing")
        assert rec.started[0]["secret"] == "topsecret"

    def test_ack_template_includes_channel(self):
        rec = _Recorder()
        relay = Relay(_cfg(secondary_channel="slack"), sync_handler=lambda t: "x",
                      starter=rec.starter, deliver=rec.deliver)
        resp = relay.handle("build a website")
        assert "slack" in resp.immediate


class TestDelivery:
    def test_deliver_result_pushes_to_secondary_channel(self):
        rec = _Recorder()
        relay = Relay(_cfg(), sync_handler=lambda t: "x", starter=rec.starter, deliver=rec.deliver)
        ok = relay.deliver_result("here is your finished report", context={"goal_id": "g1"})
        assert ok is True
        assert rec.delivered[0]["channel"] == "telegram"
        assert rec.delivered[0]["result"] == "here is your finished report"
        assert rec.delivered[0]["context"]["goal_id"] == "g1"

    def test_deliver_failure_returns_false_not_raises(self):
        def bad_deliver(channel, result, *, context=None):
            raise RuntimeError("telegram down")
        relay = Relay(_cfg(), sync_handler=lambda t: "x",
                      starter=lambda *a, **k: {}, deliver=bad_deliver)
        assert relay.deliver_result("result") is False


class TestSigning:
    def test_sign_body_matches_webhooks_construction(self):
        body = b'{"goal":"x"}'
        sig, ts = sign_body(body, "secret", timestamp="1700000000")
        material = b"1700000000." + body
        expected = "sha256=" + hmac.new(b"secret", material, hashlib.sha256).hexdigest()
        assert sig == expected
        assert ts == "1700000000"

    def test_build_start_request_signs_when_secret_set(self):
        cfg = _cfg(hmac_secret="k")
        body, headers = build_start_request({"goal": "research X"}, cfg)
        assert headers["X-Maverick-Signature"].startswith("sha256=")
        assert "X-Maverick-Timestamp" in headers
        # body is valid JSON and the signature covers it
        assert json.loads(body)["goal"] == "research X"
        material = (headers["X-Maverick-Timestamp"] + ".").encode() + body
        expected = "sha256=" + hmac.new(b"k", material, hashlib.sha256).hexdigest()
        assert headers["X-Maverick-Signature"] == expected

    def test_build_start_request_unsigned_without_secret(self):
        body, headers = build_start_request({"goal": "x"}, _cfg())
        assert "X-Maverick-Signature" not in headers
        assert headers["Content-Type"] == "application/json"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
