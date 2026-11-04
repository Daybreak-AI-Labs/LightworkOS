"""saas_trigger: HMAC webhook verify + glob routing. No network."""
from __future__ import annotations

import hashlib
import hmac

from maverick.tools.saas_trigger import saas_trigger


def _run(**kw):
    return saas_trigger().fn(kw)


def _sig(secret, payload, algo=hashlib.sha256):
    return hmac.new(secret.encode(), payload.encode(), algo).hexdigest()


def test_verify_valid():
    payload = '{"event":"x"}'
    out = _run(op="verify", secret="topsecret", payload=payload, signature=_sig("topsecret", payload))
    assert out.startswith("VALID") and "sha256" in out


def test_verify_invalid_wrong_secret():
    payload = '{"event":"x"}'
    out = _run(op="verify", secret="topsecret", payload=payload, signature=_sig("other", payload))
    assert out.startswith("INVALID")


def test_verify_accepts_prefixed_signature():
    payload = '{"event":"x"}'
    out = _run(
        op="verify",
        secret="topsecret",  # pragma: allowlist secret
        payload=payload,
        signature="sha256=" + _sig("topsecret", payload),
    )
    assert out.startswith("VALID")


def test_route_most_specific_wins():
    routes = {"*": "g_catchall", "issues.*": "g_issues", "issues.opened": "g_opened"}
    assert _run(op="route", event_type="issues.opened", routes=routes) == "ROUTE: g_opened"
    assert _run(op="route", event_type="issues.closed", routes=routes) == "ROUTE: g_issues"
    assert _run(op="route", event_type="push", routes=routes) == "ROUTE: g_catchall"


def test_route_none():
    out = _run(op="route", event_type="unmatched", routes={"issues.*": "g"})
    assert out.startswith("NONE")


def test_errors():
    t = saas_trigger()
    assert t.fn({"op": "verify", "secret": "s", "payload": "p"}).startswith("ERROR")  # no sig
    assert t.fn({"op": "verify", "secret": "s", "payload": "p", "signature": "x", "algo": "md5"}).startswith("ERROR")
    assert t.fn({"op": "route", "event_type": "x"}).startswith("ERROR")  # no routes
    assert t.fn({"op": "nope"}).startswith("ERROR")
