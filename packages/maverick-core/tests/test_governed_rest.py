"""Governed REST connector: a LIVE system of record routed through the
simulate -> approve -> commit -> lineage pipeline.

Network-free: the SSRF-safe client boundary (``_ssrf.safe_client``) is faked,
exactly as the enterprise-connector tests do, so the write path is exercised
without touching the network. The key behaviors under test:

  * ``preview_write`` makes NO network call (the simulate contract) yet renders
    a faithful, approvable effect;
  * a write is high-risk, so it hits the approval floor and is refused without
    an approver, then commits + records tamper-evident lineage with one;
  * the request rides the same egress-guarded path the Tool form uses.
"""
from __future__ import annotations

from contextlib import closing, contextmanager
from unittest.mock import MagicMock

import httpx
import pytest
from maverick.governed_actions import ActionError, GovernedActions
from maverick.governed_connectors import register_connector
from maverick.governed_rest import (
    RestConnector,
    available_rest_connectors,
    register_rest_connectors,
    salesforce_connector,
)


def _fake_safe_client(monkeypatch, **methods):
    client = MagicMock()
    for name, value in methods.items():
        setattr(client, name, value)

    @contextmanager
    def stream(method, url, **kwargs):
        response = methods["request"](method, url, **kwargs)
        with closing(httpx.Response(response.status_code, headers=response.headers,
                                    stream=httpx.ByteStream(response.content))) as streamed:
            yield streamed

    client.stream = stream

    @contextmanager
    def _ctx(url, **kwargs):
        yield client

    from maverick.tools import _ssrf
    monkeypatch.setattr(_ssrf, "safe_client", _ctx)
    return client


def _resp(status, body):
    return httpx.Response(status, json=body)


def _conn():
    return RestConnector(
        name="acme", base_url_env="ACME_BASE_URL", token_env="ACME_TOKEN")


def _env(monkeypatch):
    monkeypatch.setenv("ACME_BASE_URL", "https://acme.example.com")
    monkeypatch.setenv("ACME_TOKEN", "tok123")


def _wired(monkeypatch):
    _env(monkeypatch)
    ga = GovernedActions()
    rname, wname = register_connector(ga, _conn())
    return ga, rname, wname


class TestGovernedSurface:
    def test_register_exposes_read_low_and_write_high(self, monkeypatch):
        ga, rname, wname = _wired(monkeypatch)
        assert (rname, wname) == ("acme.read", "acme.write")
        assert ga.get(rname).risk == "low"
        assert ga.get(wname).risk == "high"


class TestPreviewWrite:
    def test_preview_makes_no_network_call(self, monkeypatch):
        # A request through safe_client would explode (no methods set); the
        # preview must never reach it.
        req = MagicMock(side_effect=AssertionError("preview must not call network"))
        _fake_safe_client(monkeypatch, request=req)
        ga, _r, wname = _wired(monkeypatch)
        pv = ga.simulate(wname, {"op": "patch", "path": "/services/data/x",
                                 "body": {"Stage": "Closed"}})
        assert "would PATCH acme/services/data/x" in pv.effect
        assert "Stage" in pv.effect
        assert pv.requires_approval is True
        req.assert_not_called()

    def test_preview_normalizes_path_and_rejects_bad_op(self):
        c = _conn()
        assert c.preview_write({"op": "get", "path": "/x"}).startswith("ERROR")
        assert c.preview_write({"op": "post", "path": "x", "body": {}}) == \
            "would POST acme/x"


class TestWrite:
    def test_write_requires_approver_then_commits_with_lineage(self, monkeypatch):
        req = MagicMock(return_value=_resp(201, {"id": "006xx", "success": True}))
        _fake_safe_client(monkeypatch, request=req)
        ga, _r, wname = _wired(monkeypatch)
        params = {"op": "post", "path": "/services/data/v60.0/sobjects/Account",
                  "body": {"Name": "Acme"}}
        with pytest.raises(ActionError, match="requires an approver"):
            ga.commit(wname, params)
        out = ga.commit(wname, params, approver="alice", sources=("ticket-7",))
        assert "006xx" in out
        # The request went out as a real POST through the egress-guarded client.
        assert req.call_args.args[0] == "POST"
        assert ga.verify_lineage().startswith("VALID")
        assert ga.trace()["approver"] == "alice"

    def test_read_is_low_risk_get(self, monkeypatch):
        req = MagicMock(return_value=_resp(200, {"records": []}))
        _fake_safe_client(monkeypatch, request=req)
        ga, rname, _w = _wired(monkeypatch)
        out = ga.commit(rname, {"path": "/services/data/v60.0/query"})
        assert "records" in out
        assert req.call_args.args[0] == "GET"

    def test_write_typing_enforced(self, monkeypatch):
        ga, _r, wname = _wired(monkeypatch)
        # body declared dict; a string body is refused by the action typing.
        with pytest.raises(ActionError, match="must be dict"):
            ga.commit(wname, {"op": "post", "path": "/x", "body": "nope"},
                      approver="x")

    def test_missing_env_is_loud_error(self, monkeypatch):
        monkeypatch.delenv("ACME_BASE_URL", raising=False)
        monkeypatch.delenv("ACME_TOKEN", raising=False)
        c = _conn()
        out = c.write({"op": "post", "path": "/x", "body": {"a": 1}})
        assert out.startswith("ERROR") and "ACME_BASE_URL" in out

    def test_bad_op_rejected_before_network(self, monkeypatch):
        req = MagicMock(side_effect=AssertionError("must not be called"))
        _fake_safe_client(monkeypatch, request=req)
        _env(monkeypatch)
        out = _conn().write({"op": "get", "path": "/x", "body": {}})
        assert out.startswith("ERROR") and "op must be" in out
        req.assert_not_called()


class TestRegistry:
    def test_reference_connectors_available(self):
        names = available_rest_connectors()
        assert "salesforce" in names and "servicenow" in names

    def test_salesforce_env_wiring(self):
        c = salesforce_connector()
        assert c.base_url_env == "SALESFORCE_INSTANCE_URL"
        assert c.token_env == "SALESFORCE_ACCESS_TOKEN"

    def test_register_rest_connectors_registers_known_skips_unknown(self):
        ga = GovernedActions()
        out = register_rest_connectors(ga, ["salesforce", "does-not-exist"])
        assert set(out) == {"salesforce"}
        assert out["salesforce"] == ("salesforce.read", "salesforce.write")
        assert ga.get("salesforce.write").risk == "high"


class TestConfiguredFactory:
    def test_disabled_registers_nothing(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_GOVERNED_CONNECTORS", raising=False)
        import maverick.config as cfg
        monkeypatch.setattr(cfg, "get_governed_connectors",
                            lambda: {"enable": False, "connectors": ["salesforce"]})
        from maverick.governed_rest import configured_governed_actions
        ga, registered = configured_governed_actions()
        assert registered == {}

    def test_enabled_registers_selected(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_GOVERNED_CONNECTORS", raising=False)
        import maverick.config as cfg
        monkeypatch.setattr(cfg, "get_governed_connectors",
                            lambda: {"enable": True, "connectors": ["servicenow"]})
        from maverick.governed_rest import configured_governed_actions
        ga, registered = configured_governed_actions()
        assert set(registered) == {"servicenow"}
        assert ga.get("servicenow.write").risk == "high"

    def test_env_override_forces_off(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_GOVERNED_CONNECTORS", "0")
        import maverick.config as cfg
        monkeypatch.setattr(cfg, "get_governed_connectors",
                            lambda: {"enable": True, "connectors": ["salesforce"]})
        from maverick.governed_rest import configured_governed_actions
        _ga, registered = configured_governed_actions()
        assert registered == {}
