"""The explicit transport checks policy before delegating network effects."""
import httpx
import pytest
from maverick.enterprise import EgressBlocked
from maverick.governed_http import (
    GuardedClient,
    admit_client_request,
    guarded_redirect_get,
    guarded_sender,
    request,
)


def test_denied_host_never_reaches_injected_sender(monkeypatch):
    monkeypatch.setattr("maverick.enterprise.enterprise_enabled", lambda: False)
    monkeypatch.setattr("maverick.tenant.egress.host_allowed", lambda host: False)
    monkeypatch.setattr("maverick.audit.writer.audit_event", lambda *args, **kwargs: None)
    sent = []

    with pytest.raises(EgressBlocked):
        request("POST", "https://api.example.com/write", send=lambda *a, **kw: sent.append(a))
    assert not sent


def test_sender_receives_original_request_after_admission(monkeypatch):
    seen = []
    monkeypatch.setattr("maverick.egress_guard._check", lambda url: seen.append(("check", url)))

    def send(url, **kwargs):
        seen.append(("send", url, kwargs))
        return "response"

    assert request("PUT", "https://api.example.com", send=send, json={"x": 1}, timeout=7) == "response"
    assert seen == [
        ("check", "https://api.example.com"),
        ("send", "https://api.example.com", {"json": {"x": 1}, "timeout": 7}),
    ]


def test_implicit_redirects_are_rejected_before_sending(monkeypatch):
    seen = []
    monkeypatch.setattr("maverick.egress_guard._check", lambda url: seen.append(url))
    with pytest.raises(ValueError, match="redirect"):
        request("GET", "https://api.example.com", send=lambda *a, **kw: None, follow_redirects=True)
    assert not seen


@pytest.mark.parametrize("url", ["/relative", "//other.example/path", "file:///secret", "http://"])
def test_relative_or_invalid_target_is_rejected_before_sending(monkeypatch, url):
    sent = []
    monkeypatch.setattr("maverick.egress_guard._check", lambda target: sent.append(target))
    with pytest.raises(ValueError, match="absolute HTTP URL"):
        guarded_sender(lambda *args, **kwargs: sent.append(args))(url)
    assert not sent


def test_bound_redirecting_httpx_client_is_refused_without_explicit_override(monkeypatch):
    checked = []
    sent = []
    monkeypatch.setattr("maverick.egress_guard._check", checked.append)
    with httpx.Client(follow_redirects=True, transport=httpx.MockTransport(
        lambda request: sent.append(request.url) or httpx.Response(200),
    )) as client:
        sender = guarded_sender(client.get)
        with pytest.raises(ValueError, match="redirect"):
            sender("https://api.example.com")
        assert not checked and not sent
        response = sender("https://api.example.com", follow_redirects=False)
    assert response.status_code == 200
    assert checked == ["https://api.example.com"] and len(sent) == 1


def test_requests_style_redirect_flag_is_rejected(monkeypatch):
    seen = []
    monkeypatch.setattr("maverick.egress_guard._check", lambda url: seen.append(url))
    with pytest.raises(ValueError, match="redirect"):
        guarded_sender(lambda *a, **kw: seen.append("sent"))(
            "https://api.example.com", allow_redirects=True,
        )
    assert not seen


@pytest.mark.parametrize("method", ["get", "post", "put", "patch", "delete", "head", "options"])
def test_migrated_httpx_sender_preserves_arguments_and_monkeypatch_seam(monkeypatch, method):
    events = []
    response = object()
    timeout = httpx.Timeout(2.5)

    def sender(*args, **kwargs):
        events.append(("send", args, kwargs))
        return response

    monkeypatch.setattr(httpx, method, sender)
    monkeypatch.setattr("maverick.egress_guard._check", lambda url: events.append(("check", url)))
    result = guarded_sender(getattr(httpx, method))(
        "https://api.example.com/path", headers={"X-Test": "value"}, timeout=timeout,
        follow_redirects=False,
    )
    assert result is response
    assert events == [
        ("check", "https://api.example.com/path"),
        ("send", ("https://api.example.com/path",), {
            "headers": {"X-Test": "value"}, "timeout": timeout, "follow_redirects": False,
        }),
    ]


def test_sender_failure_is_not_retried_or_replaced(monkeypatch):
    calls = []
    failure = httpx.ConnectTimeout("upstream timeout")
    monkeypatch.setattr("maverick.egress_guard._check", lambda url: None)

    def sender(url, **kwargs):
        calls.append(url)
        raise failure

    with pytest.raises(httpx.ConnectTimeout) as caught:
        guarded_sender(sender)("https://api.example.com", timeout=2)
    assert caught.value is failure
    assert calls == ["https://api.example.com"]


def test_guarded_client_preserves_context_and_checks_every_operation(monkeypatch):
    events = []
    monkeypatch.setattr("maverick.egress_guard._check", lambda url: events.append(("check", url)))

    class Client:
        follow_redirects = False

        def __enter__(self):
            events.append(("enter",))
            return self

        def __exit__(self, *exc):
            events.append(("exit",))

        def get(self, url, **kwargs):
            events.append(("get", url, kwargs))
            return "response"

    with GuardedClient(Client()) as client:
        assert client.get("https://api.example.com/one", params={"page": 1}) == "response"
        assert client.get("https://api.example.com/two", timeout=4) == "response"
        with pytest.raises(AttributeError, match="explicit transport"):
            _ = client.stream
    assert events == [
        ("enter",),
        ("check", "https://api.example.com/one"),
        ("get", "https://api.example.com/one", {"params": {"page": 1}}),
        ("check", "https://api.example.com/two"),
        ("get", "https://api.example.com/two", {"timeout": 4}),
        ("exit",),
    ]


def test_guarded_client_exits_when_policy_denies(monkeypatch):
    events = []

    class Client:
        follow_redirects = False

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            events.append("closed")

        def get(self, url):
            events.append("sent")

    def deny(url):
        raise EgressBlocked("denied")

    monkeypatch.setattr("maverick.egress_guard._check", deny)
    with pytest.raises(EgressBlocked):
        with GuardedClient(Client()) as client:
            client.get("https://denied.example")
    assert events == ["closed"]


def test_owned_client_admission_keeps_in_process_exemption_and_client_lifetime(monkeypatch):
    checks = []
    monkeypatch.setattr("maverick.egress_guard._check", lambda target: checks.append(target))
    with httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200))) as mock:
        admit_client_request(mock, "https://local-fixture.example/test")
        assert not mock.is_closed
    assert checks == []

    with httpx.Client(transport=httpx.HTTPTransport()) as network:
        admit_client_request(network, "https://provider.example/test")
        assert not network.is_closed
    assert checks == ["https://provider.example/test"]


def test_owned_client_rechecks_current_policy_and_treats_unknown_transport_as_network(monkeypatch):
    checks = []
    monkeypatch.setattr("maverick.egress_guard._check", lambda target: checks.append(target))
    unknown = object()
    admit_client_request(unknown, "https://first.example")
    admit_client_request(unknown, "https://second.example")
    assert checks == ["https://first.example", "https://second.example"]


def test_owned_client_adapter_without_httpx_request_is_checked(monkeypatch):
    import sys
    from types import SimpleNamespace

    checks = []
    monkeypatch.setitem(sys.modules, "httpx", SimpleNamespace(Client=object))
    monkeypatch.setattr("maverick.egress_guard._check", checks.append)
    admit_client_request(object(), "https://adapter.example/path")
    assert checks == ["https://adapter.example/path"]


def test_owned_client_adapter_without_probe_is_denied_before_dispatch(monkeypatch):
    import sys
    from types import SimpleNamespace

    def deny(_url):
        raise EgressBlocked("blocked")

    monkeypatch.setitem(sys.modules, "httpx", SimpleNamespace(Client=object))
    monkeypatch.setattr("maverick.egress_guard._check", deny)
    with pytest.raises(EgressBlocked, match="blocked"):
        admit_client_request(object(), "https://adapter.example/path")


def test_policy_is_rechecked_each_time_a_sender_is_used(monkeypatch):
    checks = []
    monkeypatch.setattr("maverick.egress_guard._check", lambda url: checks.append(url))
    sender = guarded_sender(lambda url: url)
    assert sender("https://one.example") == "https://one.example"
    assert sender("https://two.example") == "https://two.example"
    assert checks == ["https://one.example", "https://two.example"]


def test_redirects_check_each_hop_and_preserve_httpx_credential_and_cookie_rules(monkeypatch):
    checked = []
    seen = []
    monkeypatch.setattr("maverick.egress_guard._check", lambda url: checked.append(url))
    real_client = httpx.Client

    def upstream(req):
        seen.append(req)
        if req.url.host == "first.example":
            return httpx.Response(302, headers={"Location": "https://second.example/step"})
        if req.url.path == "/step":
            return httpx.Response(302, headers={"Location": "/done", "Set-Cookie": "session=demo; Path=/"})
        return httpx.Response(200, text="complete")

    transport = httpx.MockTransport(upstream)

    def initial_get(url, **kwargs):
        with real_client(transport=transport) as client:
            return client.get(url, **kwargs)

    monkeypatch.setattr(httpx, "Client", lambda **kwargs: real_client(transport=transport, **kwargs))
    response = guarded_redirect_get(initial_get)(
        "https://first.example/start", headers={"Authorization": "Bearer sample"},
        timeout=3.0, follow_redirects=True,
    )
    assert response.text == "complete"
    assert [r.status_code for r in response.history] == [302, 302]
    assert checked == ["https://first.example/start", "https://second.example/step",
                       "https://second.example/done"]
    assert seen[0].headers["Authorization"] == "Bearer sample"
    assert "Authorization" not in seen[1].headers
    assert "Authorization" not in seen[2].headers
    assert seen[2].headers["Cookie"] == "session=demo"


def test_redirect_denial_happens_before_following_destination(monkeypatch):
    calls = []
    real_client = httpx.Client

    def upstream(req):
        calls.append(str(req.url))
        return httpx.Response(302, headers={"Location": "https://denied.example/next"})

    transport = httpx.MockTransport(upstream)

    def initial_get(url, **kwargs):
        with real_client(transport=transport) as client:
            return client.get(url, **kwargs)

    def check(url):
        if "denied.example" in url:
            raise EgressBlocked("redirect destination denied")

    monkeypatch.setattr("maverick.egress_guard._check", check)
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: real_client(transport=transport, **kwargs))
    with pytest.raises(EgressBlocked, match="redirect destination"):
        guarded_redirect_get(initial_get)("https://allowed.example/start", timeout=3.0)
    assert calls == ["https://allowed.example/start"]


def test_https_only_redirect_refuses_a_downgrade_before_the_next_request(monkeypatch):
    calls = []
    real_client = httpx.Client

    def upstream(req):
        calls.append(str(req.url))
        return httpx.Response(302, headers={"Location": "http://issuer.example/metadata"})

    transport = httpx.MockTransport(upstream)

    def initial_get(url, **kwargs):
        with real_client(transport=transport) as client:
            return client.get(url, **kwargs)

    monkeypatch.setattr("maverick.egress_guard._check", lambda url: None)
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: real_client(transport=transport, **kwargs))
    with pytest.raises(ValueError, match="HTTPS is required"):
        guarded_redirect_get(initial_get, require_https=True)("https://issuer.example/start")
    assert calls == ["https://issuer.example/start"]


def test_redirect_limit_stops_a_loop_without_replaying_a_write(monkeypatch):
    calls = []
    real_client = httpx.Client

    def upstream(req):
        calls.append(str(req.url))
        assert req.method == "GET"
        return httpx.Response(302, headers={"Location": "/again"})

    transport = httpx.MockTransport(upstream)

    def initial_get(url, **kwargs):
        with real_client(transport=transport) as client:
            return client.get(url, **kwargs)

    monkeypatch.setattr("maverick.egress_guard._check", lambda url: None)
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: real_client(transport=transport, **kwargs))
    with pytest.raises(httpx.TooManyRedirects):
        guarded_redirect_get(initial_get)("https://allowed.example/start", timeout=3.0)
    assert len(calls) == 21


def test_pinned_client_checks_policy_before_resolving_dns(monkeypatch):
    from maverick.tools import _ssrf

    def deny(url):
        raise EgressBlocked("denied")

    def no_dns(*args, **kwargs):
        pytest.fail("a denied host must not be resolved")

    monkeypatch.setattr("maverick.egress_guard._check", deny)
    monkeypatch.setattr(_ssrf.socket, "getaddrinfo", no_dns)
    with pytest.raises(EgressBlocked):
        _ssrf.safe_client("https://example.com")


@pytest.mark.asyncio
async def test_pinned_transports_check_original_host_before_sending(monkeypatch):
    from maverick.tools._ssrf import _AsyncPinnedTransport, _PinnedTransport

    checks = []
    monkeypatch.setattr("maverick.egress_guard._check", lambda url: checks.append(url))

    class Inner:
        def handle_request(self, request):
            assert request.url.host == "93.184.216.34"
            return httpx.Response(200)

        async def handle_async_request(self, request):
            assert request.url.host == "93.184.216.34"
            return httpx.Response(200)

    target = "https://example.com/path"
    _PinnedTransport("example.com", "example.com", "93.184.216.34", Inner()).handle_request(
        httpx.Request("GET", target),
    )
    await _AsyncPinnedTransport("example.com", "example.com", "93.184.216.34", Inner()).handle_async_request(
        httpx.Request("GET", target),
    )
    assert checks == [target, target]
