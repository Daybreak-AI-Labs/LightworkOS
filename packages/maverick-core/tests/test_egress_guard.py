"""The enterprise boundary, tested at the layer where requests leave.

``enterprise.py`` promises one property -- *"Sensitive data physically cannot
reach a third-party API"*. The guard wraps the HTTP client libraries, so
connectors that make direct outbound HTTP, such as ``gmail_tool``,
``salesforce_tool``, ``slack_bot``, ``replicate_tool`` and
``maverick_knowledge/embed.py``, are covered without calling a check
themselves.

A pure-policy test asserting ``egress_permitted(...)`` returns False, or a
per-tool test that calls one tool's ``_run`` and greps its returned error
string, cannot detect a bypass, because neither ever issues a request. A
connector added with raw ``httpx`` calls would keep both green.

So these tests make real calls through real client libraries and assert on what
the network layer does. The blocked cases never reach a socket -- the guard
raises above the transport -- and the permitted cases are asserted by their
*connection* failing, which proves the guard let them through.
"""

from __future__ import annotations

import urllib.request

import pytest
from maverick import egress_guard
from maverick.enterprise import EgressBlocked

httpx = pytest.importorskip("httpx")

#: Refused by DNS/connect rather than by policy, so a connection error proves
#: the guard permitted the request instead of blocking it.
UNROUTABLE = "http://127.0.0.1:9/probe"


@pytest.fixture(autouse=True)
def _leave_the_guard_installed():
    """Restore the process-wide guard after every test in this file.

    Several tests here uninstall it deliberately. Leaving it off would silently
    disarm the boundary for every later test in the session.
    """
    yield
    egress_guard.uninstall()
    # Direct compatibility probes patch synthetic client classes while the
    # process guard is intentionally uninstalled.  They do not participate in
    # the runtime ``_patched`` registry, so discard their synthetic restore
    # entries before reinstalling the real libraries.
    egress_guard._originals.clear()
    egress_guard._compatibility.clear()
    egress_guard.install()


@pytest.fixture
def guarded(monkeypatch):
    """Enterprise mode on, guard installed, torn down cleanly."""
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    egress_guard.uninstall()
    egress_guard.install()
    yield
    egress_guard.uninstall()


@pytest.fixture
def unguarded_mode(monkeypatch):
    """Guard installed but enterprise mode OFF -- the default posture."""
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    egress_guard.uninstall()
    egress_guard.install()
    yield
    egress_guard.uninstall()


def _allowed(monkeypatch, *hosts):
    monkeypatch.setattr(
        "maverick.enterprise._allowed_egress_hosts", lambda: frozenset(hosts))


# -- the test that did not exist -------------------------------------------

def test_a_raw_httpx_call_is_blocked(guarded) -> None:
    """No tool, no wrapper, no gate call. Just httpx, as 60 connectors use it.

    This is the assertion the suite never had. Before the guard it fails: the
    request goes out.
    """
    with pytest.raises(EgressBlocked):
        httpx.get("https://api.example.com/v1/customers", timeout=1.0)


def test_a_raw_httpx_client_is_blocked(guarded) -> None:
    with pytest.raises(EgressBlocked), httpx.Client(timeout=1.0) as c:
        c.post("https://api.example.com/upload", json={"pii": "x"})


@pytest.mark.asyncio
async def test_a_raw_async_httpx_client_is_blocked(guarded) -> None:
    async with httpx.AsyncClient(timeout=1.0) as c:
        with pytest.raises(EgressBlocked):
            await c.get("https://api.example.com/v1/me")


def test_a_raw_urllib_call_is_blocked(guarded) -> None:
    """Nine production modules use urllib, including http_fetch itself."""
    with pytest.raises(EgressBlocked):
        urllib.request.urlopen("https://api.example.com/data", timeout=1.0)


def test_a_urllib_opener_is_blocked(guarded) -> None:
    """build_opener bypasses urlopen, so the wrapper sits on OpenerDirector."""
    opener = urllib.request.build_opener()
    with pytest.raises(EgressBlocked):
        opener.open("https://api.example.com/data", timeout=1.0)


def test_a_urllib_request_object_is_blocked(guarded) -> None:
    """urlopen also accepts a Request, whose URL lives on .full_url."""
    req = urllib.request.Request(
        "https://api.example.com/data", headers={"X": "1"})
    with pytest.raises(EgressBlocked):
        urllib.request.urlopen(req, timeout=1.0)


def test_a_wrapped_urllib_string_is_checked_on_its_real_host(unguarded_mode, monkeypatch) -> None:
    """urllib unwraps `URL:http://h/` and `<http://h/>`; the guard must see
    `h`, not an empty host that skips the tenant egress plane."""
    monkeypatch.setattr("maverick.tenant.egress.host_allowed",
                        lambda host: host != "169.254.169.254")
    opener = urllib.request.build_opener()
    for url in ("URL:http://169.254.169.254/latest", "<http://169.254.169.254/latest>"):
        with pytest.raises(EgressBlocked):
            opener.open(url, timeout=1.0)


def test_a_raw_requests_call_is_blocked(guarded) -> None:
    requests = pytest.importorskip("requests")
    with pytest.raises(EgressBlocked):
        requests.get("https://api.example.com/data", timeout=1.0)


def test_without_the_guard_the_same_call_escapes(monkeypatch) -> None:
    """Proof the guard is load-bearing, not incidental.

    Enterprise mode ON, guard NOT installed -- exactly the state the platform
    shipped in. The request is attempted and fails on the network rather than
    on policy, which is the 87-module hole reproduced in one assertion. If this
    ever starts raising EgressBlocked, something else is enforcing the boundary
    and the tests above no longer prove what they claim.
    """
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    egress_guard.uninstall()
    try:
        with pytest.raises(httpx.HTTPError):
            httpx.get(UNROUTABLE, timeout=0.5)
    finally:
        egress_guard.install()


def test_a_real_previously_ungated_connector_is_blocked(guarded, monkeypatch) -> None:
    """End-to-end on shipped code, not a synthetic httpx call.

    ``asana_tool`` is one of the 60 connectors under ``tools/`` that reached
    the network with a bare ``httpx.get`` and no gate. Nothing about the
    connector changed; it is covered because the guard sits under it. This is
    the assertion that generalises to the other 86.
    """
    monkeypatch.setenv("ASANA_TOKEN", "t-fake")
    from maverick.tools import asana_tool

    with pytest.raises(EgressBlocked):
        asana_tool._get("/workspaces")


# -- what must still be allowed --------------------------------------------

def test_the_guard_is_a_noop_when_enterprise_mode_is_off(unguarded_mode) -> None:
    """The load-bearing negative control.

    A guard that blocked by default would "pass" every test above while
    breaking every default install -- the zero-config path calls a cloud LLM.
    A connection error here proves the request was permitted and simply had
    nowhere to go.
    """
    with pytest.raises(httpx.HTTPError):
        httpx.get(UNROUTABLE, timeout=0.5)


def test_a_local_endpoint_is_permitted_under_enterprise_mode(guarded) -> None:
    """Local LLMs and sidecars must keep working inside the boundary."""
    with pytest.raises(httpx.HTTPError):
        httpx.get(UNROUTABLE, timeout=0.5)


def test_an_allowlisted_host_is_permitted(guarded, monkeypatch) -> None:
    _allowed(monkeypatch, "allowed.internal")
    try:
        httpx.get("https://allowed.internal/x", timeout=0.5)
    except EgressBlocked:  # pragma: no cover - the failure this pins
        pytest.fail("an allow-listed host must not be blocked")
    except Exception:
        pass  # DNS/connect failure is the expected outcome


def test_a_non_allowlisted_host_is_still_blocked(guarded, monkeypatch) -> None:
    """Negative control for the allow-list: it must not become allow-all."""
    _allowed(monkeypatch, "allowed.internal")
    with pytest.raises(EgressBlocked):
        httpx.get("https://other.example.com/x", timeout=0.5)


# -- redirects: every network hop gets a fresh policy decision --------------

def test_a_redirect_to_a_denied_host_is_blocked(guarded, monkeypatch) -> None:
    """An allow-listed host must not be able to hand off to a denied one.

    The first endpoint is genuinely reached and returns a 302. The second URL
    is then checked as a new request and refused before DNS/connect.
    """
    import http.server
    import socketserver
    import threading

    ports: dict[str, int] = {}

    class _Redirector(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", f"http://denied.test:{ports['b']}/x")
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = socketserver.TCPServer(("127.0.0.1", 0), _Redirector)
    ports["a"] = srv.server_address[1]
    ports["b"] = 9
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        # Permit the first hop only, and prove policy is invoked again with the
        # rebuilt redirect URL rather than reusing the first-hop decision.
        checked_urls = []

        def local_only_for_first_hop(url):
            checked_urls.append(url)
            return f":{ports['a']}" in url

        monkeypatch.setattr(
            "maverick.enterprise._is_local_endpoint",
            local_only_for_first_hop,
        )
        _allowed(monkeypatch)
        with pytest.raises(EgressBlocked):
            httpx.get(f"http://127.0.0.1:{ports['a']}/start",
                      follow_redirects=True, timeout=3.0)
        assert any(f":{ports['a']}/start" in url for url in checked_urls)
        assert any("denied.test" in url for url in checked_urls)
    finally:
        srv.shutdown()
        srv.server_close()


def test_the_first_hop_is_still_permitted(guarded, monkeypatch) -> None:
    """Positive control for the test above.

    If the guard simply blocked everything once redirects were involved, the
    redirect test would pass while the feature was broken.
    """
    monkeypatch.setattr("maverick.enterprise._is_local_endpoint",
                        lambda url: True)
    with pytest.raises(httpx.HTTPError):
        httpx.get(UNROUTABLE, timeout=0.5)


@pytest.mark.asyncio
async def test_async_permitted_hop_preserves_async_stream_contract(
    guarded,
) -> None:
    """The async wrapper must delegate to AsyncClient's own one-hop method."""
    async with httpx.AsyncClient(timeout=0.5) as client:
        with pytest.raises(httpx.HTTPError) as caught:
            await client.get(UNROUTABLE)
    assert "sync Client instance" not in str(caught.value)


# -- in-process transports are not egress ----------------------------------

def test_an_in_process_asgi_request_is_not_blocked(guarded) -> None:
    """A request that never opens a socket cannot leak, so it must not be
    refused.

    Otherwise the guard would block every TestClient request (host
    "testserver") under enterprise mode. That is not a test artifact -- it
    would refuse any in-process ASGI call a deployment makes.
    """
    starlette = pytest.importorskip("starlette.testclient")

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-length", b"2")]})
        await send({"type": "http.response.body", "body": b"ok"})

    # Starlette's TestClient, which is the exact shape that broke: it ships its
    # own `_TestClientTransport`, not httpx's ASGITransport.
    # No `with`: entering the client runs the ASGI lifespan, which this bare
    # app does not implement. The request path is what is under test.
    assert starlette.TestClient(app).get("/x").status_code == 200


def test_a_mock_transport_is_not_blocked(guarded) -> None:
    def handler(request):
        return httpx.Response(200, text="ok")

    with httpx.Client(transport=httpx.MockTransport(handler)) as c:
        assert c.get("https://denied.example.com/x").status_code == 200


def test_an_unknown_sync_transport_is_checked_before_it_can_run(guarded) -> None:
    """A custom BaseTransport is network-capable unless explicitly proven not."""

    class SocketLikeTransport(httpx.BaseTransport):
        reached = False

        def handle_request(self, request):
            self.reached = True
            return httpx.Response(200, text="escaped", request=request)

    transport = SocketLikeTransport()
    with httpx.Client(transport=transport) as client:
        with pytest.raises(EgressBlocked):
            client.get("https://denied.example.com/x")
    assert transport.reached is False


def test_an_unknown_transport_redirect_is_checked_before_second_hop(
    guarded,
    monkeypatch,
) -> None:
    """Custom transports cannot use an allowed first hop to bypass policy."""
    calls = []

    class RedirectingTransport(httpx.BaseTransport):
        def handle_request(self, request):
            calls.append(str(request.url))
            return httpx.Response(
                302,
                headers={"location": "https://denied.example.com/steal"},
                request=request,
            )

    _allowed(monkeypatch, "allowed.example.com")
    with httpx.Client(transport=RedirectingTransport()) as client:
        with pytest.raises(EgressBlocked):
            client.get(
                "https://allowed.example.com/start",
                follow_redirects=True,
            )
    assert calls == ["https://allowed.example.com/start"]


@pytest.mark.asyncio
async def test_an_unknown_async_transport_is_checked_before_it_can_run(
    guarded,
) -> None:
    """The same fail-closed classification applies to AsyncBaseTransport."""

    class AsyncSocketLikeTransport(httpx.AsyncBaseTransport):
        reached = False

        async def handle_async_request(self, request):
            self.reached = True
            return httpx.Response(200, text="escaped", request=request)

    transport = AsyncSocketLikeTransport()
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(EgressBlocked):
            await client.get("https://denied.example.com/x")
    assert transport.reached is False


def test_a_custom_mock_subclass_is_not_allowed_to_claim_in_process(
    guarded,
) -> None:
    """Only the exact known mock type is exempt; overrides can perform I/O."""

    class SocketLikeMock(httpx.MockTransport):
        reached = False

        def handle_request(self, request):
            self.reached = True
            return httpx.Response(200, text="escaped", request=request)

    transport = SocketLikeMock(lambda request: httpx.Response(200))
    with httpx.Client(transport=transport) as client:
        with pytest.raises(EgressBlocked):
            client.get("https://denied.example.com/x")
    assert transport.reached is False


def test_a_wrapped_network_transport_is_still_checked(guarded, monkeypatch) -> None:
    """The negative control that makes the rule above safe.

    `tools/_ssrf._PinnedTransport` WRAPS an httpx network transport rather than
    being one, so a rule of "only HTTPTransport counts as network" would skip
    the check for exactly the requests most worth checking. Unknown transports
    fail closed, and this pins that behavior.
    """
    from maverick.tools import _ssrf

    inner = httpx.HTTPTransport()
    pinned = _ssrf._PinnedTransport("denied.example.com",
                                    "denied.example.com", "203.0.113.1", inner)
    from maverick.egress_guard import _is_network_transport
    assert _is_network_transport(pinned) is True
    assert _is_network_transport(httpx.MockTransport(lambda r: None)) is False


def test_an_unresolvable_transport_fails_closed() -> None:
    """"We cannot tell what this is" must mean "check it"."""
    from maverick.egress_guard import _reaches_the_network

    class _Odd:
        def _transport_for_url(self, url):
            raise RuntimeError("no idea")

    assert _reaches_the_network(_Odd(), type("R", (), {"url": "x"})()) is True


# -- composition with SSRF pinning -----------------------------------------

def test_the_guard_does_not_disable_ssrf_pinning(guarded, monkeypatch) -> None:
    """The pinned transport sits below the one-hop seam; both must still apply.

    If the guard had replaced the transport rather than wrapping the client
    method, this would silently drop SSRF protection.
    """
    from maverick.tools import _ssrf

    _allowed(monkeypatch, "localhost")
    with pytest.raises(_ssrf.BlockedHost):
        _ssrf.safe_client("http://127.0.0.1/x")


# -- fail closed -----------------------------------------------------------

def test_an_unevaluable_policy_blocks_rather_than_allows(guarded, monkeypatch) -> None:
    """"We cannot tell" must not resolve to "let it out"."""
    monkeypatch.setattr(
        "maverick.enterprise.egress_permitted",
        lambda url: (_ for _ in ()).throw(RuntimeError("config on fire")))
    with pytest.raises(EgressBlocked):
        httpx.get("https://api.example.com/x", timeout=0.5)


def test_host_parser_failure_blocks_even_without_enterprise_mode(guarded, monkeypatch) -> None:
    """Tenant checks cannot be skipped when host extraction is unavailable."""
    monkeypatch.setattr("maverick.enterprise.enterprise_enabled", lambda: False)

    def fail_host_parser(url):
        raise RuntimeError("host parser unavailable")

    monkeypatch.setattr("maverick.enterprise._host_of", fail_host_parser)
    with pytest.raises(EgressBlocked, match="could not be evaluated"):
        httpx.get("https://api.example.com/x", timeout=0.5)


def test_a_block_is_audited(guarded, monkeypatch) -> None:
    """A blocked exfiltration attempt is exactly what an auditor needs to see."""
    seen = []
    monkeypatch.setattr("maverick.audit.record",
                        lambda kind, **kw: seen.append((kind, kw)) or True)
    with pytest.raises(EgressBlocked):
        httpx.get("https://api.example.com/x", timeout=0.5)
    assert seen, "a blocked egress attempt must be recorded"
    assert any("api.example.com" in str(kw) for _, kw in seen), seen


# -- the tenant egress plane, hooked into this same seam --
#
# Before this, maverick.tenant.egress was consulted directly by exactly one
# tool (http_fetch) despite its own module docstring claiming it "applies to
# every tool a tenant's agents run" -- any other tool's raw httpx/requests/
# urllib call reached a tenant-denied host fine. The tenant plane is
# independent of enterprise mode (a tenant boundary matters whether or not
# the separate enterprise allow-list is on), so these tests exercise it with
# enterprise mode both off and on.

def _tenant_denies(monkeypatch, *hosts):
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {"egress": {"deny": list(hosts)}},
    )


def test_tenant_plane_blocks_even_with_enterprise_mode_off(
    unguarded_mode, monkeypatch,
) -> None:
    """The load-bearing case: with enterprise mode off (the default posture),
    a tenant-denied host must still be refused at this seam -- not just when
    the one tool (http_fetch) that already called tenant.egress is used."""
    _tenant_denies(monkeypatch, "denied.example.com")
    with pytest.raises(EgressBlocked, match="egress policy"):
        httpx.get("https://denied.example.com/x", timeout=0.5)


def test_tenant_plane_with_enterprise_off_permits_a_host_not_denied(
    unguarded_mode, monkeypatch,
) -> None:
    """Negative control: a configured tenant deny-list must not become deny-all."""
    _tenant_denies(monkeypatch, "denied.example.com")
    with pytest.raises(httpx.HTTPError):
        httpx.get(UNROUTABLE, timeout=0.5)


def test_tenant_denial_applies_even_when_the_enterprise_allowlist_permits(
    guarded, monkeypatch,
) -> None:
    """The two planes compose with AND: passing the enterprise allow-list is
    not enough to bypass a tenant deny."""
    _allowed(monkeypatch, "denied.example.com")
    _tenant_denies(monkeypatch, "denied.example.com")
    with pytest.raises(EgressBlocked, match="egress policy"):
        httpx.get("https://denied.example.com/x", timeout=0.5)


def test_tenant_plane_unconfigured_falls_through_to_the_enterprise_decision(
    guarded,
) -> None:
    """No [egress] / [tenancy.egress.<t>] configured -> the tenant plane is
    allow-all, so the enterprise allow-list alone still decides (no
    regression for a deployment that only uses enterprise mode)."""
    with pytest.raises(EgressBlocked, match="enterprise mode"):
        httpx.get("https://api.example.com/x", timeout=0.5)


def test_an_unevaluable_tenant_policy_blocks_rather_than_allows(
    guarded, monkeypatch,
) -> None:
    """"We cannot tell" must not resolve to "let it out", for the tenant plane
    exactly like it already doesn't for the enterprise one. Allow-list the
    host under enterprise first, so only the tenant-policy exception -- not
    enterprise's own independent default-deny -- can explain the block."""
    _allowed(monkeypatch, "api.example.com")
    monkeypatch.setattr(
        "maverick.tenant.egress.host_allowed",
        lambda host, **k: (_ for _ in ()).throw(RuntimeError("config on fire")))
    with pytest.raises(EgressBlocked):
        httpx.get("https://api.example.com/x", timeout=0.5)


# -- install/uninstall mechanics -------------------------------------------

#: The attribute the HTTPX-family wrappers actually replace. Named here so these
#: mechanics tests fail loudly if the seam moves again, rather than quietly
#: asserting nothing about the method that carries the check.
_SEAM = "_send_single_request"


def test_the_seam_is_recorded() -> None:
    """Pins WHICH method carries the check, not merely that one does.

    ``_send_single_request`` is entered once per actual redirect hop; wrapping
    ``send`` would inspect only the first URL in the chain.
    """
    assert hasattr(httpx.Client, _SEAM)
    status = egress_guard.compatibility_status()
    assert status["active"] is True
    assert status["clients"]["httpx"] == {
        "compatible": True,
        "reason": "",
        "seam": _SEAM,
    }


@pytest.mark.asyncio
async def test_one_hop_wrappers_forward_signature_extensions(
    monkeypatch,
) -> None:
    """Future optional seam parameters must reach the matching client method."""
    egress_guard.uninstall()
    calls = []
    checked = []

    class SyncClient:
        def _send_single_request(self, request, *args, **kwargs):
            calls.append(("sync", request, args, kwargs))
            return "sync-result"

    class AsyncClient:
        async def _send_single_request(self, request, *args, **kwargs):
            calls.append(("async", request, args, kwargs))
            return "async-result"

    FakeHttpx = type(
        "FakeHttpx",
        (),
        {"Client": SyncClient, "AsyncClient": AsyncClient},
    )

    request = type("Request", (), {"url": "https://allowed.example/x"})()
    monkeypatch.setattr(egress_guard, "_reaches_the_network", lambda *a: True)
    monkeypatch.setattr(egress_guard, "_check", lambda url: checked.append(url))

    egress_guard._patch_httpx(FakeHttpx)

    assert (
        SyncClient()._send_single_request(request, "future", option=1)
        == "sync-result"
    )
    assert (
        await AsyncClient()._send_single_request(request, "future", option=2)
        == "async-result"
    )
    assert calls == [
        ("sync", request, ("future",), {"option": 1}),
        ("async", request, ("future",), {"option": 2}),
    ]
    assert checked == [
        "https://allowed.example/x",
        "https://allowed.example/x",
    ]


@pytest.mark.asyncio
async def test_httpx2_one_hop_wrappers_enforce_sync_and_async(
    monkeypatch,
) -> None:
    """Provider SDK traffic cannot bypass policy through the httpx2 fork."""
    egress_guard.uninstall()
    delegated = []

    class SyncClient:
        def _send_single_request(self, request, *args, **kwargs):
            delegated.append(("sync", request, args, kwargs))
            return "network"

    class AsyncClient:
        async def _send_single_request(self, request, *args, **kwargs):
            delegated.append(("async", request, args, kwargs))
            return "network"

    fake_httpx2 = type(
        "FakeHttpx2",
        (),
        {"Client": SyncClient, "AsyncClient": AsyncClient},
    )
    request = type("Request", (), {"url": "https://api.example.com/x"})()

    def deny(url):
        raise EgressBlocked(f"refused {url}")

    monkeypatch.setattr(egress_guard, "_reaches_the_network", lambda *a: True)
    monkeypatch.setattr(egress_guard, "_check", deny)
    egress_guard._patch_httpx2(fake_httpx2)

    with pytest.raises(EgressBlocked, match="api.example.com"):
        SyncClient()._send_single_request(request, "future", option=1)
    with pytest.raises(EgressBlocked, match="api.example.com"):
        await AsyncClient()._send_single_request(request, "future", option=2)
    assert delegated == []
    assert egress_guard.compatibility_status()["clients"]["httpx2"] == {
        "compatible": True,
        "reason": "",
        "seam": _SEAM,
    }


@pytest.mark.asyncio
async def test_installed_httpx2_enforces_and_exempts_local_mock(guarded) -> None:
    """Exercise the exact provider-SDK transport version when it is installed."""
    httpx2 = pytest.importorskip("httpx2")

    assert egress_guard.compatibility_status()["clients"]["httpx2"] == {
        "compatible": True,
        "reason": "",
        "seam": _SEAM,
    }
    with pytest.raises(EgressBlocked):
        httpx2.get("https://api.example.com/x", timeout=0.1)
    async with httpx2.AsyncClient(timeout=0.1) as client:
        with pytest.raises(EgressBlocked):
            await client.get("https://api.example.com/x")

    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx2.Response(200, text="local")

    with httpx2.Client(transport=httpx2.MockTransport(handler)) as client:
        response = client.get("https://in-process.invalid/x")
    assert response.status_code == 200
    assert seen == ["https://in-process.invalid/x"]


def test_httpx2_exact_in_process_transports_are_exempt() -> None:
    """The new family keeps exact-type local transports off the egress path."""
    import sys

    class MockTransport:
        pass

    class ASGITransport:
        pass

    class WSGITransport:
        pass

    fake_httpx2 = type(
        "FakeHttpx2",
        (),
        {
            "MockTransport": MockTransport,
            "ASGITransport": ASGITransport,
            "WSGITransport": WSGITransport,
        },
    )
    missing = object()
    previous = sys.modules.get("httpx2", missing)
    sys.modules["httpx2"] = fake_httpx2
    try:
        assert egress_guard._is_network_transport(MockTransport()) is False
        assert egress_guard._is_network_transport(ASGITransport()) is False
        assert egress_guard._is_network_transport(WSGITransport()) is False

        class SocketCapableSubclass(MockTransport):
            pass

        assert (
            egress_guard._is_network_transport(SocketCapableSubclass()) is True
        )
    finally:
        if previous is missing:
            sys.modules.pop("httpx2", None)
        else:
            sys.modules["httpx2"] = previous


@pytest.mark.parametrize(
    ("client_name", "patcher_name"),
    (("httpx", "_patch_httpx"), ("httpx2", "_patch_httpx2")),
)
def test_incompatible_httpx_seam_is_visible_in_readiness(
    monkeypatch,
    client_name,
    patcher_name,
) -> None:
    egress_guard.uninstall()

    class MissingSeam:
        pass

    class IncompatibleHttpx:
        Client = MissingSeam
        AsyncClient = MissingSeam

    with pytest.raises(RuntimeError, match="_send_single_request"):
        getattr(egress_guard, patcher_name)(IncompatibleHttpx)

    status = egress_guard.compatibility_status()
    assert status["active"] is False
    assert status["clients"][client_name]["compatible"] is False
    assert status["clients"][client_name]["fail_closed_fallback"] is False
    assert "_send_single_request" in status["clients"][client_name]["reason"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("client_name", "patcher_name"),
    (("httpx", "_patch_httpx"), ("httpx2", "_patch_httpx2")),
)
async def test_incompatible_httpx_fails_closed_without_delegating(
    monkeypatch,
    client_name,
    patcher_name,
) -> None:
    """A future HTTPX cannot silently open the enterprise data boundary."""
    egress_guard.uninstall()
    calls = []

    class SyncClient:
        def send(self, request, *args, **kwargs):
            calls.append(("sync", request, args, kwargs))
            return "network"

    class AsyncClient:
        async def send(self, request, *args, **kwargs):
            calls.append(("async", request, args, kwargs))
            return "network"

    FakeHttpx = type(
        "FakeHttpx",
        (),
        {"Client": SyncClient, "AsyncClient": AsyncClient},
    )
    request = type("Request", (), {"url": "https://api.example.com/x"})()
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    monkeypatch.setattr("maverick.audit.writer.audit_event", lambda *a, **k: True)

    getattr(egress_guard, patcher_name)(FakeHttpx)

    status = egress_guard.compatibility_status()
    assert status["active"] is False
    assert status["clients"][client_name]["compatible"] is False
    assert status["clients"][client_name]["fail_closed_fallback"] is True
    assert status["clients"][client_name]["fallback_seam"] == "send"
    with pytest.raises(EgressBlocked, match="every redirect hop"):
        SyncClient().send(request, "future", option=1)
    with pytest.raises(EgressBlocked, match="every redirect hop"):
        await AsyncClient().send(request, "future", option=2)
    assert calls == []


def test_incompatible_httpx_fallback_preserves_default_mode(
    monkeypatch,
) -> None:
    """The degraded guard is fail-closed only where the boundary is asserted."""
    egress_guard.uninstall()
    calls = []

    class SyncClient:
        def send(self, request, *args, **kwargs):
            calls.append((request, args, kwargs))
            return "delegated"

    class AsyncClient:
        async def send(self, request, *args, **kwargs):
            return "delegated"

    FakeHttpx = type(
        "FakeHttpx",
        (),
        {"Client": SyncClient, "AsyncClient": AsyncClient},
    )
    request = type("Request", (), {"url": "https://api.example.com/x"})()
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    egress_guard._patch_httpx(FakeHttpx)

    assert SyncClient().send(request, "future", option=1) == "delegated"
    assert calls == [(request, ("future",), {"option": 1})]


def test_install_is_idempotent() -> None:
    egress_guard.uninstall()
    assert egress_guard.install() is True
    first = getattr(httpx.Client, _SEAM)
    assert egress_guard.install() is True
    assert getattr(httpx.Client, _SEAM) is first, (
        "double-wrapping would stack checks")
    egress_guard.uninstall()


def test_uninstall_restores_the_original_method() -> None:
    egress_guard.uninstall()
    original = getattr(httpx.Client, _SEAM)
    egress_guard.install()
    assert getattr(httpx.Client, _SEAM) is not original
    egress_guard.uninstall()
    assert getattr(httpx.Client, _SEAM) is original
    assert egress_guard.active() is False


def test_install_rolls_back_every_family_when_a_later_family_fails(
    monkeypatch,
) -> None:
    """Install is one transaction, not a sequence of lasting partial patches."""
    requests = pytest.importorskip("requests")
    egress_guard.uninstall()
    original_httpx = getattr(httpx.Client, _SEAM)
    original_requests = requests.Session.send
    original_patcher = egress_guard._TARGETS["requests"]

    def fail_requests(_module):
        raise RuntimeError("synthetic requests patch failure")

    monkeypatch.setitem(egress_guard._TARGETS, "requests", fail_requests)
    try:
        with pytest.raises(RuntimeError, match="synthetic requests"):
            egress_guard.install()

        assert getattr(httpx.Client, _SEAM) is original_httpx
        assert requests.Session.send is original_requests
        assert egress_guard._originals == {}
        assert egress_guard._patched == set()
        assert egress_guard._hook is None
        assert egress_guard.compatibility_status()["installed"] is False
        assert egress_guard.active() is False
    finally:
        # Restore before the autouse fixture re-arms the process-wide guard.
        egress_guard._TARGETS["requests"] = original_patcher


def test_install_rolls_back_a_half_patched_client_family() -> None:
    """A rejected async seam also restores the sync seam already replaced."""
    import sys
    import types

    egress_guard.uninstall()

    class SyncClient:
        def _send_single_request(self, request):
            return request

    class RejectGuardWrapper(type):
        def __setattr__(cls, name, value):
            target = getattr(
                value,
                egress_guard._WRAPPER_TARGET,
                None,
            )
            if name == _SEAM and target == "httpx2.AsyncClient." + _SEAM:
                raise RuntimeError("synthetic async seam rejection")
            super().__setattr__(name, value)

    class AsyncClient(metaclass=RejectGuardWrapper):
        async def _send_single_request(self, request):
            return request

    fake_httpx2 = types.ModuleType("httpx2")
    fake_httpx2.Client = SyncClient
    fake_httpx2.AsyncClient = AsyncClient
    original_sync = SyncClient._send_single_request
    original_async = AsyncClient._send_single_request
    missing = object()
    previous = sys.modules.get("httpx2", missing)
    sys.modules["httpx2"] = fake_httpx2
    try:
        with pytest.raises(RuntimeError, match="async seam rejection"):
            egress_guard.install()

        assert SyncClient._send_single_request is original_sync
        assert AsyncClient._send_single_request is original_async
        assert egress_guard._originals == {}
        assert egress_guard._hook is None
        assert egress_guard.active() is False
    finally:
        egress_guard.uninstall()
        if previous is missing:
            sys.modules.pop("httpx2", None)
        else:
            sys.modules["httpx2"] = previous


def test_uninstall_cleans_partial_state_when_installed_flag_is_false() -> None:
    """A failed install must remain recoverable before its commit flag is set."""
    egress_guard.uninstall()

    class SyncClient:
        def _send_single_request(self, request):
            return request

    class AsyncClient:
        async def _send_single_request(self, request):
            return request

    fake_httpx = type(
        "FakeHttpx",
        (),
        {"Client": SyncClient, "AsyncClient": AsyncClient},
    )
    original_sync = SyncClient._send_single_request
    original_async = AsyncClient._send_single_request

    egress_guard._patch_httpx(fake_httpx)
    assert egress_guard._installed is False
    assert SyncClient._send_single_request is not original_sync
    assert AsyncClient._send_single_request is not original_async

    egress_guard.uninstall()

    assert SyncClient._send_single_request is original_sync
    assert AsyncClient._send_single_request is original_async
    assert egress_guard._originals == {}
    assert egress_guard._compatibility == {}


def test_install_and_uninstall_restore_httpx2() -> None:
    """Lifecycle bookkeeping is isolated by family and fully reversible."""
    import sys
    import types

    egress_guard.uninstall()

    class SyncClient:
        def _send_single_request(self, request):
            return request

    class AsyncClient:
        async def _send_single_request(self, request):
            return request

    fake_httpx2 = types.ModuleType("httpx2")
    fake_httpx2.Client = SyncClient
    fake_httpx2.AsyncClient = AsyncClient
    missing = object()
    previous = sys.modules.get("httpx2", missing)
    sys.modules["httpx2"] = fake_httpx2
    original_sync = SyncClient._send_single_request
    original_async = AsyncClient._send_single_request
    try:
        assert egress_guard.install() is True
        assert SyncClient._send_single_request is not original_sync
        assert AsyncClient._send_single_request is not original_async
        assert egress_guard.compatibility_status()["clients"]["httpx2"][
            "compatible"
        ] is True

        egress_guard.uninstall()
        assert SyncClient._send_single_request is original_sync
        assert AsyncClient._send_single_request is original_async
    finally:
        egress_guard.uninstall()
        if previous is missing:
            sys.modules.pop("httpx2", None)
        else:
            sys.modules["httpx2"] = previous


def test_importing_maverick_does_not_import_httpx_families() -> None:
    """Arming the guard must not cost cold-start time.

    The first version imported httpx eagerly and broke the CLI's cold-start
    guarantee -- `maverick --help` is pinned not to load httpx, the provider
    SDKs, numpy or fastapi, because a stray module-level import taxes every
    invocation. The guard now hooks the import instead of forcing it.
    """
    import subprocess
    import sys
    out = subprocess.run(
        [sys.executable, "-c",
         "import maverick, sys; print('httpx' in sys.modules, "
         "'httpx2' in sys.modules)"],
        capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "False False", (
        "importing maverick pulled in an HTTPX family"
    )


def test_a_library_imported_after_the_guard_is_still_wrapped() -> None:
    """The other half: lazy must not mean unguarded.

    Most connectors do ``import httpx`` inside the function body, so the module
    loads long after ``import maverick``. If the hook only covered
    already-loaded libraries, exactly those connectors would stay unprotected
    -- which is the population the whole change exists to cover.

    Exercise this in a subprocess. Evicting and re-importing HTTPX in the
    pytest process creates two incompatible ``Request``/``SyncByteStream``
    class families and can corrupt already-collected Starlette TestClient
    classes even when the guard restores every method correctly.
    """
    import subprocess
    import sys

    script = (
        "import os, sys; "
        "os.environ['MAVERICK_ENTERPRISE']='1'; "
        "import maverick; "
        "assert 'httpx' not in sys.modules; "
        "import httpx; "
        "from maverick.enterprise import EgressBlocked; "
        "\ntry:\n"
        " httpx.get('https://api.example.com/x', timeout=1.0)\n"
        "except EgressBlocked:\n"
        " print('blocked')\n"
        "else:\n"
        " raise SystemExit('late HTTPX import was not guarded')\n"
    )
    out = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "blocked"


def test_httpx2_imported_after_the_guard_is_still_wrapped() -> None:
    """A provider SDK's lazy httpx2 import is intercepted immediately."""
    import subprocess
    import sys

    script = """
import os
import pathlib
import sys
import tempfile

root = pathlib.Path(tempfile.mkdtemp())
(root / "httpx2.py").write_text(
    "class Client:\\n"
    "    def _transport_for_url(self, url): return object()\\n"
    "    def _send_single_request(self, request): return 'network'\\n"
    "class AsyncClient:\\n"
    "    def _transport_for_url(self, url): return object()\\n"
    "    async def _send_single_request(self, request): return 'network'\\n",
    encoding="utf-8",
)
sys.path.insert(0, str(root))
os.environ["MAVERICK_ENTERPRISE"] = "1"
import maverick
assert "httpx2" not in sys.modules
import httpx2
from maverick.enterprise import EgressBlocked
request = type("Request", (), {"url": "https://api.example.com/x"})()
try:
    httpx2.Client()._send_single_request(request)
except EgressBlocked:
    print("blocked")
else:
    raise SystemExit("late httpx2 import was not guarded")
"""
    out = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "blocked"


def test_a_shared_zipimport_loader_still_imports_other_modules() -> None:
    """zipimport keeps one loader per archive; wrapping it for httpx2 must not
    turn the next plain import from the same archive into a refusal."""
    import subprocess
    import sys

    script = """
import os
import pathlib
import sys
import tempfile
import zipfile

archive = pathlib.Path(tempfile.mkdtemp()) / "bundle.zip"
with zipfile.ZipFile(archive, "w") as bundle:
    bundle.writestr("httpx2.py",
        "class Client:\\n"
        "    def _transport_for_url(self, url): return object()\\n"
        "    def _send_single_request(self, request): return 'network'\\n"
        "class AsyncClient:\\n"
        "    def _transport_for_url(self, url): return object()\\n"
        "    async def _send_single_request(self, request): return 'network'\\n")
    bundle.writestr("othermod.py", "VALUE = 1\\n")
sys.path.insert(0, str(archive))
os.environ["MAVERICK_ENTERPRISE"] = "1"
import maverick
import httpx2
import othermod
assert othermod.VALUE == 1
from maverick.enterprise import EgressBlocked
request = type("Request", (), {"url": "https://api.example.com/x"})()
try:
    httpx2.Client()._send_single_request(request)
except EgressBlocked:
    print("blocked")
"""
    out = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "blocked"


@pytest.mark.parametrize("client_name", ("httpx", "httpx2"))
def test_reloading_a_client_family_rearms_both_module_generations(
    client_name,
) -> None:
    """Reload cannot replace guarded classes while readiness remains active."""
    import subprocess
    import sys

    script = f'''
import importlib
import os
import pathlib
import sys
import tempfile

root = pathlib.Path(tempfile.mkdtemp())
(root / "{client_name}.py").write_text(
    "class Client:\\n"
    "    def _transport_for_url(self, url): return object()\\n"
    "    def _send_single_request(self, request): return 'network'\\n"
    "class AsyncClient:\\n"
    "    def _transport_for_url(self, url): return object()\\n"
    "    async def _send_single_request(self, request): return 'network'\\n",
    encoding="utf-8",
)
sys.path.insert(0, str(root))
os.environ["MAVERICK_ENTERPRISE"] = "1"
import maverick
client = importlib.import_module("{client_name}")
from maverick import egress_guard
from maverick.enterprise import EgressBlocked

old_client = client.Client
old_method = old_client._send_single_request
assert egress_guard.active()
client = importlib.reload(client)
new_client = client.Client
new_method = new_client._send_single_request
assert new_client is not old_client
assert egress_guard.active()
request = type("Request", (), {{"url": "https://api.example.com/x"}})()
for owner in (old_client, new_client):
    try:
        owner()._send_single_request(request)
    except EgressBlocked:
        pass
    else:
        raise SystemExit("module generation bypassed the egress guard")

egress_guard.uninstall()
assert old_client._send_single_request is not old_method
assert new_client._send_single_request is not new_method
assert old_client()._send_single_request(request) == "network"
assert new_client()._send_single_request(request) == "network"
print("reload-guarded")
'''
    out = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "reload-guarded"


def test_reloading_the_guard_does_not_leak_import_hooks() -> None:
    """Each module generation replaces, rather than stacks, its import hook."""
    import subprocess
    import sys

    script = r'''
import importlib
import sys

import maverick.egress_guard as guard

marker = "__maverick_egress_guard_import_hook__"

def hooks():
    return [finder for finder in sys.meta_path if getattr(finder, marker, False)]

assert len(hooks()) == 1
for _ in range(3):
    guard = importlib.reload(guard)
    assert guard.install()
    assert len(hooks()) == 1

import httpx2

assert guard.active()
guard.uninstall()
assert not guard.active()
assert hooks() == []
print("guard-reload-clean")
'''
    out = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "guard-reload-clean"


@pytest.mark.parametrize(
    ("setting", "value"),
    (
        ("MAVERICK_ENTERPRISE", "1"),
        ("MAVERICK_COMPLIANCE_PROFILES", "hipaa"),
    ),
)
def test_asserted_boundary_refuses_preloaded_incompatible_client_startup(
    setting,
    value,
) -> None:
    """An asserted boundary cannot be converted into best-effort bootstrap."""
    import subprocess
    import sys

    script = f'''
import os
import pathlib
import sys
import tempfile

root = pathlib.Path(tempfile.mkdtemp())
(root / "httpx.py").write_text(
    "class Client:\\n    pass\\nclass AsyncClient:\\n    pass\\n",
    encoding="utf-8",
)
sys.path.insert(0, str(root))
os.environ["MAVERICK_HOME"] = str(root / "home")
os.environ.pop("MAVERICK_ENTERPRISE", None)
os.environ.pop("MAVERICK_COMPLIANCE_PROFILES", None)
os.environ["{setting}"] = "{value}"
import httpx
try:
    import maverick
except RuntimeError as exc:
    assert "process-wide egress boundary could not be installed" in str(exc)
    print("startup-refused")
else:
    raise SystemExit("asserted boundary started without an enforceable guard")
'''
    out = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "startup-refused"


def test_default_startup_tolerates_a_preloaded_incompatible_client() -> None:
    """The zero-config import contract stays tolerant outside the boundary."""
    import subprocess
    import sys

    script = r'''
import os
import pathlib
import sys
import tempfile

root = pathlib.Path(tempfile.mkdtemp())
(root / "httpx.py").write_text(
    "class Client:\n    pass\nclass AsyncClient:\n    pass\n",
    encoding="utf-8",
)
sys.path.insert(0, str(root))
os.environ["MAVERICK_HOME"] = str(root / "home")
os.environ["MAVERICK_ENTERPRISE"] = "0"
os.environ.pop("MAVERICK_COMPLIANCE_PROFILES", None)
import httpx
import maverick
from maverick import egress_guard
status = egress_guard.compatibility_status()
assert status["installed"] is False
assert status["active"] is False
print("startup-tolerated")
'''
    out = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "startup-tolerated"


@pytest.mark.parametrize("client_name", ("httpx", "httpx2"))
def test_late_client_import_is_refused_when_no_guard_seam_exists(
    client_name,
) -> None:
    """A future client shape cannot remain imported and silently unguarded."""
    import subprocess
    import sys

    script = f"""
import pathlib
import sys
import tempfile

root = pathlib.Path(tempfile.mkdtemp())
(root / "{client_name}.py").write_text(
    "class Client:\\n    pass\\nclass AsyncClient:\\n    pass\\n",
    encoding="utf-8",
)
sys.path.insert(0, str(root))
import maverick
try:
    __import__("{client_name}")
except RuntimeError as exc:
    assert "egress boundary could not be installed" in str(exc)
    print("refused")
else:
    raise SystemExit("incompatible HTTP client remained importable without a guard")
"""
    out = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "refused"


def test_importing_maverick_installs_the_guard() -> None:
    """The wiring that cannot be forgotten.

    Explicit per-entry-point installation is the same shape of mistake as
    per-tool gating: it works until someone adds an entry point.
    """
    import subprocess
    import sys
    out = subprocess.run(
        [sys.executable, "-c",
         "import maverick; from maverick import egress_guard;"
         " print(egress_guard.active())"],
        capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "True", out.stdout
