"""Redirect pinning must preserve TLS identity and caller transport settings."""
from __future__ import annotations

import datetime
import ipaddress
import select
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
from maverick.governed_http import _send_pinned_redirect, guarded_redirect_get


@pytest.fixture
def tls_origins(tmp_path, monkeypatch):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "alpha.example")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName("first.example"), x509.DNSName("alpha.example"),
                x509.DNSName("xn--bcher-kva.example"), x509.DNSName("proxy.example"),
            ]), False).sign(key, hashes.SHA256()))
    certpath, keypath = tmp_path / "cert.pem", tmp_path / "key.pem"
    certpath.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keypath.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                         serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    seen, snis = [], []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_GET(self):
            host = self.headers["Host"].split(":")[0]
            seen.append(host)
            target = ("xn--bcher-kva.example" if self.path == "/idn" else
                      {"first.example": "alpha.example", "alpha.example": "beta.example"}.get(host))
            self.send_response(302 if target else 200)
            if target:
                self.send_header("Location", f"https://{target}:{self.server.server_port}/next")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certpath, keypath)
    ctx.set_servername_callback(lambda sock, sni, context: snis.append(sni))
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    trust = ssl.create_default_context(cafile=str(certpath))
    real_resolve = socket.getaddrinfo

    def dns(host, *args, **kwargs):
        return real_resolve("127.0.0.1" if str(host).endswith(".example") else host, *args, **kwargs)

    # Map the public shared-IP scenario to an isolated local server. Certificate
    # validation, hostname verification, TLS SNI and actual pooling remain real.
    monkeypatch.setattr(socket, "getaddrinfo", dns)
    monkeypatch.setattr("maverick.tools._ssrf.resolve_pinned_ip", lambda *a, **k: "127.0.0.1")
    monkeypatch.setattr("maverick.egress_guard._check", lambda url: None)
    try:
        yield server.server_port, trust, seen, snis, ctx
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_redirect_does_not_reuse_another_host_tls_identity(tls_origins):
    port, trust, seen, snis, _ctx = tls_origins
    with httpx.Client(verify=trust, trust_env=False, timeout=2) as client:
        with pytest.raises(httpx.ConnectError, match="CERTIFICATE_VERIFY_FAILED"):
            guarded_redirect_get(client.get)(f"https://first.example:{port}/start")
        assert not client.is_closed
    assert seen == ["first.example", "alpha.example"]
    assert snis == ["first.example", "alpha.example", "beta.example"]


def test_idn_redirect_uses_ascii_host_and_tls_identity(tls_origins):
    port, trust, seen, snis, _ctx = tls_origins
    with httpx.Client(verify=trust, trust_env=False, timeout=2) as client:
        response = guarded_redirect_get(client.get)(f"https://first.example:{port}/idn")
        assert response.text == "ok"
    assert seen == ["first.example", "xn--bcher-kva.example"]
    assert snis == ["first.example", "xn--bcher-kva.example"]


@pytest.mark.parametrize("proxy_scheme", [None, "http", "https"])
def test_isolated_redirect_retains_tls_proxy_and_pool_configuration(proxy_scheme):
    from maverick.governed_http import _isolated_redirect_transport

    trust = ssl.create_default_context()
    proxy_trust = ssl.create_default_context()
    proxy = None if proxy_scheme is None else httpx.Proxy(
        f"{proxy_scheme}://proxy.example:8080", auth=("account", "sample"),
        headers={"X-Proxy-Route": "fixed"}, ssl_context=proxy_trust if proxy_scheme == "https" else None,
    )
    with httpx.HTTPTransport(verify=trust, proxy=proxy, retries=2,
                             limits=httpx.Limits(max_connections=3, max_keepalive_connections=1)) as original:
        isolated = _isolated_redirect_transport(original, host="next.example")
        try:
            assert isolated._pool is not original._pool
            assert isolated._pool._ssl_context is trust
            for option in ("max_connections", "max_keepalive_connections", "http1", "http2", "retries"):
                assert getattr(isolated._pool, "_" + option) == getattr(original._pool, "_" + option)
            assert isolated._pool._connections is not original._pool._connections
            assert isolated._pool._optional_thread_lock is not original._pool._optional_thread_lock
            if proxy is not None:
                assert isolated._pool._proxy_url == original._pool._proxy_url
                assert isolated._pool._proxy_headers == original._pool._proxy_headers
                assert isolated._pool._proxy_ssl_context is original._pool._proxy_ssl_context
        finally:
            isolated.close()
        assert original._pool._connections == []


def test_unknown_network_redirect_transport_is_refused(monkeypatch):
    sent = []

    class UnknownTransport(httpx.BaseTransport):
        def handle_request(self, request):
            sent.append(request)
            return httpx.Response(200)

    monkeypatch.setattr("maverick.egress_guard._check", lambda url: None)
    monkeypatch.setattr("maverick.tools._ssrf.resolve_pinned_ip", lambda *a, **k: "93.184.216.34")
    with httpx.Client(transport=UnknownTransport()) as client:
        with pytest.raises(ValueError, match="cannot safely isolate"):
            _send_pinned_redirect(client, httpx.Request("GET", "https://next.example/"))
    assert sent == []


@pytest.mark.parametrize("scheme,path,wrong_certificate,bad_proxy", [
    ("http", "/idn", False, False), ("https", "/idn", False, False),
    ("http", "/start", True, False), ("https", "/start", True, False),
    ("https", "/idn", True, True),
])
def test_proxy_redirect_connects_by_name_and_verifies_each_tls_identity(
    tls_origins, scheme, path, wrong_certificate, bad_proxy,
):
    port, trust, seen, snis, server_tls = tls_origins
    tunnels = []

    class ProxyHandler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_CONNECT(self):
            tunnels.append((self.path, self.headers.get("Proxy-Authorization")))
            host, target_port = self.path.rsplit(":", 1)
            with socket.create_connection((host, int(target_port)), timeout=2) as upstream:
                self.send_response(200)
                self.end_headers()
                peers = (self.connection, upstream)
                while True:
                    ready, _, _ = select.select(peers, [], [], 2)
                    if not ready:
                        return
                    for source in ready:
                        data = source.recv(65536)
                        if not data:
                            return
                        (upstream if source is self.connection else self.connection).sendall(data)

    proxy_server = ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
    if scheme == "https":
        proxy_server.socket = server_tls.wrap_socket(proxy_server.socket, server_side=True)
    thread = threading.Thread(target=proxy_server.serve_forever, daemon=True)
    thread.start()
    proxy_host = "bad-proxy.example" if bad_proxy else "proxy.example"
    proxy = httpx.Proxy(f"{scheme}://{proxy_host}:{proxy_server.server_port}", auth=("account", "sample"),
                       ssl_context=trust if scheme == "https" else None)
    try:
        with httpx.Client(verify=trust, proxy=proxy, trust_env=False, timeout=2) as client:
            if wrong_certificate:
                with pytest.raises(httpx.ConnectError, match="CERTIFICATE_VERIFY_FAILED"):
                    if bad_proxy:
                        _send_pinned_redirect(client, httpx.Request("GET", f"https://first.example:{port}{path}"))
                    else:
                        guarded_redirect_get(client.get)(f"https://first.example:{port}{path}")
            else:
                assert guarded_redirect_get(client.get)(f"https://first.example:{port}{path}").text == "ok"
    finally:
        proxy_server.shutdown()
        proxy_server.server_close()
        thread.join(timeout=2)
    if bad_proxy:
        assert seen == [] and tunnels == []
        assert snis == ["bad-proxy.example"]
        return
    expected = ["first.example", "alpha.example"] if wrong_certificate else ["first.example", "xn--bcher-kva.example"]
    assert seen == expected
    tls_names = ["first.example", "alpha.example", "beta.example"] if wrong_certificate else expected
    # Every CONNECT names the origin host; the proxy resolves it.
    assert [target for target, _auth in tunnels] == [f"{name}:{port}" for name in tls_names]
    assert all(auth == "Basic YWNjb3VudDpzYW1wbGU=" for _target, auth in tunnels)
    expected_snis = [name for origin in tls_names for name in (("proxy.example", origin) if scheme == "https" else (origin,))]
    assert snis == expected_snis


def test_proxy_resolves_redirect_names_this_host_cannot(monkeypatch):
    """Proxy-only egress: the proxy, not local DNS, resolves each redirect hop."""
    from maverick.tools import _ssrf

    real_resolve = socket.getaddrinfo
    forwarded = []

    def no_public_dns(host, *args, **kwargs):
        try:
            ipaddress.ip_address(str(host))
        except ValueError:
            raise socket.gaierror(socket.EAI_NONAME, "no local resolver") from None
        return real_resolve(host, *args, **kwargs)

    class ForwardProxy(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_GET(self):
            forwarded.append(self.path)
            location = {"http://first.example/start": "http://next.example/done",
                        "http://next.example/done": "http://169.254.169.254/latest/meta-data/"}.get(self.path)
            self.send_response(302 if location else 200)
            if location:
                self.send_header("Location", location)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

    monkeypatch.setattr(socket, "getaddrinfo", no_public_dns)
    monkeypatch.setattr("maverick.egress_guard._check", lambda url: None)
    monkeypatch.delenv("MAVERICK_FETCH_ALLOW_PRIVATE", raising=False)
    server = ThreadingHTTPServer(("127.0.0.1", 0), ForwardProxy)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with httpx.Client(proxy=f"http://127.0.0.1:{server.server_port}", trust_env=False, timeout=2) as client:
            # The metadata literal is refused before it reaches the proxy.
            with pytest.raises(_ssrf.BlockedHost):
                guarded_redirect_get(client.get)("http://first.example/start")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    assert forwarded == ["http://first.example/start", "http://next.example/done"]


def test_direct_redirect_honors_private_network_setting(monkeypatch):
    """With private networks allowed, an internal issuer may redirect to itself."""
    from maverick.tools import _ssrf

    seen = []
    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")
    monkeypatch.setattr("maverick.egress_guard._check", lambda url: None)
    monkeypatch.setattr(_ssrf.socket, "getaddrinfo", lambda host, *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (host if host[0].isdigit() else "10.0.0.5", 0))])

    def network_handle_request(self, request):
        seen.append(str(request.url))
        if len(seen) == 1:
            return httpx.Response(302, headers={"Location": "/realms/main/config"})
        if len(seen) == 2:
            return httpx.Response(302, headers={"Location": "https://169.254.169.254/latest/"})
        return httpx.Response(200, text="ok")

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", network_handle_request)
    with httpx.Client(transport=httpx.HTTPTransport()) as client:
        # The private same-origin hop is pinned and sent; metadata stays blocked.
        with pytest.raises(_ssrf.BlockedHost):
            guarded_redirect_get(client.get)("https://issuer.internal/start")
    assert seen == ["https://issuer.internal/start", "https://10.0.0.5/realms/main/config"]


def test_isolated_redirect_supports_httpcore_without_pool_proxy(monkeypatch):
    """httpcore 1.0.0-1.0.6 (allowed by httpx 0.27) has no ConnectionPool proxy."""
    import httpcore
    from maverick.governed_http import _isolated_redirect_transport

    real_init = httpcore.ConnectionPool.__init__
    with httpx.HTTPTransport() as original:
        del original._pool._proxy

        def legacy_init(self, *args, **kwargs):
            if "proxy" in kwargs:
                raise TypeError("__init__() got an unexpected keyword argument 'proxy'")
            real_init(self, *args, **kwargs)
            del self._proxy

        monkeypatch.setattr(httpcore.ConnectionPool, "__init__", legacy_init)
        isolated = _isolated_redirect_transport(original, host="next.example")
        try:
            assert isolated._pool is not original._pool
            assert type(isolated._pool) is httpcore.ConnectionPool
        finally:
            isolated.close()
