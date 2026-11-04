"""TLS / mTLS for the gRPC surfaces. Covers the enabled/required logic, the
fail-closed behaviour when TLS is required but unconfigured, real credential
building, and the federation client refusing to dial in the clear when required."""
from __future__ import annotations

import pytest
from maverick import grpc_tls

# (_FakeServer is defined further down with the other bind_port tests.)


@pytest.fixture
def _no_tls_config(monkeypatch):
    # Hermetic for the bind tests: no TLS configured, not client-bound/enterprise,
    # no insecure opt-out -- so only the loopback check decides the outcome.
    monkeypatch.setattr(grpc_tls, "_section", lambda name: {})
    monkeypatch.setattr(grpc_tls, "tls_required", lambda *a, **k: False)
    monkeypatch.delenv("MAVERICK_ALLOW_INSECURE_GRPC", raising=False)


def test_host_parsing():
    assert grpc_tls._is_loopback_address("127.0.0.1:50051")
    assert grpc_tls._is_loopback_address("localhost:50051")
    assert grpc_tls._is_loopback_address("[::1]:50051")
    assert not grpc_tls._is_loopback_address("0.0.0.0:50051")
    assert not grpc_tls._is_loopback_address("10.0.0.5:50051")


def test_loopback_plaintext_allowed(_no_tls_config):
    s = _FakeServer()
    assert grpc_tls.bind_port(s, "127.0.0.1:50051", "grpc") is False
    assert s.insecure == "127.0.0.1:50051"


def test_nonloopback_plaintext_refused_fail_closed(_no_tls_config):
    s = _FakeServer()
    with pytest.raises(grpc_tls.TlsConfigError):
        grpc_tls.bind_port(s, "0.0.0.0:50051", "grpc")
    assert s.insecure is None  # nothing bound


def test_nonloopback_plaintext_allowed_with_explicit_optout(monkeypatch, _no_tls_config):
    monkeypatch.setenv("MAVERICK_ALLOW_INSECURE_GRPC", "1")
    s = _FakeServer()
    assert grpc_tls.bind_port(s, "0.0.0.0:50051", "grpc") is False
    assert s.insecure == "0.0.0.0:50051"


def test_plaintext_client_policy_matches_server_policy(monkeypatch, _no_tls_config):
    assert grpc_tls.insecure_channel_allowed("localhost:50051")
    assert grpc_tls.insecure_channel_allowed("[::1]:50051")
    assert not grpc_tls.insecure_channel_allowed("worker.example:50051")
    monkeypatch.setenv("MAVERICK_ALLOW_INSECURE_GRPC", "1")
    assert grpc_tls.insecure_channel_allowed("worker.example:50051")


def test_goal_client_refuses_remote_plaintext_before_loading_stubs(
    monkeypatch, _no_tls_config,
):
    pytest.importorskip("grpc")
    from maverick.grpc_dispatcher import GrpcDispatcher

    monkeypatch.setattr(grpc_tls, "channel_credentials", lambda _section: None)
    with pytest.raises(grpc_tls.TlsConfigError, match="non-loopback"):
        GrpcDispatcher("worker.example:50051")._build_stub()


# ---- enabled / required logic (hermetic via cfg=) -------------------------


def test_tls_enabled():
    assert grpc_tls.tls_enabled("grpc", {"tls": True})
    assert grpc_tls.tls_enabled("grpc", {"tls": "yes"})
    assert not grpc_tls.tls_enabled("grpc", {})
    assert not grpc_tls.tls_enabled("grpc", {"tls": False})


def test_tls_required_via_config():
    assert grpc_tls.tls_required("grpc", {"tls_required": True})
    assert not grpc_tls.tls_required("grpc", {})


def test_tls_required_when_client_bound(monkeypatch):
    from maverick import client
    monkeypatch.setattr(client, "client_binding_enforced", lambda: True)
    assert grpc_tls.tls_required("federation", {}) is True


def test_tls_not_required_by_default(monkeypatch):
    from maverick import client
    monkeypatch.setattr(client, "client_binding_enforced", lambda: False)
    assert grpc_tls.tls_required("federation", {}) is False


# ---- fail-closed server credentials ---------------------------------------


def test_server_credentials_none_when_off_and_not_required(monkeypatch):
    from maverick import client
    monkeypatch.setattr(client, "client_binding_enforced", lambda: False)
    assert grpc_tls.server_credentials("grpc", {}) is None


def test_server_credentials_raises_when_required_but_unconfigured(monkeypatch):
    from maverick import client
    monkeypatch.setattr(client, "client_binding_enforced", lambda: True)
    with pytest.raises(grpc_tls.TlsConfigError):
        grpc_tls.server_credentials("grpc", {})  # required (bound) but no tls


def test_server_credentials_raises_when_enabled_but_certs_missing(monkeypatch):
    from maverick import client
    monkeypatch.setattr(client, "client_binding_enforced", lambda: False)
    with pytest.raises(grpc_tls.TlsConfigError):
        grpc_tls.server_credentials("grpc", {"tls": True})  # tls on, no cert/key


def test_read_missing_file_raises():
    with pytest.raises(grpc_tls.TlsConfigError):
        grpc_tls.server_credentials("grpc", {"tls": True, "tls_cert": "/no/such.crt",
                                             "tls_key": "/no/such.key"})


# ---- bind_port with a fake server -----------------------------------------


class _FakeServer:
    def __init__(self):
        self.secure = None
        self.insecure = None

    def add_secure_port(self, addr, creds):
        self.secure = addr
        return 1

    def add_insecure_port(self, addr):
        self.insecure = addr
        return 1


def test_bind_port_insecure_when_off(monkeypatch):
    from maverick import client
    monkeypatch.setattr(client, "client_binding_enforced", lambda: False)
    monkeypatch.setattr(grpc_tls, "_section", lambda name: {})
    srv = _FakeServer()
    assert grpc_tls.bind_port(srv, "127.0.0.1:9", "grpc") is False
    assert srv.insecure == "127.0.0.1:9" and srv.secure is None


def test_bind_port_raises_when_required(monkeypatch):
    from maverick import client
    monkeypatch.setattr(client, "client_binding_enforced", lambda: True)
    monkeypatch.setattr(grpc_tls, "_section", lambda name: {})
    with pytest.raises(grpc_tls.TlsConfigError):
        grpc_tls.bind_port(_FakeServer(), "127.0.0.1:9", "federation")


# ---- real credential building (needs grpc + cryptography) -----------------


def _selfsigned(tmp_path):
    pytest.importorskip("cryptography")
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    cert_p = tmp_path / "s.crt"
    key_p = tmp_path / "s.key"
    cert_p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_p.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    return cert_p, key_p


def test_server_credentials_built_with_real_cert(tmp_path):
    pytest.importorskip("grpc")
    cert_p, key_p = _selfsigned(tmp_path)
    creds = grpc_tls.server_credentials(
        "grpc", {"tls": True, "tls_cert": str(cert_p), "tls_key": str(key_p)})
    assert creds is not None  # a grpc.ServerCredentials


def test_channel_credentials_built(tmp_path):
    pytest.importorskip("grpc")
    cert_p, _ = _selfsigned(tmp_path)
    creds = grpc_tls.channel_credentials("federation", {"tls": True, "tls_ca": str(cert_p)})
    assert creds is not None
    assert grpc_tls.channel_credentials("federation", {}) is None


# ---- federation client refuses plaintext when required --------------------


def test_federation_client_refuses_insecure_when_required(monkeypatch):
    pytest.importorskip("grpc")
    from maverick import client
    from maverick.federation import FederationError, Peer, _GrpcTransport
    monkeypatch.setattr(client, "client_binding_enforced", lambda: True)
    monkeypatch.setattr(grpc_tls, "_section", lambda name: {})  # TLS not configured
    t = _GrpcTransport(Peer("vega", "vega:50061", "tok"))
    with pytest.raises(FederationError):
        t._bind()
