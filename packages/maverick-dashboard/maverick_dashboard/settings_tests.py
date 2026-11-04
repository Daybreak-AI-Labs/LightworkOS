"""The "Test connection" and "Check" buttons on Settings > All settings.

A catalog row names one check here in its ``test`` field (``path`` rows are
always checkable). :func:`run` tries the value a person entered -- or the
saved one -- and answers with one plain sentence. The rules every check keeps:

* Bounded: each network step waits at most :data:`TIMEOUT` seconds and reads
  at most :data:`MAX_BYTES` of any answer.
* Guarded: every network address goes through ``maverick.tools._ssrf``
  (resolved once, public addresses only unless the deployment allows private
  ones, the connection pinned to the checked address, no redirects).
* Quiet: sentences are fixed text. They never repeat the value, an address, a
  key, or an error from the other side (which could carry a password).

The same checks back the sign-in and key lock-out guards
(``settings_access_guard``), so a change that could lock people or data out
is only accepted when its check passes.
"""
from __future__ import annotations

import secrets
import socket
import ssl
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

TIMEOUT = 5.0
MAX_BYTES = 512 * 1024


@dataclass(frozen=True)
class Outcome:
    ok: bool
    message: str


_PRIVATE = Outcome(
    False,
    "Lightwork won't test this address from the dashboard because it points inside a "
    "private network or to this computer. It can still be saved.",
)
_UNREACHABLE = Outcome(False, "Lightwork could not reach this address. Check it and try again.")
_SLOW = Outcome(False, "The address did not answer in time. Check it and try again.")
_CERTIFICATE = Outcome(
    False, "Lightwork reached the address, but its security certificate could not be verified.",
)


class _Failed(Exception):
    def __init__(self, outcome: Outcome) -> None:
        super().__init__(outcome.message)
        self.outcome = outcome


# --------------------------------------------------------------- network
def _network_failure(exc: BaseException) -> Outcome:
    from maverick.tools import _ssrf

    if isinstance(exc, _ssrf.BlockedHost):
        return _PRIVATE
    try:
        import httpx

        if isinstance(exc, httpx.TimeoutException):
            return _SLOW
    except ImportError:  # pragma: no cover - httpx ships with the dashboard
        pass
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return _SLOW
    cause: BaseException | None = exc
    while cause is not None:
        if isinstance(cause, ssl.SSLError) or "CERTIFICATE_VERIFY_FAILED" in str(cause):
            return _CERTIFICATE
        cause = cause.__cause__ or cause.__context__
    return _UNREACHABLE


def fetch(url: str, *, headers: Mapping[str, str] | None = None) -> tuple[int, bytes]:
    """GET ``url`` through the SSRF guard: ``(status, first MAX_BYTES of body)``."""
    from maverick.tools import _ssrf

    try:
        with _ssrf.safe_client(url, timeout=TIMEOUT) as client:
            with client.stream("GET", url, headers=dict(headers or {})) as response:
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > MAX_BYTES:
                        break
                return response.status_code, bytes(body[:MAX_BYTES])
    except Exception as exc:  # every failure becomes one fixed sentence
        raise _Failed(_network_failure(exc)) from None


def reach(host: str, port: int) -> None:
    """Open (and close) a connection to ``host:port`` through the SSRF guard."""
    from maverick.tools import _ssrf

    try:
        address = _ssrf.resolve_pinned_ip(host)
        with socket.create_connection((address, int(port)), timeout=TIMEOUT):
            pass
    except Exception as exc:
        raise _Failed(_network_failure(exc)) from None


def _json(body: bytes) -> object:
    import json

    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None


def _address(value: object, *, local_ok: bool = False) -> str:
    text = str(value or "").strip()
    parsed = urlparse(text)
    if parsed.scheme == "https" and parsed.hostname:
        return text
    if local_ok and parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}:
        return text
    raise _Failed(Outcome(False, "Enter a secure web address that starts with https:// first."))


# ---------------------------------------------------------------- checks
def _check_https(value: object, values: Mapping[str, object]) -> Outcome:
    status, _body = fetch(_address(value, local_ok=True))
    if status >= 500:
        return Outcome(False, "Lightwork reached the address, but the service there reported a problem.")
    return Outcome(True, "Lightwork reached this address.")


def _oidc_issuer(values: Mapping[str, object]) -> str:
    issuer = str(values.get("auth.oidc.issuer") or "").strip()
    if not issuer:
        raise _Failed(Outcome(False, "Fill in the sign-in provider's address first."))
    return _address(issuer)


def check_oidc(values: Mapping[str, object]) -> Outcome:
    """The sign-in provider answers and publishes usable sign-in details."""
    try:
        return _oidc_details(values)
    except _Failed as failed:
        return failed.outcome


def check_oidc_login(values: Mapping[str, object]) -> Outcome:
    """Check the saved browser-login contract before it can replace current access.

    Provider discovery alone cannot establish that a person can sign in, but
    missing local fields guarantee that the callback cannot complete.
    """
    needed = (
        ("auth.oidc.client_id", "Lightwork's name at the provider"),
        ("auth.oidc.client_secret", "Lightwork's password at the provider"),
        ("auth.oidc.audience", "Accepted sign-in audience"),
        ("auth.oidc.session_secret", "Sign-in session key"),
    )
    for key, label in needed:
        if not str(values.get(key) or "").strip():
            return Outcome(False, f"Fill in {label} before turning on company sign-in.")
    redirect = urlparse(str(values.get("auth.oidc.redirect_uri") or "").strip())
    if (redirect.path != "/auth/callback" or not redirect.hostname
            or redirect.username or redirect.password or redirect.query or redirect.fragment
            or not (redirect.scheme == "https" or
                    (redirect.scheme == "http" and redirect.hostname in {"localhost", "127.0.0.1", "::1"}))):
        return Outcome(False, "Set the return address to this Lightwork site's /auth/callback page before turning on company sign-in.")
    return check_oidc(values)


def _oidc_details(values: Mapping[str, object]) -> Outcome:
    issuer = _oidc_issuer(values)
    status, body = fetch(issuer.rstrip("/") + "/.well-known/openid-configuration")
    doc = _json(body) if status == 200 else None
    if not isinstance(doc, dict):
        return Outcome(False, "Lightwork reached the address, but it did not answer like a sign-in provider.")
    if str(doc.get("issuer") or "").rstrip("/") != issuer.rstrip("/"):
        return Outcome(False, "The sign-in provider describes itself with a different address. "
                              "Copy the address exactly as your provider shows it.")
    for key in ("authorization_endpoint", "token_endpoint"):
        if not str(doc.get(key) or "").lower().startswith("https://"):
            return Outcome(False, "The sign-in provider's details are incomplete, so browser sign-in would not work.")
    keys_url = str(values.get("auth.oidc.jwks_uri") or doc.get("jwks_uri") or "").strip()
    status, body = fetch(_address(keys_url))
    keys = _json(body) if status == 200 else None
    if not (isinstance(keys, dict) and isinstance(keys.get("keys"), list) and keys["keys"]):
        return Outcome(False, "The sign-in provider did not share the keys Lightwork needs to check sign-ins.")
    return Outcome(True, "Lightwork reached your sign-in provider and read its sign-in details.")


def _check_oidc(value: object, values: Mapping[str, object]) -> Outcome:
    return check_oidc(values)


def check_saml(values: Mapping[str, object]) -> Outcome:
    """The sign-in provider's details (its metadata) can be read."""
    from xml.etree import ElementTree

    url = str(values.get("auth.saml.idp_metadata_url") or "").strip()
    if not url:
        return Outcome(False, "Fill in the address of your sign-in provider's details first.")
    try:
        status, body = fetch(_address(url))
    except _Failed as failed:
        return failed.outcome
    try:
        root = ElementTree.fromstring(body) if status == 200 else None
    except ElementTree.ParseError:
        root = None
    if root is None or not any(
        node.tag.rsplit("}", 1)[-1] == "SingleSignOnService"
        and str(node.attrib.get("Location") or "").startswith("https://")
        for descriptor in root.iter()
        if descriptor.tag.rsplit("}", 1)[-1] == "IDPSSODescriptor"
        for node in descriptor.iter()
    ):
        return Outcome(False, "Lightwork reached the address, but it did not find a sign-in provider's details there.")
    return Outcome(True, "Lightwork read your sign-in provider's details.")


def check_saml_login(values: Mapping[str, object]) -> Outcome:
    """Require the local SAML callback contract as well as valid provider metadata."""
    for key, label in (
        ("auth.saml.sp_entity_id", "Lightwork's name for single sign-on"),
        ("auth.oidc.session_secret", "Sign-in session key"),
    ):
        if not str(values.get(key) or "").strip():
            return Outcome(False, f"Fill in {label} before turning on single sign-on.")
    callback = urlparse(str(values.get("auth.saml.acs_url") or "").strip())
    if (callback.scheme != "https" or not callback.hostname or callback.path != "/saml/acs"
            or callback.username or callback.password or callback.query or callback.fragment):
        return Outcome(False, "Set the single sign-on return address to this Lightwork site's /saml/acs page.")
    try:
        import saml2  # noqa: F401 -- needed by the real login route
    except ImportError:
        return Outcome(False, "Single sign-on support is not installed here. Ask the installation owner to add it before turning this on.")
    return check_saml(values)


def _check_saml(value: object, values: Mapping[str, object]) -> Outcome:
    return check_saml(values)


def _check_siem(value: object, values: Mapping[str, object]) -> Outcome:
    text = str(value or "").strip()
    parsed = urlparse(text)
    scheme = (parsed.scheme or "").lower()
    if scheme in {"http", "https"}:
        return _check_https(text, values)
    if scheme == "tcp" and parsed.hostname and parsed.port:
        reach(parsed.hostname, parsed.port)
        return Outcome(True, "Lightwork reached your security monitoring service.")
    if scheme == "udp":
        return Outcome(False, "This kind of address sends records without any reply, so it can't be tested. "
                              "Check your monitoring service for new records after saving.")
    if scheme in {"datadog", "sentinel"}:
        from maverick.audit import forwarder
        try:
            _, host, port, _ = forwarder.parse_dest(text)
        except ValueError:
            return Outcome(False, "This address is not in the form this service needs. "
                                  "Check the example in the help.")
        reach(host, port)
        return Outcome(True, "Lightwork reached your security monitoring service.")
    return Outcome(False, "Enter an address that starts with https://, tcp://, udp://, datadog:// "
                          "or sentinel:// first.")


_DEFAULT_PORTS = {"redis": 6379, "rediss": 6379, "postgres": 5432, "postgresql": 5432}


def _host_port(text: str, default_port: int) -> tuple[str, int]:
    parsed = urlparse(text if "://" in text else "//" + text)
    host = parsed.hostname or ""
    try:
        port = parsed.port or default_port
    except ValueError:
        port = 0
    if not host or not 0 < port < 65536:
        raise _Failed(Outcome(False, "Enter the server's name and port first."))
    return host, port


def _keyword_dsn(text: str) -> tuple[str, int] | None:
    """``host=db port=5432 ...`` connection text -> ``(host, port)``."""
    fields = dict(part.split("=", 1) for part in text.split() if "=" in part)
    if "host" not in fields:
        return None
    try:
        port = int(fields.get("port") or 5432)
    except ValueError:
        port = 0
    return fields["host"], port


def _check_server(value: object, values: Mapping[str, object]) -> Outcome:
    """A database, queue or worker address: the server accepts a connection."""
    text = str(value or "").strip()
    if not text:
        return Outcome(False, "Fill this in first.")
    scheme = text.split("://", 1)[0].lower() if "://" in text else ""
    if scheme == "unix" or text.startswith("/"):
        return Outcome(True, "This is a connection on this computer. Lightwork uses it when it next starts.")
    keyword = _keyword_dsn(text) if not scheme else None
    if keyword is not None:
        host, port = keyword
        if host.startswith("/"):
            return Outcome(True, "This is a connection on this computer. Lightwork uses it when it next starts.")
    else:
        host, port = _host_port(text, _DEFAULT_PORTS.get(scheme, 50051))
    if not 0 < port < 65536:
        return Outcome(False, "Enter the server's name and port first.")
    reach(host, port)
    return Outcome(True, "Lightwork reached this server.")


_KMS_KEYS = ("provider", "key_id", "region", "address", "mount")


def _wrapped_keys() -> list[tuple[str | None, Any]]:
    """Existing locked data keys that the installation-wide key service opens."""
    from maverick.tenant import kms as tenant_kms

    found: list[tuple[str | None, Any]] = []
    try:
        path = tenant_kms._wrapped_dek_path(None)
        if path.exists():
            found.append((None, path))
    except Exception:  # an unreadable key folder is checked by the unlock itself
        pass
    try:
        from maverick.tenant.registry import list_tenants

        tenants = [str(getattr(t, "id", "") or "") for t in list_tenants()][:200]
    except Exception:
        tenants = []
    for tenant_id in filter(None, tenants):
        try:
            own = tenant_kms._kms_config_for(tenant_id)
            if own.get("provider") and own != tenant_kms._kms_config_for(None):
                continue  # that workspace uses its own key service
            path = tenant_kms._wrapped_dek_path(tenant_id)
            if path.exists():
                found.append((tenant_id, path))
        except Exception:
            continue
    return found


def check_kms(values: Mapping[str, object]) -> Outcome:
    """The key service locks and unlocks a test value and every data key."""
    from maverick.tenant import kms as tenant_kms

    provider = str(values.get("kms.provider") or "local").strip().lower()
    cfg = {key: values.get(f"kms.{key}") for key in _KMS_KEYS if values.get(f"kms.{key}")}
    try:
        if provider in {"", "local"}:
            backend = tenant_kms.LocalKMS()
        else:
            from maverick.kms_backends import build_cloud_kms

            backend = build_cloud_kms(provider, cfg)
        probe = secrets.token_bytes(32)
        context = b"lightwork-settings-check"
        if backend.unwrap(backend.wrap(probe, context=context), context=context) != probe:
            raise ValueError("round trip")
    except Exception:
        return Outcome(False, "Lightwork could not use this key service to lock and unlock a test "
                              "value. Check the key details and the server's access to the service.")
    for tenant_id, path in _wrapped_keys():
        try:
            dek = backend.unwrap(path.read_bytes(),
                                 context=tenant_kms._tenant_context(tenant_id, b"dek-wrap"))
            if len(dek) != 32:
                raise ValueError("malformed")
        except Exception:
            return Outcome(False, "This key service can't open the data keys Lightwork already uses, "
                                  "so saved records would become unreadable.")
    return Outcome(True, "Lightwork used this key service to lock and unlock a test value "
                         "and can still open its existing data keys.")


def _check_kms(value: object, values: Mapping[str, object]) -> Outcome:
    return check_kms(values)


TESTERS: dict[str, Callable[[object, Mapping[str, object]], Outcome]] = {
    "https": _check_https,
    "oidc": _check_oidc,
    "saml": _check_saml,
    "siem": _check_siem,
    "server": _check_server,
    "kms": _check_kms,
}

BUTTON_LABELS = {"path": "Check this location"}


def button_label(setting) -> str:
    if setting.control == "path":
        return BUTTON_LABELS["path"]
    return "Test connection" if setting.test else ""


def run(setting, value: object, values: Mapping[str, object]) -> Outcome:
    """Try ``value`` for ``setting`` (``values``: every setting's value to use)."""
    if setting.control == "path":
        from . import settings_paths

        try:
            stored = settings_paths.check(str(value or ""), kind=setting.path_kind,
                                          writable=setting.path_writable,
                                          private=setting.path_private,
                                          new_ok=setting.path_new, scope=setting.path_scope)
        except settings_paths.PathRefused as exc:
            text = str(exc)
            return Outcome(False, text[:1].upper() + text[1:])
        from pathlib import Path

        later = setting.path_new and not Path(stored).exists()
        return Outcome(True, settings_paths.describe_ok(setting.path_kind, created_later=later))
    tester = TESTERS.get(setting.test)
    if tester is None:
        return Outcome(False, "This setting has nothing to test.")
    try:
        return tester(value, values)
    except _Failed as failed:
        return failed.outcome


__all__ = ["BUTTON_LABELS", "Outcome", "TESTERS", "TIMEOUT", "button_label", "check_kms",
           "check_oidc", "check_saml", "fetch", "reach", "run"]
