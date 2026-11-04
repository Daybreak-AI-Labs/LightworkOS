"""Per-tenant OAuth token vault: sealed-at-rest, refresh-aware, tenant-isolated.

Hermetic: HOME/MAVERICK_HOME under tmp, and the KMS KEK pinned to a test value
so envelope sealing works without external key material. Needs the
``cryptography`` extra (AES-GCM); self-skips if it's absent.
"""
from __future__ import annotations

import importlib.util
import time

import pytest

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("cryptography") is None,
    reason="cryptography extra not installed (AES-GCM sealing unavailable)",
)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    # A valid 32-byte KEK (64 hex chars) so envelope sealing works hermetically.
    monkeypatch.setenv("MAVERICK_KMS_KEK", "ab" * 32)
    # Clear any cached DEKs between tests so each tmp HOME is independent.
    from maverick.tenant import kms
    kms._clear_cache()


def _vault(tenant="__active__"):
    from maverick.oauth_vault import OAuthVault
    return OAuthVault(tenant)


class TestRoundTrip:
    def test_put_get_roundtrip(self):
        v = _vault()
        v.put("notion", {"access_token": "at-1", "refresh_token": "rt-1", "scope": "read"})
        rec = v.get("notion")
        assert rec["access_token"] == "at-1"
        assert rec["refresh_token"] == "rt-1"
        assert "obtained_at" in rec  # stamped

    def test_get_missing_is_none(self):
        assert _vault().get("nope") is None

    def test_delete(self):
        v = _vault()
        v.put("slack", {"access_token": "x"})
        assert v.delete("slack") is True
        assert v.get("slack") is None
        assert v.delete("slack") is False

    def test_providers_sorted(self):
        v = _vault()
        v.put("zebra", {"access_token": "z"})
        v.put("alpha", {"access_token": "a"})
        assert v.providers() == ["alpha", "zebra"]

    def test_overwrite(self):
        v = _vault()
        v.put("p", {"access_token": "old"})
        v.put("p", {"access_token": "new"})
        assert v.get("p")["access_token"] == "new"


class TestAtRestSealing:
    def test_file_is_sealed_not_plaintext(self):
        from maverick.paths import data_dir
        v = _vault()
        v.put("notion", {"access_token": "super-secret-token", "refresh_token": "rt"})
        blob = data_dir("oauth", "tokens.sealed").read_bytes()
        assert b"super-secret-token" not in blob
        assert b"rt" not in blob or b"refresh_token" not in blob  # not cleartext JSON

    def test_tenant_isolation(self, monkeypatch):
        # A second tenant's vault must not read the first's tokens, and the KMS
        # context binding means the blobs aren't interchangeable.
        from maverick.tenant import kms
        a = _vault("tenant-a")
        a.put("notion", {"access_token": "a-secret"})
        kms._clear_cache()
        b = _vault("tenant-b")
        assert b.get("notion") is None
        assert a.get("notion")["access_token"] == "a-secret"


class TestExpiryAndRefresh:
    @pytest.mark.parametrize("body", [{}, {"error": "temporarily_unavailable"},
        {"access_token": 42}, {"access_token": ""},
        {"access_token": "fresh", "expires_in": "bad"},
        {"access_token": "fresh", "expires_in": float("inf")},
        {"access_token": "fresh", "expires_at": float("nan")},
        {"access_token": "fresh", "refresh_token": []}])
    def test_invalid_production_refresh_preserves_authorization_and_requires_reconnect(self, monkeypatch, body):
        from maverick import automation_events
        from maverick.oauth_vault import OAuthRefreshError
        from maverick.tools import oauth_helper

        calls = []
        monkeypatch.setenv("MAVERICK_OAUTH_VAULT", "1")

        def respond(url, data):
            calls.append(data)
            return body

        monkeypatch.setattr(oauth_helper, "_post_form", respond)
        v = _vault()
        v.put("p", {"access_token": "stale", "refresh_token": "old-refresh", "expires_at": time.time() - 10})
        from maverick import oauth_providers
        oauth_providers.register(oauth_providers.OAuthProvider(
            "p", "https://fixture.invalid/auth", "https://fixture.invalid/token"))
        monkeypatch.setenv("P_OAUTH_CLIENT_ID", "fixture")
        config = {"provider": "p"}
        with pytest.raises(OAuthRefreshError, match="reconnect"):
            automation_events._oauth_bearer(config)
        assert v.get("p")["access_token"] == "stale"
        assert v.get("p")["refresh_token"] == "old-refresh"
        assert v.status("p")["reconnect_required"] is True
        with pytest.raises(OAuthRefreshError, match="reconnect"):
            automation_events._oauth_bearer(config)
        assert len(calls) == 1
        v.put("p", {"access_token": "reauthorized", "expires_in": 3600})
        assert automation_events._oauth_bearer(config) == "reauthorized"
        assert v.status("p")["reconnect_required"] is False

    def test_refresh_interruption_leaves_a_durable_hold(self):
        from maverick.oauth_vault import OAuthRefreshError

        v = _vault()
        v.put("p", {"access_token": "stale", "refresh_token": "old", "expires_at": time.time() - 10})

        def interrupted(record):
            raise KeyboardInterrupt

        with pytest.raises(KeyboardInterrupt):
            v.access_token("p", refresher=interrupted)
        assert _vault().status("p")["refresh_state"] == "refresh_in_progress"
        with pytest.raises(OAuthRefreshError):
            _vault().access_token("p", refresher=lambda record: pytest.fail("uncertain rotation replayed"))

    def test_is_expired_semantics(self):
        from maverick.oauth_vault import is_expired
        now = 1_000_000.0
        assert is_expired({"expires_at": now - 10}, now=now) is True
        assert is_expired({"expires_at": now + 1000}, now=now, skew=0) is False
        # within skew window counts as expired
        assert is_expired({"expires_at": now + 30}, now=now, skew=60) is True
        # no expiry info -> never expired
        assert is_expired({"access_token": "x"}, now=now) is False

    def test_access_token_returns_valid(self):
        v = _vault()
        v.put("p", {"access_token": "good", "expires_at": time.time() + 3600})
        assert v.access_token("p") == "good"

    def test_access_token_expired_without_refresher_is_none(self):
        v = _vault()
        v.put("p", {"access_token": "stale", "expires_at": time.time() - 10})
        assert v.access_token("p") is None

    def test_access_token_refreshes_and_persists(self):
        v = _vault()
        v.put("p", {"access_token": "stale", "refresh_token": "rt-keep",
                    "expires_at": time.time() - 10})
        calls = []

        def refresher(record):
            calls.append(record)
            # Provider omits refresh_token on refresh (common) -> vault keeps old.
            return {"access_token": "fresh", "expires_in": 3600}

        assert v.access_token("p", refresher=refresher) == "fresh"
        assert len(calls) == 1
        # Rotated record persisted, old refresh token preserved.
        rec = v.get("p")
        assert rec["access_token"] == "fresh"
        assert rec["refresh_token"] == "rt-keep"
        # And a subsequent call uses the now-valid token, no refresh.
        assert v.access_token("p", refresher=refresher) == "fresh"
        assert len(calls) == 1

    def test_access_token_missing_provider_is_none(self):
        assert _vault().access_token("absent", refresher=lambda r: {}) is None


class TestStatus:
    def test_status_none_when_absent(self):
        assert _vault().status("nope") is None

    def test_status_is_token_free_and_reports_health(self):
        v = _vault()
        v.put("slack", {"access_token": "at", "refresh_token": "rt",
                        "scope": "chat:write", "expires_in": 3600})
        st = v.status("slack")
        assert st["provider"] == "slack"
        assert st["expired"] is False
        assert st["has_refresh_token"] is True
        assert st["scope"] == "chat:write"
        assert st["expires_at"] is not None
        # Never leaks the token material itself.
        assert "access_token" not in st and "refresh_token" not in st

    def test_status_flags_expired(self):
        v = _vault()
        v.put("g", {"access_token": "at", "expires_at": time.time() - 10})
        assert v.status("g")["expired"] is True


class TestToggles:
    def test_enabled_off_by_default(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_OAUTH_VAULT", raising=False)
        import maverick.config as cfg
        monkeypatch.setattr(cfg, "load_config", lambda *a, **k: {})
        from maverick.oauth_vault import enabled
        assert enabled() is False

    def test_env_override_on(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_OAUTH_VAULT", "1")
        from maverick.oauth_vault import enabled
        assert enabled() is True


class TestActiveTenantSealContext:
    def test_active_seal_uses_raw_tenant_id_not_path_encoded(self):
        # The active-tenant vault must seal under the RAW tenant id: the KMS
        # path-encodes it itself (to find the [kms] BYOK overlay and bind the
        # AEAD context). Passing the already path-encoded current_tenant()
        # double-encodes -- so a non-slug tenant misses its BYOK key and seals
        # under a different context than every other tenant-KMS caller.
        import json

        from maverick.oauth_vault import OAuthVault
        from maverick.paths import (
            current_tenant,
            current_tenant_id,
            reset_tenant,
            set_tenant,
        )
        from maverick.tenant import kms
        from maverick.tenant.kms import unseal_text_for_tenant

        tid = "Acme Corp"  # non-slug: path-encoding changes it
        token = set_tenant(tid)
        try:
            assert current_tenant() != current_tenant_id()  # sanity: it encodes
            v = OAuthVault("__active__")
            assert v._seal_tenant() == current_tenant_id() == tid  # raw, not encoded
            v.put("notion", {"access_token": "secret-at"})
            blob = v._path().read_bytes()
            kms._clear_cache()
            # Readable with the canonical RAW-id KMS context -> oauth seals the
            # same way as everything else (an encoded-id context would fail on
            # the AEAD tag mismatch).
            raw = unseal_text_for_tenant(tid, blob)
            assert json.loads(raw)["notion"]["access_token"] == "secret-at"
        finally:
            reset_tenant(token)
