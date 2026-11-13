"""SCIM 2.0 user provisioning endpoints.

Hermetic: HOME/MAVERICK_HOME under tmp, the SCIM bearer set on, the world DB and
USER_TEMPLATES isolated like the other dashboard tests. Exercises the IdP
lifecycle (create -> read -> filter -> deprovision -> delete), auth gating, and
that the surface is invisible (404) when no SCIM token is configured.
"""
from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from starlette.testclient import TestClient

_TOKEN = "scim-secret-token-xyz"  # pragma: allowlist secret


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    import maverick.templates as tpl
    monkeypatch.setattr(tpl, "USER_TEMPLATES", tmp_path / ".maverick" / "templates")


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _auth(token: str = _TOKEN) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("MAVERICK_SCIM_TOKEN", _TOKEN)
    return _client()


def _make_user(client, username="alice@example.com", **extra):
    payload = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": username,
        "name": {"givenName": "Alice", "familyName": "Smith"},
        "emails": [{"value": username, "primary": True}],
        "active": True,
        **extra,
    }
    return client.post("/scim/v2/Users", json=payload, headers=_auth())


class TestAuth:
    def test_disabled_returns_404(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_SCIM_TOKEN", raising=False)
        r = _client().get("/scim/v2/Users", headers=_auth())
        assert r.status_code == 404

    def test_missing_bearer_401(self, client):
        r = client.get("/scim/v2/Users")
        assert r.status_code == 401
        assert r.json()["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]

    def test_wrong_bearer_401(self, client):
        r = client.get("/scim/v2/Users", headers=_auth("nope"))
        assert r.status_code == 401

    def test_configured_secret_that_is_not_valid_utf8_refuses_with_401(self, monkeypatch):
        # Python decodes invalid UTF-8 in the environment as lone surrogates.
        monkeypatch.setenv("MAVERICK_SCIM_TOKEN", "tok-\udcff")  # pragma: allowlist secret
        r = _client().get("/scim/v2/Users", headers=_auth("tok-x"))
        assert r.status_code == 401

    def test_comma_separated_rotation_accepts_old_and_new(self, monkeypatch):
        # During a rotation, old + new are both valid; a retired token is not.
        monkeypatch.setenv("MAVERICK_SCIM_TOKEN", "old-tok,new-tok")  # pragma: allowlist secret
        c = _client()
        assert c.get("/scim/v2/Users", headers=_auth("old-tok")).status_code == 200
        assert c.get("/scim/v2/Users", headers=_auth("new-tok")).status_code == 200
        assert c.get("/scim/v2/Users", headers=_auth("retired")).status_code == 401

    def test_sha256_hashed_secret_keeps_plaintext_out_of_env(self, monkeypatch):
        import hashlib
        tok = "plain-scim-token"  # pragma: allowlist secret
        digest = hashlib.sha256(tok.encode()).hexdigest()
        monkeypatch.setenv("MAVERICK_SCIM_TOKEN", f"sha256:{digest}")
        c = _client()
        assert c.get("/scim/v2/Users", headers=_auth(tok)).status_code == 200
        assert c.get("/scim/v2/Users", headers=_auth("wrong")).status_code == 401

    def test_non_ascii_hashed_secret_refuses_with_401_not_a_server_error(self, monkeypatch):
        # A hashed secret pasted with a stray non-ASCII character matches no
        # bearer; it must not turn every provisioning call into a 500.
        monkeypatch.setenv("MAVERICK_SCIM_TOKEN", "sha256:abc\u2026")  # pragma: allowlist secret
        assert _client().get("/scim/v2/Users", headers=_auth("wrong")).status_code == 401

    def test_deprovision_revokes_live_sessions(self, client):
        # Deprovisioning must end current access, not just future logins:
        # the SCIM user's identifiers get a revocation epoch so live sessions die.
        from maverick_dashboard import session_revocation as sr
        r = _make_user(client, externalId="okta-sub-123")
        uid = r.json()["id"]
        assert sr.revocation_epoch("okta-sub-123") == 0.0
        client.delete(f"/scim/v2/Users/{uid}", headers=_auth())
        assert sr.revocation_epoch("okta-sub-123") > 0.0   # externalId (= OIDC sub)
        assert sr.revocation_epoch("alice@example.com") > 0.0  # userName too

    def test_deprovision_revokes_pairwise_sub_via_directory(self, client):
        # Entra case: the OIDC `sub` is pairwise and appears in NO SCIM attribute.
        # The subject directory recorded it at login keyed by the user's email;
        # deprovision must look it up and revoke it, not just the SCIM ids.
        from maverick_dashboard import session_revocation as sr
        from maverick_dashboard import subject_directory as sd
        # Login recorded: email/oid -> the pairwise session sub.
        sd.record_login("pairwise-AAA", ["bob@example.com", "aad-oid-9"])
        r = _make_user(client, username="bob@example.com", externalId="aad-oid-9")
        uid = r.json()["id"]
        assert sr.revocation_epoch("pairwise-AAA") == 0.0   # not a SCIM attribute
        client.patch(f"/scim/v2/Users/{uid}", headers=_auth(), json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "active", "value": False}],
        })
        # The pairwise sub -- the actual session key -- is now revoked.
        assert sr.revocation_epoch("pairwise-AAA") > 0.0

    def test_put_string_active_false_deprovisions(self, client):
        # Azure AD sends `active` as the STRING "False". bool("False") is True,
        # so a plain bool() on the PUT path would leave the user ACTIVE -- a
        # deprovisioning bypass. The string must be coerced to False.
        uid = _make_user(client, username="sf@example.com").json()["id"]
        r = client.put(f"/scim/v2/Users/{uid}", headers=_auth(), json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "sf@example.com",
            "active": "False",
        })
        assert r.status_code == 200
        assert r.json()["active"] is False
        assert client.get(f"/scim/v2/Users/{uid}",
                          headers=_auth()).json()["active"] is False

    def test_put_deactivation_without_external_id_still_revokes_the_subject(self, client):
        # An IdP that sends PUT {userName, active: false} with no externalId
        # must still end the sessions of the stored subject.
        from maverick_dashboard import session_revocation as sr
        uid = _make_user(client, username="dee@example.com",
                         externalId="sub-dee").json()["id"]
        assert sr.revocation_epoch("sub-dee") == 0.0
        r = client.put(f"/scim/v2/Users/{uid}", headers=_auth(), json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "dee@example.com",
            "active": False,
        })
        assert r.status_code == 200
        assert sr.revocation_epoch("sub-dee") > 0.0
        assert r.json()["externalId"] == "sub-dee"

    def test_hard_delete_durably_denies_direct_and_pairwise_fresh_tokens(self, client):
        from fastapi import HTTPException
        from maverick.oidc import VerifiedPrincipal
        from maverick_dashboard import auth
        from maverick_dashboard import subject_directory as sd

        sd.record_login("pairwise-BBB", ["entra-object-carol"])
        r = _make_user(
            client,
            username="carol@example.com",
            externalId="entra-object-carol",
        )
        uid = r.json()["id"]
        assert client.delete(f"/scim/v2/Users/{uid}", headers=_auth()).status_code == 204

        # The raw SCIM resource is gone, but its hashed lifecycle binding and
        # pairwise-sub bridge remain authoritative instead of falling through
        # to the deployment's default role.
        assert client.get(f"/scim/v2/Users/{uid}", headers=_auth()).status_code == 404
        assert sd.subs_for(["entra-object-carol"]) == {"pairwise-BBB"}
        assert sd.is_retired("entra-object-carol") is True
        assert sd.is_retired("pairwise-BBB") is True
        # A lagging IdP may mint a brand-new pairwise subject after DELETE. Its
        # login-time binding to the retired immutable object id must inherit the
        # tombstone rather than falling through as an unknown/default user.
        sd.record_login("pairwise-AFTER-delete", ["entra-object-carol"])
        assert sd.is_retired("pairwise-AFTER-delete") is True
        for sub in (
            "entra-object-carol",
            "pairwise-BBB",
            "pairwise-AFTER-delete",
        ):
            with pytest.raises(HTTPException) as exc:
                auth._enforce_scim_active(
                    VerifiedPrincipal(sub=sub, issuer="issuer", audience="aud")
                )
            assert exc.value.status_code == 401


class TestDiscovery:
    def test_service_provider_config(self, client):
        r = client.get("/scim/v2/ServiceProviderConfig", headers=_auth())
        assert r.status_code == 200
        assert r.json()["patch"]["supported"] is True

    def test_resource_types(self, client):
        r = client.get("/scim/v2/ResourceTypes", headers=_auth())
        assert r.status_code == 200
        assert r.json()[0]["endpoint"] == "/Users"


class TestLifecycle:
    def test_create_returns_201_with_id(self, client):
        r = _make_user(client)
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["userName"] == "alice@example.com"
        assert body["id"]
        assert body["active"] is True
        assert body["emails"][0]["value"] == "alice@example.com"
        assert body["meta"]["resourceType"] == "User"

    def test_create_provisions_tenant(self, client):
        uid = _make_user(client).json()["id"]
        from maverick.tenant import registry
        assert registry.get_tenant(uid) is not None

    def test_create_tenant_failure_never_commits_active_scim_identity(
        self, client, monkeypatch
    ):
        from maverick.tenant import registry

        attempts = []

        def fail_create(*_args, **_kwargs):
            attempts.append(True)
            raise RuntimeError("simulated tenant provisioning failure")

        monkeypatch.setattr(registry, "create_tenant", fail_create)
        response = _make_user(client, username="no-tenant@example.com")
        assert response.status_code == 500
        assert len(attempts) == 1
        listed = client.get("/scim/v2/Users", headers=_auth()).json()
        assert listed["totalResults"] == 0

    def test_uncertain_tenant_create_is_not_adopted_or_deleted_after_failure(
        self, client, monkeypatch
    ):
        from maverick.tenant import registry

        original_create = registry.create_tenant
        attempts = []

        def fail_after_registry_commit(*args, **kwargs):
            attempts.append(True)
            original_create(*args, **kwargs)
            raise OSError("simulated workspace materialization failure")

        monkeypatch.setattr(registry, "create_tenant", fail_after_registry_commit)
        response = _make_user(client, username="partial-tenant@example.com")
        assert response.status_code == 500
        assert len(attempts) == 1
        # A raised create did not hand back an owned incarnation. It might be
        # a competing provisioner's record, so SCIM cannot safely delete it.
        retained = registry.list_tenants()
        assert len(retained) == 1
        assert client.get("/scim/v2/Users", headers=_auth()).json()["totalResults"] == 0
        monkeypatch.setattr(registry, "create_tenant", original_create)
        with pytest.raises(ValueError):
            registry.create_tenant(retained[0].id)
        retry = _make_user(client, username="partial-tenant@example.com")
        assert retry.status_code == 201
        assert retry.json()["id"] != retained[0].id
        assert registry.get_tenant(retry.json()["id"]).display_name == (
            "Alice Smith (partial-tenant@example.com)"
        )

    def test_only_name_conflicts_get_a_bounded_numbered_retry(self):
        from maverick.tenant import registry
        from maverick_dashboard import scim

        registry.create_tenant("first", display_name="Alice Smith")
        registry.create_tenant("second", display_name="Alice Smith (alice@example.com)")
        scim._provision_tenant("third", "Alice Smith", "alice@example.com")
        assert registry.get_tenant("third").display_name == (
            "Alice Smith (alice@example.com) #2"
        )

    def test_create_uuid_race_never_deletes_another_provisioners_tenant(self, monkeypatch):
        from maverick.tenant import registry
        from maverick_dashboard import scim

        original = registry.create_tenant

        def competitor_wins(uid, **kwargs):
            original(uid, display_name="Other provisioner")
            return original(uid, **kwargs)

        monkeypatch.setattr(registry, "create_tenant", competitor_wins)
        with pytest.raises(ValueError, match="already exists"):
            scim._provision_tenant("race", "SCIM candidate")
        assert registry.get_tenant("race").display_name == "Other provisioner"

    def test_known_provision_is_compensated_if_scim_publication_fails(self, client, monkeypatch):
        from maverick.tenant import registry
        from maverick_dashboard import scim

        def failed_save(_users):
            raise OSError("synthetic storage failure")

        monkeypatch.setattr(scim, "_save", failed_save)
        response = _make_user(client, username="failed-save@example.com")
        assert response.status_code == 500
        assert registry.list_tenants() == []
        assert client.get("/scim/v2/Users", headers=_auth()).json()["totalResults"] == 0

    def test_reprovision_clears_hard_delete_tombstone_for_pairwise_subject(self, client):
        from maverick.oidc import VerifiedPrincipal
        from maverick_dashboard import auth
        from maverick_dashboard import subject_directory as sd

        sd.record_login("pairwise-reprovisioned", ["entra-object-reprovisioned"])
        # This unverified-email binding is safe for over-revocation, but must
        # never be treated as authoritative when access is restored.
        sd.record_login("forged-email-sub", ["returning@example.com"])
        first = _make_user(
            client,
            username="returning@example.com",
            externalId="entra-object-reprovisioned",
        )
        assert first.status_code == 201
        uid = first.json()["id"]
        assert client.delete(f"/scim/v2/Users/{uid}", headers=_auth()).status_code == 204
        assert sd.is_retired("pairwise-reprovisioned") is True

        second = _make_user(
            client,
            username="returning@example.com",
            externalId="entra-object-reprovisioned",
        )
        assert second.status_code == 201
        assert second.json()["id"] != uid
        assert sd.is_retired("pairwise-reprovisioned") is False
        assert sd.is_retired("forged-email-sub") is True
        # The retained authoritative externalId -> pairwise-sub binding now
        # resolves the newly durable active record.
        auth._enforce_scim_active(
            VerifiedPrincipal(
                sub="pairwise-reprovisioned", issuer="issuer", audience="aud"
            )
        )

    def test_duplicate_username_409(self, client):
        _make_user(client)
        r = _make_user(client)
        assert r.status_code == 409
        assert r.json()["scimType"] == "uniqueness"

    def test_missing_username_400(self, client):
        r = client.post("/scim/v2/Users", json={"active": True}, headers=_auth())
        assert r.status_code == 400

    def test_get_by_id(self, client):
        uid = _make_user(client).json()["id"]
        r = client.get(f"/scim/v2/Users/{uid}", headers=_auth())
        assert r.status_code == 200 and r.json()["id"] == uid

    def test_get_unknown_404(self, client):
        r = client.get("/scim/v2/Users/does-not-exist", headers=_auth())
        assert r.status_code == 404

    def test_list_and_filter(self, client):
        first = _make_user(client, username="a@x.com")
        second = _make_user(client, username="b@x.com")
        assert first.status_code == second.status_code == 201
        assert first.json()["displayName"] == second.json()["displayName"] == "Alice Smith"
        from maverick.tenant import registry
        assert registry.get_tenant(first.json()["id"]).display_name == "Alice Smith"
        assert registry.get_tenant(second.json()["id"]).display_name == "Alice Smith (b@x.com)"
        r = client.get("/scim/v2/Users", headers=_auth())
        assert r.json()["totalResults"] == 2
        # userName eq filter (the IdP existence probe).
        r2 = client.get('/scim/v2/Users?filter=userName eq "a@x.com"', headers=_auth())
        body = r2.json()
        assert body["totalResults"] == 1
        assert body["Resources"][0]["userName"] == "a@x.com"

    def test_long_scim_name_keeps_resource_and_bounded_workspace_label(self, client):
        from maverick.tenant import registry

        long_name = "Alexandra " * 29 + "Alexandra"
        created = _make_user(client, username="long@example.com", displayName=long_name)
        assert created.status_code == 201
        assert created.json()["displayName"] == long_name
        uid = created.json()["id"]
        label = registry.get_tenant(uid).display_name
        assert len(label) <= 200
        assert label.startswith("Alexandra") and label.endswith("…")
        assert uid not in label

    def test_unsupported_filter_400(self, client):
        r = client.get('/scim/v2/Users?filter=displayName co "z"', headers=_auth())
        assert r.status_code == 400
        assert r.json()["scimType"] == "invalidFilter"

    def test_pagination(self, client):
        for i in range(3):
            _make_user(client, username=f"u{i}@x.com")
        r = client.get("/scim/v2/Users?startIndex=1&count=2", headers=_auth())
        body = r.json()
        assert body["totalResults"] == 3 and body["itemsPerPage"] == 2

    def test_put_replaces(self, client):
        uid = _make_user(client).json()["id"]
        r = client.put(f"/scim/v2/Users/{uid}", headers=_auth(), json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "alice@example.com", "displayName": "Alice R", "active": True,
        })
        assert r.status_code == 200 and r.json()["displayName"] == "Alice R"

    def test_patch_deprovision_suspends_tenant(self, client):
        uid = _make_user(client).json()["id"]
        from maverick.tenant import registry
        assert registry.get_tenant(uid).active is True
        # Okta deprovision: PATCH replace active=false.
        r = client.patch(f"/scim/v2/Users/{uid}", headers=_auth(), json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "active", "value": False}],
        })
        assert r.status_code == 200 and r.json()["active"] is False
        assert registry.get_tenant(uid).active is False

    def test_patch_azure_no_path_form(self, client):
        uid = _make_user(client).json()["id"]
        r = client.patch(f"/scim/v2/Users/{uid}", headers=_auth(), json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "value": {"active": False}}],
        })
        assert r.status_code == 200 and r.json()["active"] is False

    def test_patch_unsupported_400(self, client):
        uid = _make_user(client).json()["id"]
        r = client.patch(f"/scim/v2/Users/{uid}", headers=_auth(), json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "nickName", "value": "x"}],
        })
        assert r.status_code == 400

    def test_delete_removes_user_and_tenant(self, client):
        uid = _make_user(client).json()["id"]
        r = client.delete(f"/scim/v2/Users/{uid}", headers=_auth())
        assert r.status_code == 204
        assert client.get(f"/scim/v2/Users/{uid}", headers=_auth()).status_code == 404
        from maverick.tenant import registry
        assert registry.get_tenant(uid) is None

    def test_patch_tenant_suspend_failure_does_not_commit_scim_inactive(self, client, monkeypatch):
        uid = _make_user(client).json()["id"]
        from maverick.tenant import registry

        def fail_suspend(_uid):
            raise RuntimeError("simulated suspend failure")

        monkeypatch.setattr(registry, "suspend_tenant", fail_suspend)
        r = client.patch(f"/scim/v2/Users/{uid}", headers=_auth(), json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "active", "value": False}],
        })
        assert r.status_code == 500
        assert client.get(f"/scim/v2/Users/{uid}", headers=_auth()).json()["active"] is True
        assert registry.get_tenant(uid).active is True

    def test_delete_tenant_failure_keeps_scim_user_for_retry(self, client, monkeypatch):
        uid = _make_user(client).json()["id"]
        from maverick.tenant import registry

        def fail_delete(_uid):
            raise RuntimeError("simulated delete failure")

        monkeypatch.setattr(registry, "delete_tenant", fail_delete)
        r = client.delete(f"/scim/v2/Users/{uid}", headers=_auth())
        assert r.status_code == 500
        assert client.get(f"/scim/v2/Users/{uid}", headers=_auth()).status_code == 200
        assert registry.get_tenant(uid) is not None

    def test_corrupt_retirement_ledger_prevents_delete_acknowledgement(self, client):
        from maverick.tenant import registry
        from maverick_dashboard import subject_directory as sd

        uid = _make_user(
            client,
            username="retry-delete@example.com",
            externalId="immutable-retry-delete",
        ).json()["id"]
        damaged = '{"subjects":{"bad":NaN}}'
        sd._retired_path().write_text(damaged, encoding="utf-8")

        response = client.delete(f"/scim/v2/Users/{uid}", headers=_auth())
        assert response.status_code == 500
        assert client.get(f"/scim/v2/Users/{uid}", headers=_auth()).status_code == 200
        assert registry.get_tenant(uid) is not None
        assert sd._retired_path().read_text(encoding="utf-8") == damaged


class TestUserStoreHardening:
    def test_missing_store_retains_empty_bootstrap_semantics(self):
        from maverick_dashboard import scim

        assert not scim._store_path().exists()
        assert scim._load() == {}

    def test_corrupt_present_store_fails_closed_and_is_not_overwritten(self, monkeypatch):
        from maverick_dashboard import scim
        from maverick_dashboard.app import app

        monkeypatch.setenv("MAVERICK_SCIM_TOKEN", _TOKEN)
        damaged = '{"users": ['
        scim._store_path().write_text(damaged, encoding="utf-8")
        with pytest.raises(scim.ScimStoreError):
            scim._load()

        client = TestClient(
            app, base_url="http://127.0.0.1",
            headers={"Origin": "http://127.0.0.1"},
            raise_server_exceptions=False,
        )
        response = _make_user(client, username="must-not-commit@example.com")
        assert response.status_code == 500
        assert scim._store_path().read_text(encoding="utf-8") == damaged

    def test_unreadable_present_store_fails_closed(self, monkeypatch):
        from maverick_dashboard import scim

        scim._store_path().write_text('{"users": []}', encoding="utf-8")

        def denied(_path):
            raise PermissionError("simulated ACL denial")

        monkeypatch.setattr(scim, "atomic_read_text", denied)
        with pytest.raises(scim.ScimStoreError, match="unreadable"):
            scim._load()

    def test_schema_rejects_non_boolean_active_and_duplicate_external_id(self, client):
        from maverick_dashboard import scim

        _make_user(client, username="a@example.com", externalId="shared-id")
        _make_user(client, username="b@example.com", externalId="other-id")
        data = json.loads(scim._store_path().read_text(encoding="utf-8"))
        data["users"][0]["active"] = "true"
        scim._store_path().write_text(json.dumps(data), encoding="utf-8")
        with pytest.raises(scim.ScimStoreError, match="active"):
            scim._load()

        data["users"][0]["active"] = True
        for record in data["users"]:
            record["externalId"] = "shared-id"
        scim._store_path().write_text(json.dumps(data), encoding="utf-8")
        with pytest.raises(scim.ScimStoreError, match="duplicate externalId"):
            scim._load()

        data["users"][0]["externalId"] = "first-external-id"
        data["users"][1]["externalId"] = data["users"][0]["id"]
        scim._store_path().write_text(json.dumps(data), encoding="utf-8")
        with pytest.raises(scim.ScimStoreError, match="identity collision"):
            scim._load()

    def test_concurrent_user_mutations_do_not_lose_updates(self):
        from maverick_dashboard import scim

        start = threading.Event()

        def add_user(index: int):
            start.wait()
            with scim._locked_users():
                users = scim._load()
                # Make an unlocked implementation reliably overlap here.
                time.sleep(0.03)
                uid = f"{index + 1:032x}"
                users[uid] = scim._record_from_resource(
                    {"userName": f"user-{index}@example.com"}, uid=uid
                )
                scim._save(users)

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(add_user, index) for index in range(2)]
            start.set()
            for future in futures:
                future.result(timeout=5)
        assert set(scim._load()) == {f"{index + 1:032x}" for index in range(2)}

    def test_store_and_parent_are_private(self, client):
        from maverick.file_lock import private_path_is_restricted
        from maverick_dashboard import scim

        assert _make_user(client).status_code == 201
        assert private_path_is_restricted(scim._store_path(), 0o600)
        assert private_path_is_restricted(scim._store_path().parent, 0o700)
