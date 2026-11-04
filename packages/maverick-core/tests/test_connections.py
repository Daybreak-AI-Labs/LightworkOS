"""Named, sealed SaaS connections + the connector env fallback."""
from __future__ import annotations

import asyncio

import pytest
from maverick import connections


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr("maverick.paths.data_dir", lambda *p, **k: tmp_path.joinpath(*p))
    monkeypatch.setattr(connections, "data_dir", lambda *p, **k: tmp_path.joinpath(*p))
    monkeypatch.setenv("MAVERICK_CONNECTIONS", "1")
    # a plaintext seal so the test needs no KMS backend
    monkeypatch.setattr("maverick.connections.seal_text_for_tenant",
                        lambda t, s: s.encode("utf-8"))
    monkeypatch.setattr("maverick.connections.unseal_text_for_tenant",
                        lambda t, b: b.decode("utf-8"))


def test_set_list_get_delete_roundtrip():
    rec = connections.set_connection("salesforce-eu", connector="salesforce",
                                     base_url="https://eu.salesforce.com/", token="sekret")
    assert rec == {"name": "salesforce-eu", "connector": "salesforce",
                   "base_url": "https://eu.salesforce.com", "has_token": True,
                   "created": rec["created"], "owner": "", "access": "owner",
                   "allowed_principals": [], "revision": rec["revision"],
                   "last_test": None, "test_history": [], "capability_receipts": []}
    listed = connections.list_connections()
    assert listed[0]["name"] == "salesforce-eu" and "token" not in listed[0]
    full = connections.get_connection("salesforce-eu")
    assert full["token"] == "sekret"                 # internal read keeps the token
    assert connections.delete_connection("salesforce-eu") is True
    assert connections.list_connections() == []


def test_reviewed_delete_does_not_remove_replacement_or_reveal_other_owner():
    old = connections.set_connection("reviewed", owner="user:owner", token="old-fixture")
    replacement = connections.set_connection("reviewed", owner="user:owner", token="replacement-fixture")
    before = connections._path().read_bytes()
    assert not connections.delete_connection("reviewed", "user:other", expected_revision=old["revision"])
    with pytest.raises(connections.ConnectionVersionConflict, match="changed"):
        connections.delete_connection("reviewed", "user:owner", expected_revision=old["revision"])
    assert connections._path().read_bytes() == before
    assert connections.get_connection("reviewed")["revision"] == replacement["revision"]
    assert connections.delete_connection("reviewed", "user:owner", expected_revision=replacement["revision"])
    assert connections.get_connection("reviewed") is None


@pytest.mark.parametrize(
    "corrupt_payload",
    (b"not-json", b"[]", b'{"existing":"not-a-record"}'),
)
def test_corrupt_store_fails_closed_without_overwrite(corrupt_payload):
    path = connections._path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(corrupt_payload)

    with pytest.raises(connections.ConnectionStoreUnavailable, match="unavailable"):
        connections.set_connection("replacement", token="must-not-persist")

    assert path.read_bytes() == corrupt_payload


def test_decryption_failure_fails_closed_without_overwrite(monkeypatch):
    connections.set_connection("existing", token="original")
    path = connections._path()
    original_ciphertext = path.read_bytes()

    def reject_ciphertext(_tenant, _blob):
        raise ValueError("authentication failed")

    monkeypatch.setattr(connections, "unseal_text_for_tenant", reject_ciphertext)

    with pytest.raises(connections.ConnectionStoreUnavailable, match="unavailable"):
        connections.set_connection("replacement", token="must-not-persist")

    assert path.read_bytes() == original_ciphertext


def test_token_only_patch_preserves_connection_metadata():
    created = connections.set_connection(
        "acme",
        connector="salesforce",
        base_url="https://tenant.example",
        token="old",
        owner="user:alice",
        access="tenant",
        allowed_principals=["agent:finance"],
    )

    updated = connections.set_connection(
        "acme",
        token="new",
        expected_owner="user:alice",
        expected_revision=created["revision"],
        require_revision=True,
    )
    stored = connections.get_connection("acme")

    assert stored is not None
    assert stored["token"] == "new"
    assert updated["connector"] == "salesforce"
    assert updated["base_url"] == "https://tenant.example"
    assert updated["owner"] == "user:alice"
    assert updated["access"] == "tenant"
    assert updated["allowed_principals"] == ["agent:finance"]
    assert updated["revision"] != created["revision"]


def test_existing_connection_update_requires_current_revision():
    created = connections.set_connection("acme", token="old")

    with pytest.raises(connections.ConnectionVersionConflict, match="required"):
        connections.set_connection("acme", token="missing", require_revision=True)
    with pytest.raises(connections.ConnectionVersionConflict, match="changed"):
        connections.set_connection(
            "acme",
            token="stale",
            expected_revision="not-current",
            require_revision=True,
        )

    assert connections.get_connection("acme")["token"] == "old"
    assert connections.list_connections()[0]["revision"] == created["revision"]


def test_internal_get_returns_a_detached_credential_record():
    connections.set_connection("private", token="original")

    first = connections.get_connection("private")
    assert first is not None
    first["token"] = "mutated-in-memory"

    assert connections.get_connection("private")["token"] == "original"


def test_invalid_name_rejected():
    with pytest.raises(ValueError):
        connections.set_connection("!!!", token="x")


def test_resolve_prefers_exact_name_then_connector_field():
    connections.set_connection("acme", connector="acme", base_url="https://a", token="t1")
    connections.set_connection("acme-staging", connector="acme", base_url="https://s", token="t2")
    # exact name wins
    assert connections.resolve("acme") == ("https://a", "t1")
    # unknown name falls through to the first connection whose connector matches
    connections.delete_connection("acme")
    assert connections.resolve("acme")[1] in ("t2",)


def test_resolve_returns_none_when_disabled(monkeypatch):
    connections.set_connection("x", base_url="https://x", token="t")
    monkeypatch.delenv("MAVERICK_CONNECTIONS", raising=False)
    monkeypatch.setattr("maverick.config.load_config", dict)
    assert connections.resolve("x") is None


def test_connector_env_fallback_uses_a_connection(monkeypatch):
    # env unset -> the REST connector's _env_config falls back to a connection
    from maverick.tools import _rest_connector
    monkeypatch.delenv("ACME_BASE_URL", raising=False)
    monkeypatch.delenv("ACME_TOKEN", raising=False)
    connections.set_connection("acme", connector="acme",
                               base_url="https://api.acme.test", token="conn-tok")
    base, tok = _rest_connector._env_config("acme", "ACME_BASE_URL", "ACME_TOKEN")
    assert base == "https://api.acme.test" and tok == "conn-tok"


def test_env_still_wins_over_connection(monkeypatch):
    from maverick.tools import _rest_connector
    monkeypatch.setenv("ACME_BASE_URL", "https://env.acme")
    monkeypatch.setenv("ACME_TOKEN", "env-tok")
    connections.set_connection("acme", connector="acme",
                               base_url="https://conn.acme", token="conn-tok")
    base, tok = _rest_connector._env_config("acme", "ACME_BASE_URL", "ACME_TOKEN")
    assert base == "https://env.acme" and tok == "env-tok"    # env precedence


def test_env_base_wins_per_field_when_only_token_missing(monkeypatch):
    # A set base_url env must NOT be swapped for the connection's URL just
    # because the token env is unset (per-field precedence, not all-or-nothing).
    from maverick.tools import _rest_connector
    monkeypatch.setenv("ACME_BASE_URL", "https://sandbox.acme")
    monkeypatch.delenv("ACME_TOKEN", raising=False)
    connections.set_connection("acme", connector="acme",
                               base_url="https://prod.acme", token="conn-tok")
    base, tok = _rest_connector._env_config("acme", "ACME_BASE_URL", "ACME_TOKEN")
    assert base == "https://sandbox.acme"   # env base kept, not prod.acme
    assert tok == "conn-tok"                # token filled from the connection


def test_authenticated_enterprise_principal_cannot_borrow_env_credentials(
    monkeypatch,
):
    from maverick.tools import _rest_connector

    monkeypatch.setattr("maverick.enterprise.enterprise_enabled", lambda: True)
    monkeypatch.setenv("ACME_BASE_URL", "https://operator.acme")
    monkeypatch.setenv("ACME_TOKEN", "operator-secret")
    connections.set_connection(
        "acme", connector="acme", base_url="https://alice.acme",
        token="alice-secret", owner="user:alice",
    )

    with connections.bind_principal("user:mallory"):
        with pytest.raises(RuntimeError, match="principal-authorized"):
            _rest_connector._env_config("acme", "ACME_BASE_URL", "ACME_TOKEN")


def test_scoped_connector_error_is_actionable_without_ambient_details(monkeypatch):
    from maverick.tools._rest_connector import make_rest_tool

    monkeypatch.setattr("maverick.enterprise.enterprise_enabled", lambda: True)
    operator_base = "https://operator-private.acme"
    operator_token = "operator-low-entropy-secret"  # pragma: allowlist secret
    monkeypatch.setenv("ACME_BASE_URL", operator_base)
    monkeypatch.setenv("ACME_TOKEN", operator_token)
    connections.set_connection(
        "acme", connector="acme", base_url="https://alice.acme",
        token="alice-secret", owner="user:alice",
    )
    tool = make_rest_tool(
        name="acme", base_url_env="ACME_BASE_URL", token_env="ACME_TOKEN",
        description="Acme test connector",
    )

    with connections.bind_principal("user:mallory"):
        out = tool.fn({"op": "get", "path": "/things"})

    assert "principal-authorized saved connection" in out
    assert "ACME_BASE_URL" not in out and "ACME_TOKEN" not in out
    assert operator_base not in out and operator_token not in out


def test_authenticated_enterprise_uses_its_saved_grant_not_env(monkeypatch):
    from maverick.tools import _rest_connector

    monkeypatch.setattr("maverick.enterprise.enterprise_enabled", lambda: True)
    monkeypatch.setenv("ACME_BASE_URL", "https://operator.acme")
    monkeypatch.setenv("ACME_TOKEN", "operator-secret")
    connections.set_connection(
        "acme-bob", connector="acme", base_url="https://bob.acme",
        token="bob-secret", owner="user:bob",
    )

    with connections.bind_principal("user:bob"):
        assert _rest_connector._env_config(
            "acme", "ACME_BASE_URL", "ACME_TOKEN",
        ) == ("https://bob.acme", "bob-secret")


def test_authenticated_enterprise_rejects_ambient_extra_header_credentials(
    monkeypatch,
):
    from maverick.tools import _rest_connector

    monkeypatch.setattr("maverick.enterprise.enterprise_enabled", lambda: True)
    monkeypatch.setenv("ACME_SECONDARY_KEY", "ambient-secret")
    with connections.bind_principal("user:alice"):
        with pytest.raises(RuntimeError, match="ambient extra-header"):
            _rest_connector._build_auth_headers(
                "saved-token",
                basic=False,
                token_header="Authorization",
                scheme="Bearer",
                extra_headers_env={"X-Secondary": "ACME_SECONDARY_KEY"},
            )


def test_resolve_enforces_owner_and_uses_allowed_fallback():
    connections.set_connection(
        "acme", connector="acme", base_url="https://alice", token="alice-token",
        owner="user:alice",
    )
    connections.set_connection(
        "acme-bob", connector="acme", base_url="https://bob", token="bob-token",
        owner="user:bob",
    )

    assert connections.resolve("acme", principal="user:alice") == (
        "https://alice", "alice-token",
    )
    # The exact-name record is not usable by Bob, so resolution selects his
    # authorized alias rather than borrowing Alice's credential.
    assert connections.resolve("acme", principal="user:bob") == (
        "https://bob", "bob-token",
    )
    assert connections.resolve("acme", principal="user:mallory") is None
    assert connections.resolve("acme") is None


def test_explicit_use_grant_and_tenant_sharing():
    connections.set_connection(
        "granted", token="g", owner="user:alice",
        allowed_principals=["user:bob", "agent:finance"],
    )
    assert connections.resolve("granted", principal="user:bob")[1] == "g"
    assert connections.resolve("granted", principal="agent:finance")[1] == "g"
    assert connections.resolve("granted", principal="user:eve") is None

    connections.set_connection(
        "shared", token="s", owner="user:alice", access="tenant",
    )
    assert connections.resolve("shared", principal="user:eve")[1] == "s"
    # Tenant sharing still requires an authenticated tenant principal when the
    # record has an owner; an unscoped background run cannot consume it.
    assert connections.resolve("shared") is None


def test_principals_that_differ_only_by_trailing_space_never_share_credentials():
    connections.set_connection(
        "acme", connector="acme", token="plain",
        owner="user:alice",
    )
    connections.set_connection(
        "acme-spaced", connector="acme", token="spaced",
        owner="user:alice ",
    )

    assert connections.resolve("acme", principal="user:alice") == ("", "plain")
    assert connections.resolve("acme", principal="user:alice ") == ("", "spaced")

    with connections.bind_principal("user:alice "):
        assert connections.current_principal() == "user:alice "
        assert connections.resolve("acme") == ("", "spaced")


def test_allowed_principal_grants_are_exact_and_not_trimmed():
    connections.set_connection(
        "granted-exact",
        token="secret",
        owner="agent:owner",
        allowed_principals=["user:alice "],
    )

    assert connections.resolve("granted-exact", principal="user:alice") is None
    assert connections.resolve("granted-exact", principal="user:alice ") == (
        "", "secret",
    )


def test_registry_binds_identity_at_credential_use_boundary():
    from maverick.tools import Tool, ToolRegistry

    connections.set_connection("private", token="secret", owner="user:alice")
    tool = Tool(
        name="probe",
        description="resolve in the execution context",
        input_schema={"type": "object", "properties": {}},
        fn=lambda _args: str(connections.resolve("private")),
    )
    alice = ToolRegistry(principal="user:alice")
    alice.register(tool)
    bob = ToolRegistry(principal="user:bob")
    bob.register(tool)
    assert "secret" in asyncio.run(alice.run("probe", {}))
    assert asyncio.run(bob.run("probe", {})) == "None"


def test_enterprise_refuses_unscoped_bespoke_ambient_connector(monkeypatch):
    from maverick.tools import Tool, ToolRegistry

    monkeypatch.setattr("maverick.enterprise.enterprise_enabled", lambda: True)
    calls = []
    reg = ToolRegistry(principal="user:alice")
    reg.register(Tool(
        name="asana",
        description="legacy ambient connector",
        input_schema={"type": "object", "properties": {}},
        fn=lambda _args: calls.append(True) or "borrowed operator credential",
    ))

    out = asyncio.run(reg.run("asana", {}))

    assert out.startswith("REFUSED (credentials)")
    assert "principal-authorized saved connection" in out
    assert calls == []


def test_standard_local_operator_retains_ambient_connector_compatibility(monkeypatch):
    from maverick.tools import Tool, ToolRegistry

    monkeypatch.setattr("maverick.enterprise.enterprise_enabled", lambda: False)
    reg = ToolRegistry(principal="user:alice")
    reg.register(Tool(
        name="asana",
        description="legacy ambient connector",
        input_schema={"type": "object", "properties": {}},
        fn=lambda _args: "operator credential used",
    ))

    assert asyncio.run(reg.run("asana", {})) == "operator credential used"


def test_readiness_receipt_is_non_secret_and_rotation_invalidates_it():
    connections.set_connection("ready", token="old", owner="user:alice")
    public = connections.record_test_result(
        "ready", reachable=True, authenticated=True, status=204,
        expected_owner="user:alice",
    )
    assert public["last_test"]["authenticated"] is True
    assert "token" not in public and "old" not in str(public)

    rotated = connections.set_connection(
        "ready", token="new", owner="user:alice", expected_owner="user:alice",
    )
    assert rotated["last_test"]["revision"] != rotated["revision"]


def test_stale_readiness_probe_cannot_certify_rotated_credentials():
    connections.set_connection("ready", token="old", owner="user:alice")
    original = connections.get_connection("ready")
    assert original is not None and original["revision"]

    connections.set_connection(
        "ready", token="new", owner="user:alice", expected_owner="user:alice",
    )

    with pytest.raises(connections.ConnectionVersionConflict):
        connections.record_test_result(
            "ready",
            reachable=True,
            authenticated=True,
            status=200,
            expected_owner="user:alice",
            expected_revision=original["revision"],
        )

    replacement = connections.get_connection("ready")
    assert replacement is not None
    assert replacement["token"] == "new"
    assert "last_test" not in replacement


def test_invalid_connection_use_principal_is_rejected():
    with pytest.raises(ValueError, match="printable"):
        connections.set_connection("bad-grant", token="x", allowed_principals=["bad\nuser"])


def test_connection_principal_length_boundary():
    accepted = "p" * 256
    connections.set_connection("boundary", token="x", owner=accepted)
    assert connections.resolve("boundary", principal=accepted) == ("", "x")

    with pytest.raises(ValueError, match="1-256 printable"):
        connections.set_connection("too-long", token="x", owner="p" * 257)


def test_readiness_receipt_is_bound_to_credential_revision_and_capability():
    saved = connections.set_connection("test", connector="zendesk", token="test-token")
    checked = connections.record_test_result("test", reachable=True, authenticated=False,
        status=200, expected_revision=saved["revision"], outcome="access_unverified")
    assert checked["last_test"]["revision"] == saved["revision"]
    assert checked["last_test"]["outcome"] == "access_unverified"
    assert "task access is not checked" in checked["last_test"]["capability"]
    rotated = connections.set_connection("test", token="replacement", expected_revision=saved["revision"])
    assert rotated["last_test"]["revision"] != rotated["revision"]
    with pytest.raises(connections.ConnectionVersionConflict):
        connections.record_test_result("test", reachable=True, authenticated=True, expected_revision=saved["revision"])


def test_bad_aws_region_refuses_without_overwriting_saved_record():
    import json

    saved = connections.set_connection("storage", connector="aws_s3", token=json.dumps({"region": "ap-southeast-7", "access_key_id": "fixture", "secret_access_key": "fixture"}))
    with pytest.raises(ValueError, match="region"):
        connections.set_connection("storage", token=json.dumps({"region": "bad/region"}), expected_revision=saved["revision"])
    assert connections.get_connection("storage")["revision"] == saved["revision"]


def test_staged_replacement_fences_both_versions_and_preserves_old_receipts():
    target = connections.set_connection("production", connector="github", base_url="https://api.github.com", token="old-key", owner="user:a", allowed_principals=["user:b"])
    checked_target = connections.record_test_result("production", reachable=True, authenticated=False, expected_revision=target["revision"])
    staged = connections.set_connection("candidate", connector="github", base_url="https://api.github.com", token="new-key", owner="user:a")
    connections.record_test_result("candidate", reachable=True, authenticated=True, expected_revision=staged["revision"])
    with pytest.raises(connections.ConnectionVersionConflict):
        connections.replace_from_staged("production", "candidate", owner="user:a", expected_revision=target["revision"], replacement_revision="stale")
    # Compose under the same lock, as the impact-review API does.
    with connections._mutation_lock():
        switched = connections.replace_from_staged("production", "candidate", owner="user:a", expected_revision=target["revision"], replacement_revision=staged["revision"])
    assert connections.get_connection("production")["token"] == "new-key"
    assert switched["allowed_principals"] == ["user:b"]
    assert switched["test_history"][-1] == checked_target["last_test"]
    assert switched["last_test"]["staged_revision"] == staged["revision"]
    assert "token" not in switched and connections.get_connection("candidate") is not None


def test_capability_probe_uses_one_fixed_read_and_persists_no_provider_payload(monkeypatch):
    import contextlib
    import json

    from maverick.connection_capabilities import probe

    saved = connections.set_connection("drive", connector="gdrive", base_url="https://www.googleapis.com", token="fixture", owner="user:a")
    calls = []
    class Reply:
        status_code = 200
        def __enter__(self): return self
        def __exit__(self, *_): return False
        def iter_bytes(self): yield json.dumps({"id": "file-a", "private_value": "must-not-persist"}).encode()
    class Client:
        def stream(self, method, url, **kwargs):
            calls.append((method, url, kwargs))
            return Reply()
    @contextlib.contextmanager
    def safe_client(_url, **_kwargs): yield Client()
    monkeypatch.setattr("maverick.tools._ssrf.safe_client", safe_client)
    receipt = probe("drive", "drive_file_metadata", "file-a", actor="user:a", expected_revision=saved["revision"], authorize=lambda: None)
    assert receipt["verified"] and receipt["external_writes"] is False
    assert calls[0][0] == "GET" and "/drive/v3/files/file-a?fields=id" in calls[0][1]
    assert calls[0][2]["follow_redirects"] is False and len(calls) == 1
    assert "must-not-persist" not in str(connections.get_connection("drive"))
    assert "file-a" not in str(receipt)
    with pytest.raises(ValueError):
        probe("drive", "drive_file_metadata", "../different", actor="user:a", expected_revision=saved["revision"], authorize=lambda: None)
    assert len(calls) == 1
