"""HTTP contracts for native data-use provider enrollment and execution."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
API = "/api/v1/data-use/providers"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _config_text(*, enabled: bool = True, provider_audit: bool = False) -> str:
    if not enabled:
        return "[data_use_governance]\nenable = true\n"
    text = (
        "[data_use_governance]\n"
        "enable = true\n"
        "[data_use_governance.compiler]\n"
        "enable = true\n"
        "[data_use_governance.enforcement]\n"
        "enable = true\n"
        "max_attempts = 2\n"
        "[data_use_governance.snowflake]\n"
        "enable = true\n"
        'origin = "https://acct1.snowflakecomputing.com"\n'
        'credential_secret_ref = "$LIGHTWORK_TEST_SNOWFLAKE_TOKEN"\n'
        "credential_revision = 3\n"
        "timeout_seconds = 4\n"
        "max_response_bytes = 65536\n"
    )
    if provider_audit:
        text += (
            "[data_use_governance.provider_audit]\n"
            "enable = true\n"
            "audit_window_seconds = 300\n"
            "retention_seconds = 3600\n"
            "max_attempts = 2\n"
        )
    return text


@pytest.fixture(autouse=True)
def isolated_provider_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer

    path = tmp_path / "config.toml"
    path.write_text(_config_text(), encoding="utf-8")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(path))
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    for name in (
        "MAVERICK_DASHBOARD_ADMINS",
        "MAVERICK_DASHBOARD_TOKEN",
        "MAVERICK_DASHBOARD_REQUIRE_AUTH",
        "MAVERICK_OIDC_ENABLED",
        "MAVERICK_PROXY_AUTH",
        "MAVERICK_TENANT_BY_USER",
        "LIGHTWORK_TEST_SNOWFLAKE_TOKEN",
    ):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    for name in (
        "data_use_provider_adapter_factory",
        "data_use_provider_audit_composition_factory",
        "data_use_provider_credential_owner",
        "data_use_provider_transport",
    ):
        if hasattr(app.state, name):
            delattr(app.state, name)
    yield path
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    for name in (
        "data_use_provider_adapter_factory",
        "data_use_provider_audit_composition_factory",
        "data_use_provider_credential_owner",
        "data_use_provider_transport",
    ):
        if hasattr(app.state, name):
            delattr(app.state, name)


def _enrollment() -> dict[str, Any]:
    return {
        "account_or_workspace_id": "acct1",
        "asset_id": "customers",
        "catalog": "APP_DB",
        "schema_name": "PUBLIC",
        "table": "CUSTOMERS",
        "principal": "ANALYST_ROLE",
        "compute_id": "GOVERNANCE_WH",
        "field_map": {"email": "EMAIL", "region": "REGION"},
        "mask_bindings": {"hash_sha256": "GOV.POLICY.MASK_SHA256"},
        "row_filter_bindings": {},
        "state_anchor": "GOV.TAGS.DATA_USE_STATE",
        "catalog_snapshot_sha256": _digest("catalog snapshot"),
        "field_inventory_complete": True,
        "expected_revision": 0,
        "idempotency_key": "enroll-snowflake-1",
    }


def _enable_provider_audit(config_path: Path) -> None:
    from maverick import config

    config_path.write_text(
        _config_text(provider_audit=True),
        encoding="utf-8",
    )
    config.reset_config_cache()


def test_provider_api_is_default_off_and_never_accepts_client_origin_or_credentials(
    isolated_provider_runtime: Path,
) -> None:
    from maverick import config

    isolated_provider_runtime.write_text(_config_text(enabled=False), encoding="utf-8")
    config.reset_config_cache()
    assert client.get(f"{API}/snowflake/bindings").status_code == 403

    isolated_provider_runtime.write_text(_config_text(), encoding="utf-8")
    config.reset_config_cache()
    forged = {
        **_enrollment(),
        "origin": "https://attacker.example",
        "credential": "secret",
    }
    response = client.put(f"{API}/snowflake/bindings/native-customers", json=forged)
    assert response.status_code == 422


def test_enroll_list_rotate_and_permanently_revoke_without_secret_persistence(
    tmp_path: Path,
) -> None:
    first_response = client.put(f"{API}/snowflake/bindings/native-customers", json=_enrollment())
    assert first_response.status_code == 200, first_response.text
    first = first_response.json()
    assert first["origin"] == "https://acct1.snowflakecomputing.com"
    assert first["credential_revision"] == 3
    assert "credential_key_id" not in first
    assert "LIGHTWORK_TEST_SNOWFLAKE_TOKEN" not in str(first)

    listed = client.get(f"{API}/snowflake/bindings").json()
    assert listed["truncated"] is False
    assert [item["binding_id"] for item in listed["items"]] == ["native-customers"]
    assert listed["items"][0]["revoked"] is False

    revoked_response = client.post(
        f"{API}/snowflake/bindings/native-customers/revoke",
        json={
            "expected_revision": 1,
            "reason_sha256": _digest("provider scope retired"),
            "idempotency_key": "revoke-native-customers-1",
        },
    )
    assert revoked_response.status_code == 200, revoked_response.text
    assert revoked_response.json()["revoked"] is True
    fetched = client.get(f"{API}/snowflake/bindings/native-customers").json()
    assert fetched["revoked"] is True
    assert "provider scope retired" not in str(fetched)

    database = next((tmp_path / "home").rglob("data-use-providers.sqlite3"))
    stored = database.read_bytes()
    assert b"LIGHTWORK_TEST_SNOWFLAKE_TOKEN" not in stored
    assert b"provider scope retired" not in stored


class _FakeAdapter:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any], str]] = []

    def status(self) -> dict[str, Any]:
        return {
            "provider_writes_possible": True,
            "live_provider_acceptance_verified": False,
        }

    def apply_control_ir(
        self, control_ir: dict[str, Any], *, idempotency_sha256: str
    ) -> dict[str, Any]:
        self.calls.append(("apply", control_ir, idempotency_sha256))
        return {
            "schema": "test-provider-result",
            "operation": "apply",
            "live_provider_acceptance_verified": False,
        }

    def rollback_control_ir(
        self, control_ir: dict[str, Any], *, idempotency_sha256: str
    ) -> dict[str, Any]:
        self.calls.append(("rollback", control_ir, idempotency_sha256))
        return {
            "schema": "test-provider-result",
            "operation": "rollback",
            "rollback_mode": "compiled_safe_deny",
            "restored_prior_native_state": False,
            "live_provider_acceptance_verified": False,
        }


class _AuditValue:
    def __init__(self, **values: Any) -> None:
        for key, value in values.items():
            setattr(self, key, value)


class _FakeAuditComposition:
    def __init__(
        self,
        order: list[str],
        *,
        stage_error: Exception | None = None,
        completion_failures: int = 0,
    ) -> None:
        self.order = order
        self.stage_error = stage_error
        self.completion_failures = completion_failures
        self.stage_calls: list[dict[str, Any]] = []
        self.complete_calls: list[str] = []
        self.authority_id = f"DUAO-{'a' * 32}"
        self.expectation_id = f"DUA-{'b' * 32}"

    def stage_operation(self, **kwargs: Any) -> _AuditValue:
        self.order.append("stage")
        self.stage_calls.append(dict(kwargs))
        if self.stage_error is not None:
            raise self.stage_error
        return _AuditValue(authority_id=self.authority_id, state="staged")

    def complete_operation(self, authority_id: str) -> _AuditValue:
        self.order.append("complete")
        self.complete_calls.append(authority_id)
        if self.completion_failures:
            self.completion_failures -= 1
            raise RuntimeError("credential=raw-secret-that-must-not-leak")
        return _AuditValue(
            authority=_AuditValue(
                authority_id=self.authority_id,
                state="registered",
            ),
            expectation=_AuditValue(
                expectation_id=self.expectation_id,
                state="pending",
            ),
        )


class _IdempotentFakeAdapter(_FakeAdapter):
    def __init__(self, order: list[str]) -> None:
        super().__init__()
        self.order = order
        self.external_mutations = 0
        self._results: dict[str, dict[str, Any]] = {}

    def apply_control_ir(
        self, control_ir: dict[str, Any], *, idempotency_sha256: str
    ) -> dict[str, Any]:
        self.order.append("adapter")
        self.calls.append(("apply", control_ir, idempotency_sha256))
        existing = self._results.get(idempotency_sha256)
        if existing is not None:
            return dict(existing)
        self.external_mutations += 1
        result = {
            "schema": "test-provider-result",
            "operation": "apply",
            "live_provider_acceptance_verified": False,
        }
        self._results[idempotency_sha256] = result
        return dict(result)


def test_apply_and_rollback_recompile_server_authority_and_reject_caller_ir(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maverick_dashboard import data_use_provider_api as api_module

    enrolled = client.put(f"{API}/snowflake/bindings/native-customers", json=_enrollment())
    assert enrolled.status_code == 200, enrolled.text
    fake = _FakeAdapter()
    app.state.data_use_provider_adapter_factory = lambda **_kwargs: fake
    compiled = {
        "schema": "lightwork.data-use.control-ir.v1",
        "ir_sha256": _digest("server compiled ir"),
        "desired_state": [],
        "rollback_state": [],
    }
    compile_calls: list[tuple[str, str, object | None]] = []

    async def server_compile(
        decision_id: str,
        expected: str,
        *,
        native_adapter: object | None = None,
    ) -> dict[str, Any]:
        compile_calls.append((decision_id, expected, native_adapter))
        return compiled

    monkeypatch.setattr(api_module, "_compile", server_compile)
    decision_sha = _digest("decision authority")
    forged = client.post(
        f"{API}/snowflake/bindings/native-customers/decisions/decision-1/apply",
        json={
            "expected_decision_sha256": decision_sha,
            "idempotency_key": "apply-decision-1",
            "control_ir": {"statement": "DROP TABLE customers"},
        },
    )
    assert forged.status_code == 422
    assert fake.calls == []

    applied = client.post(
        f"{API}/snowflake/bindings/native-customers/decisions/decision-1/apply",
        json={
            "expected_decision_sha256": decision_sha,
            "idempotency_key": "apply-decision-1",
        },
    )
    assert applied.status_code == 200, applied.text
    assert compile_calls == [("decision-1", decision_sha, fake)]
    assert fake.calls[0][0:2] == ("apply", compiled)
    assert applied.json()["operation_idempotency_sha256"] == fake.calls[0][2]
    assert "provider_audit" not in applied.json()

    rolled_back = client.post(
        f"{API}/snowflake/bindings/native-customers/decisions/decision-1/rollback",
        json={
            "expected_decision_sha256": decision_sha,
            "idempotency_key": "rollback-decision-1",
        },
    )
    assert rolled_back.status_code == 200, rolled_back.text
    assert fake.calls[-1][0] == "rollback"
    assert rolled_back.json()["restored_prior_native_state"] is False


def test_provider_audit_stages_server_ir_before_adapter_and_completes_afterward(
    isolated_provider_runtime: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maverick_dashboard import data_use_provider_api as api_module

    enrolled = client.put(f"{API}/snowflake/bindings/native-customers", json=_enrollment())
    assert enrolled.status_code == 200, enrolled.text
    _enable_provider_audit(isolated_provider_runtime)

    order: list[str] = []
    adapter = _IdempotentFakeAdapter(order)
    composition = _FakeAuditComposition(order)
    factory_calls: list[dict[str, Any]] = []

    def composition_factory(**kwargs: Any) -> _FakeAuditComposition:
        order.append("factory")
        factory_calls.append(dict(kwargs))
        return composition

    app.state.data_use_provider_adapter_factory = lambda **_kwargs: adapter
    app.state.data_use_provider_audit_composition_factory = composition_factory
    compiled = {
        "schema": "lightwork.data-use.control-ir.v1",
        "ir_sha256": _digest("server compiled ir with audit"),
        "desired_state": [],
        "rollback_state": [],
    }

    async def server_compile(
        _decision_id: str,
        _expected: str,
        *,
        native_adapter: object | None = None,
    ) -> dict[str, Any]:
        assert native_adapter is adapter
        order.append("compile")
        return compiled

    monkeypatch.setattr(api_module, "_compile", server_compile)
    response = client.post(
        f"{API}/snowflake/bindings/native-customers/decisions/decision-1/apply",
        json={
            "expected_decision_sha256": _digest("decision authority"),
            "idempotency_key": "apply-decision-with-audit-1",
        },
    )

    assert response.status_code == 200, response.text
    assert order == ["factory", "compile", "stage", "adapter", "complete"]
    assert factory_calls[0]["tenant_id"] == "tenant-a"
    expected_principal = hashlib.sha256(
        b"lightwork.data-use.provider-audit.api-principal.v1:tenant-a:operator:authorized-local"
    ).hexdigest()
    assert factory_calls[0]["principal_ref"] == (f"provider-audit-api.{expected_principal[:40]}")
    assert factory_calls[0]["require_worker"] is False
    assert factory_calls[0]["request"] is not None
    assert composition.stage_calls[0]["control_ir"] is compiled
    assert composition.stage_calls[0]["operation"] == "apply"
    assert composition.stage_calls[0]["operation_idempotency_sha256"] == (adapter.calls[0][2])
    assert response.json()["provider_audit"] == {
        "required": True,
        "authority_id": composition.authority_id,
        "expectation_id": composition.expectation_id,
        "state": "registered",
    }


def test_provider_audit_missing_composition_fails_before_adapter_or_compile(
    isolated_provider_runtime: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maverick_dashboard import data_use_provider_api as api_module

    enrolled = client.put(f"{API}/snowflake/bindings/native-customers", json=_enrollment())
    assert enrolled.status_code == 200, enrolled.text
    _enable_provider_audit(isolated_provider_runtime)
    adapter_builds = 0
    compile_calls = 0

    def adapter_factory(**_kwargs: Any) -> _FakeAdapter:
        nonlocal adapter_builds
        adapter_builds += 1
        return _FakeAdapter()

    async def server_compile(
        _decision_id: str,
        _expected: str,
        *,
        native_adapter: object | None = None,
    ) -> dict[str, Any]:
        del native_adapter
        nonlocal compile_calls
        compile_calls += 1
        return {}

    app.state.data_use_provider_adapter_factory = adapter_factory
    monkeypatch.setattr(api_module, "_compile", server_compile)
    response = client.post(
        f"{API}/snowflake/bindings/native-customers/decisions/decision-1/apply",
        json={
            "expected_decision_sha256": _digest("decision authority"),
            "idempotency_key": "apply-without-audit-runtime",
        },
    )

    assert response.status_code == 503
    assert "provider write was not attempted" in response.json()["detail"]
    assert adapter_builds == 0
    assert compile_calls == 0


def test_provider_audit_read_authority_failure_stops_before_adapter_io(
    isolated_provider_runtime: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maverick import data_use_provider_audit as audit
    from maverick_dashboard import data_use_provider_api as api_module

    enrolled = client.put(f"{API}/snowflake/bindings/native-customers", json=_enrollment())
    assert enrolled.status_code == 200, enrolled.text
    _enable_provider_audit(isolated_provider_runtime)
    order: list[str] = []
    adapter = _IdempotentFakeAdapter(order)
    composition = _FakeAuditComposition(
        order,
        stage_error=audit.DataUseProviderAuditConflict(
            "exact active provider audit read grant is unavailable"
        ),
    )
    app.state.data_use_provider_adapter_factory = lambda **_kwargs: adapter
    app.state.data_use_provider_audit_composition_factory = lambda **_kwargs: composition

    async def server_compile(
        _decision_id: str,
        _expected: str,
        *,
        native_adapter: object | None = None,
    ) -> dict[str, Any]:
        assert native_adapter is adapter
        order.append("compile")
        return {
            "schema": "lightwork.data-use.control-ir.v1",
            "ir_sha256": _digest("server compiled ir with missing grant"),
            "desired_state": [],
            "rollback_state": [],
        }

    monkeypatch.setattr(api_module, "_compile", server_compile)
    response = client.post(
        f"{API}/snowflake/bindings/native-customers/decisions/decision-1/apply",
        json={
            "expected_decision_sha256": _digest("decision authority"),
            "idempotency_key": "apply-without-read-authority",
        },
    )

    assert response.status_code == 409
    assert response.json()["detail"] == ("exact active provider audit read grant is unavailable")
    assert order == ["compile", "stage"]
    assert adapter.calls == []
    assert adapter.external_mutations == 0


def test_provider_audit_post_write_failure_recovers_on_exact_retry_without_remutation(
    isolated_provider_runtime: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maverick_dashboard import data_use_provider_api as api_module

    enrolled = client.put(f"{API}/snowflake/bindings/native-customers", json=_enrollment())
    assert enrolled.status_code == 200, enrolled.text
    _enable_provider_audit(isolated_provider_runtime)
    order: list[str] = []
    adapter = _IdempotentFakeAdapter(order)
    composition = _FakeAuditComposition(order, completion_failures=1)
    app.state.data_use_provider_adapter_factory = lambda **_kwargs: adapter
    app.state.data_use_provider_audit_composition_factory = lambda **_kwargs: composition
    compiled = {
        "schema": "lightwork.data-use.control-ir.v1",
        "ir_sha256": _digest("stable server compiled ir"),
        "desired_state": [],
        "rollback_state": [],
    }

    async def server_compile(
        _decision_id: str,
        _expected: str,
        *,
        native_adapter: object | None = None,
    ) -> dict[str, Any]:
        assert native_adapter is adapter
        order.append("compile")
        return compiled

    monkeypatch.setattr(api_module, "_compile", server_compile)
    payload = {
        "expected_decision_sha256": _digest("decision authority"),
        "idempotency_key": "apply-recover-provider-audit",
    }
    url = f"{API}/snowflake/bindings/native-customers/decisions/decision-1/apply"

    first = client.post(url, json=payload)
    assert first.status_code == 200, first.text
    assert first.json()["provider_audit"] == {
        "required": True,
        "authority_id": composition.authority_id,
        "expectation_id": None,
        "state": "recovery_pending",
    }
    assert "raw-secret" not in first.text
    assert adapter.external_mutations == 1

    second = client.post(url, json=payload)
    assert second.status_code == 200, second.text
    assert second.json()["provider_audit"] == {
        "required": True,
        "authority_id": composition.authority_id,
        "expectation_id": composition.expectation_id,
        "state": "registered",
    }
    assert adapter.external_mutations == 1
    assert len(adapter.calls) == 2
    assert adapter.calls[0][2] == adapter.calls[1][2]
    assert len(composition.stage_calls) == 2
    assert (
        composition.stage_calls[0]["operation_idempotency_sha256"]
        == (composition.stage_calls[1]["operation_idempotency_sha256"])
    )
    assert composition.complete_calls == [
        composition.authority_id,
        composition.authority_id,
    ]


def test_row_filter_choices_match_the_adapter_digest_and_stay_in_the_workspace(
    isolated_provider_runtime: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:

    from maverick import data_use_policy_compiler as compiler
    from maverick import data_use_provider_adapters as adapters

    governance = "/api/v1/data-use"
    assert client.put(
        f"{governance}/assets/customers",
        json={"asset_type": "table", "catalog_binding_sha256": _digest("c"),
              "expected_revision": 0, "idempotency_key": "asset-1"},
    ).status_code == 200
    assert client.put(
        f"{governance}/assets/customers/fields/country",
        json={"data_type": "string", "nullable": False, "catalog_binding_sha256": _digest("c"),
              "expected_revision": 0, "idempotency_key": "field-1"},
    ).status_code == 200
    row_filter = {"op": "in", "field": "country", "values": ["FR", "DE"]}
    created = client.post(
        f"{governance}/policies/eu-only/versions",
        json={"version": 1, "expected_current_version": 0, "expected_revision": 0,
              "idempotency_key": "policy-1",
              "document": {"scope": {"asset_ids": ["customers"]}, "conditions": {},
                           "controls": [{"control_id": "eu", "effect": "row_filter",
                                         "field_ids": [], "row_filter": row_filter}]}},
    )
    assert created.status_code == 201, created.text
    listed = client.get(f"{API}/row-filters")
    assert listed.status_code == 200, listed.text
    items = listed.json()["items"]
    expected = adapters._sha256(
        compiler.normalize_row_filter_ast(row_filter, {"country": "string"})
    )
    assert [item["row_filter_sha256"] for item in items] == [expected]
    assert items[0]["asset_id"] == "customers"
    assert items[0]["policy_id"] == "eu-only"

    monkeypatch.setenv("MAVERICK_TENANT", "tenant-b")
    assert client.get(f"{API}/row-filters").json()["items"] == []
