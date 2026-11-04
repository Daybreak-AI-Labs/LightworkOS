"""No-network contract and adversarial tests for native data-use adapters."""

from __future__ import annotations

import hashlib
import itertools
import json
import re
import sqlite3
from collections.abc import Callable, Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest
from maverick.data_use_governance import DataUseGovernanceStore
from maverick.data_use_policy_compiler import DataUsePolicyCompiler, thaw_control_ir
from maverick.data_use_provider_adapters import (
    CredentialLease,
    DatabricksDataUseControlAdapter,
    DataUseProviderAmbiguousEffect,
    DataUseProviderConfigError,
    DataUseProviderConflict,
    DataUseProviderCredentialError,
    DataUseProviderProtocolError,
    DataUseProviderRequestNotSent,
    DataUseProviderTransportAmbiguous,
    DataUseProviderUnavailable,
    DataUseProviderValidationError,
    ProviderBindingStore,
    ProviderHttpResponse,
    ProviderLimits,
    SnowflakeDataUseControlAdapter,
    provider_config_enabled,
)
from maverick.data_use_provider_audit import operation_correlation_sha256

from tests.test_data_use_governance import TENANT, Clock, _digest
from tests.test_data_use_policy_compiler import _compiled_decision

_AUTHORITY_SHA256 = _digest("native-adapter-authority")
_CREDENTIAL_AUTHORITY_SHA256 = _digest("credential-authority")
_ROW_AST = {"op": "eq", "left": {"field": "region"}, "value": "US"}
_STATE_RE = re.compile(r"'([0-9a-f]{64})'")


def _object_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    ).hexdigest()


def _enabled(provider: str) -> dict[str, Any]:
    return {
        "data_use_governance": {
            "enable": True,
            "compiler": {"enable": True},
            "enforcement": {"enable": True},
            provider: {"enable": True},
        }
    }


class CredentialOwner:
    def __init__(self, lease: CredentialLease) -> None:
        self.current = lease
        self.calls: list[tuple[str, str, str]] = []

    def lease(self, *, provider_id: str, tenant_id: str, binding_id: str) -> CredentialLease:
        self.calls.append((provider_id, tenant_id, binding_id))
        return self.current


class MockProviderTransport:
    """Provider-shaped transport that never opens a socket."""

    def __init__(self, provider: str, *, state: str | None = None) -> None:
        self.provider = provider
        self.state = state
        self.calls: list[dict[str, Any]] = []
        self.statements: list[str] = []
        self.read_events: list[object] = []
        self.mutation_events: list[object] = []
        self.poll_events: list[object] = []
        self.after_response: Callable[[], None] | None = None
        self.last_handle = "stmt-initial"

    def _success(
        self,
        *,
        observed: bool,
        status_code: int = 200,
        handle: str | None = None,
    ) -> ProviderHttpResponse:
        data = [[self.state or ""]] if observed else []
        selected_handle = handle or self.last_handle
        if self.provider == "snowflake":
            body = {"statementHandle": selected_handle, "data": data}
        else:
            body = {
                "statement_id": selected_handle,
                "status": {"state": "SUCCEEDED"},
                "result": {"data_array": data},
            }
        return ProviderHttpResponse(
            status_code=status_code,
            headers={"content-type": "application/json"},
            body=json.dumps(body).encode("utf-8"),
        )

    @staticmethod
    def _resolve_event(event: object) -> ProviderHttpResponse | None:
        if event is None:
            return None
        if isinstance(event, BaseException):
            raise event
        assert isinstance(event, ProviderHttpResponse)
        return event

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float,
        max_response_bytes: int,
        allow_redirects: bool,
    ) -> ProviderHttpResponse:
        decoded = None if body is None else json.loads(body.decode("utf-8"))
        statement = decoded.get("statement") if isinstance(decoded, dict) else None
        observation = isinstance(statement, str) and statement.startswith(
            ("SELECT SYSTEM$GET_TAG", "SHOW TBLPROPERTIES")
        )
        poll = method == "GET"
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": dict(headers),
                "body": decoded,
                "timeout": timeout,
                "max_response_bytes": max_response_bytes,
                "allow_redirects": allow_redirects,
                "observation": observation,
                "poll": poll,
            }
        )
        if isinstance(statement, str):
            self.statements.append(statement)
            self.last_handle = "stmt-" + hashlib.sha256(statement.encode()).hexdigest()[:24]
        events = (
            self.poll_events if poll else self.read_events if observation else self.mutation_events
        )
        if events:
            response = self._resolve_event(events.pop(0))
            if response is not None:
                try:
                    event_body = json.loads(response.body)
                except (TypeError, ValueError):
                    event_body = None
                if isinstance(event_body, dict):
                    reference = event_body.get("statementHandle") or event_body.get("statement_id")
                    if isinstance(reference, str):
                        self.last_handle = reference
                return response
        if isinstance(statement, str) and not observation:
            match = _STATE_RE.search(statement)
            if match is not None and ("SET TAG" in statement or "SET TBLPROPERTIES" in statement):
                self.state = match.group(1)
        response = self._success(observed=observation or poll, handle=self.last_handle)
        if self.after_response is not None:
            callback = self.after_response
            self.after_response = None
            callback()
        return response


def _lease(
    *,
    key_id: str = "credential-key-1",
    revision: int = 1,
    authorization: str = "Bearer super-secret-provider-token",
    revoked: bool = False,
) -> CredentialLease:
    return CredentialLease(
        authorization=authorization,
        key_id=key_id,
        key_revision=revision,
        authority_sha256=_CREDENTIAL_AUTHORITY_SHA256,
        expires_at=2_000.0,
        revoked=revoked,
    )


def _pending_response(provider: str, *, handle: str = "stmt-pending") -> ProviderHttpResponse:
    body: dict[str, Any]
    if provider == "snowflake":
        body = {"statementHandle": handle}
    else:
        body = {
            "statement_id": handle,
            "status": {"state": "RUNNING"},
        }
    return ProviderHttpResponse(
        202,
        {"content-type": "application/json"},
        json.dumps(body).encode("utf-8"),
    )


def _enroll(
    bindings: ProviderBindingStore,
    provider: str,
    *,
    tenant: str = TENANT,
    binding_id: str = "native-customers",
    expected_revision: int = 0,
    idempotency_key: str = "enroll-native-1",
    key_id: str = "credential-key-1",
    credential_revision: int = 1,
    origin: str | None = None,
    field_map: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    common = {
        "asset_id": "customers",
        "schema": "PUBLIC" if provider == "snowflake" else "default",
        "table": "CUSTOMERS" if provider == "snowflake" else "customers",
        "principal": "ANALYST_ROLE" if provider == "snowflake" else "analysts@example.com",
        "compute_id": "GOVERNANCE_WH" if provider == "snowflake" else "warehouse-1",
        "field_map": field_map
        or {
            "email": "EMAIL" if provider == "snowflake" else "email",
            "region": "REGION" if provider == "snowflake" else "region",
        },
        "mask_bindings": {
            "hash_sha256": (
                "GOV.POLICY.MASK_SHA256"
                if provider == "snowflake"
                else "governance.policy.mask_sha256"
            )
        },
        "row_filter_bindings": {
            _object_digest(_ROW_AST): (
                "GOV.POLICY.US_REGION" if provider == "snowflake" else "governance.policy.us_region"
            )
        },
        "catalog_snapshot_sha256": _digest(f"{provider}-catalog-snapshot"),
        "field_inventory_complete": True,
        "credential_key_id": key_id,
        "credential_revision": credential_revision,
        "credential_authority_sha256": _CREDENTIAL_AUTHORITY_SHA256,
        "expected_revision": expected_revision,
        "idempotency_key": idempotency_key,
    }
    if provider == "snowflake":
        return bindings.enroll_snowflake(
            tenant,
            binding_id,
            origin=origin or "https://acct1.snowflakecomputing.com",
            account_or_workspace_id="acct1",
            catalog="APP_DB",
            state_anchor="GOV.TAGS.DATA_USE_STATE",
            **common,
        )
    return bindings.enroll_databricks(
        tenant,
        binding_id,
        origin=origin or "https://adb-123.cloud.databricks.com",
        account_or_workspace_id="adb-123",
        catalog="main",
        **common,
    )


def _prepared(
    tmp_path: Path,
    provider: str,
    *,
    transport: MockProviderTransport | None = None,
    owner: CredentialOwner | None = None,
    config: Mapping[str, Any] | None = None,
    limits: ProviderLimits | None = None,
    sleeper: Callable[[float], None] | None = None,
) -> tuple[
    Any,
    dict[str, Any],
    ProviderBindingStore,
    CredentialOwner,
    MockProviderTransport,
]:
    counter = itertools.count(1)
    clock = Clock()
    authority = DataUseGovernanceStore(
        tmp_path / f"governance-{provider}.sqlite",
        clock=clock,
        id_factory=lambda prefix: f"{prefix}-{next(counter)}",
    )
    decision, _ = _compiled_decision(authority)
    bindings = ProviderBindingStore(tmp_path / f"bindings-{provider}.sqlite", clock=clock)
    _enroll(bindings, provider)
    owner = owner or CredentialOwner(_lease())
    transport = transport or MockProviderTransport(provider)
    adapter_class = (
        SnowflakeDataUseControlAdapter
        if provider == "snowflake"
        else DatabricksDataUseControlAdapter
    )
    adapter = adapter_class(
        tenant_id=TENANT,
        binding_id="native-customers",
        adapter_authority_sha256=_AUTHORITY_SHA256,
        binding_store=bindings,
        credential_owner=owner,
        transport=transport,
        config=config or _enabled(provider),
        limits=limits,
        clock=clock,
        sleeper=sleeper or (lambda _delay: None),
    )
    compiler = DataUsePolicyCompiler(
        authority,
        clock=clock,
        native_adapter=adapter,
    )
    ir = thaw_control_ir(
        compiler.compile(
            TENANT,
            str(decision["decision_id"]),
            expected_decision_sha256=str(decision["decision_sha256"]),
        )
    )
    return adapter, ir, bindings, owner, transport


def _rebind_ir(ir: dict[str, Any]) -> None:
    ir["bindings_sha256"] = _object_digest(ir["bindings"])
    for kind, state_key in (
        ("desired", "desired_state"),
        ("rollback", "rollback_state"),
    ):
        ir[f"{state_key}_sha256"] = _object_digest(
            {
                "kind": kind,
                "bindings_sha256": ir["bindings_sha256"],
                "controls": ir[state_key],
            }
        )
    ir_digest = _object_digest(
        {key: value for key, value in ir.items() if key not in {"compilation_id", "ir_sha256"}}
    )
    ir["ir_sha256"] = ir_digest
    ir["compilation_id"] = f"duc-{ir_digest[:40]}"


def test_provider_config_requires_all_four_literal_gates() -> None:
    assert provider_config_enabled("snowflake", {}) is False
    config = _enabled("snowflake")
    assert provider_config_enabled("snowflake", config) is True
    for path in ("enable", "compiler", "enforcement", "provider"):
        candidate = json.loads(json.dumps(config))
        root = candidate["data_use_governance"]
        if path == "enable":
            root["enable"] = 1
        elif path == "provider":
            root["snowflake"]["enable"] = False
        else:
            root[path]["enable"] = False
        assert provider_config_enabled("snowflake", candidate) is False
    invented_nested = {
        "data_use_governance": {
            "enable": True,
            "compiler": {"enable": True},
            "enforcement": {"enable": True},
            "providers": {"snowflake": {"enable": True}},
        }
    }
    assert provider_config_enabled("snowflake", invented_nested) is False
    direct_plus_nested = _enabled("snowflake")
    direct_plus_nested["data_use_governance"]["providers"] = {"snowflake": {"enable": True}}
    assert provider_config_enabled("snowflake", direct_plus_nested) is False
    assert provider_config_enabled("databricks", _enabled("databricks")) is True
    assert provider_config_enabled("unknown", config) is False


def test_native_provider_binding_and_adapter_share_canonical_tenant_identity(
    tmp_path: Path,
) -> None:
    decomposed = "Acme Cafe\u0301 Corp"
    canonical = "Acme Caf\u00e9 Corp"
    bindings = ProviderBindingStore(tmp_path / "canonical-bindings.sqlite", clock=Clock())
    enrolled = _enroll(bindings, "snowflake", tenant=decomposed)

    assert enrolled["tenant_id"] == canonical
    assert bindings.get_binding(canonical, "native-customers") == {
        **enrolled,
        "revoked": False,
    }
    assert bindings.get_binding("Other Corp", "native-customers") is None

    adapter = SnowflakeDataUseControlAdapter(
        tenant_id=decomposed,
        binding_id="native-customers",
        adapter_authority_sha256=_AUTHORITY_SHA256,
        binding_store=bindings,
        credential_owner=CredentialOwner(_lease()),
        transport=MockProviderTransport("snowflake"),
        config=_enabled("snowflake"),
        clock=Clock(),
    )
    assert adapter._tenant_id == canonical

    with pytest.raises(DataUseProviderValidationError, match="opaque identifier"):
        bindings.get_binding(canonical, "native customers")


def test_binding_enrollment_rejects_origins_injection_rebinding_and_stale_cas(
    tmp_path: Path,
) -> None:
    bindings = ProviderBindingStore(tmp_path / "bindings.sqlite", clock=Clock())
    first = _enroll(bindings, "snowflake")
    assert first == _enroll(bindings, "snowflake")
    assert "credential_key_id" not in first
    assert bindings.get_binding("tenant-beta", "native-customers") is None
    with pytest.raises(DataUseProviderConflict, match="another provider"):
        _enroll(
            bindings,
            "databricks",
            expected_revision=1,
            idempotency_key="cross-provider",
        )
    with pytest.raises(DataUseProviderConflict, match="revision"):
        _enroll(
            bindings,
            "snowflake",
            expected_revision=0,
            idempotency_key="stale-cas",
        )
    for origin in (
        "http://acct1.snowflakecomputing.com",
        "https://acct1.snowflakecomputing.com.evil.test",
        "https://user@acct1.snowflakecomputing.com",
        "https://acct1.snowflakecomputing.com/path",
    ):
        with pytest.raises(DataUseProviderValidationError, match="HTTPS origin"):
            _enroll(
                ProviderBindingStore(tmp_path / f"bad-{hash(origin)}.sqlite"),
                "snowflake",
                origin=origin,
            )
    with pytest.raises(DataUseProviderValidationError):
        _enroll(
            ProviderBindingStore(tmp_path / "inject.sqlite"),
            "snowflake",
            field_map={"email": "EMAIL; DROP TABLE USERS", "region": "REGION"},
        )


def test_binding_listing_and_permanent_revocation_are_tenant_scoped_and_idempotent(
    tmp_path: Path,
) -> None:
    bindings = ProviderBindingStore(tmp_path / "binding-revocation.sqlite", clock=Clock())
    enrolled = _enroll(bindings, "snowflake")
    assert bindings.list_bindings(TENANT, provider_id="snowflake") == [
        {**enrolled, "revoked": False}
    ]
    assert bindings.list_bindings("tenant-beta") == []

    revoked = bindings.revoke_binding(
        TENANT,
        "native-customers",
        expected_revision=1,
        reason_sha256=_digest("binding retired by data owner"),
        idempotency_key="revoke-native-customers-1",
    )
    assert revoked["revoked"] is True
    assert revoked == bindings.revoke_binding(
        TENANT,
        "native-customers",
        expected_revision=1,
        reason_sha256=_digest("binding retired by data owner"),
        idempotency_key="revoke-native-customers-1",
    )
    stored = bindings.get_binding(TENANT, "native-customers")
    assert stored is not None and stored["revoked"] is True
    assert "binding retired" not in json.dumps(stored)
    with pytest.raises(DataUseProviderConflict, match="revoked"):
        _enroll(
            bindings,
            "snowflake",
            expected_revision=1,
            idempotency_key="rotate-after-revocation",
            credential_revision=2,
        )
    with pytest.raises(DataUseProviderConflict, match="already revoked"):
        bindings.revoke_binding(
            TENANT,
            "native-customers",
            expected_revision=1,
            reason_sha256=_digest("second reason"),
            idempotency_key="second-revocation",
        )


def test_revoked_binding_disables_adapter_before_secret_or_transport_use(
    tmp_path: Path,
) -> None:
    adapter, _ir, bindings, owner, transport = _prepared(tmp_path, "snowflake")
    before_secret_calls = len(owner.calls)
    bindings.revoke_binding(
        TENANT,
        "native-customers",
        expected_revision=1,
        reason_sha256=_digest("scope decommissioned"),
        idempotency_key="revoke-before-write",
    )
    assert adapter.provider_writes_possible is False
    assert len(owner.calls) == before_secret_calls
    assert transport.calls == []


@pytest.mark.parametrize("provider", ["snowflake", "databricks"])
def test_native_apply_is_exact_origin_reconciled_and_credential_free(
    tmp_path: Path, provider: str
) -> None:
    adapter, ir, bindings, _owner, transport = _prepared(tmp_path, provider)
    operation_idempotency_sha256 = _digest(f"{provider}-apply")
    result = adapter.apply_control_ir(ir, idempotency_sha256=operation_idempotency_sha256)
    assert result["reconciliation"] == "converged"
    assert result["observed_after_sha256"] == ir["desired_state_sha256"]
    assert result["provider_writes_possible"] is True
    assert result["live_provider_acceptance_verified"] is False
    assert result["credential_material_recorded"] is False
    serialized = json.dumps(result, sort_keys=True)
    assert "super-secret-provider-token" not in serialized
    assert "credential-key-1" not in serialized
    assert all(call["allow_redirects"] is False for call in transport.calls)
    expected_origin = (
        "https://acct1.snowflakecomputing.com"
        if provider == "snowflake"
        else "https://adb-123.cloud.databricks.com"
    )
    assert all(call["url"].startswith(expected_origin + "/api/") for call in transport.calls)
    assert any("MASK" in statement for statement in transport.statements)
    assert any("ROW " in statement for statement in transport.statements)
    assert not any(";" in statement or "--" in statement for statement in transport.statements)
    correlation_sha256 = operation_correlation_sha256(
        provider_id=provider,
        binding_sha256=result["binding_sha256"],
        operation_idempotency_sha256=operation_idempotency_sha256,
        operation_request_sha256=result["request_sha256"],
    )
    mutation_calls = [
        call for call in transport.calls if call["method"] == "POST" and not call["observation"]
    ]
    observation_calls = [call for call in transport.calls if call["observation"]]
    assert mutation_calls
    binding = bindings.get_binding(TENANT, "native-customers")
    assert binding is not None
    object_sha256 = _object_digest(
        {
            key: binding[key]
            for key in (
                "provider_id",
                "account_or_workspace_id",
                "catalog",
                "schema_name",
                "table",
            )
        }
    )
    if provider == "snowflake":
        parsed_tags = [
            call["body"]["parameters"]["query_tag"].split(":") for call in mutation_calls
        ]
        assert all(len(tag) == 6 and tag[0] == "lw2" for tag in parsed_tags)
        assert {tag[1] for tag in parsed_tags} == {correlation_sha256}
        assert {tag[2] for tag in parsed_tags} <= {
            "grant",
            "masking_policy",
            "revoke",
            "row_filter",
            "state_anchor",
        }
        assert all(re.fullmatch(r"[0-9a-f]{64}", tag[3]) for tag in parsed_tags)
        assert {tag[4] for tag in parsed_tags} == {object_sha256}
        assert sum(tag[5] == ir["desired_state_sha256"] for tag in parsed_tags) == 1
        assert all(tag[5] == "-" or tag[2] == "state_anchor" for tag in parsed_tags)
        assert all("parameters" not in call["body"] for call in observation_calls)
    else:
        parsed_tags = [
            {item["key"]: item["value"] for item in call["body"]["query_tags"]}
            for call in mutation_calls
        ]
        assert all(
            set(tag) == {"lw_corr", "lw_kind", "lw_ctrl", "lw_obj", "lw_state"}
            for tag in parsed_tags
        )
        assert {tag["lw_corr"] for tag in parsed_tags} == {correlation_sha256}
        assert {tag["lw_obj"] for tag in parsed_tags} == {object_sha256}
        assert all(re.fullmatch(r"[0-9a-f]{64}", tag["lw_ctrl"]) for tag in parsed_tags)
        assert sum(tag["lw_state"] == ir["desired_state_sha256"] for tag in parsed_tags) == 1
        assert all(
            tag["lw_state"] == "-" or tag["lw_kind"] == "state_anchor" for tag in parsed_tags
        )
        assert all("query_tags" not in call["body"] for call in observation_calls)
    mutation_receipts = [
        receipt
        for receipt in result["http_receipts"]
        if isinstance(receipt, dict)
        and isinstance(receipt.get("request"), dict)
        and receipt["request"].get("safe_read") is False
        and isinstance(receipt.get("response"), dict)
    ]
    assert mutation_receipts
    assert all(
        re.fullmatch(
            r"[0-9a-f]{64}",
            str(receipt["response"].get("provider_statement_sha256")),
        )
        for receipt in mutation_receipts
    )
    assert len(
        {receipt["response"]["provider_statement_sha256"] for receipt in mutation_receipts}
    ) == len(mutation_receipts)
    assert result["http_receipts_sha256"] == _object_digest(result["http_receipts"])
    stored = (tmp_path / f"bindings-{provider}.sqlite").read_bytes()
    assert b"super-secret-provider-token" not in stored
    assert b"credential-key-1" not in stored
    assert b"stmt-" not in stored
    assert "stmt-" not in serialized
    operation = bindings.get_operation(
        tenant_id=TENANT,
        provider_id=provider,
        binding_id="native-customers",
        idempotency_sha256=_digest(f"{provider}-apply"),
    )
    assert operation is not None and operation["status"] == "complete"


@pytest.mark.parametrize("timeout", [0, 1, 4, 51, 60])
def test_databricks_rejects_http_timeout_without_polling_margin(
    tmp_path: Path, timeout: int
) -> None:
    with pytest.raises(DataUseProviderConfigError):
        _prepared(
            tmp_path,
            "databricks",
            limits=ProviderLimits(timeout_seconds=timeout),
        )


@pytest.mark.parametrize("timeout", [5, 50])
def test_databricks_uses_immediate_statement_return_and_bounded_polling(
    tmp_path: Path, timeout: int
) -> None:
    adapter, ir, _bindings, _owner, transport = _prepared(
        tmp_path,
        "databricks",
        limits=ProviderLimits(timeout_seconds=timeout),
    )

    adapter.apply_control_ir(ir, idempotency_sha256=_digest(f"databricks-wait-{timeout}"))

    statement_calls = [call for call in transport.calls if call["method"] == "POST"]
    assert statement_calls
    assert all(call["body"]["wait_timeout"] == "0s" for call in statement_calls)
    assert all(call["timeout"] == timeout for call in statement_calls)


@pytest.mark.parametrize("provider", ["snowflake", "databricks"])
def test_no_change_acceptance_and_idempotent_replay(tmp_path: Path, provider: str) -> None:
    adapter, ir, _bindings, _owner, transport = _prepared(tmp_path, provider)
    transport.state = ir["desired_state_sha256"]
    idem = _digest(f"{provider}-no-change")
    first = adapter.apply_control_ir(ir, idempotency_sha256=idem)
    call_count = len(transport.calls)
    second = adapter.apply_control_ir(ir, idempotency_sha256=idem)
    assert first == second
    assert first["no_change"] is True
    assert first["reconciliation"] == "no_change"
    assert len(transport.calls) == call_count == 1
    changed = json.loads(json.dumps(ir))
    changed["desired_state"][0]["control_id"] = "changed-control"
    _rebind_ir(changed)
    with pytest.raises(DataUseProviderConflict, match="rebound"):
        adapter.apply_control_ir(changed, idempotency_sha256=idem)


@pytest.mark.parametrize("provider", ["snowflake", "databricks"])
def test_rollback_is_compiled_safe_deny_and_does_not_claim_restoration(
    tmp_path: Path, provider: str
) -> None:
    adapter, ir, _bindings, _owner, transport = _prepared(tmp_path, provider)
    result = adapter.rollback_control_ir(ir, idempotency_sha256=_digest(f"{provider}-rollback"))
    assert result["operation"] == "rollback"
    assert result["rollback_mode"] == "compiled_safe_deny"
    assert result["restored_prior_native_state"] is False
    assert result["target_state_sha256"] == ir["rollback_state_sha256"]
    assert any(statement.startswith("REVOKE SELECT") for statement in transport.statements)


def test_thawed_digest_verified_ir_and_closed_filter_contract(tmp_path: Path) -> None:
    adapter, ir, _bindings, _owner, _transport = _prepared(tmp_path, "snowflake")
    with pytest.raises(DataUseProviderValidationError, match="thawed"):
        adapter.apply_control_ir(
            MappingProxyType(ir),  # type: ignore[arg-type]
            idempotency_sha256=_digest("immutable-ir"),
        )
    bad = json.loads(json.dumps(ir))
    row_control = next(item for item in bad["desired_state"] if item["operation"] == "row_filter")
    row_control["parameters"]["ast"] = {
        "function": "sql",
        "args": [{"field": "region"}],
    }
    _rebind_ir(bad)
    with pytest.raises(DataUseProviderValidationError, match="function"):
        adapter.apply_control_ir(bad, idempotency_sha256=_digest("unknown-function"))
    injected = json.loads(json.dumps(ir))
    row_control = next(
        item for item in injected["desired_state"] if item["operation"] == "row_filter"
    )
    row_control["parameters"]["ast"]["value"] = "US' OR 1=1 --"
    _rebind_ir(injected)
    with pytest.raises(DataUseProviderValidationError, match="prohibited"):
        adapter.apply_control_ir(injected, idempotency_sha256=_digest("raw-sql"))
    crossed = json.loads(json.dumps(ir))
    crossed["tenant_id"] = "tenant-beta"
    _rebind_ir(crossed)
    with pytest.raises(DataUseProviderConflict, match="tenant"):
        adapter.apply_control_ir(crossed, idempotency_sha256=_digest("cross-tenant-ir"))
    corrupt = json.loads(json.dumps(ir))
    corrupt["desired_state"][0]["operation"] = "allow"
    with pytest.raises(DataUseProviderValidationError, match="digest"):
        adapter.apply_control_ir(corrupt, idempotency_sha256=_digest("corrupt-ir"))
    missing_context = json.loads(json.dumps(ir))
    missing_context["bindings"]["contexts"].pop()
    _rebind_ir(missing_context)
    with pytest.raises(DataUseProviderValidationError, match="all four"):
        adapter.apply_control_ir(
            missing_context,
            idempotency_sha256=_digest("missing-compiler-context"),
        )
    wrong_compiler = json.loads(json.dumps(ir))
    wrong_compiler["compiler"]["version"] = "attacker-compiler/1"
    _rebind_ir(wrong_compiler)
    with pytest.raises(DataUseProviderConflict, match="compiler binding"):
        adapter.apply_control_ir(
            wrong_compiler,
            idempotency_sha256=_digest("wrong-compiler"),
        )
    source_rebound = json.loads(json.dumps(ir))
    source_rebound["desired_state"][0]["source"]["policy_sha256"] = "0" * 64
    _rebind_ir(source_rebound)
    with pytest.raises(DataUseProviderConflict, match="policy binding"):
        adapter.apply_control_ir(
            source_rebound,
            idempotency_sha256=_digest("rebound-policy-source"),
        )


def test_credential_rotation_revocation_and_non_disclosure(tmp_path: Path) -> None:
    owner = CredentialOwner(_lease())
    adapter, ir, bindings, _owner, transport = _prepared(tmp_path, "snowflake", owner=owner)
    owner.current = _lease(key_id="credential-key-2", revision=2)
    assert adapter.provider_writes_possible is False
    with pytest.raises(DataUseProviderConfigError, match="fully controlled"):
        adapter.apply_control_ir(ir, idempotency_sha256=_digest("stale-key"))
    _enroll(
        bindings,
        "snowflake",
        expected_revision=1,
        idempotency_key="rotate-key",
        key_id="credential-key-2",
        credential_revision=2,
    )
    assert adapter.provider_writes_possible is True
    result = adapter.apply_control_ir(ir, idempotency_sha256=_digest("rotated-key"))
    assert result["reconciliation"] == "converged"
    owner.current = _lease(key_id="credential-key-2", revision=2, revoked=True)
    assert adapter.provider_writes_possible is False
    with pytest.raises(DataUseProviderConfigError):
        adapter.apply_control_ir(ir, idempotency_sha256=_digest("revoked-key"))
    serialized = json.dumps(result)
    database = (tmp_path / "bindings-snowflake.sqlite").read_bytes()
    for forbidden in (
        b"super-secret-provider-token",
        b"credential-key-1",
        b"credential-key-2",
    ):
        assert forbidden not in database
        assert forbidden.decode() not in serialized
    assert transport.calls


def test_binding_change_during_reconciliation_is_rejected_before_mutation(
    tmp_path: Path,
) -> None:
    transport = MockProviderTransport("snowflake")
    adapter, ir, bindings, _owner, transport = _prepared(tmp_path, "snowflake", transport=transport)

    def rotate_binding() -> None:
        _enroll(
            bindings,
            "snowflake",
            expected_revision=1,
            idempotency_key="concurrent-binding-rotation",
        )

    transport.after_response = rotate_binding
    idem = _digest("stale-binding")
    with pytest.raises(DataUseProviderConflict, match="changed during"):
        adapter.apply_control_ir(ir, idempotency_sha256=idem)
    assert all(call["observation"] for call in transport.calls)
    operation = bindings.get_operation(
        tenant_id=TENANT,
        provider_id="snowflake",
        binding_id="native-customers",
        idempotency_sha256=idem,
    )
    assert operation is not None and operation["status"] == "failed_no_effect"


def test_safe_retry_timeout_and_ambiguous_mutation_are_distinct(tmp_path: Path) -> None:
    limits = ProviderLimits(
        timeout_seconds=0.5,
        max_response_bytes=2048,
        max_attempts=2,
        max_polls=2,
    )
    transport = MockProviderTransport("snowflake")
    transport.mutation_events.append(DataUseProviderRequestNotSent("not sent"))
    adapter, ir, _bindings, _owner, transport = _prepared(
        tmp_path, "snowflake", transport=transport, limits=limits
    )
    result = adapter.apply_control_ir(ir, idempotency_sha256=_digest("safe-retry"))
    assert result["reconciliation"] == "converged"
    assert all(call["timeout"] == 0.5 for call in transport.calls)
    assert all(call["max_response_bytes"] == 2048 for call in transport.calls)
    mutation_calls = [
        call for call in transport.calls if call["method"] == "POST" and not call["observation"]
    ]
    assert len(mutation_calls) >= 2
    first_attempt, retry_attempt = mutation_calls[:2]
    assert first_attempt["body"] == retry_attempt["body"]
    assert "&retry=true" not in first_attempt["url"]
    assert retry_attempt["url"] == f"{first_attempt['url']}&retry=true"

    never_sent = MockProviderTransport("snowflake")
    never_sent.mutation_events.extend(
        [
            DataUseProviderRequestNotSent("not sent"),
            DataUseProviderRequestNotSent("not sent"),
        ]
    )
    adapter, ir, bindings, _owner, never_sent = _prepared(
        tmp_path / "never-sent",
        "snowflake",
        transport=never_sent,
        limits=limits,
    )
    idem = _digest("proved-not-sent")
    with pytest.raises(DataUseProviderUnavailable, match="no mutation"):
        adapter.apply_control_ir(ir, idempotency_sha256=idem)
    operation = bindings.get_operation(
        tenant_id=TENANT,
        provider_id="snowflake",
        binding_id="native-customers",
        idempotency_sha256=idem,
    )
    assert operation is not None and operation["status"] == "failed_no_effect"
    assert adapter.apply_control_ir(ir, idempotency_sha256=idem)["reconciliation"] == "converged"

    ambiguous_transport = MockProviderTransport("snowflake")
    ambiguous_transport.mutation_events.append(
        DataUseProviderTransportAmbiguous("secret upstream detail")
    )
    adapter, ir, bindings, _owner, ambiguous_transport = _prepared(
        tmp_path / "ambiguous",
        "snowflake",
        transport=ambiguous_transport,
        limits=limits,
    )
    idem = _digest("ambiguous")
    with pytest.raises(DataUseProviderAmbiguousEffect, match="manual reconciliation"):
        adapter.apply_control_ir(ir, idempotency_sha256=idem)
    assert sum(not call["observation"] for call in ambiguous_transport.calls) == 1
    operation = bindings.get_operation(
        tenant_id=TENANT,
        provider_id="snowflake",
        binding_id="native-customers",
        idempotency_sha256=idem,
    )
    assert operation is not None and operation["status"] == "ambiguous"
    with pytest.raises(DataUseProviderAmbiguousEffect, match="reconcile manually"):
        adapter.apply_control_ir(ir, idempotency_sha256=idem)


def test_only_documented_snowflake_request_retry_resubmits_after_response(
    tmp_path: Path,
) -> None:
    safe = MockProviderTransport("snowflake")
    safe.mutation_events.append(
        ProviderHttpResponse(
            503,
            {"content-type": "application/json"},
            b'{"error_code":"temporarily_unavailable"}',
        )
    )
    adapter, ir, _bindings, _owner, safe = _prepared(tmp_path / "safe", "snowflake", transport=safe)
    assert (
        adapter.apply_control_ir(ir, idempotency_sha256=_digest("explicit-retry"))["reconciliation"]
        == "converged"
    )
    snowflake_retries = [
        call for call in safe.calls if call["method"] == "POST" and not call["observation"]
    ][:2]
    assert len(snowflake_retries) == 2
    assert snowflake_retries[1]["url"] == f"{snowflake_retries[0]['url']}&retry=true"

    unsafe = MockProviderTransport("databricks")
    unsafe.mutation_events.append(
        ProviderHttpResponse(
            503,
            {"content-type": "application/json"},
            b'{"accepted":false,"retryable":true}',
        )
    )
    adapter, ir, _bindings, _owner, unsafe = _prepared(
        tmp_path / "unsafe", "databricks", transport=unsafe
    )
    with pytest.raises(DataUseProviderAmbiguousEffect):
        adapter.apply_control_ir(ir, idempotency_sha256=_digest("unproved-outage"))
    assert sum(not call["observation"] for call in unsafe.calls) == 1


@pytest.mark.parametrize("provider", ["snowflake", "databricks"])
def test_async_provider_acceptance_uses_bounded_status_polling(
    tmp_path: Path, provider: str
) -> None:
    transport = MockProviderTransport(provider)
    transport.mutation_events.append(_pending_response(provider))
    delays: list[float] = []
    adapter, ir, _bindings, _owner, transport = _prepared(
        tmp_path,
        provider,
        transport=transport,
        limits=ProviderLimits(max_polls=2),
        sleeper=delays.append,
    )
    result = adapter.apply_control_ir(ir, idempotency_sha256=_digest(f"{provider}-async"))
    assert result["reconciliation"] == "converged"
    polls = [call for call in transport.calls if call["poll"]]
    assert len(polls) == 1
    assert delays == [0.25]
    assert polls[0]["method"] == "GET"
    assert polls[0]["url"].endswith("/statements/stmt-pending")
    serialized = json.dumps(result, sort_keys=True)
    assert "stmt-pending" not in serialized
    assert "stmt-ok" not in serialized
    statement_digests = {
        receipt["response"].get("provider_statement_sha256")
        for receipt in result["http_receipts"]
        if isinstance(receipt, dict) and isinstance(receipt.get("response"), dict)
    }
    assert hashlib.sha256(b"stmt-pending").hexdigest() in statement_digests


def test_async_poll_bound_is_ambiguous_and_not_resubmitted(tmp_path: Path) -> None:
    transport = MockProviderTransport("snowflake")
    transport.mutation_events.append(_pending_response("snowflake"))
    transport.poll_events.extend([_pending_response("snowflake"), _pending_response("snowflake")])
    delays: list[float] = []
    adapter, ir, bindings, _owner, transport = _prepared(
        tmp_path,
        "snowflake",
        transport=transport,
        limits=ProviderLimits(max_attempts=1, max_polls=2),
        sleeper=delays.append,
    )
    idem = _digest("poll-bound")
    with pytest.raises(DataUseProviderAmbiguousEffect, match="manual reconciliation"):
        adapter.apply_control_ir(ir, idempotency_sha256=idem)
    assert len([call for call in transport.calls if call["poll"]]) == 2
    assert (
        len([call for call in transport.calls if not call["observation"] and not call["poll"]]) == 1
    )
    assert delays == [0.25, 0.5]
    operation = bindings.get_operation(
        tenant_id=TENANT,
        provider_id="snowflake",
        binding_id="native-customers",
        idempotency_sha256=idem,
    )
    assert operation is not None and operation["status"] == "ambiguous"


@pytest.mark.parametrize("provider", ["snowflake", "databricks"])
def test_async_poll_rejects_changed_statement_identity(tmp_path: Path, provider: str) -> None:
    transport = MockProviderTransport(provider)
    transport.mutation_events.append(_pending_response(provider, handle="stmt-original"))
    transport.poll_events.append(_pending_response(provider, handle="stmt-substituted"))
    adapter, ir, _bindings, _owner, _transport = _prepared(
        tmp_path,
        provider,
        transport=transport,
        limits=ProviderLimits(max_attempts=1, max_polls=2),
    )

    with pytest.raises(DataUseProviderAmbiguousEffect):
        adapter.apply_control_ir(ir, idempotency_sha256=_digest(f"{provider}-handle-drift"))

    assert len([call for call in transport.calls if call["poll"]]) == 1
    assert (
        len([call for call in transport.calls if not call["observation"] and not call["poll"]]) == 1
    )


@pytest.mark.parametrize("provider", ["snowflake", "databricks"])
def test_mutation_success_without_statement_identity_is_ambiguous(
    tmp_path: Path, provider: str
) -> None:
    body = (
        {"data": []}
        if provider == "snowflake"
        else {"status": {"state": "SUCCEEDED"}, "result": {"data_array": []}}
    )
    transport = MockProviderTransport(provider)
    transport.mutation_events.append(
        ProviderHttpResponse(
            200,
            {"content-type": "application/json"},
            json.dumps(body).encode(),
        )
    )
    adapter, ir, _bindings, _owner, _transport = _prepared(
        tmp_path,
        provider,
        transport=transport,
        limits=ProviderLimits(max_attempts=1),
    )

    with pytest.raises(DataUseProviderAmbiguousEffect):
        adapter.apply_control_ir(ir, idempotency_sha256=_digest(f"{provider}-missing-handle"))


def test_bounded_response_and_post_mutation_reconciliation_fail_closed(
    tmp_path: Path,
) -> None:
    oversized = MockProviderTransport("snowflake")
    oversized.read_events.append(
        ProviderHttpResponse(
            200,
            {"content-type": "application/json"},
            b"x" * 2049,
        )
    )
    adapter, ir, bindings, _owner, _transport = _prepared(
        tmp_path / "oversized",
        "snowflake",
        transport=oversized,
        limits=ProviderLimits(max_response_bytes=2048, max_attempts=1),
    )
    idem = _digest("oversized")
    with pytest.raises(DataUseProviderProtocolError, match="byte bound"):
        adapter.apply_control_ir(ir, idempotency_sha256=idem)
    operation = bindings.get_operation(
        tenant_id=TENANT,
        provider_id="snowflake",
        binding_id="native-customers",
        idempotency_sha256=idem,
    )
    assert operation is not None and operation["status"] == "failed_no_effect"

    outage = MockProviderTransport("databricks")
    outage.read_events.extend([None, DataUseProviderTransportAmbiguous("post-write timeout")])
    adapter, ir, bindings, _owner, _transport = _prepared(
        tmp_path / "post-write",
        "databricks",
        transport=outage,
        limits=ProviderLimits(max_attempts=1),
    )
    idem = _digest("post-write-outage")
    with pytest.raises(DataUseProviderAmbiguousEffect, match="unavailable"):
        adapter.apply_control_ir(ir, idempotency_sha256=idem)
    operation = bindings.get_operation(
        tenant_id=TENANT,
        provider_id="databricks",
        binding_id="native-customers",
        idempotency_sha256=idem,
    )
    assert operation is not None and operation["status"] == "ambiguous"
    assert operation["evidence"]["completed_statements"] > 0


def test_binding_corruption_and_cross_tenant_operation_reads_fail_closed(
    tmp_path: Path,
) -> None:
    bindings = ProviderBindingStore(tmp_path / "corrupt.sqlite", clock=Clock())
    _enroll(bindings, "snowflake")
    with sqlite3.connect(bindings.path) as conn:
        conn.execute(
            "UPDATE data_use_provider_bindings SET binding_sha256 = ?",
            ("0" * 64,),
        )
        conn.commit()
    with pytest.raises(Exception, match="digest"):
        bindings.get_binding(TENANT, "native-customers")
    assert (
        bindings.get_operation(
            tenant_id="tenant-beta",
            provider_id="snowflake",
            binding_id="native-customers",
            idempotency_sha256=_digest("missing"),
        )
        is None
    )


def test_default_off_and_revoked_adapters_do_not_expose_writes(tmp_path: Path) -> None:
    bindings = ProviderBindingStore(tmp_path / "off.sqlite", clock=Clock())
    _enroll(bindings, "snowflake")
    transport = MockProviderTransport("snowflake")
    off = SnowflakeDataUseControlAdapter(
        tenant_id=TENANT,
        binding_id="native-customers",
        adapter_authority_sha256=_AUTHORITY_SHA256,
        binding_store=bindings,
        credential_owner=CredentialOwner(_lease()),
        transport=transport,
        config={},
        clock=Clock(),
    )
    assert off.provider_writes_possible is False
    assert off.supported_effects == frozenset()
    assert off.status()["default_mode"] == "off"
    revoked = SnowflakeDataUseControlAdapter(
        tenant_id=TENANT,
        binding_id="native-customers",
        adapter_authority_sha256=_AUTHORITY_SHA256,
        binding_store=bindings,
        credential_owner=CredentialOwner(_lease(revoked=True)),
        transport=transport,
        config=_enabled("snowflake"),
        clock=Clock(),
    )
    assert revoked.provider_writes_possible is False
    assert revoked.supported_effects == frozenset()
    assert revoked.status()["provider_writes_possible"] is False
    with pytest.raises(DataUseProviderCredentialError):
        revoked._lease(bindings.get_binding(TENANT, "native-customers") or {})


def test_provider_limits_are_bounded() -> None:
    with pytest.raises(DataUseProviderConfigError):
        ProviderLimits(timeout_seconds=0.0)
    with pytest.raises(DataUseProviderConfigError):
        ProviderLimits(max_response_bytes=1024 * 1024)
    with pytest.raises(DataUseProviderConfigError):
        ProviderLimits(max_attempts=10)
