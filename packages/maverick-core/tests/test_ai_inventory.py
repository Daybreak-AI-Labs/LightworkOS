"""Protocol and reconciliation tests for external AI-estate discovery."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import pytest
from maverick import ai_inventory as inventory
from maverick import model_risk_assurance as mra
from maverick.paths import tenant_scope


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_SECURE_DEFAULT", "0")
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    monkeypatch.setenv("AZURE_AI_FOUNDRY_TOKEN", "azure-test-token")
    monkeypatch.setenv("VERTEX_ACCESS_TOKEN", "vertex-test-token")
    monkeypatch.setenv("DATABRICKS_TOKEN", "databricks-test-token")
    monkeypatch.setenv("COPILOT_STUDIO_TOKEN", "copilot-test-token")
    monkeypatch.setenv("DATABRICKS_HOST", "https://workspace.example.databricks.com")
    monkeypatch.setenv("VERTEX_PROJECT", "test-project")
    monkeypatch.setenv("VERTEX_LOCATION", "us-central1")
    monkeypatch.setenv("COPILOT_STUDIO_DATAVERSE_URL", "https://org.crm.dynamics.com")
    (tmp_path / "config.toml").write_text(
        "[governed_records]\n"
        'backend = "local"\n'
        "\n[evidence_graph]\n"
        "enable = true\n"
        "\n[model_risk_assurance]\n"
        "enable = true\n"
        "gate_promotions = true\n"
        "\n[ai_inventory]\n"
        "enable = true\n"
        'connectors = ["bedrock", "azure_ai_foundry", "vertex_ai", '
        '"databricks_unity_catalog", "copilot_studio"]\n'
        "page_cap = 20\n"
        "record_cap = 100\n"
        "retry_attempts = 3\n"
        "timeout_seconds = 5\n"
        "missing_grace_runs = 2\n",
        encoding="utf-8",
    )
    from maverick import audit, config

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    config.reset_config_cache()
    yield
    config.reset_config_cache()


@dataclass
class _Response:
    payload: Any
    status_code: int = 200
    headers: dict[str, str] | None = None

    def __post_init__(self):
        self.headers = dict(self.headers or {})

    def json(self):
        return self.payload


class _Transport:
    def __init__(self, handler):
        self.handler = handler
        self.calls: list[dict[str, Any]] = []

    def get(self, url, *, headers, params, timeout):
        call = {
            "url": url,
            "headers": dict(headers),
            "params": dict(params or {}),
            "timeout": timeout,
        }
        self.calls.append(call)
        return self.handler(call)


class _BedrockControl:
    def __init__(self):
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def list_custom_models(self, **kwargs):
        self.calls.append(("custom", kwargs))
        now = datetime(2026, 8, 1, tzinfo=timezone.utc)
        if kwargs.get("nextToken") == "custom-2":
            return {
                "modelSummaries": [
                    {
                        "modelArn": "arn:aws:bedrock:us-east-1:123:custom-model/two",
                        "modelName": "Custom Two",
                        "baseModelArn": "arn:aws:bedrock::foundation-model/base-two",
                        "creationTime": now,
                    }
                ]
            }
        return {
            "modelSummaries": [
                {
                    "modelArn": "arn:aws:bedrock:us-east-1:123:custom-model/one",
                    "modelName": "Custom One",
                    "baseModelArn": "arn:aws:bedrock::foundation-model/base-one",
                    "creationTime": now,
                }
            ],
            "nextToken": "custom-2",
        }

    def list_imported_models(self, **kwargs):
        self.calls.append(("imported", kwargs))
        return {
            "modelSummaries": [
                {
                    "modelArn": "arn:aws:bedrock:us-east-1:123:imported-model/one",
                    "modelName": "Imported One",
                    "modelArchitecture": "llama",
                    "creationTime": "2026-08-02T00:00:00Z",
                }
            ]
        }

    def list_provisioned_model_throughputs(self, **kwargs):
        self.calls.append(("provisioned", kwargs))
        return {
            "provisionedModelSummaries": [
                {
                    "provisionedModelArn": "arn:aws:bedrock:us-east-1:123:provisioned-model/p1",
                    "provisionedModelName": "Production Throughput",
                    "modelArn": "arn:aws:bedrock:us-east-1:123:custom-model/one",
                    "status": "InService",
                    "lastModifiedTime": "2026-08-03T00:00:00Z",
                }
            ]
        }

    def list_tags_for_resource(self, **kwargs):
        self.calls.append(("tags", kwargs))
        return {"tags": {"owner": "ai-platform@example.com"}}


class _BedrockAgent:
    def __init__(self):
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def list_agents(self, **kwargs):
        self.calls.append(("agents", kwargs))
        return {
            "agentSummaries": [
                {
                    "agentId": "AGENT123",
                    "agentName": "Claims Agent",
                    "latestAgentVersion": "7",
                    "updatedAt": "2026-08-04T00:00:00Z",
                }
            ]
        }

    def get_agent(self, **kwargs):
        self.calls.append(("get_agent", kwargs))
        return {
            "agent": {
                "agentId": kwargs["agentId"],
                "agentArn": "arn:aws:bedrock:us-east-1:123:agent/AGENT123",
                "foundationModel": "anthropic.claude",
            }
        }

    def list_tags_for_resource(self, **kwargs):
        self.calls.append(("tags", kwargs))
        return {"tags": {"owner": "claims@example.com"}}


def _limits(**overrides):
    values = {"page_cap": 20, "record_cap": 100, "retry_attempts": 3}
    values.update(overrides)
    return inventory.DiscoveryLimits(**values)


def test_bedrock_uses_all_customer_owned_list_operations_and_full_pagination():
    control = _BedrockControl()
    agent = _BedrockAgent()
    adapter = inventory.BedrockInventoryAdapter(
        control_client=control,
        agent_client=agent,
        region="us-east-1",
        limits=_limits(),
        sleep=lambda _delay: None,
        clock=lambda: 1_780_000_000.0,
    )

    result = adapter.discover()

    assert len(result.assets) == 5
    assert result.pages == 5
    assert [name for name, _ in control.calls if name != "tags"] == [
        "custom",
        "custom",
        "imported",
        "provisioned",
    ]
    assert [name for name, _ in agent.calls if name != "tags"] == ["agents", "get_agent"]
    assert all(asset.platform == "AWS Bedrock" for asset in result.assets)
    assert {asset.owner for asset in result.assets} == {
        "ai-platform@example.com",
        "claims@example.com",
    }
    assert not hasattr(control, "list_foundation_models")


def test_foundry_v1_agents_and_deployments_are_paginated_and_typed():
    def handler(call):
        if call["url"].endswith("/agents") and "after" not in call["params"]:
            return _Response(
                {
                    "data": [
                        {
                            "id": "agent-1",
                            "name": "Underwriting Agent",
                            "version": "4",
                            "updated_at": "2026-08-05T00:00:00Z",
                            "metadata": {"owner": "risk@example.com"},
                            "definition": {"kind": "prompt", "model": "gpt-5"},
                        }
                    ],
                    "has_more": True,
                    "last_id": "agent-1",
                }
            )
        if call["url"].endswith("/agents"):
            assert call["params"]["after"] == "agent-1"
            return _Response({"data": [], "has_more": False})
        if call["url"].endswith("/deployments"):
            return _Response(
                {
                    "value": [
                        {
                            "id": "deployment-1",
                            "name": "gpt-prod",
                            "version": "2026-08-01",
                            "model": "gpt-5",
                            "systemData": {
                                "lastModifiedBy": "platform@example.com",
                                "lastModifiedAt": "2026-08-06T00:00:00Z",
                            },
                            "properties": {"provisioningState": "Succeeded"},
                        }
                    ]
                }
            )
        raise AssertionError(call)

    transport = _Transport(handler)
    adapter = inventory.AzureAIFoundryInventoryAdapter(
        endpoint="https://foundry.services.ai.azure.com/api/projects/project-one",
        transport=transport,
        limits=_limits(),
        sleep=lambda _delay: None,
    )

    result = adapter.discover()

    assert result.pages == 3
    assert [(asset.asset_type, asset.model) for asset in result.assets] == [
        ("agent", "gpt-5"),
        ("model", "gpt-5"),
    ]
    assert all(call["params"].get("api-version") == "v1" for call in transport.calls)
    assert result.assets[0].owner == "risk@example.com"


def test_vertex_lists_models_endpoints_and_reasoning_engines_with_tokens():
    def handler(call):
        if call["url"].endswith("/models"):
            if call["params"].get("pageToken") == "models-2":
                return _Response({"models": []})
            return _Response(
                {
                    "models": [
                        {
                            "name": "projects/p/locations/us-central1/models/123",
                            "displayName": "Fraud Model",
                            "artifactSha256": "a" * 64,
                            "updateTime": "2026-08-07T00:00:00Z",
                            "labels": {"owner": "fraud@example.com"},
                        }
                    ],
                    "nextPageToken": "models-2",
                }
            )
        if call["url"].endswith("/endpoints"):
            return _Response(
                {
                    "endpoints": [
                        {
                            "name": "projects/p/locations/us-central1/endpoints/456",
                            "displayName": "Fraud Endpoint",
                            "updateTime": "2026-08-08T00:00:00Z",
                            "deployedModels": [
                                {
                                    "id": "one",
                                    "model": "projects/p/locations/us-central1/models/123",
                                }
                            ],
                        }
                    ]
                }
            )
        if call["url"].endswith("/reasoningEngines"):
            return _Response(
                {
                    "reasoningEngines": [
                        {
                            "name": "projects/p/locations/us-central1/reasoningEngines/789",
                            "displayName": "Collections Agent",
                            "revisionId": "11",
                            "model": "gemini-2.5-pro",
                            "updateTime": "2026-08-09T00:00:00Z",
                        }
                    ]
                }
            )
        raise AssertionError(call)

    transport = _Transport(handler)
    result = inventory.VertexAIInventoryAdapter(
        project="p",
        location="us-central1",
        transport=transport,
        limits=_limits(),
        sleep=lambda _delay: None,
    ).discover()

    assert result.pages == 4
    assert [asset.metadata["resource_kind"] for asset in result.assets] == [
        "model",
        "endpoint",
        "reasoning_engine",
    ]
    assert result.assets[0].binding_strength == "exact_artifact"
    assert result.assets[0].version_digest == "a" * 64
    assert result.assets[1].dependencies == (
        "projects/p/locations/us-central1/models/123",
    )


def test_databricks_lists_registered_models_and_every_version_page():
    def handler(call):
        if call["url"].endswith("/api/2.1/unity-catalog/models"):
            return _Response(
                {
                    "registered_models": [
                        {
                            "full_name": "main.risk.fraud",
                            "name": "fraud",
                            "owner": "risk@example.com",
                            "updated_at": "1785715200000",
                        }
                    ]
                }
            )
        if call["params"].get("page_token") == "versions-2":
            return _Response(
                {
                    "model_versions": [
                        {
                            "version": "2",
                            "source": "dbfs:/models/fraud/2",
                            "created_at": 1_785_801_600_000,
                        }
                    ]
                }
            )
        return _Response(
            {
                "model_versions": [
                    {
                        "version": "1",
                        "source": "dbfs:/models/fraud/1",
                        "created_at": 1_785_715_200_000,
                    }
                ],
                "next_page_token": "versions-2",
            }
        )

    transport = _Transport(handler)
    result = inventory.DatabricksUnityCatalogInventoryAdapter(
        host="https://workspace.example.databricks.com",
        transport=transport,
        limits=_limits(),
        sleep=lambda _delay: None,
    ).discover()

    assert result.pages == 3
    assert len(result.assets) == 3
    assert result.assets[0].binding_strength == "observed_snapshot"
    assert [asset.metadata["version"] for asset in result.assets[1:]] == ["1", "2"]
    assert all(
        asset.binding_strength == "immutable_provider_revision" for asset in result.assets[1:]
    )


def test_copilot_studio_follows_same_origin_odata_nextlink_and_extracts_model():
    def handler(call):
        if "skiptoken=page2" in call["url"]:
            return _Response(
                {
                    "value": [
                        {
                            "botid": "bot-2",
                            "name": "Support Copilot",
                            "versionnumber": 10,
                            "modifiedon": "2026-08-11T00:00:00Z",
                            "_ownerid_value": "owner-guid",
                            "configuration": json.dumps({"modelId": "gpt-4.1"}),
                        }
                    ]
                }
            )
        return _Response(
            {
                "value": [
                    {
                        "botid": "bot-1",
                        "name": "Finance Copilot",
                        "versionnumber": 9,
                        "modifiedon": "2026-08-10T00:00:00Z",
                        "_ownerid_value@OData.Community.Display.V1.FormattedValue": (
                            "Finance Owner"
                        ),
                        "configuration": json.dumps({"settings": {"gptModel": "gpt-5"}}),
                    }
                ],
                "@odata.nextLink": (
                    "https://org.crm.dynamics.com/api/data/v9.2/bots?$skiptoken=page2"
                ),
            }
        )

    transport = _Transport(handler)
    result = inventory.CopilotStudioInventoryAdapter(
        dataverse_url="https://org.crm.dynamics.com",
        transport=transport,
        limits=_limits(),
        sleep=lambda _delay: None,
    ).discover()

    assert result.pages == 2
    assert [asset.model for asset in result.assets] == ["gpt-5", "gpt-4.1"]
    assert result.assets[0].owner == "Finance Owner"
    assert all(asset.asset_type == "agent" for asset in result.assets)


def test_http_retry_honors_retry_after_without_persisting_response_body():
    sleeps: list[float] = []
    responses = [
        _Response({"secret": "must-not-be-read"}, 429, {"Retry-After": "3"}),  # pragma: allowlist secret
        _Response({"value": []}),
    ]
    transport = _Transport(lambda _call: responses.pop(0))
    adapter = inventory.CopilotStudioInventoryAdapter(
        dataverse_url="https://org.crm.dynamics.com",
        transport=transport,
        limits=_limits(),
        sleep=sleeps.append,
    )

    assert adapter.discover().assets == ()
    assert sleeps == [3.0]
    assert len(transport.calls) == 2


def test_malformed_pages_cycles_and_record_caps_fail_closed():
    malformed = _Transport(lambda _call: _Response({"data": {"not": "a list"}}))
    with pytest.raises(inventory.DiscoveryProtocolError, match="array"):
        inventory.AzureAIFoundryInventoryAdapter(
            endpoint="https://foundry.services.ai.azure.com/api/projects/p",
            transport=malformed,
            limits=_limits(),
            sleep=lambda _delay: None,
        ).discover()

    def cycle(call):
        if call["url"].endswith("/models"):
            return _Response({"models": [], "nextPageToken": "same"})
        return _Response({"endpoints": []})

    with pytest.raises(inventory.DiscoveryProtocolError, match="cycle"):
        inventory.VertexAIInventoryAdapter(
            project="p",
            location="us-central1",
            transport=_Transport(cycle),
            limits=_limits(),
            sleep=lambda _delay: None,
        ).discover()

    control = _BedrockControl()
    with pytest.raises(inventory.DiscoveryLimitError, match="record cap"):
        inventory.BedrockInventoryAdapter(
            control_client=control,
            agent_client=_BedrockAgent(),
            region="us-east-1",
            limits=_limits(record_cap=1),
            sleep=lambda _delay: None,
        ).discover()


def _asset(label: str) -> inventory.DiscoveredAsset:
    return inventory.DiscoveredAsset(
        asset_type="model",
        source="google_vertex_ai",
        source_id=f"projects/p/locations/us-central1/models/{label}",
        display_name=f"Model {label}",
        version_digest=hashlib.sha256(f"version:{label}".encode()).hexdigest(),
        binding_strength="immutable_provider_revision",
        owner="owner@example.com",
        platform="Google Vertex AI",
        model=f"model-{label}",
        last_seen=1_780_000_000.0,
        source_url=f"https://us-central1-aiplatform.googleapis.com/models/{label}",
        metadata={"resource_kind": "model"},
    )


class _StaticAdapter:
    name = "vertex_ai"
    source = "google_vertex_ai"
    limits = inventory.DiscoveryLimits(page_cap=5, record_cap=10)

    def __init__(self, assets):
        self.assets = list(assets)

    def discover(self):
        return inventory.DiscoveryResult(tuple(self.assets), 1)


def test_sync_is_idempotent_and_preserves_source_and_run_lineage():
    service = inventory.DiscoveryService(clock=lambda: 1_780_000_100.0)
    adapter = _StaticAdapter([_asset("one")])

    first = service.sync(adapter, actor="inventory-service")
    state = service.list_asset_states()[0]
    observation = mra.get_observation(state["asset_id"])
    second = service.sync(adapter, actor="inventory-service")
    later_state = service.list_asset_states()[0]
    later_observation = mra.get_observation(state["asset_id"])

    assert first["completed_sequence"] == 1
    assert second["completed_sequence"] == 2
    assert observation["revision"] == later_observation["revision"]
    assert later_state["last_run_id"] == second["id"]
    assert later_state["last_seen_sequence"] == 2
    assert later_observation["metadata"] == {
        "record_origin": "discovered",
        "platform": "Google Vertex AI",
        "model": "model-one",
        "discovered_owner": "owner@example.com",
        "source_url": "https://us-central1-aiplatform.googleapis.com/models/one",
        "binding_strength": "immutable_provider_revision",
        "resource_kind": "model",
    }
    assert later_observation["evidence_node_id"].startswith("EGN-")


def test_failed_partial_run_never_advances_completed_missing_sequence():
    service = inventory.DiscoveryService(clock=lambda: 1_780_000_200.0)
    adapter = _StaticAdapter([_asset("one"), _asset("two")])
    complete = service.sync(adapter, actor="inventory-service")
    assert complete["completed_sequence"] == 1

    class FailSecond:
        def __init__(self):
            self.calls = 0

        def get_observation(self, asset_id):
            return mra.get_observation(asset_id)

        def observe_asset(self, **kwargs):
            self.calls += 1
            if self.calls == 2:
                raise RuntimeError("upstream detail must not persist")
            return mra.observe_asset(**kwargs)

    partial_service = inventory.DiscoveryService(
        observer=FailSecond(),
        clock=lambda: 1_780_000_300.0,
    )
    with pytest.raises(inventory.DiscoverySyncError, match="did not complete"):
        partial_service.sync(adapter, actor="inventory-service")

    status = partial_service.status("vertex_ai")
    states = partial_service.list_asset_states(missing_grace_runs=1)
    assert status["state"] == "partial"
    assert status["completed_sequence"] == 1
    assert {row["missing_count"] for row in states} == {0}
    failed_run = partial_service.list_runs(limit=1)[0]
    assert failed_run["error_type"] == "RuntimeError"
    assert "upstream detail" not in json.dumps(failed_run)

    # The failed run staged "one" at sequence 2. A later complete sequence 2
    # that sees only "two" must not mistake that failed sighting for success.
    service.sync(_StaticAdapter([_asset("two")]), actor="inventory-service")
    by_name = {row["display_name"]: row for row in service.list_asset_states(
        missing_grace_runs=1
    )}
    assert by_name["Model one"]["discovery_status"] == "missing"
    assert by_name["Model one"]["missing_count"] == 1
    assert by_name["Model two"]["discovery_status"] == "present"


def test_missing_grace_is_derived_only_from_complete_runs_and_never_deletes():
    service = inventory.DiscoveryService(clock=lambda: 1_780_000_400.0)
    adapter = _StaticAdapter([_asset("one")])
    service.sync(adapter, actor="inventory-service")
    adapter.assets = []

    service.sync(adapter, actor="inventory-service")
    first_absence = service.list_asset_states()[0]
    assert first_absence["discovery_status"] == "grace"
    assert first_absence["missing_count"] == 1

    service.sync(adapter, actor="inventory-service")
    missing = service.list_asset_states()[0]
    assert missing["discovery_status"] == "missing"
    assert missing["missing_count"] == 2
    assert mra.get_observation(missing["asset_id"]) is not None


def test_tenant_state_isolated_and_provider_secrets_are_not_persisted(monkeypatch):
    secret = "top-secret-copilot-token"  # pragma: allowlist secret
    monkeypatch.setenv("COPILOT_STUDIO_TOKEN", secret)

    def handler(_call):
        return _Response(
            {
                "value": [
                    {
                        "botid": "bot-secret-test",
                        "name": "Safe Bot",
                        "versionnumber": 3,
                        "modifiedon": "2026-08-12T00:00:00Z",
                        "_ownerid_value": "owner-id",
                        "configuration": json.dumps(
                            {"model": "gpt-5", "api_token": secret}
                        ),
                    }
                ]
            }
        )

    transport = _Transport(handler)
    adapter = inventory.CopilotStudioInventoryAdapter(
        dataverse_url="https://org.crm.dynamics.com",
        transport=transport,
        limits=_limits(),
        sleep=lambda _delay: None,
    )
    service = inventory.DiscoveryService(clock=lambda: 1_780_000_500.0)
    service.sync(adapter, actor="inventory-service")
    persisted = {
        "runs": service.list_runs(),
        "status": service.status("copilot_studio"),
        "assets": service.list_asset_states(),
    }
    state = persisted["assets"][0]
    persisted["observation"] = mra.get_observation(state["asset_id"])

    assert secret in transport.calls[0]["headers"]["Authorization"]
    assert secret not in json.dumps(persisted, default=str)
    assert "api_token" not in json.dumps(persisted, default=str)
    with tenant_scope(tenant="tenant-b"):
        assert service.list_asset_states() == []
        assert service.status("copilot_studio") is None


def test_read_projections_strip_audit_outbox_and_unknown_fields(monkeypatch):
    from maverick import audit

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: False)
    service = inventory.DiscoveryService(clock=lambda: 1_780_000_600.0)
    service.sync(_StaticAdapter([_asset("projection")]), actor="inventory-service")

    raw_status = service._statuses.get(inventory._status_id("vertex_ai"))
    raw_asset = service._asset_states.list(limit=2)[0]
    assert raw_status is not None
    assert "_audit_pending" in raw_status
    assert "_audit_pending" in raw_asset

    def add_unexpected(row):
        row["unexpected_provider_blob"] = {
            "authorization": "must-not-cross-the-read-boundary"
        }

    service._statuses.update(
        raw_status["id"],
        add_unexpected,
        expected_revision=raw_status["revision"],
        action="test_unknown_status_field",
        actor="inventory-test",
    )
    service._asset_states.update(
        raw_asset["id"],
        add_unexpected,
        expected_revision=raw_asset["revision"],
        action="test_unknown_asset_field",
        actor="inventory-test",
    )

    status = service.status("vertex_ai")
    state = service.list_asset_states()[0]
    assert set(status) == {
        "id",
        "schema",
        "connector",
        "source",
        "state",
        "completed_sequence",
        "revision",
        "created_at",
        "updated_at",
        "last_attempt_id",
        "last_attempt_at",
        "last_completed_id",
        "last_completed_at",
        "last_asset_count",
        "last_identity_digest",
        "last_error_type",
    }
    assert set(state) == {
        "id",
        "schema",
        "connector",
        "source",
        "source_id",
        "asset_type",
        "first_seen_at",
        "revision",
        "created_at",
        "updated_at",
        "asset_id",
        "display_name",
        "version_digest",
        "binding_strength",
        "owner",
        "platform",
        "model",
        "source_url",
        "provider_last_seen_at",
        "last_seen_at",
        "last_seen_sequence",
        "last_run_id",
        "observation_revision",
        "observation_snapshot_sha256",
        "missing_count",
        "discovery_status",
        "status",
    }
    assert "must-not-cross-the-read-boundary" not in json.dumps(
        {"status": status, "state": state}
    )


def test_read_projections_reject_corrupted_governed_fields():
    service = inventory.DiscoveryService(clock=lambda: 1_780_000_700.0)
    service.sync(_StaticAdapter([_asset("corrupt")]), actor="inventory-service")

    raw_status = service._statuses.get(inventory._status_id("vertex_ai"))
    assert raw_status is not None
    service._statuses.update(
        raw_status["id"],
        lambda row: row.update({"completed_sequence": "1"}),
        expected_revision=raw_status["revision"],
        action="test_corrupt_status",
        actor="inventory-test",
    )
    with pytest.raises(inventory.DiscoveryProtocolError, match="completed_sequence"):
        service.status("vertex_ai")

    corrupted_status = service._statuses.get(raw_status["id"])
    assert corrupted_status is not None
    service._statuses.update(
        raw_status["id"],
        lambda row: row.update({"completed_sequence": 1}),
        expected_revision=corrupted_status["revision"],
        action="test_repair_status",
        actor="inventory-test",
    )
    raw_asset = service._asset_states.list(limit=2)[0]
    service._asset_states.update(
        raw_asset["id"],
        lambda row: row.update({"pending_version_digest": "not-a-digest"}),
        expected_revision=raw_asset["revision"],
        action="test_corrupt_asset",
        actor="inventory-test",
    )
    with pytest.raises(inventory.DiscoveryProtocolError, match="version_digest"):
        service.list_asset_states()


def test_config_gate_is_default_off_and_rejects_unknown_connector(tmp_path):
    from maverick import config

    (tmp_path / "config.toml").write_text("[ai_inventory]\nenable = false\n", encoding="utf-8")
    config.reset_config_cache()
    assert inventory.enabled() is False
    with pytest.raises(inventory.AIInventoryConfigError, match="disabled"):
        inventory.require_enabled()

    (tmp_path / "config.toml").write_text(
        '[ai_inventory]\nenable = true\nconnectors = ["made_up"]\n',
        encoding="utf-8",
    )
    config.reset_config_cache()
    assert inventory.enabled() is False
    with pytest.raises(inventory.AIInventoryConfigError, match="unknown"):
        inventory.get_ai_inventory_config()


class _SageMaker:
    def __init__(self):
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def list_models(self, **kwargs):
        self.calls.append(("models", kwargs))
        created = datetime(2026, 8, 1, tzinfo=timezone.utc)
        if kwargs.get("NextToken") == "models-2":
            return {
                "Models": [
                    {
                        "ModelName": "fraud-scorer-b",
                        "ModelArn": "arn:aws:sagemaker:us-east-1:123:model/fraud-scorer-b",
                        "CreationTime": created,
                    }
                ]
            }
        return {
            "Models": [
                {
                    "ModelName": "fraud-scorer-a",
                    "ModelArn": "arn:aws:sagemaker:us-east-1:123:model/fraud-scorer-a",
                    "CreationTime": created,
                }
            ],
            "NextToken": "models-2",
        }

    def list_endpoints(self, **kwargs):
        self.calls.append(("endpoints", kwargs))
        return {
            "Endpoints": [
                {
                    "EndpointName": "fraud-scorer-prod",
                    "EndpointArn": "arn:aws:sagemaker:us-east-1:123:endpoint/fraud-scorer-prod",
                    "CreationTime": datetime(2026, 8, 2, tzinfo=timezone.utc),
                    "LastModifiedTime": datetime(2026, 8, 3, tzinfo=timezone.utc),
                    "EndpointStatus": "InService",
                }
            ]
        }

    def list_tags(self, **kwargs):
        self.calls.append(("tags", kwargs))
        return {"Tags": [{"Key": "owner", "Value": "fraud-team@example.com"}]}


def test_sagemaker_lists_models_and_endpoints_with_normalized_tag_owners():
    client = _SageMaker()
    adapter = inventory.SageMakerInventoryAdapter(
        sagemaker_client=client,
        region="us-east-1",
        limits=_limits(),
        sleep=lambda _delay: None,
    )

    result = adapter.discover()

    assert [(asset.asset_type, asset.display_name) for asset in result.assets] == [
        ("model", "fraud-scorer-a"),
        ("model", "fraud-scorer-b"),
        ("model", "fraud-scorer-prod"),
    ]
    # AWS Key/Value tag casing is normalized before owner extraction.
    assert all(asset.owner == "fraud-team@example.com" for asset in result.assets)
    assert result.assets[0].source_id.startswith("arn:aws:sagemaker:")
    assert result.assets[2].binding_strength == "observed_snapshot"
    assert result.assets[2].metadata["resource_kind"] == "endpoint"
    # Pagination followed the token exactly once, then stopped.
    model_calls = [kwargs for op, kwargs in client.calls if op == "models"]
    assert model_calls == [{"MaxResults": 100}, {"MaxResults": 100, "NextToken": "models-2"}]


def test_sagemaker_rejects_pagination_token_cycles():
    class _Cyclic(_SageMaker):
        def list_models(self, **kwargs):
            return {
                "Models": [],
                "NextToken": "same-token",
            }

    adapter = inventory.SageMakerInventoryAdapter(
        sagemaker_client=_Cyclic(),
        limits=_limits(),
        sleep=lambda _delay: None,
    )
    with pytest.raises(inventory.DiscoveryProtocolError, match="cycle"):
        adapter.discover()


def test_mlflow_registered_models_and_latest_versions_bind_exactly(monkeypatch):
    monkeypatch.setenv("MLFLOW_TRACKING_TOKEN", "mlflow-test-token")

    def handler(call):
        assert call["url"].endswith("/api/2.0/mlflow/registered-models/search")
        if call["params"].get("page_token") == "page-2":
            return _Response(
                {
                    "registered_models": [
                        {
                            "name": "churn-model",
                            "user_id": "ml-platform@example.com",
                            "creation_timestamp": 1_754_000_000_000,
                            "last_updated_timestamp": 1_754_100_000_000,
                            "latest_versions": [
                                {
                                    "name": "churn-model",
                                    "version": "7",
                                    "current_stage": "Production",
                                    "run_id": "run-777",
                                    "source": "s3://bucket/artifacts/run-777",
                                    "last_updated_timestamp": 1_754_100_000_000,
                                }
                            ],
                        }
                    ]
                }
            )
        return _Response(
            {
                "registered_models": [
                    {
                        "name": "triage-model",
                        "tags": [{"key": "owner", "value": "risk@example.com"}],
                        "last_updated_timestamp": 1_753_000_000_000,
                        "latest_versions": [],
                    }
                ],
                "next_page_token": "page-2",
            }
        )

    transport = _Transport(handler)
    adapter = inventory.MLflowInventoryAdapter(
        tracking_uri="https://mlflow.internal.example.com",
        transport=transport,
        limits=_limits(),
        sleep=lambda _delay: None,
    )

    result = adapter.discover()

    assert result.pages == 2
    names = [asset.display_name for asset in result.assets]
    assert names == ["triage-model", "churn-model", "churn-model v7"]
    assert result.assets[0].owner == "risk@example.com"
    assert result.assets[1].owner == "ml-platform@example.com"
    version = result.assets[2]
    assert version.binding_strength == "immutable_provider_revision"
    assert version.dependencies == (f"{adapter._server_key}:churn-model",)
    # Millisecond epochs are converted, never persisted raw.
    assert all(asset.last_seen < 1e11 for asset in result.assets)
    assert version.metadata["stage"] == "Production"


def test_huggingface_follows_same_origin_link_cursor_and_binds_sha(monkeypatch):
    monkeypatch.setenv("HUGGINGFACE_TOKEN", "hf-test-token")
    fake_revision = "0f0e0d0c0b0a09080706050403020100aabbccdd"  # pragma: allowlist secret

    def handler(call):
        if "cursor" not in call["url"]:
            assert call["params"]["author"] == "example-org"
            return _Response(
                [
                    {
                        "id": "example-org/classifier",
                        "sha": fake_revision,
                        "lastModified": "2026-08-05T00:00:00Z",
                        "pipeline_tag": "text-classification",
                        "private": True,
                    }
                ],
                headers={
                    "Link": '<https://huggingface.co/api/models?cursor=abc>; rel="next"'
                },
            )
        return _Response(
            [
                {
                    "id": "example-org/reranker",
                    "lastModified": "2026-08-06T00:00:00Z",
                    "private": True,
                }
            ]
        )

    transport = _Transport(handler)
    adapter = inventory.HuggingFaceInventoryAdapter(
        organization="example-org",
        transport=transport,
        limits=_limits(),
        sleep=lambda _delay: None,
    )

    result = adapter.discover()

    assert result.pages == 2
    exact, snapshot = result.assets
    assert exact.binding_strength == "immutable_provider_revision"
    assert exact.metadata["revision"] == fake_revision
    assert snapshot.binding_strength == "observed_snapshot"
    assert all(asset.owner == "example-org" for asset in result.assets)


def test_huggingface_rejects_off_origin_links_foreign_repos_and_non_lists(
    monkeypatch,
):
    monkeypatch.setenv("HUGGINGFACE_TOKEN", "hf-test-token")

    hostile_link = _Transport(
        lambda call: _Response(
            [],
            headers={"Link": '<https://evil.example.com/api/models?cursor=x>; rel="next"'},
        )
    )
    adapter = inventory.HuggingFaceInventoryAdapter(
        organization="example-org",
        transport=hostile_link,
        limits=_limits(),
        sleep=lambda _delay: None,
    )
    with pytest.raises(inventory.DiscoveryProtocolError):
        adapter.discover()

    foreign_repo = _Transport(
        lambda call: _Response([{"id": "someone-else/exfil", "private": False}])
    )
    adapter = inventory.HuggingFaceInventoryAdapter(
        organization="example-org",
        transport=foreign_repo,
        limits=_limits(),
        sleep=lambda _delay: None,
    )
    with pytest.raises(inventory.DiscoveryProtocolError, match="organization"):
        adapter.discover()

    non_list = _Transport(lambda call: _Response({"error": "nope"}))
    adapter = inventory.HuggingFaceInventoryAdapter(
        organization="example-org",
        transport=non_list,
        limits=_limits(),
        sleep=lambda _delay: None,
    )
    with pytest.raises(inventory.DiscoveryProtocolError, match="list"):
        adapter.discover()


class _SqlTransport:
    """A transport with both verbs, for the statement-based adapter."""

    def __init__(self, post_handler, get_handler=None):
        self.post_handler = post_handler
        self.get_handler = get_handler
        self.posts: list[dict[str, Any]] = []
        self.gets: list[dict[str, Any]] = []

    def post(self, url, *, headers, json, timeout):
        call = {"url": url, "headers": dict(headers), "json": dict(json), "timeout": timeout}
        self.posts.append(call)
        return self.post_handler(call)

    def get(self, url, *, headers, params, timeout):
        call = {"url": url, "headers": dict(headers), "params": dict(params or {}), "timeout": timeout}
        self.gets.append(call)
        return self.get_handler(call)


_SNOWFLAKE_COLUMNS = [
    "created_on", "name", "model_type", "database_name", "schema_name",
    "owner", "comment", "versions", "default_version_name", "aliases",
]


def _snowflake_row(name, versions='["V1"]', default="V1"):
    return [
        "2026-08-01T00:00:00+00:00", name, "USER_MODEL", "ML", "REGISTRY",
        "ML_ADMIN", "", versions, default, "{}",
    ]


def test_snowflake_sends_one_fixed_statement_and_fetches_partitions(monkeypatch):
    monkeypatch.setenv("SNOWFLAKE_TOKEN", "snowflake-test-token")

    def post_handler(call):
        assert call["json"]["statement"] == "SHOW MODELS IN ACCOUNT"
        assert call["headers"]["X-Snowflake-Authorization-Token-Type"] == "OAUTH"
        return _Response(
            {
                "statementHandle": "01b2c3d4-0000-1111-2222-333344445555",
                "resultSetMetaData": {
                    "rowType": [{"name": column} for column in _SNOWFLAKE_COLUMNS],
                    "partitionInfo": [{"rowCount": 1}, {"rowCount": 1}],
                },
                "data": [_snowflake_row("churn_scorer")],
            }
        )

    def get_handler(call):
        assert call["params"] == {"partition": 1}
        assert "01b2c3d4" in call["url"]
        return _Response({"data": [_snowflake_row("fraud_scorer", '["V1","V2"]', "V2")]})

    transport = _SqlTransport(post_handler, get_handler)
    adapter = inventory.SnowflakeInventoryAdapter(
        account_url="https://acme-prod.snowflakecomputing.com",
        transport=transport,
        limits=_limits(),
        sleep=lambda _delay: None,
    )

    result = adapter.discover()

    names = [asset.display_name for asset in result.assets]
    assert names == [
        "ML.REGISTRY.churn_scorer",
        "ML.REGISTRY.churn_scorer V1",
        "ML.REGISTRY.fraud_scorer",
        "ML.REGISTRY.fraud_scorer V1",
        "ML.REGISTRY.fraud_scorer V2",
    ]
    root, version = result.assets[0], result.assets[1]
    assert root.binding_strength == "observed_snapshot"
    assert version.binding_strength == "immutable_provider_revision"
    assert version.dependencies == (root.source_id,)
    assert all(asset.owner == "ML_ADMIN" for asset in result.assets)
    # One statement post plus one partition get -- never a second statement.
    assert len(transport.posts) == 1
    assert len(transport.gets) == 1


def test_snowflake_fails_closed_on_async_shape_drift_and_bad_versions(monkeypatch):
    monkeypatch.setenv("SNOWFLAKE_TOKEN", "snowflake-test-token")

    deferred = _SqlTransport(lambda call: _Response({}, 202))
    adapter = inventory.SnowflakeInventoryAdapter(
        account_url="https://acme-prod.snowflakecomputing.com",
        transport=deferred,
        limits=_limits(retry_attempts=1),
        sleep=lambda _delay: None,
    )
    with pytest.raises(inventory.DiscoveryTransportError, match="asynchronous"):
        adapter.discover()

    ragged = _SqlTransport(
        lambda call: _Response(
            {
                "statementHandle": "01b2c3d4-0000-1111-2222-333344445555",
                "resultSetMetaData": {
                    "rowType": [{"name": column} for column in _SNOWFLAKE_COLUMNS],
                    "partitionInfo": [{"rowCount": 1}],
                },
                "data": [["only", "two"]],
            }
        )
    )
    adapter = inventory.SnowflakeInventoryAdapter(
        account_url="https://acme-prod.snowflakecomputing.com",
        transport=ragged,
        limits=_limits(),
        sleep=lambda _delay: None,
    )
    with pytest.raises(inventory.DiscoveryProtocolError, match="row shape"):
        adapter.discover()

    hostile_versions = _SqlTransport(
        lambda call: _Response(
            {
                "statementHandle": "01b2c3d4-0000-1111-2222-333344445555",
                "resultSetMetaData": {
                    "rowType": [{"name": column} for column in _SNOWFLAKE_COLUMNS],
                    "partitionInfo": [{"rowCount": 1}],
                },
                "data": [_snowflake_row("bad_model", "not-json")],
            }
        )
    )
    adapter = inventory.SnowflakeInventoryAdapter(
        account_url="https://acme-prod.snowflakecomputing.com",
        transport=hostile_versions,
        limits=_limits(),
        sleep=lambda _delay: None,
    )
    with pytest.raises(inventory.DiscoveryProtocolError, match="versions"):
        adapter.discover()

    monkeypatch.setenv("SNOWFLAKE_TOKEN_TYPE", "PASSWORD")
    with pytest.raises(inventory.AIInventoryConfigError, match="token type"):
        inventory.SnowflakeInventoryAdapter(
            account_url="https://acme-prod.snowflakecomputing.com",
            transport=deferred,
            limits=_limits(),
            sleep=lambda _delay: None,
        )


def test_agentforce_fixed_soql_follows_next_records_and_normalizes_instants(
    monkeypatch,
):
    monkeypatch.setenv("SALESFORCE_TOKEN", "salesforce-test-token")

    def handler(call):
        if call["url"].endswith("/services/data/v61.0/query"):
            assert "BotDefinition" in call["params"]["q"]
            return _Response(
                {
                    "totalSize": 2,
                    "done": False,
                    "nextRecordsUrl": "/services/data/v61.0/query/01gRO-2000",
                    "records": [
                        {
                            "attributes": {"type": "BotDefinition"},
                            "Id": "0Xx000000000001AAA",
                            "DeveloperName": "Service_Agent",
                            "MasterLabel": "Service Agent",
                            "CreatedDate": "2026-07-01T00:00:00.000+0000",
                            "LastModifiedDate": "2026-08-01T12:30:00.000+0000",
                        }
                    ],
                }
            )
        assert call["url"].endswith("/services/data/v61.0/query/01gRO-2000")
        return _Response(
            {
                "totalSize": 2,
                "done": True,
                "records": [
                    {
                        "attributes": {"type": "BotDefinition"},
                        "Id": "0Xx000000000002AAA",
                        "DeveloperName": "Order_Agent",
                        "MasterLabel": "Order Agent",
                        "CreatedDate": "2026-07-02T00:00:00.000+0000",
                        "LastModifiedDate": "2026-08-02T12:30:00.000+0000",
                    }
                ],
            }
        )

    transport = _Transport(handler)
    adapter = inventory.AgentforceInventoryAdapter(
        instance_url="https://acme.my.salesforce.com",
        transport=transport,
        limits=_limits(),
        sleep=lambda _delay: None,
    )

    result = adapter.discover()

    assert result.pages == 2
    assert [asset.display_name for asset in result.assets] == [
        "Service Agent",
        "Order Agent",
    ]
    assert all(asset.asset_type == "agent" for asset in result.assets)
    # Salesforce's +0000 offset parses on every supported Python.
    assert result.assets[0].last_seen == datetime(
        2026, 8, 1, 12, 30, tzinfo=timezone.utc,
    ).timestamp()


def test_agentforce_rejects_off_origin_next_and_endless_not_done_pages(
    monkeypatch,
):
    monkeypatch.setenv("SALESFORCE_TOKEN", "salesforce-test-token")

    hostile = _Transport(
        lambda call: _Response(
            {
                "done": False,
                "nextRecordsUrl": "https://evil.example.com/services/data/v61.0/query/x",
                "records": [],
            }
        )
    )
    adapter = inventory.AgentforceInventoryAdapter(
        instance_url="https://acme.my.salesforce.com",
        transport=hostile,
        limits=_limits(),
        sleep=lambda _delay: None,
    )
    with pytest.raises(inventory.DiscoveryProtocolError, match="origin"):
        adapter.discover()

    missing_cursor = _Transport(
        lambda call: _Response({"done": False, "records": []})
    )
    adapter = inventory.AgentforceInventoryAdapter(
        instance_url="https://acme.my.salesforce.com",
        transport=missing_cursor,
        limits=_limits(),
        sleep=lambda _delay: None,
    )
    with pytest.raises(inventory.DiscoveryProtocolError, match="nextRecordsUrl"):
        adapter.discover()


def test_openai_lists_models_with_ownership(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

    def handler(call):
        assert call["url"] == "https://api.openai.com/v1/models"
        assert call["headers"]["Authorization"] == "Bearer sk-test"
        return _Response(
            {
                "object": "list",
                "data": [
                    {
                        "id": "gpt-5.2",
                        "object": "model",
                        "created": 1_764_000_000,
                        "owned_by": "system",
                    },
                    {
                        "id": "ft:gpt-5-mini:acme:triage:9x",
                        "object": "model",
                        "created": 1_765_000_000,
                        "owned_by": "org-acme",
                    },
                ],
            }
        )

    adapter = inventory.OpenAIInventoryAdapter(
        transport=_Transport(handler),
        limits=_limits(),
        sleep=lambda _delay: None,
    )

    result = adapter.discover()

    assert result.pages == 1
    vendor, tuned = result.assets
    assert vendor.source_id == "gpt-5.2"
    assert vendor.owner == "system"
    assert vendor.metadata["fine_tuned"] is False
    assert tuned.owner == "org-acme"
    assert tuned.metadata["fine_tuned"] is True
    assert all(
        asset.binding_strength == "observed_snapshot" for asset in result.assets
    )


def test_openai_rejects_a_malformed_listing(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    adapter = inventory.OpenAIInventoryAdapter(
        transport=_Transport(lambda call: _Response({"object": "list", "data": "no"})),
        limits=_limits(),
        sleep=lambda _delay: None,
    )
    with pytest.raises(inventory.DiscoveryProtocolError):
        adapter.discover()


_FAKE_REPLICATE_VERSION = (
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"  # pragma: allowlist secret
)


def test_replicate_pages_account_deployments_and_binds_versions(monkeypatch):
    monkeypatch.setenv("REPLICATE_API_TOKEN", "r8-test")

    def handler(call):
        if "cursor" not in call["url"]:
            return _Response(
                {
                    "results": [
                        {
                            "owner": "acme",
                            "name": "support-triage",
                            "current_release": {
                                "number": 7,
                                "model": "acme/triage-llm",
                                "version": _FAKE_REPLICATE_VERSION,
                                "created_at": "2026-08-10T00:00:00Z",
                            },
                        }
                    ],
                    "next": "https://api.replicate.com/v1/deployments?cursor=abc",
                }
            )
        return _Response(
            {
                "results": [
                    {
                        "owner": "acme",
                        "name": "experimental",
                        "current_release": {"number": 1, "model": "acme/exp"},
                    }
                ],
                "next": None,
            }
        )

    adapter = inventory.ReplicateInventoryAdapter(
        transport=_Transport(handler),
        limits=_limits(),
        sleep=lambda _delay: None,
    )

    result = adapter.discover()

    assert result.pages == 2
    pinned, floating = result.assets
    assert pinned.source_id == "acme/support-triage"
    assert pinned.binding_strength == "immutable_provider_revision"
    assert pinned.metadata["version"] == _FAKE_REPLICATE_VERSION
    assert floating.binding_strength == "observed_snapshot"
    assert all(asset.platform == "Replicate" for asset in result.assets)


def test_replicate_rejects_an_off_origin_next_url(monkeypatch):
    monkeypatch.setenv("REPLICATE_API_TOKEN", "r8-test")
    adapter = inventory.ReplicateInventoryAdapter(
        transport=_Transport(
            lambda call: _Response(
                {"results": [], "next": "https://evil.example/v1/deployments?c=1"}
            )
        ),
        limits=_limits(),
        sleep=lambda _delay: None,
    )
    with pytest.raises(inventory.DiscoveryProtocolError):
        adapter.discover()


def test_every_connector_has_a_read_side_source_mapping():
    # The read-side projections refuse persisted records whose connector
    # is missing from _CONNECTOR_SOURCES -- one absent entry makes a
    # connector's successful sync unreadable and poisons the listing.
    assert set(inventory._CONNECTOR_SOURCES) == set(inventory._CONNECTORS)


def test_dependency_token_normalizes_source_native_references():
    # Source-native references (dotted catalog names, ARNs, dotted model
    # names) must all normalize to the model-risk token grammar.
    token = inventory._dependency_token
    pattern = r"[a-z][a-z0-9_:-]{0,63}"
    import re as re_mod

    for reference in (
        "main.support.triage_model",
        "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-v2",
        "gpt-3.5-turbo",
        "  Mixed Case/Name  ",
        "42-leading-digit",
        "",
    ):
        assert re_mod.fullmatch(pattern, token(reference)), reference


def test_second_wave_connectors_are_registered_and_use_the_bounded_factory(monkeypatch):
    from maverick import ai_inventory_connectors as second_wave

    limits = inventory.DiscoveryLimits(
        page_cap=7,
        record_cap=31,
        retry_attempts=2,
        timeout_seconds=4,
    )
    enabled = ["mlflow", "aws_sagemaker", "snowflake_cortex"]
    monkeypatch.setattr(
        inventory,
        "require_enabled",
        lambda: {
            "enable": True,
            "connectors": enabled,
            "limits": limits,
            "missing_grace_runs": 2,
        },
    )
    sentinel = object()
    captured: dict[str, Any] = {}

    def build(name, **kwargs):
        captured.update({"name": name, **kwargs})
        return sentinel

    monkeypatch.setattr(second_wave, "build_second_wave_adapter", build)
    transport = object()
    sagemaker_client = object()
    adapter = inventory.build_configured_adapter(
        "aws_sagemaker",
        transport=transport,
        sagemaker_client=sagemaker_client,
        sleep=lambda _seconds: None,
        clock=lambda: 1_780_000_800.0,
    )

    assert adapter is sentinel
    assert captured["name"] == "aws_sagemaker"
    assert captured["enabled_connectors"] == enabled
    assert captured["transport"] is transport
    assert captured["sagemaker_client"] is sagemaker_client
    assert captured["limits"] is limits
    assert set(second_wave.available_second_wave_connectors()).issubset(
        inventory.available_connectors()
    )
    assert inventory._CONNECTOR_SOURCES["hugging_face"] == "hugging_face_hub"
    assert inventory._CONNECTOR_SOURCES["mlflow"] == "mlflow_model_registry"
