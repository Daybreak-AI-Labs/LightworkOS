"""Contract and fail-closed tests for second-wave AI inventory connectors."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from maverick import ai_inventory as inventory
from maverick import ai_inventory_connectors as connectors


@pytest.fixture(autouse=True)
def _provider_references(monkeypatch):
    monkeypatch.setenv("MLFLOW_TRACKING_URI", "https://mlflow.example.test")
    monkeypatch.setenv("MLFLOW_TRACKING_TOKEN", "mlflow-test-secret")
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT_URL", "https://account.snowflakecomputing.com")
    monkeypatch.setenv("SNOWFLAKE_TOKEN", "snowflake-test-secret")
    monkeypatch.setenv(
        "SNOWFLAKE_CORTEX_SCOPES",
        '[{"database":"AI_DB","schema":"GOVERNED"}]',
    )
    monkeypatch.setenv("SNOWFLAKE_ROLE", "AI_GOVERNANCE_READER")
    monkeypatch.setenv("SALESFORCE_INSTANCE_URL", "https://tenant.my.salesforce.com")
    monkeypatch.setenv("SALESFORCE_ACCESS_TOKEN", "salesforce-test-secret")
    monkeypatch.setenv("HUGGING_FACE_NAMESPACE", "tenant-ai")
    monkeypatch.setenv("HUGGING_FACE_ENDPOINT", "https://huggingface.co")
    monkeypatch.setenv("HF_TOKEN", "hugging-face-test-secret")


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


def _limits(**overrides):
    values = {
        "page_cap": 20,
        "record_cap": 100,
        "retry_attempts": 2,
        "timeout_seconds": 4.5,
    }
    values.update(overrides)
    return inventory.DiscoveryLimits(**values)


def test_mlflow_consumes_registered_model_and_version_pagination():
    def handler(call):
        path = urlsplit(call["url"]).path
        token = call["params"].get("page_token")
        if path.endswith("registered-models/search"):
            if token == "registered-2":
                return _Response(
                    {
                        "registered_models": [
                            {
                                "name": "fraud-model",
                                "last_updated_timestamp": 1_786_000_200_000,
                                "tags": [{"key": "owner", "value": "risk@example.com"}],
                            }
                        ]
                    }
                )
            return _Response(
                {
                    "registered_models": [
                        {
                            "name": "claims-model",
                            "last_updated_timestamp": 1_786_000_100_000,
                            "tags": [{"key": "team", "value": "claims-ai"}],
                        }
                    ],
                    "next_page_token": "registered-2",
                }
            )
        if path.endswith("model-versions/search"):
            if token == "version-2":
                return _Response(
                    {
                        "model_versions": [
                            {
                                "name": "fraud-model",
                                "version": "7",
                                "source": "s3://models/fraud/7",
                                "status": "READY",
                                "current_stage": "Production",
                                "last_updated_timestamp": 1_786_000_400_000,
                            }
                        ]
                    }
                )
            return _Response(
                {
                    "model_versions": [
                        {
                            "name": "claims-model",
                            "version": "3",
                            "source": "runs:/safe-run/model",
                            "run_id": "safe-run",
                            "status": "READY",
                            "current_stage": "Staging",
                            "last_updated_timestamp": 1_786_000_300_000,
                        }
                    ],
                    "next_page_token": "version-2",
                }
            )
        raise AssertionError(f"unexpected MLflow path: {path}")

    transport = _Transport(handler)
    result = connectors.MLflowInventoryAdapter(
        transport=transport,
        limits=_limits(),
        clock=lambda: 1_786_001_000.0,
    ).discover()

    assert result.pages == 4
    assert len(result.assets) == 4
    assert {(asset.metadata["resource_kind"], asset.display_name) for asset in result.assets} == {
        ("registered_model", "claims-model"),
        ("registered_model", "fraud-model"),
        ("model_version", "claims-model v3"),
        ("model_version", "fraud-model v7"),
    }
    assert all(asset.source == "mlflow_model_registry" for asset in result.assets)
    assert all(call["params"]["max_results"] == 100 for call in transport.calls)
    assert all(call["timeout"] == 4.5 for call in transport.calls)
    assert all(call["headers"]["Authorization"] == "Bearer mlflow-test-secret" for call in transport.calls)
    assert "mlflow-test-secret" not in json.dumps(result, default=str)


def test_mlflow_rejects_partial_marker_and_orphan_versions():
    partial = _Transport(
        lambda _call: _Response({"registered_models": [], "IsTruncated": True})
    )
    with pytest.raises(inventory.DiscoveryProtocolError, match="partial page"):
        connectors.MLflowInventoryAdapter(transport=partial, limits=_limits()).discover()

    def orphan_handler(call):
        if urlsplit(call["url"]).path.endswith("registered-models/search"):
            return _Response({"registered_models": []})
        return _Response(
            {
                "model_versions": [
                    {
                        "name": "not-in-registry-page",
                        "version": "1",
                        "source": "runs:/one/model",
                    }
                ]
            }
        )

    with pytest.raises(inventory.DiscoveryProtocolError, match="without registered models"):
        connectors.MLflowInventoryAdapter(
            transport=_Transport(orphan_handler),
            limits=_limits(),
        ).discover()


class _SageMaker:
    def __init__(self):
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def list_models(self, **kwargs):
        self.calls.append(("models", kwargs))
        if kwargs.get("NextToken") == "models-2":
            return {
                "Models": [
                    {
                        "ModelName": "fraud",
                        "ModelArn": "arn:aws:sagemaker:us-east-1:123:model/fraud",
                        "CreationTime": datetime(2026, 8, 2, tzinfo=timezone.utc),
                    }
                ]
            }
        return {
            "Models": [
                {
                    "ModelName": "claims",
                    "ModelArn": "arn:aws:sagemaker:us-east-1:123:model/claims",
                    "CreationTime": datetime(2026, 8, 1, tzinfo=timezone.utc),
                }
            ],
            "NextToken": "models-2",
        }

    def list_endpoints(self, **kwargs):
        self.calls.append(("endpoints", kwargs))
        return {
            "Endpoints": [
                {
                    "EndpointName": "claims-live",
                    "EndpointArn": "arn:aws:sagemaker:us-east-1:123:endpoint/claims-live",
                    "EndpointStatus": "InService",
                    "CreationTime": datetime(2026, 8, 3, tzinfo=timezone.utc),
                    "LastModifiedTime": datetime(2026, 8, 4, tzinfo=timezone.utc),
                }
            ]
        }


def test_sagemaker_uses_only_fixed_bounded_list_operations():
    client = _SageMaker()
    result = connectors.SageMakerInventoryAdapter(
        client=client,
        region="us-east-1",
        limits=_limits(),
        clock=lambda: 1_786_001_000.0,
    ).discover()

    assert result.pages == 3
    assert [kind for kind, _kwargs in client.calls] == ["models", "models", "endpoints"]
    assert client.calls[0][1] == {"MaxResults": 100}
    assert client.calls[1][1] == {"MaxResults": 100, "NextToken": "models-2"}
    assert len(result.assets) == 3
    assert {asset.metadata["resource_kind"] for asset in result.assets} == {"model", "endpoint"}
    endpoint = next(asset for asset in result.assets if asset.metadata["resource_kind"] == "endpoint")
    assert endpoint.metadata["status"] == "InService"
    assert endpoint.owner == "unknown"


def test_sagemaker_rejects_cycles_caps_and_missing_fixed_methods():
    class CycleClient:
        def list_models(self, **_kwargs):
            return {"Models": [], "NextToken": "again"}

        def list_endpoints(self, **_kwargs):
            return {"Endpoints": []}

    with pytest.raises(inventory.DiscoveryProtocolError, match="cycle"):
        connectors.SageMakerInventoryAdapter(
            client=CycleClient(),
            limits=_limits(),
        ).discover()

    with pytest.raises(inventory.DiscoveryLimitError, match="record cap"):
        connectors.SageMakerInventoryAdapter(
            client=_SageMaker(),
            limits=_limits(record_cap=1),
        ).discover()

    with pytest.raises(inventory.AIInventoryConfigError, match="fixed list operations"):
        connectors.SageMakerInventoryAdapter(
            client=object(),
            limits=_limits(),
        ).discover()


def _snowflake_agent(name: str, owner: str):
    return {
        "name": name,
        "database": "AI_DB",
        "schema": "GOVERNED",
        "created_on": "2026-08-01T00:00:00Z",
        "owner": owner,
        "profile": {"display_name": f"{name} display"},
    }


def test_snowflake_cortex_uses_explicit_scopes_links_and_describe():
    def handler(call):
        parsed = urlsplit(call["url"])
        if parsed.path.endswith("/agents"):
            if "fromName=CLAIMS" in parsed.query:
                return _Response([_snowflake_agent("FRAUD", "RISK_ROLE")])
            next_url = (
                "https://account.snowflakecomputing.com/api/v2/databases/AI_DB/"
                "schemas/GOVERNED/agents?showLimit=100&fromName=CLAIMS"
            )
            return _Response(
                [_snowflake_agent("CLAIMS", "CLAIMS_ROLE")],
                headers={"Link": f'<{next_url}>; rel="next"'},
            )
        if parsed.path.endswith("/agents/CLAIMS"):
            return _Response(
                {
                    "name": "CLAIMS",
                    "owner": "CLAIMS_ROLE",
                    "created_on": "2026-08-01T00:00:00Z",
                    "agent_spec": json.dumps(
                        {
                            "models": {"orchestration": "claude-4-sonnet"},
                            "instructions": {"response": "do not persist this"},
                            "tools": [
                                {"tool_spec": {"name": "policy_search", "type": "cortex_search"}}
                            ],
                        }
                    ),
                }
            )
        if parsed.path.endswith("/agents/FRAUD"):
            return _Response(
                {
                    "name": "FRAUD",
                    "owner": "RISK_ROLE",
                    "created_on": "2026-08-02T00:00:00Z",
                    "agent_spec": json.dumps(
                        {"models": {"orchestration": "auto"}, "tools": []}
                    ),
                }
            )
        raise AssertionError(f"unexpected Snowflake path: {parsed.path}")

    transport = _Transport(handler)
    result = connectors.SnowflakeCortexInventoryAdapter(
        transport=transport,
        limits=_limits(),
        clock=lambda: 1_786_001_000.0,
    ).discover()

    assert result.pages == 4
    assert len(result.assets) == 2
    claims = next(asset for asset in result.assets if asset.display_name == "CLAIMS display")
    assert claims.model == "claude-4-sonnet"
    assert claims.metadata["tool_types"] == ["cortex_search"]
    assert claims.dependencies == ("claude-4-sonnet",)
    assert all(call["headers"]["X-Snowflake-Role"] == "AI_GOVERNANCE_READER" for call in transport.calls)
    assert all(call["timeout"] == 4.5 for call in transport.calls)
    encoded = json.dumps(result, default=str)
    assert "snowflake-test-secret" not in encoded
    assert "do not persist this" not in encoded


def test_snowflake_rejects_cross_origin_pagination_and_unbounded_tools():
    cross_origin = _Transport(
        lambda _call: _Response(
            [_snowflake_agent("CLAIMS", "OWNER")],
            headers={"Link": '<https://evil.example/api/v2/agents>; rel="next"'},
        )
    )
    with pytest.raises(inventory.DiscoveryProtocolError, match="fixed API surface"):
        connectors.SnowflakeCortexInventoryAdapter(
            transport=cross_origin,
            limits=_limits(),
        ).discover()

    changed_page_size = _Transport(
        lambda _call: _Response(
            [_snowflake_agent("CLAIMS", "OWNER")],
            headers={
                "Link": (
                    '<https://account.snowflakecomputing.com/api/v2/databases/AI_DB/'
                    'schemas/GOVERNED/agents?showLimit=1&fromName=CLAIMS>; rel="next"'
                )
            },
        )
    )
    with pytest.raises(inventory.DiscoveryProtocolError, match="page size"):
        connectors.SnowflakeCortexInventoryAdapter(
            transport=changed_page_size,
            limits=_limits(),
        ).discover()

    tools = [
        {"tool_spec": {"name": f"tool_{index}", "type": "generic"}}
        for index in range(129)
    ]

    def tool_handler(call):
        if urlsplit(call["url"]).path.endswith("/agents"):
            return _Response([_snowflake_agent("CLAIMS", "OWNER")])
        return _Response(
            {
                "name": "CLAIMS",
                "agent_spec": json.dumps({"models": {"orchestration": "auto"}, "tools": tools}),
            }
        )

    with pytest.raises(inventory.DiscoveryLimitError, match="tool cap"):
        connectors.SnowflakeCortexInventoryAdapter(
            transport=_Transport(tool_handler),
            limits=_limits(record_cap=500),
        ).discover()


def test_snowflake_scope_configuration_is_bounded_and_reference_only(monkeypatch):
    monkeypatch.setenv(
        "SNOWFLAKE_CORTEX_SCOPES",
        '[{"database":"AI_DB","schema":"GOVERNED","token":"inline-secret"}]',
    )
    with pytest.raises(inventory.AIInventoryConfigError, match="unsupported fields"):
        connectors.SnowflakeCortexInventoryAdapter(
            transport=_Transport(lambda _call: None),
            limits=_limits(),
        )

    with pytest.raises(inventory.AIInventoryConfigError, match="unique"):
        connectors.SnowflakeCortexInventoryAdapter(
            scopes=[("AI_DB", "GOVERNED"), ("ai_db", "governed")],
            transport=_Transport(lambda _call: None),
            limits=_limits(),
        )


def _salesforce_agent(agent_id: str, developer_name: str):
    return {
        "Id": agent_id,
        "DeveloperName": developer_name,
        "MasterLabel": developer_name.replace("_", " "),
        "Type": "ExternalCopilot",
        "AgentType": "AgentforceServiceAgent",
        "CreatedById": "005CREATOR",
        "CreatedDate": "2026-08-01T00:00:00Z",
        "LastModifiedById": "005OWNER",
        "LastModifiedDate": "2026-08-02T00:00:00Z",
    }


def test_agentforce_uses_fixed_queries_and_proves_complete_totals():
    agent_one = _salesforce_agent("0Xx000000000000001", "Claims_Agent")
    agent_two = _salesforce_agent("0Xx000000000000002", "Fraud_Agent")

    def handler(call):
        parsed = urlsplit(call["url"])
        query = call["params"].get("q")
        if query and "FROM BotDefinition" in query:
            return _Response(
                {
                    "totalSize": 2,
                    "done": False,
                    "records": [agent_one],
                    "nextRecordsUrl": "/services/data/v65.0/query/01g-agents",
                }
            )
        if parsed.path.endswith("/query/01g-agents"):
            return _Response({"totalSize": 2, "done": True, "records": [agent_two]})
        if query and "FROM BotVersion" in query:
            return _Response(
                {
                    "totalSize": 2,
                    "done": True,
                    "records": [
                        {
                            "Id": "0X9000000000000001",
                            "BotDefinitionId": agent_one["Id"],
                            "DeveloperName": "v3",
                            "VersionNumber": 3,
                            "Status": "Active",
                            "LastModifiedDate": "2026-08-03T00:00:00Z",
                        },
                        {
                            "Id": "0X9000000000000002",
                            "BotDefinitionId": agent_two["Id"],
                            "DeveloperName": "v2",
                            "VersionNumber": 2,
                            "Status": "Inactive",
                            "LastModifiedDate": "2026-08-03T00:00:00Z",
                        },
                    ],
                }
            )
        raise AssertionError(f"unexpected Salesforce request: {call}")

    transport = _Transport(handler)
    result = connectors.SalesforceAgentforceInventoryAdapter(
        transport=transport,
        limits=_limits(),
        clock=lambda: 1_786_001_000.0,
    ).discover()

    assert result.pages == 3
    assert len(result.assets) == 2
    claims = next(asset for asset in result.assets if asset.display_name == "Claims Agent")
    assert claims.metadata["active_version"] == "3"
    assert claims.metadata["version_count"] == 1
    first_queries = [call["params"]["q"] for call in transport.calls if "q" in call["params"]]
    assert len(first_queries) == 2
    assert "FIELDS(ALL)" not in " ".join(first_queries)
    assert "LIMIT" not in " ".join(first_queries)
    assert all(call["timeout"] == 4.5 for call in transport.calls)
    assert "salesforce-test-secret" not in json.dumps(result, default=str)


def test_agentforce_rejects_partial_done_marker_total_mismatch_and_bad_next_path():
    partial = _Transport(
        lambda _call: _Response({"totalSize": 1, "done": False, "records": []})
    )
    with pytest.raises(inventory.DiscoveryProtocolError, match="omitted nextRecordsUrl"):
        connectors.SalesforceAgentforceInventoryAdapter(
            transport=partial,
            limits=_limits(),
        ).discover()

    mismatch = _Transport(
        lambda _call: _Response(
            {"totalSize": 2, "done": True, "records": [_salesforce_agent("0Xx1", "One")]}
        )
    )
    with pytest.raises(inventory.DiscoveryProtocolError, match="partial result"):
        connectors.SalesforceAgentforceInventoryAdapter(
            transport=mismatch,
            limits=_limits(),
        ).discover()

    bad_next = _Transport(
        lambda _call: _Response(
            {
                "totalSize": 1,
                "done": False,
                "records": [],
                "nextRecordsUrl": "/services/data/v65.0/sobjects/Account",
            }
        )
    )
    with pytest.raises(inventory.DiscoveryProtocolError, match="fixed API surface"):
        connectors.SalesforceAgentforceInventoryAdapter(
            transport=bad_next,
            limits=_limits(),
        ).discover()


def _hf_model(repo_id: str, revision: str, **overrides):
    value = {
        "id": repo_id,
        "author": repo_id.split("/", 1)[0],
        "sha": revision,
        "lastModified": "2026-08-01T00:00:00Z",
        "private": True,
        "gated": False,
        "pipeline_tag": "text-generation",
        "library_name": "transformers",
    }
    value.update(overrides)
    return value


def test_hugging_face_is_namespace_scoped_and_follows_validated_links():
    first_revision = "a" * 40
    second_revision = "b" * 40

    def handler(call):
        parsed = urlsplit(call["url"])
        query = parse_qs(parsed.query)
        if query.get("cursor") == ["next-page"]:
            return _Response([_hf_model("tenant-ai/fraud", second_revision)])
        return _Response(
            [_hf_model("tenant-ai/claims", first_revision)],
            headers={"Link": f'<{call["url"]}&cursor=next-page>; rel="next"'},
        )

    transport = _Transport(handler)
    result = connectors.HuggingFaceInventoryAdapter(
        transport=transport,
        limits=_limits(),
        clock=lambda: 1_786_001_000.0,
    ).discover()

    assert result.pages == 2
    assert {asset.source_id for asset in result.assets} == {
        "tenant-ai/claims",
        "tenant-ai/fraud",
    }
    assert all(asset.binding_strength == "immutable_provider_revision" for asset in result.assets)
    assert all(asset.owner == "tenant-ai" for asset in result.assets)
    first_query = parse_qs(urlsplit(transport.calls[0]["url"]).query)
    assert first_query["author"] == ["tenant-ai"]
    assert first_query["limit"] == ["100"]
    assert first_query["expand"] == [
        "author",
        "sha",
        "lastModified",
        "private",
        "gated",
        "pipeline_tag",
        "library_name",
    ]
    assert all(call["timeout"] == 4.5 for call in transport.calls)
    assert "hugging-face-test-secret" not in json.dumps(result, default=str)


def test_hugging_face_rejects_namespace_drift_bad_revision_and_link_mutation():
    namespace_drift = _Transport(
        lambda _call: _Response([_hf_model("someone-else/model", "a" * 40)])
    )
    with pytest.raises(inventory.DiscoveryProtocolError, match="configured namespace"):
        connectors.HuggingFaceInventoryAdapter(
            transport=namespace_drift,
            limits=_limits(),
        ).discover()

    bad_revision = _Transport(
        lambda _call: _Response([_hf_model("tenant-ai/model", "main")])
    )
    with pytest.raises(inventory.DiscoveryProtocolError, match="immutable commit"):
        connectors.HuggingFaceInventoryAdapter(
            transport=bad_revision,
            limits=_limits(),
        ).discover()

    def mutated_link(call):
        changed = call["url"].replace("author=tenant-ai", "author=other")
        return _Response(
            [_hf_model("tenant-ai/model", "a" * 40)],
            headers={"Link": f'<{changed}&cursor=next>; rel="next"'},
        )

    with pytest.raises(inventory.DiscoveryProtocolError, match="namespace or page size"):
        connectors.HuggingFaceInventoryAdapter(
            transport=_Transport(mutated_link),
            limits=_limits(),
        ).discover()


def test_http_retry_timeout_and_record_cap_are_enforced():
    responses = [
        _Response({}, status_code=429, headers={"Retry-After": "0"}),
        _Response({"registered_models": []}),
        _Response({"model_versions": []}),
    ]
    sleeps: list[float] = []
    transport = _Transport(lambda _call: responses.pop(0))
    result = connectors.MLflowInventoryAdapter(
        transport=transport,
        limits=_limits(timeout_seconds=2.25),
        sleep=sleeps.append,
    ).discover()
    assert result.assets == ()
    assert sleeps == [0.0]
    assert all(call["timeout"] == 2.25 for call in transport.calls)

    over_cap = _Transport(
        lambda _call: _Response(
            [
                _hf_model("tenant-ai/one", "a" * 40),
                _hf_model("tenant-ai/two", "b" * 40),
            ]
        )
    )
    with pytest.raises(inventory.DiscoveryLimitError, match="record cap"):
        connectors.HuggingFaceInventoryAdapter(
            transport=over_cap,
            limits=_limits(record_cap=1),
        ).discover()


def test_secret_references_and_base_urls_are_validated_before_requests():
    with pytest.raises(inventory.AIInventoryConfigError, match="environment-variable name"):
        connectors.MLflowInventoryAdapter(
            token_env="literal-secret",
            transport=_Transport(lambda _call: None),
            limits=_limits(),
        )

    with pytest.raises(inventory.AIInventoryConfigError, match="credential-free HTTPS"):
        connectors.MLflowInventoryAdapter(
            tracking_uri="https://user:password@mlflow.example.test",
            transport=_Transport(lambda _call: None),
            limits=_limits(),
        )

    with pytest.raises(inventory.AIInventoryConfigError, match="credential-free HTTPS"):
        connectors.HuggingFaceInventoryAdapter(
            endpoint="http://huggingface.example.test",
            transport=_Transport(lambda _call: None),
            limits=_limits(),
        )


def test_second_wave_factory_is_explicit_and_default_off():
    assert connectors.available_second_wave_connectors() == [
        "mlflow",
        "aws_sagemaker",
        "snowflake_cortex",
        "salesforce_agentforce",
        "hugging_face",
    ]
    with pytest.raises(inventory.AIInventoryConfigError, match="not enabled"):
        connectors.build_second_wave_adapter("mlflow")
    with pytest.raises(inventory.AIInventoryConfigError, match="unsupported"):
        connectors.build_second_wave_adapter("made_up", enabled_connectors=["made_up"])
    with pytest.raises(inventory.AIInventoryConfigError, match="unknown"):
        connectors.build_second_wave_adapter(
            "mlflow",
            enabled_connectors=["mlflow", "made_up"],
        )

    adapter = connectors.build_second_wave_adapter(
        "mlflow",
        enabled_connectors=["bedrock", "mlflow"],
        transport=_Transport(lambda _call: _Response({})),
        limits=_limits(),
    )
    assert isinstance(adapter, connectors.MLflowInventoryAdapter)


def test_core_factory_accepts_mixed_first_and_second_wave_configuration(monkeypatch):
    limits = _limits()
    monkeypatch.setattr(
        inventory,
        "require_enabled",
        lambda: {
            "enable": True,
            "connectors": ["bedrock", "vertex_ai", "mlflow"],
            "limits": limits,
            "missing_grace_runs": 2,
        },
    )
    adapter = inventory.build_configured_adapter(
        "mlflow",
        transport=_Transport(lambda _call: _Response({})),
    )
    assert isinstance(adapter, connectors.MLflowInventoryAdapter)
    assert adapter.limits is limits


def test_missing_secrets_fail_closed_without_calling_transport(monkeypatch):
    monkeypatch.delenv("HF_TOKEN")
    transport = _Transport(lambda _call: pytest.fail("transport must not be called"))
    adapter = connectors.HuggingFaceInventoryAdapter(
        transport=transport,
        limits=_limits(),
    )
    with pytest.raises(inventory.AIInventoryConfigError, match="unavailable"):
        adapter.discover()
    assert transport.calls == []
