"""Closed external-gateway constraint import and projection contracts."""
from __future__ import annotations

import json

import pytest
from maverick import gateway_constraint_import as imports


def _constraint(
    constraint_id: str,
    *,
    effect: str = "deny",
    actions: list[str] | None = None,
    min_risk: str | None = None,
    deny_tools: list[str] | None = None,
) -> dict[str, object]:
    return {
        "id": constraint_id,
        "effect": effect,
        "actions": actions or [],
        "min_risk": min_risk,
        "deny_tools": deny_tools or [],
        "source_sha256": "c" * 64,
    }


def _document(*constraints: dict[str, object]) -> dict[str, object]:
    return {
        "schema": imports.GATEWAY_CONSTRAINT_IMPORT_SCHEMA,
        "gateway": {"id": "airia_gateway", "revision_sha256": "b" * 64},
        "constraints": list(constraints),
    }


def test_constraint_import_is_canonical_digest_only_and_restrictive():
    document = _document(
        _constraint("deny-shell", actions=["shell"]),
        _constraint("human-high", effect="require_human", min_risk="high"),
    )

    parsed = imports.parse_gateway_constraint_import(document)

    assert parsed.gateway_id == "airia_gateway"
    assert parsed.revision_sha256 == "b" * 64
    assert parsed.import_sha256 == imports.parse_gateway_constraint_import(document).import_sha256
    assert parsed.to_dict()["constraints"][0]["id"] == "deny-shell"
    assert "prompt" not in json.dumps(parsed.to_dict()).lower()


@pytest.mark.parametrize(
    "document",
    [
        _document(_constraint("allow-shell", effect="allow", actions=["shell"])),
        _document(_constraint("empty")),
        _document(_constraint("unordered", actions=["shell", "apply_patch"])),
        {
            "schema": imports.GATEWAY_CONSTRAINT_IMPORT_SCHEMA,
            "gateway": {"id": "airia_gateway", "revision_sha256": "b" * 64},
            "constraints": [_constraint("deny-shell", actions=["shell"])],
            "allow": True,
        },
    ],
)
def test_constraint_import_rejects_widening_vacuous_and_nonclosed_documents(document):
    with pytest.raises(imports.GatewayConstraintImportError):
        imports.parse_gateway_constraint_import(document)


def test_projection_never_widens_a_compiler_verdict_and_retains_constraint_links():
    projection = imports.project_gateway_constraints(
        _document(
            _constraint("deny-shell", actions=["shell"]),
            _constraint("human-high", effect="require_human", min_risk="high"),
        ),
        profiles=["eu_ai_act"],
    )

    shell = next(row for row in projection["verdicts"] if row["action"] == "shell")
    assert shell["compiler_decision"] == "require_human"
    assert shell["effective_decision"] == "deny"
    assert shell["gateway_constraint_ids"] == ["deny-shell", "human-high"]
    assert projection["complete"] is True
    assert projection["runtime_enforcement_changed"] is False
    assert projection["gateway_source_verified"] is False
    assert projection["import"]["gateway"]["revision_sha256"] == "b" * 64


def test_projection_reports_unmapped_gateway_selectors_without_silently_dropping_them():
    projection = imports.project_gateway_constraints(
        _document(_constraint("unknown", actions=["not-a-lightwork-action"])),
        profiles=["soc2"],
    )

    assert projection["complete"] is False
    assert projection["incomplete_constraint_ids"] == ["unknown"]
    assert projection["coverage"] == [{
        "constraint_id": "unknown",
        "mapped_actions": [],
        "unmapped_actions": ["not-a-lightwork-action"],
        "complete": False,
    }]


def test_attenuation_is_projected_as_a_restrictive_gateway_effect():
    projection = imports.project_gateway_constraints(
        _document(_constraint("attenuate-shell", effect="attenuate", deny_tools=["shell"])),
        profiles=["iso_42001"],
    )

    shell = next(row for row in projection["verdicts"] if row["action"] == "shell")
    assert shell["effective_decision"] == "deny"
    assert shell["attenuated"] is True
    assert shell["gateway_constraint_ids"] == ["attenuate-shell"]
