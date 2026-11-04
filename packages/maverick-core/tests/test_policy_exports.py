"""Contract tests for deterministic compiler policy exports."""
from __future__ import annotations

import json

import pytest
from maverick import policy_exports as exports


def test_json_verdict_table_is_deterministic_and_preserves_provenance():
    first = exports.build_json_verdict_table(["soc2", "eu_ai_act"])
    second = exports.build_json_verdict_table(["eu_ai_act", "soc2", "soc2"])

    assert first == second
    assert first["profiles"] == ["eu_ai_act", "soc2"]
    assert first["schema"] == exports.JSON_VERDICT_TABLE_SCHEMA
    assert all(item["source_url"].startswith("https://") for item in first["obligations"])

    shell = next(row for row in first["verdicts"] if row["action"] == "shell")
    assert shell["decision"] == "require_human"
    assert shell["enforced_obligation_ids"] == ["eu-aia-art14-human-oversight"]
    assert "raw_prompt" not in json.dumps(first)


def test_text_exports_are_byte_stable_and_preserve_effect_contracts():
    opa_first = exports.render_opa_rego(["eu_ai_act", "soc2"])
    opa_second = exports.render_opa_rego(["soc2", "eu_ai_act"])
    cedar_first = exports.render_cedar(["eu_ai_act", "soc2"])
    cedar_second = exports.render_cedar(["soc2", "eu_ai_act"])

    assert opa_first == opa_second
    assert cedar_first == cedar_second
    assert "import rego.v1" in opa_first
    assert '"decision":"require_human"' in opa_first
    assert '"rule":"invalid_action"' in opa_first
    assert '@lightwork_obligation_id("eu-aia-art14-human-oversight")' in cedar_first
    assert "@lightwork_source_url(" in cedar_first
    assert "human-approval pause" in cedar_first


def test_policy_export_collects_each_representation_from_the_same_snapshot():
    export = exports.build_policy_export(["iso_42001"])
    table = export["json_verdict_table"]

    assert export["schema"] == exports.POLICY_EXPORT_SCHEMA
    assert export["profiles"] == ["iso_42001"]
    assert export["compiler_description_sha256"] == table["compiler_description_sha256"]
    assert export["obligations"] == table["obligations"]
    assert "iso-42001-a9-2-human-oversight" in export["cedar"]


@pytest.mark.parametrize(
    "profiles",
    [[], ["no_such_profile"], "soc2", ["soc2", 7]],
)
def test_exports_reject_empty_or_unrecognized_profile_selections(profiles):
    with pytest.raises(exports.PolicyExportError):
        exports.build_policy_export(profiles)


def test_rendered_json_is_canonical_and_content_free():
    rendered = exports.render_json_verdict_table(["eu_ai_act"])
    parsed = json.loads(rendered)

    assert rendered.endswith("\n")
    assert parsed == exports.build_json_verdict_table(["eu_ai_act"])
    assert "prompt" not in rendered.lower()
    assert "provider_payload" not in rendered.lower()
