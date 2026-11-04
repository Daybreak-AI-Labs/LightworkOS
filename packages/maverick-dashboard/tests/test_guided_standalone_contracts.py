from html.parser import HTMLParser
from pathlib import Path

from fastapi import FastAPI
from maverick_dashboard.consent_experiments_api import router as experiments_router
from maverick_dashboard.consent_publishing_api import router as publishing_router
from maverick_dashboard.privacy_data_discovery_api import router as discovery_router


class GuidedInputs(HTMLParser):
    def __init__(self, source: str):
        super().__init__()
        self.inputs: list[dict[str, str]] = []
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "textarea" and "data-guided-endpoint" in values:
            self.inputs.append(values)


def test_standalone_fields_resolve_the_existing_api_request_schemas():
    app = FastAPI()
    app.include_router(discovery_router, prefix="/api/v1")
    app.include_router(experiments_router, prefix="/api/v1")
    document = app.openapi()

    def resolve(schema):
        while "$ref" in schema:
            schema = document["components"]["schemas"][schema["$ref"].split("/")[-1]]
        return schema

    # Both pages now build their own forms; their request contracts keep the
    # bounds and reviewed evidence the forms were built against.
    discovery = resolve(document["paths"]["/api/v1/privacy/data-discovery/sources/{source_id}/jobs"]["post"]
                        ["requestBody"]["content"]["application/json"]["schema"])
    limits = resolve(discovery["properties"]["limits"])
    assert set(limits["properties"]) == {
        "max_records", "max_files", "max_bytes", "max_seconds",
        "max_findings", "max_fields_per_record", "max_record_bytes",
        "max_document_bytes",
    }
    for limit in limits["properties"].values():
        assert limit["type"] in {"integer", "number"}
        assert "minimum" in limit and "maximum" in limit
    variants = resolve(
        resolve(document["paths"]["/api/v1/consent/experiments"]["post"]["requestBody"]["content"]
                ["application/json"]["schema"])["properties"]["variants"]
    )
    assert variants["minItems"] == 2 and variants["maxItems"] == 10
    assert "equal_choice_evidence_sha256" in resolve(variants["items"])["required"]


def test_discovery_scan_limits_match_the_api_request_schema():
    import json
    import re

    app = FastAPI()
    app.include_router(discovery_router, prefix="/api/v1")
    document = app.openapi()
    schemas = document["components"]["schemas"]
    limits = schemas["ScanLimitsIn"]
    script = (
        Path(__file__).resolve().parents[1]
        / "maverick_dashboard" / "static" / "lightwork-privacy-data-discovery.js"
    ).read_text(encoding="utf-8")
    match = re.search(r"var DEFAULT_LIMITS = (\{[^}]*\});", script)
    assert match is not None
    defaults = json.loads(re.sub(r"(\w+):", r'"\1":', match.group(1)))
    assert set(defaults) == set(limits["properties"])
    for key, value in defaults.items():
        bound = limits["properties"][key]
        assert bound["minimum"] <= value <= bound["maximum"], key



def test_each_publishing_resource_kind_binds_its_own_closed_request_contract():
    # The publishing page builds one guided form per content kind and posts
    # it to that kind's own versioned endpoint.
    script = (
        Path(__file__).resolve().parents[1]
        / "maverick_dashboard" / "static" / "lightwork-consent-publishing.js"
    ).read_text(encoding="utf-8")
    template = Path(__file__).resolve().parents[1] / "maverick_dashboard" / "templates" / "consent_publishing.html"
    page = template.read_text(encoding="utf-8")
    assert "/static/lightwork-consent-publishing.js" in page
    bindings = {
        "purposes": "/api/v1/consent/publishing/purposes/{purpose_id}/versions",
        "topics": "/api/v1/consent/publishing/topics/{topic_id}/versions",
        "custom-preferences": "/api/v1/consent/publishing/custom-preferences/{preference_id}/versions",
        "notices": "/api/v1/consent/publishing/notices/{notice_id}/versions",
        "translations": "/api/v1/consent/publishing/translations/{catalog_id}/{locale}/versions",
        "themes": "/api/v1/consent/publishing/themes/{theme_token_id}/versions",
        "templates": "/api/v1/consent/publishing/templates/{template_id}/versions",
        "rule-groups": "/api/v1/consent/publishing/rule-groups/{rule_group_id}/versions",
    }
    for kind in bindings:
        assert f'value="{kind}"' in page
        assert f'endpoint: "{kind}"' in script
    expected = {
        "purposes": "PurposeIn", "topics": "TopicIn",
        "custom-preferences": "CustomPreferenceIn", "notices": "NoticeIn",
        "translations": "TranslationIn", "themes": "ThemeTokenIn",
        "templates": "TemplateIn", "rule-groups": "RuleGroupIn",
    }
    assert bindings.keys() == expected.keys()
    app = FastAPI()
    app.include_router(publishing_router, prefix="/api/v1")
    document = app.openapi()
    for kind, endpoint in bindings.items():
        body = document["paths"][endpoint]["post"]["requestBody"]["content"]["application/json"]["schema"]
        assert body["$ref"] == f"#/components/schemas/{expected[kind]}"
        schema = document["components"]["schemas"][expected[kind]]
        assert schema["additionalProperties"] is False
        assert {"version", "expected_current_version", "idempotency_key"} <= set(schema["required"])
    template_actions = document["components"]["schemas"]["TemplateIn"]["properties"]["actions"]
    assert set(template_actions["propertyNames"]["enum"]) == {
        "accept_all", "close", "manage_preferences", "reject_all", "save_preferences",
    }
