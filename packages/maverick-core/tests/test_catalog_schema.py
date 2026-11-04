"""Validation and indexing contracts for static product catalogs."""
from __future__ import annotations

import pytest
from maverick.catalog_schema import (
    index_connector_specs,
    index_security_catalogs,
    index_security_practices,
)
from maverick.tools import enterprise_connectors


def _connector(**changes):
    return {
        "name": "example_service",
        "description": "An example service.",
        "base_url_env": "EXAMPLE_BASE_URL",
        "token_env": "EXAMPLE_TOKEN",
        **changes,
    }


@pytest.mark.parametrize("entry", [
    ("X-1", "Section", "", "high", None),
    ("X-1", "Section", "objective", "critical", None),
    ("X-1", "Section", "objective", "high", True),
    ("X-1", "Section", "objective", "high", 4),
    ("X-1", "Section", "objective", "high"),
])
def test_security_practice_rejects_invalid_rows(entry):
    with pytest.raises(ValueError):
        index_security_practices((entry,))


def test_security_practice_rejects_duplicate_references():
    row = ("X-1", "Section", "objective", "high", None)
    with pytest.raises(ValueError, match="duplicate"):
        index_security_practices((row, row))


def test_security_catalog_requires_matching_pinned_provenance():
    row = ("X-1", "Section", "objective", "high", None)
    provenance = {
        "title": "Example", "version": "1", "source_url": "https://example.org/spec",
        "source_artifact": "spec.json", "source_sha256": "a" * 64,
        "selection": "one practice", "license": "public domain",
    }
    assert index_security_catalogs({"example": (row,)}, {"example": provenance})["example"]["X-1"] == row
    with pytest.raises(ValueError, match="same frameworks"):
        index_security_catalogs({"example": (row,)}, {})
    with pytest.raises(ValueError, match="provenance"):
        index_security_catalogs({"example": (row,)}, {"example": {**provenance, "source_sha256": "bad"}})


@pytest.mark.parametrize("changes", [
    {"name": "Bad-Name"},
    {"description": ""},
    {"base_url_env": "not valid"},
    {"token_env": ""},
    {"basic": "yes"},
    {"extra_headers_env": {"X-Header": "bad-key"}},
])
def test_connector_schema_rejects_invalid_identity_or_auth_metadata(changes):
    with pytest.raises(ValueError):
        index_connector_specs([_connector(**changes)])


def test_connector_schema_rejects_duplicate_names_and_protects_index():
    spec = _connector()
    with pytest.raises(ValueError, match="duplicate"):
        index_connector_specs([spec, dict(spec)])
    index = index_connector_specs([spec])
    assert index["example_service"] is spec
    with pytest.raises(TypeError):
        index["another"] = spec


def test_derived_connector_indexes_cover_the_source_catalog():
    rest = enterprise_connectors._SPECS
    graphql = enterprise_connectors._GRAPHQL_SPECS
    index = enterprise_connectors._CONNECTOR_INDEX
    assert len(index) == len(rest) + len(graphql)
    assert all(index[spec["name"]] is spec for spec in (*rest, *graphql))
    assert enterprise_connectors._REST_SPEC_INDEX["coupa"] is index["coupa"]
    read = enterprise_connectors._read_specs_for(["coupa"])[0]
    assert read["name"] == "coupa_read"
    assert read["token_env"] == index["coupa"]["token_env"]
