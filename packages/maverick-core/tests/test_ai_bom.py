"""The AI-BOM: the governed inventory as a CycloneDX 1.6 document.

The assertions that matter: components carry the governed asset identity
and its full SHA-256 version digest, model assets type as
``machine-learning-model``, edges become BOM dependencies, and the export
refuses to run when model-risk assurance is off.
"""
from __future__ import annotations

import hashlib
import time

import pytest
from maverick import ai_bom, config


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick import audit

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    (tmp_path / "config.toml").write_text(
        "[evidence_graph]\nenable = true\n\n"
        "[model_risk_assurance]\nenable = true\ngate_promotions = false\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def test_bom_projects_the_inventory_and_edges():
    from maverick import model_risk_assurance as mra

    officer = mra.ModelRiskAssuranceOfficer()
    model = officer.observe_asset(
        asset_type="model", source="bom_test", source_id="ranker",
        display_name="Ranking model",
        version_digest=hashlib.sha256(b"ranker-v1").hexdigest(),
        actor="inventory-operator", observed_at=time.time(),
        metadata={}, dependencies=[],
    )
    officer.observe_asset(
        asset_type="dataset", source="bom_test", source_id="clicks",
        display_name="Click log",
        version_digest=hashlib.sha256(b"clicks-v1").hexdigest(),
        actor="inventory-operator", observed_at=time.time(),
        metadata={}, dependencies=[model["asset_id"]],
    )
    document = ai_bom.export_ai_bom()
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.6"
    by_name = {component["name"]: component
               for component in document["components"]}
    assert by_name["Ranking model"]["type"] == "machine-learning-model"
    assert by_name["Click log"]["type"] == "data"
    assert by_name["Ranking model"]["hashes"][0]["content"] == hashlib.sha256(
        b"ranker-v1").hexdigest()
    dataset_ref = by_name["Click log"]["bom-ref"]
    assert document["dependencies"] == [
        {"ref": dataset_ref, "dependsOn": [model["asset_id"]]}
    ]
    # Deterministic serial for an unchanged estate.
    assert ai_bom.export_ai_bom()["serialNumber"] == document["serialNumber"]


def test_bom_requires_model_risk_assurance(tmp_path):
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    with pytest.raises(ai_bom.AIBomError, match="model_risk_assurance"):
        ai_bom.export_ai_bom()


def test_neighbourhood_projection_reads_identity_and_scans_once():
    from maverick import model_risk_assurance as mra

    officer = mra.ModelRiskAssuranceOfficer()
    stamp = time.time()
    model = officer.observe_asset(
        asset_type="model", source="bom_test", source_id="ranker",
        display_name="Ranking model",
        version_digest=hashlib.sha256(b"ranker-v1").hexdigest(),
        actor="inventory-operator", observed_at=stamp,
        metadata={}, dependencies=[],
    )
    dataset = officer.observe_asset(
        asset_type="dataset", source="bom_test", source_id="clicks",
        display_name="Click log",
        version_digest=hashlib.sha256(b"clicks-v1").hexdigest(),
        actor="inventory-operator", observed_at=stamp,
        metadata={}, dependencies=[model["asset_id"]],
    )
    officer.observe_asset(
        asset_type="model", source="bom_test", source_id="unrelated",
        display_name="Unrelated model",
        version_digest=hashlib.sha256(b"other-v1").hexdigest(),
        actor="inventory-operator", observed_at=stamp,
        metadata={}, dependencies=[],
    )

    graph = mra.dependency_graph(asset_id=model["asset_id"])
    ids = {node["asset_id"] for node in graph["nodes"]}
    # The neighbourhood keeps the asset plus its direct dependents --
    # in BOTH directions across the token/id spelling difference.
    assert ids == {model["asset_id"], dataset["asset_id"]}
    assert graph["edge_count"] == 1
    # Node metadata comes from the nested identity sub-dict.
    for node in graph["nodes"]:
        assert node["asset_type"] in {"model", "dataset"}
        assert node["source"] == "bom_test"
    # The pure projection over already-loaded rows is the same graph.
    rows = mra.list_inventory()
    assert mra.dependency_graph_from_rows(
        rows, asset_id=model["asset_id"]) == graph
    # A scoped BOM export keeps the neighbourhood only.
    document = ai_bom.export_ai_bom(asset_id=model["asset_id"])
    assert {c["bom-ref"] for c in document["components"]} == ids
