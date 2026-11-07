"""AI bill of materials: the governed inventory as a CycloneDX ML-BOM.

Exports the model-risk inventory and its dependency edges as a CycloneDX
1.6 JSON document — model components typed ``machine-learning-model``,
datasets typed ``data``, everything else ``application`` — so the AI
estate travels in the format supply-chain tooling already reads. The BOM
is a faithful projection of the governed records: nothing is invented,
and provenance properties carry each asset's source, source id, and
observed version digest.

A transparency artifact for the operator's own estate — never a vendor
attestation or a certification of any component.
"""
from __future__ import annotations

import time
import uuid
from typing import Any

from . import model_risk_assurance as mra

BOM_FORMAT = "CycloneDX"
BOM_SPEC_VERSION = "1.6"

_TYPE_MAP = {
    "model": "machine-learning-model",
    "dataset": "data",
    "data": "data",
}
class AIBomError(RuntimeError):
    """Base failure for the AI-BOM exporter."""


def _rfc3339(stamp: float) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(stamp, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def export_ai_bom(*, asset_id: str | None = None) -> dict[str, Any]:
    """Render the governed inventory as one CycloneDX 1.6 ML-BOM document.

    With ``asset_id``, the BOM keeps that asset plus its direct
    neighbourhood (the same projection as the dependency graph).
    Deterministic apart from the timestamp: component ``bom-ref`` is the
    governed asset id and the serial number derives from the included
    refs, so an unchanged estate re-exports byte-identically minus time.
    """

    if not mra.enabled():
        raise AIBomError(
            "the AI-BOM export requires [model_risk_assurance] enable = true"
        )
    inventory = mra.list_inventory()
    graph = mra.dependency_graph_from_rows(inventory, asset_id=asset_id)
    included_ids = {
        str(node.get("asset_id") or "") for node in graph.get("nodes") or []
    }
    edges = graph.get("edges") or []
    rows = [
        row for row in inventory
        if str(row.get("asset_id") or "") in included_ids
    ]
    components = []
    for node in rows:
        ref = str(node.get("asset_id") or "")
        if not ref:
            continue
        identity = node.get("identity") or {}
        properties = [
            {"name": f"lightwork:{key}", "value": str(identity.get(key))}
            for key in ("source", "source_id", "asset_type")
            if identity.get(key)
        ]
        digest = str(node.get("version_digest") or "")
        component: dict[str, Any] = {
            "type": _TYPE_MAP.get(
                str(identity.get("asset_type") or "").lower(), "application"
            ),
            "bom-ref": ref,
            "name": str(node.get("display_name") or ref),
            "properties": properties,
        }
        if digest:
            component["version"] = digest[:16]
            component["hashes"] = [{"alg": "SHA-256", "content": digest}]
        components.append(component)
    included = {component["bom-ref"] for component in components}
    # Dependencies are stored as normalized tokens (lowercase, ``-`` -> ``_``);
    # resolve them back to the governed asset ids the components carry.
    by_token = {
        ref.lower().replace("-", "_"): ref for ref in included
    }
    depends: dict[str, list[str]] = {}
    for edge in edges:
        parent = str(edge.get("asset_id") or "")
        child = by_token.get(
            str(edge.get("depends_on") or "").lower().replace("-", "_"), ""
        )
        if parent in included and child:
            depends.setdefault(parent, []).append(child)
    serial_seed = ",".join(sorted(included))
    now = time.time()
    return {
        "bomFormat": BOM_FORMAT,
        "specVersion": BOM_SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, serial_seed)}",
        "version": 1,
        "metadata": {
            "timestamp": _rfc3339(now),
            "tools": {
                "components": [
                    {"type": "application", "name": "lightwork",
                     "manufacturer": {"name": "Daybreak AI Labs"}}
                ]
            },
        },
        "components": components,
        "dependencies": [
            {"ref": parent, "dependsOn": sorted(children)}
            for parent, children in sorted(depends.items())
        ],
    }


__all__ = ["AIBomError", "BOM_FORMAT", "BOM_SPEC_VERSION", "export_ai_bom"]
