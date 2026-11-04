"""Native evidence distinguishes cumulative observations from latest-only state."""
from __future__ import annotations

import copy
import time

import pytest
from maverick.flow import action_recipe_transforms, recipe_lineage, store, workflow_transducer

from test_support.action_episode_native import native as native
from test_support.workflow_memory_native import ALLOWED, DOMAIN, SEEDS
from test_support.workflow_memory_native import memory_native as memory_native


def validate(h, package):
    recipe_lineage.validate_package(package, trust=h.trust(), expected_tenant=h.context.tenant, now=time.time())


def test_signed_actual_prefixes_prove_latest_only_collision_and_memory_resolution(memory_native):
    from maverick.flow import workflow_memory

    h = memory_native
    assert h.counts() == sum(len(quantities) for _, quantities in SEEDS)
    validate(h, h.package)
    episodes = h.package["artifact"]["episodes"]
    by_quantities = {tuple(step["result"]["quantity"] for step in episode["steps"]): episode for episode in episodes}
    finished, continues = by_quantities[(2, 3)], by_quantities[(1, 3, 1)]
    assert finished["inputs"] == continues["inputs"] == {"target": 5}
    left, right = finished["steps"][:2], continues["steps"][:2]
    assert workflow_transducer._state(left) == workflow_transducer._state(right)
    catalog = workflow_transducer._catalog(workflow_transducer._state(left), DOMAIN)
    assert workflow_transducer._flat(catalog, finished["inputs"], left) == workflow_transducer._flat(
        catalog, continues["inputs"], right)
    # This is an actual contradiction, not just failure to search far enough.
    with pytest.raises(ValueError, match="no composed program"):
        workflow_transducer.synthesize(episodes, allowed_tools=ALLOWED, domain=DOMAIN,
            max_operations=2, operators=["if", "le", "lt"], constants=[0])
    stop = workflow_memory.resolve_next(h.package["artifact"], finished["inputs"], left)
    more = workflow_memory.resolve_next(h.package["artifact"], continues["inputs"], right)
    assert stop.applied and stop.kind == "complete"
    assert more.applied and more.kind == "action" and more.arguments == {"target": 5}
    for bundle in h.bundles:
        body = bundle["body"]
        assert body["review"]["authenticated"] is True and body["review"]["accepted"] is True
        source = store.load_run(body["source"]["run_id"], owner="reviewer")
        assert source.status == "completed"
        assert len({step["call_id"] for step in body["steps"]}) == len(body["episode"]["steps"])


def test_signed_memory_refinement_preserves_original_and_complete_ancestry(memory_native):
    h = memory_native
    before = copy.deepcopy(h.package)
    extra = h.capture("refinement", 7, [2, 2, 3])
    refined = recipe_lineage.refine_package(h.package, [extra], trust=h.trust(),
        expected_tenant=h.context.tenant, now=time.time())
    validate(h, refined)
    assert h.package == before
    assert refined["artifact"]["grammar"] == before["artifact"]["grammar"]
    assert refined["artifact"]["max_steps"] == before["artifact"]["max_steps"]
    assert refined["artifact"]["episode_count"] == len(SEEDS) + 1
    assert refined["ancestors"] == [{"package_sha256": before["package_sha256"],
                                     "artifact_sha256": before["artifact"]["artifact_sha256"]}]
    admitted = h.lineage.admit(h.context, refined)
    assert h.lineage.get(h.context, admitted["id"], detail=True)["package"] == refined
    changed = copy.deepcopy(refined)
    changed["ancestors"][0]["artifact_sha256"] = "0" * 64
    changed.pop("package_sha256")
    changed["package_sha256"] = recipe_lineage._digest(changed)
    with pytest.raises(ValueError, match="parent"):
        validate(h, changed)


def test_valid_source_signatures_cannot_authorize_deleted_memory_alternatives(memory_native):
    h = memory_native
    changed = copy.deepcopy(h.package)
    # Keep signed sources untouched; forge only the supposedly derived model.
    changed["artifact"]["models"].pop()
    changed["artifact"]["model_count"] -= 1
    changed["artifact"].pop("artifact_sha256")
    changed["artifact"]["artifact_sha256"] = action_recipe_transforms._digest(changed["artifact"])
    changed.pop("package_sha256")
    changed["package_sha256"] = recipe_lineage._digest(changed)
    with pytest.raises(ValueError):
        validate(h, changed)
    with pytest.raises(ValueError):
        h.lineage.admit(h.context, changed)
    assert h.lineage.records.count() == 1
