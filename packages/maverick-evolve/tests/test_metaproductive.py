from __future__ import annotations

import copy
import random

import pytest
from maverick_evolve.eval_harness import EvalCase
from maverick_evolve.metaproductive import (
    MetaproductiveArchive,
    MetaproductiveSearchError,
    evolve_metaproductive,
)

_CASE_FAMILY_ID = "a" * 64


class _PosteriorMeanRng:
    """Deterministic stand-in: Thompson draws equal posterior means."""

    @staticmethod
    def betavariate(alpha, beta):
        return alpha / (alpha + beta)

    @staticmethod
    def random():
        return 0.0


@pytest.mark.parametrize("config", [42, {"v": float("inf")}, {"v": (1, 2)}])
def test_archive_rejects_non_object_or_noncanonical_config(config):
    archive = MetaproductiveArchive()
    with pytest.raises(ValueError, match="config"):
        archive.add_root(config)


@pytest.mark.asyncio
@pytest.mark.parametrize("cases", [None, 42, object()])
async def test_search_rejects_non_iterable_cases_before_evaluator(cases):
    calls = []

    async def evaluate_case(_config, case):
        calls.append(case)
        return 1.0

    with pytest.raises(ValueError, match="safely snapshotted"):
        await evolve_metaproductive(
            {"v": 1}, lambda config: config, evaluate_case, cases,
            evaluation_budget=1, expansion_budget=0,
        )
    assert calls == []


def test_parent_selection_uses_descendant_productivity_not_node_score():
    archive = MetaproductiveArchive(capacity=5)
    root = archive.add_root({"branch": "root"})
    weak, _ = archive.add_child(root.candidate.id, {"branch": "weak"})
    strong, _ = archive.add_child(root.candidate.id, {"branch": "strong"})
    productive, _ = archive.add_child(weak.candidate.id, {"branch": "productive"})

    # The weak ancestor itself fails, while its descendant repeatedly succeeds.
    archive.record(weak.candidate.id, 0, 0.0)
    archive.record(productive.candidate.id, 0, 1.0)
    archive.record(productive.candidate.id, 1, 1.0)
    archive.record(productive.candidate.id, 2, 1.0)
    # The competing node has a better immediate score than the weak ancestor,
    # but a worse complete-clade posterior.
    archive.record(strong.candidate.id, 0, 1.0)
    archive.record(strong.candidate.id, 1, 0.0)

    selected = archive.select_parent(_PosteriorMeanRng())
    assert selected.candidate.id == productive.candidate.id
    assert selected.candidate.id != strong.candidate.id


def test_best_belief_rejects_one_lucky_observation():
    archive = MetaproductiveArchive(capacity=3)
    root = archive.add_root({"name": "root"})
    lucky, _ = archive.add_child(root.candidate.id, {"name": "lucky"})
    supported, _ = archive.add_child(root.candidate.id, {"name": "supported"})
    archive.record(lucky.candidate.id, 0, 1.0)
    for index, outcome in enumerate([1.0] * 8 + [0.0] * 2):
        archive.record(supported.candidate.id, index, outcome)

    assert archive.best_belief().id == supported.candidate.id


@pytest.mark.asyncio
async def test_search_respects_separate_budgets_and_unique_agent_case_pairs():
    archive = MetaproductiveArchive(capacity=4)
    observed = []

    def mutate(config):
        return {"depth": config.get("depth", 0) + 1}

    async def evaluate_case(config, case):
        observed.append((config["depth"], case))
        return 1.0 if config["depth"] >= 2 else 0.0

    best = await evolve_metaproductive(
        {"depth": 0}, mutate, evaluate_case, tuple(range(8)),
        evaluation_budget=12, expansion_budget=3,
        evaluations_per_expansion=2, archive=archive,
        rng=random.Random(7), best_belief_z=0.0,
    )

    assert len(observed) == 12
    assert len(observed) == len(set(observed))
    assert len(archive.nodes) <= 4
    assert sum(node.expansion_attempts for node in archive.nodes.values()) == 3
    assert best.config["depth"] >= 2


@pytest.mark.asyncio
async def test_duplicate_mutations_consume_expansion_budget():
    archive = MetaproductiveArchive(capacity=5)
    calls = 0

    def mutate(config):
        nonlocal calls
        calls += 1
        return dict(config)

    async def evaluate_case(_config, _case):
        return 1.0

    await evolve_metaproductive(
        {"v": 1}, mutate, evaluate_case, [0, 1, 2, 3],
        evaluation_budget=4, expansion_budget=2,
        evaluations_per_expansion=1, archive=archive,
        rng=random.Random(1), best_belief_z=0.0,
    )
    assert calls == 2
    assert len(archive.nodes) == 1


@pytest.mark.asyncio
async def test_evaluator_failure_aborts_instead_of_poisoning_posterior():
    archive = MetaproductiveArchive(capacity=2)

    async def evaluate_case(_config, _case):
        return float("nan")

    with pytest.raises(MetaproductiveSearchError, match="evaluator failed"):
        await evolve_metaproductive(
            {"v": 1}, lambda config: config, evaluate_case, ["case"],
            evaluation_budget=1, expansion_budget=0, archive=archive,
            rng=random.Random(0),
        )
    root = archive.nodes[archive.root_id]
    assert root.observations == 0


def test_archive_rejects_duplicate_agent_case_observation():
    archive = MetaproductiveArchive()
    root = archive.add_root({"v": 1})
    archive.record(root.candidate.id, 0, 1.0)
    with pytest.raises(ValueError, match="only once"):
        archive.record(root.candidate.id, 0, 0.0)


def test_fractional_evidence_requires_explicit_heuristic_mode():
    archive = MetaproductiveArchive()
    root = archive.add_root({"v": 1})
    with pytest.raises(ValueError, match="binary"):
        archive.record(root.candidate.id, 0, 0.5)

    heuristic = MetaproductiveArchive(allow_fractional_outcomes=True)
    heuristic_root = heuristic.add_root({"v": 1})
    heuristic.record(heuristic_root.candidate.id, 0, 0.5)
    assert heuristic_root.successes == pytest.approx(0.5)
    assert heuristic_root.failures == pytest.approx(0.5)


def test_tree_validation_rejects_reverse_link_corruption_and_cycles():
    archive = MetaproductiveArchive(capacity=3)
    root = archive.add_root({"v": 0})
    child, _ = archive.add_child(root.candidate.id, {"v": 1})
    root.children.clear()
    with pytest.raises(ValueError, match="parent/child links disagree"):
        archive.select_parent(_PosteriorMeanRng())

    root.children.append(child.candidate.id)
    root.parent_id = child.candidate.id
    child.children.append(root.candidate.id)
    with pytest.raises(ValueError, match="root must not have a parent"):
        archive.select_parent(_PosteriorMeanRng())


def test_selection_is_seeded_independent_of_node_mapping_insertion_order():
    first = MetaproductiveArchive(capacity=4)
    root = first.add_root({"v": 0})
    left, _ = first.add_child(root.candidate.id, {"v": 1})
    right, _ = first.add_child(root.candidate.id, {"v": 2})
    first.record(left.candidate.id, 0, 1.0)
    first.record(right.candidate.id, 0, 0.0)

    reordered = copy.deepcopy(first)
    reordered.nodes = dict(reversed(tuple(reordered.nodes.items())))

    selected_first = first.select_parent(random.Random(42)).candidate.id
    selected_reordered = reordered.select_parent(random.Random(42)).candidate.id
    assert selected_first == selected_reordered


class _InvalidRng:
    @staticmethod
    def betavariate(_alpha, _beta):
        return float("nan")

    @staticmethod
    def random():
        return 1.0


def test_selection_rejects_malformed_random_source_outputs():
    archive = MetaproductiveArchive()
    archive.add_root({"v": 1})
    with pytest.raises(ValueError, match="invalid beta draw"):
        archive.select_parent(_InvalidRng())
    with pytest.raises(ValueError, match="invalid uniform draw"):
        archive.select_for_evaluation(1, _InvalidRng())


@pytest.mark.asyncio
async def test_resumption_counts_duplicate_expansion_attempts_against_budget():
    archive = MetaproductiveArchive(capacity=3)
    root = archive.add_root({"v": 1})
    archive.add_child(root.candidate.id, {"v": 1})
    archive.add_child(root.candidate.id, {"v": 1})

    async def evaluate_case(_config, _case):
        return 1.0

    with pytest.raises(ValueError, match="exceeds the run budget"):
        await evolve_metaproductive(
            {"v": 1}, lambda config: config, evaluate_case, [0],
            evaluation_budget=1, expansion_budget=1, archive=archive,
        )


@pytest.mark.asyncio
async def test_failed_mutation_is_still_charged_to_resume_budget():
    archive = MetaproductiveArchive(capacity=2)

    def mutate(_config):
        raise RuntimeError("generator outage")

    async def evaluate_case(_config, _case):
        return 1.0

    with pytest.raises(MetaproductiveSearchError, match="mutator failed"):
        await evolve_metaproductive(
            {"v": 1}, mutate, evaluate_case, [0, 1],
            evaluation_budget=2, expansion_budget=1,
            evaluations_per_expansion=1, archive=archive,
            case_family_id=_CASE_FAMILY_ID,
            rng=random.Random(1),
        )
    root = archive.nodes[archive.root_id]
    assert root.expansion_attempts == 1

    with pytest.raises(ValueError, match="exceeds the run budget"):
        await evolve_metaproductive(
            {"v": 1}, mutate, evaluate_case, [0, 1],
            evaluation_budget=2, expansion_budget=0, archive=archive,
            case_family_id=_CASE_FAMILY_ID,
            rng=random.Random(1),
        )


@pytest.mark.asyncio
async def test_resumption_rejects_same_size_different_case_manifest():
    archive = MetaproductiveArchive(capacity=1)

    async def evaluate_case(_config, _case):
        return 1.0

    await evolve_metaproductive(
        {"v": 1}, lambda config: config, evaluate_case, ["a", "b"],
        evaluation_budget=1, expansion_budget=0, archive=archive,
        rng=random.Random(1), case_family_id=_CASE_FAMILY_ID,
    )
    with pytest.raises(ValueError, match="different case family"):
        await evolve_metaproductive(
            {"v": 1}, lambda config: config, evaluate_case, ["a", "changed"],
            evaluation_budget=2, expansion_budget=0, archive=archive,
            rng=random.Random(1), case_family_id=_CASE_FAMILY_ID,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "replacement",
    [
        lambda: EvalCase(prompt="changed", check=lambda _out: True),
        lambda: EvalCase(
            prompt="dev-b", reference="changed-reference", weight=1.0),
        lambda: EvalCase(prompt="dev-b", check=lambda _out: True, weight=1.01),
    ],
    ids=["prompt", "evaluator-shape", "weight"],
)
async def test_evalcase_resumption_binds_visible_case_identity(replacement):
    archive = MetaproductiveArchive(capacity=1)
    cases = [
        EvalCase(prompt="dev-a", check=lambda _out: True),
        EvalCase(prompt="dev-b", check=lambda _out: True),
    ]

    async def evaluate_case(_config, _case):
        return 1.0

    await evolve_metaproductive(
        {"v": 1}, lambda config: config, evaluate_case, cases,
        evaluation_budget=1, expansion_budget=0, archive=archive,
        rng=random.Random(1), case_family_id=_CASE_FAMILY_ID,
    )
    with pytest.raises(ValueError, match="different case family"):
        await evolve_metaproductive(
            {"v": 1}, lambda config: config, evaluate_case,
            [cases[0], replacement()], evaluation_budget=2,
            expansion_budget=0, archive=archive,
            rng=random.Random(1), case_family_id=_CASE_FAMILY_ID,
        )


@pytest.mark.asyncio
async def test_noncanonical_case_resumption_requires_explicit_family_id():
    archive = MetaproductiveArchive(capacity=1)

    async def evaluate_case(_config, _case):
        return 1.0

    await evolve_metaproductive(
        {"v": 1}, lambda config: config, evaluate_case, [object(), object()],
        evaluation_budget=1, expansion_budget=0, archive=archive,
        rng=random.Random(1),
    )
    with pytest.raises(ValueError, match="without an explicit case_family_id"):
        await evolve_metaproductive(
            {"v": 1}, lambda config: config, evaluate_case, [object(), object()],
            evaluation_budget=2, expansion_budget=0, archive=archive,
            rng=random.Random(1),
        )


@pytest.mark.asyncio
async def test_mutator_and_evaluator_receive_detached_nested_inputs():
    archive = MetaproductiveArchive(capacity=2)
    cases = [{"payload": {"value": 0}}, {"payload": {"value": 0}}]

    def mutate(config):
        config["nested"]["value"] = 1
        return config

    async def evaluate_case(config, case):
        config["nested"]["value"] = 99
        case["payload"]["value"] = 99
        return 1.0

    await evolve_metaproductive(
        {"nested": {"value": 0}}, mutate, evaluate_case, cases,
        evaluation_budget=3, expansion_budget=1,
        evaluations_per_expansion=1, archive=archive,
        rng=random.Random(3),
    )

    root = archive.nodes[archive.root_id]
    assert root.candidate.config == {"nested": {"value": 0}}
    assert cases == [{"payload": {"value": 0}}, {"payload": {"value": 0}}]
    for node in archive.nodes.values():
        node.candidate.validate_identity()


def test_bound_manifest_rejects_out_of_range_case_index():
    archive = MetaproductiveArchive()
    root = archive.add_root({"v": 1})
    archive.bind_case_manifest(1, "a" * 64)
    with pytest.raises(ValueError, match="outside"):
        archive.record(root.candidate.id, 1, 1.0)


def test_best_belief_returns_detached_candidate():
    archive = MetaproductiveArchive()
    root = archive.add_root({"nested": {"value": 1}})
    archive.record(root.candidate.id, 0, 1.0)

    best = archive.best_belief(z=0.0)
    best.config["nested"]["value"] = 999

    assert root.candidate.config == {"nested": {"value": 1}}
    archive.select_parent(_PosteriorMeanRng())
