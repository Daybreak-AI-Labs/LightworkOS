"""Budgeted clade-metaproductive search for config-only evolution.

The original config search chooses parents from immediate benchmark scores.
That is deliberately simple, but it can abandon a mediocre-looking ancestor
whose descendants are unusually productive.  This module adds an experimental
tree-search policy inspired by HGM's clade-metaproductivity estimator:

* expansion and evaluation have separate, explicit budgets;
* every agent/case observation is recorded at most once;
* parent selection uses the aggregate Beta posterior of the complete clade;
* evaluation selection uses node-level posteriors and prioritises unevaluated
  nodes, so a newly expanded branch cannot be starved before it is measured;
* final selection uses a conservative Wilson lower bound rather than the
  largest noisy point estimate.

This is a development-search policy, not promotion evidence.  A caller must
still freeze one champion and pass it through an independent sealed
confirmation boundary before adoption.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import math
import random
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from .archive import Candidate
from .eval_harness import EvalCase

_MAX_CASE_MANIFEST_BYTES = 8 * 1024 * 1024


class MetaproductiveSearchError(RuntimeError):
    """The search could not maintain trustworthy development evidence."""


def _bounded_count(value: int, *, label: str, minimum: int = 0,
                   maximum: int = 1_000_000) -> int:
    if (not isinstance(value, int) or isinstance(value, bool)
            or not minimum <= value <= maximum):
        raise ValueError(f"{label} must be an integer in [{minimum}, {maximum}]")
    return value


def _wilson_lower(successes: float, observations: int, z: float) -> float:
    if observations <= 0:
        return float("-inf")
    rate = max(0.0, min(1.0, successes / observations))
    z2 = z * z
    denominator = 1.0 + z2 / observations
    centre = rate + z2 / (2.0 * observations)
    margin = z * math.sqrt(
        (rate * (1.0 - rate) + z2 / (4.0 * observations)) / observations)
    return (centre - margin) / denominator


def _beta_draw(rng: random.Random | Any, alpha: float, beta: float) -> float:
    try:
        raw = rng.betavariate(alpha, beta)
    except (AttributeError, OverflowError, TypeError, ValueError) as exc:
        raise ValueError("random source could not produce a beta draw") from exc
    if isinstance(raw, bool):
        raise ValueError("random source returned an invalid beta draw")
    try:
        draw = float(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("random source returned an invalid beta draw") from exc
    if not math.isfinite(draw) or not 0.0 <= draw <= 1.0:
        raise ValueError("random source returned an invalid beta draw")
    return draw


def _unit_draw(rng: random.Random | Any) -> float:
    try:
        raw = rng.random()
    except (AttributeError, OverflowError, TypeError, ValueError) as exc:
        raise ValueError("random source could not produce a uniform draw") from exc
    if isinstance(raw, bool):
        raise ValueError("random source returned an invalid uniform draw")
    try:
        draw = float(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("random source returned an invalid uniform draw") from exc
    if not math.isfinite(draw) or not 0.0 <= draw < 1.0:
        raise ValueError("random source returned an invalid uniform draw")
    return draw


def _automatic_case_manifest(cases: tuple[Any, ...]) -> str | None:
    """Return a content digest only for unambiguous canonical-JSON cases.

    Arbitrary evaluator cases can contain callables or process-local objects;
    their ``repr`` is not a durable identity. Even this digest does not identify
    evaluator semantics, so it only strengthens an explicit ``case_family_id``.
    """

    def canonicalize(value: object, *, depth: int = 0) -> object:
        if depth > 64:
            raise ValueError("development cases exceed the maximum nesting depth")
        if value is None or isinstance(value, (str, bool, int)):
            return value
        if isinstance(value, float):
            if not math.isfinite(value):
                raise ValueError("development case numbers must be finite")
            return value
        if isinstance(value, EvalCase):
            if (not isinstance(value.prompt, str) or not value.prompt.strip()
                    or value.reference is not None
                    and not isinstance(value.reference, str)
                    or value.check is not None and not callable(value.check)
                    or isinstance(value.weight, bool)
                    or not isinstance(value.weight, (int, float))
                    or not math.isfinite(float(value.weight))):
                raise ValueError("EvalCase cannot be canonically identified")
            return {
                "type": "EvalCase",
                "prompt": value.prompt,
                "reference": value.reference,
                "weight": float(value.weight),
                "uses_callable_check": value.check is not None,
            }
        if isinstance(value, (list, tuple)):
            return [canonicalize(item, depth=depth + 1) for item in value]
        if isinstance(value, dict):
            if any(not isinstance(key, str) for key in value):
                raise ValueError("development case keys must be strings")
            return {
                key: canonicalize(item, depth=depth + 1)
                for key, item in value.items()
            }
        raise TypeError("development case is not canonical JSON")

    try:
        canonical = canonicalize(cases)
        blob = json.dumps(
            canonical, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")
    except (RecursionError, TypeError, ValueError):
        return None
    if len(blob) > _MAX_CASE_MANIFEST_BYTES:
        return None
    return hashlib.sha256(b"maverick-case-manifest-v1\0" + blob).hexdigest()


def _case_family_digest(
    cases: tuple[Any, ...], case_family_id: str | None,
) -> str | None:
    if case_family_id is None:
        # Case contents alone do not bind the evaluator/scorer version. Refuse
        # to make such evidence resumable under a misleading partial identity.
        return None
    if (not isinstance(case_family_id, str) or len(case_family_id) != 64
            or any(character not in "0123456789abcdef"
                   for character in case_family_id)):
        raise ValueError(
            "case_family_id must be a full SHA-256 digest covering evaluator semantics")
    manifest = _automatic_case_manifest(cases)
    if manifest is None:
        # An external declaration cannot prove which opaque Python objects were
        # evaluated. The run may proceed, but its observations are deliberately
        # non-resumable and cannot become stale authority after a restart.
        return None
    material = (
        b"maverick-explicit-case-family-v1\0"
        + case_family_id.encode("utf-8")
        + b"\0"
        + (manifest.encode("ascii") if manifest is not None else b"noncanonical")
    )
    return hashlib.sha256(material).hexdigest()


@dataclass
class CladeNode:
    """One immutable config node plus its development-task observations."""

    candidate: Candidate
    parent_id: str | None = None
    children: list[str] = field(default_factory=list)
    successes: float = 0.0
    failures: float = 0.0
    evaluated_cases: set[int] = field(default_factory=set)
    expansion_attempts: int = 0

    @property
    def observations(self) -> int:
        return len(self.evaluated_cases)

    @property
    def mean(self) -> float:
        total = self.successes + self.failures
        return self.successes / total if total > 0 else 0.0


@dataclass
class MetaproductiveArchive:
    """In-memory lineage tree with clade-level posterior accounting.

    Nodes are never evicted: doing so would silently change every ancestor's
    clade statistic.  ``capacity`` is therefore a hard expansion ceiling.
    Persistent publication remains the responsibility of the ordinary
    checksummed :class:`~maverick_evolve.archive.Archive` *after* confirmation.
    """

    capacity: int = 50
    nodes: dict[str, CladeNode] = field(default_factory=dict)
    root_id: str | None = None
    case_count: int | None = field(default=None, repr=False)
    case_family_digest: str | None = field(default=None, repr=False)
    allow_fractional_outcomes: bool = False

    def __post_init__(self) -> None:
        _bounded_count(self.capacity, label="capacity", minimum=1, maximum=10_000)
        if not isinstance(self.nodes, dict):
            raise ValueError("metaproductive nodes must be a mapping")
        if not isinstance(self.allow_fractional_outcomes, bool):
            raise ValueError("allow_fractional_outcomes must be boolean")
        self._validate_tree()

    def _validate_case_binding(self) -> None:
        if self.case_count is not None:
            _bounded_count(self.case_count, label="case_count", minimum=1)
        if self.case_family_digest is not None:
            if (self.case_count is None
                    or not isinstance(self.case_family_digest, str)
                    or len(self.case_family_digest) != 64
                    or any(character not in "0123456789abcdef"
                           for character in self.case_family_digest)):
                raise ValueError("metaproductive case-family identity is invalid")

    def _validate_node_structure(
        self, node_id: object, node: object,
    ) -> str | None:
        if (not isinstance(node_id, str) or not isinstance(node, CladeNode)
                or not isinstance(node.candidate, Candidate)
                or node.candidate.id != node_id):
            raise ValueError("metaproductive archive node identity is invalid")
        node.candidate.validate_identity()
        if node.parent_id is not None and not isinstance(node.parent_id, str):
            raise ValueError("metaproductive archive parent is invalid")
        if node.parent_id is None and node_id != self.root_id:
            raise ValueError("only the root may have no parent")
        if node_id == self.root_id and node.parent_id is not None:
            raise ValueError("metaproductive archive root must not have a parent")
        if node.parent_id is not None and node.parent_id not in self.nodes:
            raise ValueError("metaproductive archive parent is missing")
        if (not isinstance(node.children, list)
                or any(not isinstance(child, str) or child not in self.nodes
                       for child in node.children)
                or len(node.children) != len(set(node.children))):
            raise ValueError("metaproductive archive children are invalid")
        if (not isinstance(node.expansion_attempts, int)
                or isinstance(node.expansion_attempts, bool)
                or not len(node.children) <= node.expansion_attempts <= 1_000_000):
            raise ValueError("metaproductive expansion accounting is invalid")
        return node.parent_id

    def _validate_node_evidence(self, node: CladeNode) -> None:
        if (not isinstance(node.evaluated_cases, set)
                or any(not isinstance(index, int) or isinstance(index, bool)
                       or index < 0 for index in node.evaluated_cases)
                or (self.case_count is not None
                    and any(index >= self.case_count
                            for index in node.evaluated_cases))):
            raise ValueError("metaproductive evaluated cases are invalid")
        if (isinstance(node.successes, bool)
                or not isinstance(node.successes, (int, float))
                or not math.isfinite(float(node.successes)) or node.successes < 0
                or isinstance(node.failures, bool)
                or not isinstance(node.failures, (int, float))
                or not math.isfinite(float(node.failures)) or node.failures < 0
                or abs(node.successes + node.failures - node.observations) > 1e-9):
            raise ValueError("metaproductive node evidence is invalid")
        if (not self.allow_fractional_outcomes
                and (not float(node.successes).is_integer()
                     or not float(node.failures).is_integer())):
            raise ValueError("fractional evidence requires allow_fractional_outcomes")
        expected_score = node.mean if node.observations else 0.0
        if abs(node.candidate.score - expected_score) > 1e-12:
            raise ValueError("metaproductive candidate score disagrees with evidence")

    def _validate_tree(self) -> None:
        _bounded_count(self.capacity, label="capacity", minimum=1, maximum=10_000)
        if not isinstance(self.nodes, dict):
            raise ValueError("metaproductive nodes must be a mapping")
        if not isinstance(self.allow_fractional_outcomes, bool):
            raise ValueError("allow_fractional_outcomes must be boolean")
        self._validate_case_binding()
        if len(self.nodes) > self.capacity:
            raise ValueError("metaproductive archive exceeds capacity")
        if not self.nodes:
            if self.root_id is not None:
                raise ValueError("empty metaproductive archive has a root id")
            return
        if not isinstance(self.root_id, str) or self.root_id not in self.nodes:
            raise ValueError("metaproductive archive root is missing")
        expected_children: dict[str, set[str]] = {
            node_id: set() for node_id in self.nodes
        }
        for node_id, node in self.nodes.items():
            parent_id = self._validate_node_structure(node_id, node)
            if parent_id is not None:
                expected_children[parent_id].add(node_id)
            self._validate_node_evidence(node)

        for node_id, node in self.nodes.items():
            if set(node.children) != expected_children[node_id]:
                raise ValueError("metaproductive parent/child links disagree")

        # Linear traversal proves connectivity and cycle-freedom. The previous
        # per-node parent walk was quadratic on a long adversarial lineage.
        visited: set[str] = set()
        stack = [self.root_id]
        while stack:
            current = stack.pop()
            if current in visited:
                raise ValueError("metaproductive archive contains a cycle")
            visited.add(current)
            stack.extend(self.nodes[current].children)
        if visited != set(self.nodes):
            raise ValueError("metaproductive node is disconnected from the root")

    def bind_case_manifest(
        self, case_count: int, case_family_digest: str | None,
    ) -> None:
        """Bind observations to one manifest, refusing ambiguous resumption."""
        case_count = _bounded_count(case_count, label="case_count", minimum=1)
        if case_family_digest is not None and (
                not isinstance(case_family_digest, str)
                or len(case_family_digest) != 64
                or any(character not in "0123456789abcdef"
                       for character in case_family_digest)):
            raise ValueError("case-family digest must be a full SHA-256 digest")
        has_evidence = any(node.observations for node in self.nodes.values())
        if self.case_count is None:
            if has_evidence:
                raise ValueError(
                    "cannot bind pre-existing evidence to an unknown case family")
            self.case_count = case_count
            self.case_family_digest = case_family_digest
        elif self.case_count != case_count:
            raise ValueError("metaproductive archive is bound to a different case count")
        elif self.case_family_digest is None:
            if has_evidence:
                raise ValueError(
                    "cannot resume archive created without an explicit case_family_id")
            self.case_family_digest = case_family_digest
        elif (case_family_digest is None
              or not hmac.compare_digest(
                  self.case_family_digest, case_family_digest)):
            raise ValueError("metaproductive archive is bound to a different case family")
        self._validate_tree()

    def add_root(self, config: dict) -> CladeNode:
        self._validate_tree()
        if not isinstance(config, dict):
            raise ValueError("metaproductive config must be an object")
        candidate = Candidate(config=config)
        if self.nodes:
            if self.root_id == candidate.id:
                return self.nodes[candidate.id]
            raise ValueError("metaproductive archive already has a different root")
        node = CladeNode(candidate=candidate)
        self.nodes[candidate.id] = node
        self.root_id = candidate.id
        return node

    def add_child(self, parent_id: str, config: dict) -> tuple[CladeNode, bool]:
        parent = self._record_expansion_attempt(parent_id)
        if not isinstance(config, dict):
            raise ValueError("metaproductive config must be an object")
        candidate = Candidate(config=config)
        existing = self.nodes.get(candidate.id)
        if existing is not None:
            return existing, False
        if len(self.nodes) >= self.capacity:
            raise ValueError("metaproductive archive capacity reached")
        node = CladeNode(candidate=candidate, parent_id=parent_id)
        self.nodes[candidate.id] = node
        parent.children.append(candidate.id)
        return node, True

    def _record_expansion_attempt(self, parent_id: str) -> CladeNode:
        """Spend one generation attempt before trusting mutation output."""
        self._validate_tree()
        if not isinstance(parent_id, str):
            raise ValueError("metaproductive parent id must be a string")
        parent = self.nodes.get(parent_id)
        if parent is None:
            raise ValueError("metaproductive parent does not exist")
        if parent.expansion_attempts >= 1_000_000:
            raise ValueError("metaproductive expansion accounting limit reached")
        parent.expansion_attempts += 1
        return parent

    def record(self, node_id: str, case_index: int, outcome: float) -> None:
        self._validate_tree()
        if not isinstance(node_id, str):
            raise ValueError("metaproductive node id must be a string")
        node = self.nodes.get(node_id)
        if node is None:
            raise ValueError("metaproductive node does not exist")
        if (not isinstance(case_index, int) or isinstance(case_index, bool)
                or case_index < 0):
            raise ValueError("case index must be a non-negative integer")
        if self.case_count is not None and case_index >= self.case_count:
            raise ValueError("case index is outside the bound development manifest")
        if case_index in node.evaluated_cases:
            raise ValueError("an agent/case pair may be evaluated only once")
        if (isinstance(outcome, bool) or not isinstance(outcome, (int, float))
                or not math.isfinite(float(outcome))
                or not 0.0 <= float(outcome) <= 1.0):
            raise ValueError("case outcome must be finite and in [0, 1]")
        value = float(outcome)
        if not self.allow_fractional_outcomes and value not in (0.0, 1.0):
            raise ValueError(
                "case outcome must be binary unless fractional mode is enabled")
        node.evaluated_cases.add(case_index)
        node.successes += value
        node.failures += 1.0 - value
        node.candidate.score = node.mean

    def descendants(self, node_id: str) -> tuple[CladeNode, ...]:
        self._validate_tree()
        if not isinstance(node_id, str):
            raise ValueError("metaproductive node id must be a string")
        if node_id not in self.nodes:
            raise ValueError("metaproductive node does not exist")
        result: list[CladeNode] = []
        stack = [node_id]
        while stack:
            current = stack.pop()
            node = self.nodes[current]
            result.append(node)
            stack.extend(sorted(node.children, reverse=True))
        return tuple(result)

    def _clade_evidence_map(self) -> dict[str, tuple[float, float]]:
        """Compute every subtree's evidence once in deterministic linear time."""
        self._validate_tree()
        if not self.nodes:
            return {}
        order: list[str] = []
        stack = [self.root_id]
        while stack:
            node_id = stack.pop()
            order.append(node_id)
            stack.extend(sorted(self.nodes[node_id].children, reverse=True))
        evidence: dict[str, tuple[float, float]] = {}
        for node_id in reversed(order):
            node = self.nodes[node_id]
            child_ids = sorted(node.children)
            evidence[node_id] = (
                node.successes + math.fsum(
                    evidence[child_id][0] for child_id in child_ids),
                node.failures + math.fsum(
                    evidence[child_id][1] for child_id in child_ids),
            )
        return evidence

    def clade_evidence(self, node_id: str) -> tuple[float, float]:
        evidence = self._clade_evidence_map()
        if not isinstance(node_id, str):
            raise ValueError("metaproductive node id must be a string")
        if node_id not in evidence:
            raise ValueError("metaproductive node does not exist")
        return evidence[node_id]

    def select_parent(self, rng: random.Random | Any) -> CladeNode:
        """Thompson-sample the most promising complete clade.

        A diminishing expansion-attempt penalty keeps a parent that repeatedly
        emits duplicate configs from monopolising the mutation budget. New
        descendant evidence is still aggregated into the clade posterior.
        """
        self._validate_tree()
        if not self.nodes:
            raise ValueError("cannot select from an empty metaproductive archive")
        evidence = self._clade_evidence_map()
        scored = []
        for node_id in sorted(self.nodes):
            node = self.nodes[node_id]
            successes, failures = evidence[node_id]
            draw = _beta_draw(rng, 1.0 + successes, 1.0 + failures)
            # Repeatedly expanding a parent that emits only duplicate configs is
            # not open-ended exploration. Discount its sampled promise until a
            # different clade gets a turn; fresh descendant evidence can still
            # lift the clade again on later draws.
            adjusted = draw / math.sqrt(1.0 + node.expansion_attempts)
            scored.append((adjusted, draw, node.candidate.id, node))
        return max(scored, key=lambda item: item[:3])[3]

    def select_for_evaluation(self, case_count: int,
                              rng: random.Random | Any) -> CladeNode | None:
        case_count = _bounded_count(case_count, label="case_count", minimum=1)
        self._validate_tree()
        if self.case_count is not None and self.case_count != case_count:
            raise ValueError("metaproductive archive is bound to a different case count")
        eligible = [
            self.nodes[node_id] for node_id in sorted(self.nodes)
            if self.nodes[node_id].observations < case_count
        ]
        if not eligible:
            return None
        unobserved = [node for node in eligible if node.observations == 0]
        if unobserved:
            # Stable tie order plus RNG selection keeps seeded runs reproducible.
            ordered = sorted(unobserved, key=lambda node: node.candidate.id)
            return ordered[int(_unit_draw(rng) * len(ordered))]
        scored = [
            (_beta_draw(rng, 1.0 + node.successes, 1.0 + node.failures),
             -node.observations, node.candidate.id, node)
            for node in eligible
        ]
        return max(scored, key=lambda item: item[:3])[3]

    def next_case(self, node: CladeNode, case_count: int,
                  rng: random.Random | Any) -> int:
        case_count = _bounded_count(case_count, label="case_count", minimum=1)
        self._validate_tree()
        if self.case_count is not None and self.case_count != case_count:
            raise ValueError("metaproductive archive is bound to a different case count")
        if (not isinstance(node, CladeNode)
                or not isinstance(node.candidate, Candidate)
                or self.nodes.get(node.candidate.id) is not node):
            raise ValueError("metaproductive node does not belong to this archive")
        remaining = [index for index in range(case_count)
                     if index not in node.evaluated_cases]
        if not remaining:
            raise ValueError("metaproductive node has no unevaluated cases")
        return remaining[int(_unit_draw(rng) * len(remaining))]

    def best_belief(self, *, z: float = 1.96) -> Candidate:
        self._validate_tree()
        if not self.nodes:
            raise ValueError("cannot select from an empty metaproductive archive")
        if (isinstance(z, bool) or not isinstance(z, (int, float))
                or not math.isfinite(float(z)) or float(z) < 0):
            raise ValueError("best-belief z must be finite and non-negative")
        observed = [node for node in self.nodes.values() if node.observations]
        if not observed:
            root = self.nodes[self.root_id].candidate
            return Candidate(config=root.config, score=root.score)
        best = max(
            observed,
            key=lambda node: (
                _wilson_lower(node.successes, node.observations, float(z)),
                node.mean,
                node.observations,
                node.candidate.id,
            ),
        ).candidate
        # Do not give a caller a mutable handle into the evidence archive.
        return Candidate(config=best.config, score=best.score)


CaseEvaluator = Callable[[dict, Any], Awaitable[float]]


def _expand_once(
    archive: MetaproductiveArchive,
    parent: CladeNode,
    mutate: Callable[[dict], dict],
) -> tuple[CladeNode, bool]:
    """Run one paid mutation attempt and preserve its accounting on failure."""
    try:
        child_config = mutate(copy.deepcopy(parent.candidate.config))
    except Exception as exc:
        archive._record_expansion_attempt(parent.candidate.id)
        raise MetaproductiveSearchError(
            "metaproductive mutator failed; search aborted") from exc
    try:
        # ``add_child`` records the attempt before validating mutation output,
        # so malformed/duplicate configs cannot receive a free retry on resume.
        return archive.add_child(parent.candidate.id, child_config)
    except (TypeError, ValueError) as exc:
        raise MetaproductiveSearchError(
            "metaproductive expansion produced an invalid config") from exc


async def evolve_metaproductive(
    seed_config: dict,
    mutate: Callable[[dict], dict],
    evaluate_case: CaseEvaluator,
    cases: Sequence[Any],
    *,
    evaluation_budget: int,
    expansion_budget: int = 10,
    evaluations_per_expansion: int = 2,
    min_observations_before_expansion: int = 1,
    best_belief_z: float = 1.96,
    archive: MetaproductiveArchive | None = None,
    rng: random.Random | None = None,
    case_family_id: str | None = None,
    allow_fractional_outcomes: bool = False,
) -> Candidate:
    """Search a config tree under separate task-evaluation/expansion budgets.

    The case sequence is snapshotted and never exposed to ``mutate``.  Evaluator
    errors and malformed outcomes abort the search instead of being converted to
    apparently meaningful negative evidence.  This prevents an infrastructure
    outage from reshaping the lineage policy.
    """
    evaluation_budget = _bounded_count(
        evaluation_budget, label="evaluation_budget", minimum=1)
    expansion_budget = _bounded_count(
        expansion_budget, label="expansion_budget", minimum=0)
    evaluations_per_expansion = _bounded_count(
        evaluations_per_expansion, label="evaluations_per_expansion", minimum=1)
    min_observations_before_expansion = _bounded_count(
        min_observations_before_expansion,
        label="min_observations_before_expansion", minimum=0)
    if not isinstance(allow_fractional_outcomes, bool):
        raise ValueError("allow_fractional_outcomes must be boolean")
    try:
        # Both the stored manifest and every evaluator call receive detached
        # values. A stateful evaluator cannot rewrite later tasks or evidence.
        case_snapshot = tuple(copy.deepcopy(case) for case in cases)
    except Exception as exc:
        raise ValueError("development cases could not be safely snapshotted") from exc
    if not case_snapshot:
        raise ValueError("metaproductive search requires development cases")
    rng = rng or random.Random()
    if archive is None:
        archive = MetaproductiveArchive(
            capacity=max(1, expansion_budget + 1),
            allow_fractional_outcomes=allow_fractional_outcomes,
        )
    elif not isinstance(archive, MetaproductiveArchive):
        raise ValueError("archive must be a MetaproductiveArchive")
    elif archive.allow_fractional_outcomes != allow_fractional_outcomes:
        raise ValueError(
            "archive fractional-outcome mode disagrees with the search request")
    archive.add_root(seed_config)
    archive.bind_case_manifest(
        len(case_snapshot), _case_family_digest(case_snapshot, case_family_id))

    evaluations = sum(node.observations for node in archive.nodes.values())
    expansions = sum(
        node.expansion_attempts for node in archive.nodes.values())
    if evaluations > evaluation_budget or expansions > expansion_budget:
        raise ValueError("existing metaproductive archive exceeds the run budget")

    while evaluations < evaluation_budget:
        all_seeded = all(
            node.observations >= min_observations_before_expansion
            for node in archive.nodes.values())
        expansion_due = (
            expansions < expansion_budget
            and len(archive.nodes) < archive.capacity
            and all_seeded
            and evaluations >= (expansions + 1) * evaluations_per_expansion
        )
        if expansion_due:
            parent = archive.select_parent(rng)
            _node, added = _expand_once(archive, parent, mutate)
            expansions += 1
            # A duplicate still consumes an expansion budget unit: generation
            # work was spent and retrying for free would violate equal budgets.
            if added:
                continue

        node = archive.select_for_evaluation(len(case_snapshot), rng)
        if node is None:
            if expansions >= expansion_budget or len(archive.nodes) >= archive.capacity:
                break
            # Every existing node is fully evaluated. Force the next expansion
            # without manufacturing another task observation.
            parent = archive.select_parent(rng)
            _node, _added = _expand_once(archive, parent, mutate)
            expansions += 1
            continue

        case_index = archive.next_case(node, len(case_snapshot), rng)
        try:
            outcome = await evaluate_case(
                copy.deepcopy(node.candidate.config),
                copy.deepcopy(case_snapshot[case_index]),
            )
            archive.record(node.candidate.id, case_index, outcome)
        except Exception as exc:
            raise MetaproductiveSearchError(
                "development evaluator failed; metaproductive search aborted") from exc
        evaluations += 1

    return archive.best_belief(z=best_belief_z)


__all__ = [
    "CladeNode",
    "MetaproductiveArchive",
    "MetaproductiveSearchError",
    "evolve_metaproductive",
]
