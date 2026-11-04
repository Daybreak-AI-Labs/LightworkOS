"""Bounded selective qualification through the existing pure native runner.

Components are exact linear root steps. Included workflows run as complete
components with isolated mapped inputs. This is local known-case evidence,
never permission to reuse a connector effect or publish a changed workflow.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import time

from . import learned_operator, runner, semantic_rule_evidence
from .ir import Flow


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False).encode("utf-8")).hexdigest()


def _references(values):
    names = set()
    for value in values:
        if type(value) is str and "{{" in value:
            match = re.fullmatch(r"\{\{\s*([A-Za-z][A-Za-z0-9_]*)\s*\}\}", value)
            if match is None:
                raise ValueError("Use directly named values for this selective check. Expanding or transformed expressions need a complete rerun.")
            names.add(match[1])
    return sorted(names)


def plan(flow, manifest, resolve):
    result, seen, producers = [], set(), {}
    identity = flow.start
    while identity:
        if identity in seen or len(result) >= 64:
            raise ValueError("Selective checks need a linear workflow with at most sixty-four steps.")
        seen.add(identity)
        node = flow.nodes[identity]
        if node.on_error or node.retries or node.timeout or node.retry_backoff:
            raise ValueError("Selective checks do not reuse retries, waiting or error-recovery routes.")
        if node.kind == "agent":
            artifact = (node.learned_operator or {}).get("artifact", {})
            if artifact.get("schema") != learned_operator.SCHEMA or node.learned_fallback is not False:
                raise ValueError("Use bounded taught rules with AI fallback off for each root work step.")
            reads, writes = sorted(artifact["spec"]["inputs"]), [node.output]
        elif node.kind == "setvar":
            reads, writes = _references(node.assignments.values()), list(node.assignments)
        elif node.kind == "subflow":
            if not node.subflow_inputs or not node.output:
                raise ValueError("Give each included workflow named inputs and a named result before selective checking.")
            reads, writes = _references(node.subflow_inputs.values()), [node.output]
        else:
            raise ValueError("Selective checks support a linear root of taught rules, set-value steps and included rule workflows. Other routes use the complete comparison controls.")
        children = {}
        def include(key, children=children):
            if key in children:
                return
            child = resolve(key)
            if child is None or key not in manifest:
                raise ValueError("An exact included workflow is unavailable.")
            children[key] = manifest[key]
            for entry in child.nodes.values():
                if entry.kind == "subflow":
                    include(entry.flow_ref)
        if node.kind == "subflow":
            include(node.flow_ref)
        material = node.to_dict()
        # A route belongs to the full graph. Component evidence binds the exact
        # computation, generation and included immutable versions instead.
        material["next"] = None
        result.append({"id": identity, "label": node.label or ("Taught result" if node.kind == "agent" else "Set business values" if node.kind == "setvar" else "Included workflow"),
            "source": digest([flow.revision, material, children]), "reads": reads,
            "writes": writes, "depends_on": sorted({producers[name] for name in reads if name in producers})})
        for name in writes:
            producers[name] = identity
        identity = node.next
    if seen != set(flow.nodes):
        raise ValueError("Every root step must belong to one complete linear route for selective checking.")
    return result


def evaluate(flow, manifest, inputs, *, resolve, guard, budget, original, evidence=None, semantic_reuse=False):
    """Run actual native components, or reuse one exact independently valid result."""
    components = plan(flow, manifest, resolve)
    data, results = copy.deepcopy(inputs), []
    prior = {item["id"]: item for item in (evidence or [])}
    started = time.perf_counter()
    native_steps = [0]
    def observe(*_args):
        native_steps[0] += 1
        budget.check()
        if native_steps[0] > 512:
            raise ValueError("This selective check exceeded its bounded local step allowance.")
    def refuse(*_args):
        raise ValueError("Selective checks never call AI or connected actions.")
    for component in components:
        budget.check()
        guard()
        dependencies = {name: {"present": name in data, "value": copy.deepcopy(data.get(name))} for name in component["reads"]}
        old = prior.get(component["id"])
        semantic = semantic_rule_evidence.behavior(flow, component, guard=guard, budget=budget,
            observe=observe, original=original) if semantic_reuse else None
        same_behavior = bool(old and semantic_rule_evidence.matches(old.get("semantic"), semantic))
        reusable = bool(old and old["status"] == runner.STATUS_COMPLETED
            and (old["source"] == component["source"] or same_behavior) and digest(old["inputs"]) == digest(dependencies))
        if reusable:
            data.update(copy.deepcopy(old["outputs"]))
            status = runner.STATUS_COMPLETED
            reason = "Complete supported input behavior and current case permission match" if same_behavior and old["source"] != component["source"] else "Exact component, inputs and current source permission match"
        else:
            node = copy.deepcopy(flow.nodes[component["id"]])
            node.next = None
            unit = Flow(id=flow.id, name=flow.name, owner=flow.owner, version=flow.version,
                revision=flow.revision, start=node.id, nodes={node.id: node}, max_seconds=flow.max_seconds)
            value = runner.run_flow(unit, data=data, agent_fn=refuse, action_fn=refuse,
                resolve_flow=resolve, run_id=original, on_node=observe)
            status, data = value.status, value.data
            reason = "No retained successful component" if old is None else "Component or included source changed" if old["source"] != component["source"] else "Dependency values changed"
        guard()
        budget.check()
        outputs = {name: copy.deepcopy(data[name]) for name in component["writes"] if name in data}
        if len(json.dumps(outputs, ensure_ascii=False, allow_nan=False).encode("utf-8")) > 16384:
            raise ValueError("A component result exceeds the bounded selective evidence size. Use a complete workflow comparison.")
        results.append({**component, "inputs": dependencies, "outputs": outputs, "status": status,
                        "reused": reusable, "reason": reason, **({"semantic": semantic} if semantic is not None else {})})
        if status != runner.STATUS_COMPLETED:
            return {"status": status, "data": data, "components": results, "native_steps": native_steps[0],
                    "elapsed_ms": (time.perf_counter() - started) * 1000}
    return {"status": runner.STATUS_COMPLETED, "data": data, "components": results,
            "native_steps": native_steps[0], "elapsed_ms": (time.perf_counter() - started) * 1000}


def complete(flow, inputs, *, resolve, guard, budget, original):
    steps = [0]
    def observe(*_args):
        steps[0] += 1
        guard()
        budget.check()
        if steps[0] > 512:
            raise ValueError("The complete rerun exceeded its bounded local step allowance.")
    def refuse(*_args):
        raise ValueError("The complete rule rerun never calls AI or a connected action.")
    guard()
    started = time.perf_counter()
    value = runner.run_flow(flow, data=inputs, agent_fn=refuse, action_fn=refuse,
        resolve_flow=resolve, run_id=original, on_node=observe)
    guard()
    budget.check()
    return {"status": value.status, "data": value.data, "native_steps": steps[0],
            "elapsed_ms": (time.perf_counter() - started) * 1000}
