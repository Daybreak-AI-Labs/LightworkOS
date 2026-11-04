"""Finite local work grouping with separate case obligations and comparisons.

This checks known pure rule cases. It never moves a live approval or reuses a
connector effect. Source authority and retained consent belong to the native
coordinator. There is no claimed advantage over invariant-aware batching.
"""
from __future__ import annotations

import copy
import json
import time

from ..budget import Budget
from . import runner
from .ir import Flow
from .selective_qualification import digest, plan


def obligations(flow, manifest, cases, resolve):
    components = plan(flow, manifest, resolve)
    if not 2 <= len(cases) <= 8 or len({case["id"] for case in cases}) != len(cases):
        raise ValueError("Choose two to eight different retained cases.")
    order = sorted(range(len(cases)), key=lambda index: (cases[index]["deadline"], index))
    # Independently authored same-information batching baseline: enumerate exact
    # source/dependency obligations, not the changed runner's cache decisions.
    distinct, requests = set(), 0
    for case in cases:
        retained = case["components"]
        if len(retained) != len(components):
            raise ValueError("Retained component evidence is incomplete.")
        for current, previous in zip(components, retained, strict=True):
            if (current["id"] != previous["id"] or current["source"] != previous["source"]
                    or previous["status"] != runner.STATUS_COMPLETED):
                raise ValueError("Retained component evidence no longer matches the published work.")
            requests += 1
            distinct.add(digest([case["group"], current["source"], previous["inputs"]]))
    return {"order": order, "components": components, "independent_computations": requests,
            "invariant_batching_computations": len(distinct),
            "meaning": "The batching baseline uses the same exact known component inputs and confidentiality groups. A match does not establish a new algorithm or faster work."}


class WorkLimit(ValueError):
    """The reviewed local effort or case deadline has been reached."""


class Execution:
    def __init__(self, *, guard, max_steps, max_seconds):
        self.guard, self.max_steps, self.steps = guard, max_steps, 0
        self.budget = Budget(max_dollars=0, max_tool_calls=0, max_wall_seconds=max_seconds)

    def check(self, case):
        self.budget.check()
        self.guard()
        self.budget.check()
        if time.time() >= case["deadline"]:
            raise WorkLimit("The selected case's local check deadline has passed. No further work will start.")

    def observe(self, case):
        def observed(*_args):
            self.check(case)
            if self.steps >= self.max_steps:
                raise WorkLimit("The reviewed allowance for local calculation steps has been reached.")
            self.steps += 1
        return observed


def run(flow, manifest, cases, *, resolve, guard, original, max_steps, max_seconds, save_case):
    """Execute grouped components, then an independent unchanged complete run.

    A fresh request starts with an empty cache. Every reused result is from a
    successful calculation performed during this request, under the same full
    reviewed source/permission guard, and within the same declared group.
    """
    selected = obligations(flow, manifest, cases, resolve)
    work = Execution(guard=guard, max_steps=max_steps, max_seconds=max_seconds)
    cache, results = {}, []
    started = time.perf_counter()

    def refuse(*_args):
        raise ValueError("This local grouping check never calls AI or connected actions.")

    for index in selected["order"]:
        case = cases[index]
        work.check(case)
        data, entries, grouped_status = copy.deepcopy(case["inputs"]), [], runner.STATUS_COMPLETED
        case_started, grouped_before = time.perf_counter(), work.steps
        for component in selected["components"]:
            work.check(case)
            dependencies = {name: {"present": name in data, "value": copy.deepcopy(data.get(name))} for name in component["reads"]}
            key = digest([case["group"], component["source"], dependencies])
            prior = cache.get(key)
            if prior is not None:
                data.update(copy.deepcopy(prior["outputs"]))
                status = runner.STATUS_COMPLETED
            else:
                node = copy.deepcopy(flow.nodes[component["id"]])
                node.next = None
                unit = Flow(id=flow.id, name=flow.name, owner=flow.owner, version=flow.version,
                    revision=flow.revision, start=node.id, nodes={node.id: node}, max_seconds=flow.max_seconds)
                calculation = runner.run_flow(unit, data=data, agent_fn=refuse, action_fn=refuse,
                    resolve_flow=resolve, run_id=original, on_node=work.observe(case))
                status, data = calculation.status, calculation.data
            work.check(case)
            outputs = {name: copy.deepcopy(data[name]) for name in component["writes"] if name in data}
            if len(json.dumps(outputs, ensure_ascii=False, allow_nan=False).encode("utf-8")) > 16384:
                raise ValueError("A local result is too large for the complete grouping review.")
            entry = {"label": component["label"], "source": component["source"], "inputs": dependencies,
                     "outputs": outputs, "status": status, "reused": prior is not None}
            entries.append(entry)
            if status != runner.STATUS_COMPLETED:
                grouped_status = status
                break
            cache[key] = entry
        grouped_steps = work.steps - grouped_before
        # This comparator always executes the original complete workflow; it
        # does not consume the changed plan, component cache, or saved outputs.
        complete_before = work.steps
        work.check(case)
        complete = runner.run_flow(flow, data=copy.deepcopy(case["inputs"]), agent_fn=refuse,
            action_fn=refuse, resolve_flow=resolve, run_id=original, on_node=work.observe(case))
        work.check(case)
        receipt = {"case": case["id"], "source_version": case["source_version"],
            "group": case["group"], "deadline": case["deadline"], "finished_at": time.time(),
            "grouped_status": grouped_status, "complete_status": complete.status,
            "agreement": grouped_status == complete.status == runner.STATUS_COMPLETED and digest(data) == digest(complete.data),
            "grouped_values": data, "complete_values": complete.data, "components": entries,
            "grouped_steps": grouped_steps, "complete_steps": work.steps - complete_before,
            "calculation_ms": (time.perf_counter() - case_started) * 1000}
        save_case(index, receipt)
        results.append(receipt)
    guard()
    work.budget.check()
    return {"cases": results, "native_steps": work.steps,
            "calculation_ms": (time.perf_counter() - started) * 1000,
            "computed_components": sum(not item["reused"] for row in results for item in row["components"]),
            "reused_components": sum(item["reused"] for row in results for item in row["components"]),
            "same_information_baseline": selected["invariant_batching_computations"],
            "all_agreed": all(row["agreement"] for row in results)}
