"""The data description ("domain") recipe learning needs, from capture contracts.

``maverick flow recipe learn --transforms/--choices`` and the verified workflow
learners take a hand-written domain file: bounded schemas for the inputs and
for each tool's arguments and result. Reviewed episodes already carry exactly
those schemas in their capture contract (``input_schema`` and
``tool_data_schemas``, fixed when the run was enrolled). This builds the domain
in each learner's shape from one contract, so the dashboard never asks a person
to write schemas. The learners still validate every observed value against it.
"""
from __future__ import annotations

import copy

STYLES = ("transforms", "choices", "workflow", "memory")


def _pair(contract: dict, tool: str) -> dict:
    schemas = contract.get("tool_data_schemas") or {}
    if tool not in schemas:
        raise ValueError("an episode step uses a tool outside its capture contract")
    pair = schemas[tool]
    return {"arguments": copy.deepcopy(pair["arguments"]), "result": copy.deepcopy(pair["result"])}


def domain_from_contract(style: str, contract: dict, episodes: list[dict]) -> dict:
    """Domain for ``style`` built from a capture ``contract`` and recipe ``episodes``."""
    if style not in STYLES:
        raise ValueError("unknown learning style")
    if type(contract) is not dict or type(episodes) is not list or not episodes:
        raise ValueError("a capture contract and at least one episode are required")
    inputs = copy.deepcopy(contract.get("input_schema"))
    if style in ("workflow", "memory"):
        tools = contract.get("allowed_tools") or []
        return {"inputs": inputs, "tools": {tool: _pair(contract, tool) for tool in tools}}
    first = episodes[0].get("steps") or []
    if style == "transforms":
        return {"inputs": inputs, "steps": [_pair(contract, step["tool"]) for step in first]}
    if not first:
        raise ValueError("choice learning needs a shared first action")
    branches = sorted({(e.get("steps") or [{}, {}])[-1].get("tool") for e in episodes} - {None})
    return {"inputs": inputs, "prefix": _pair(contract, first[0]["tool"]),
            "branches": {tool: _pair(contract, tool) for tool in branches}}


__all__ = ["STYLES", "domain_from_contract"]
