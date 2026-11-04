"""Trusted bootstrap supplied as immutable bytes to the restricted container."""
from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
from pathlib import Path


def main():
    payload = json.loads(Path("/candidate/sample.json").read_text(encoding="utf-8"))
    # The research runner keeps Python isolated (-I), which deliberately
    # excludes the candidate directory from import search. Load only the
    # controller-supplied helper at its fixed path; never widen that search.
    spec = importlib.util.spec_from_file_location("plugin_contracts", "/candidate/plugin_contracts.py")
    contracts = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(contracts)
    execute, execute_node, execute_grpc = contracts.execute, contracts.execute_node, contracts.execute_grpc
    inspect_contract, inspect_remote = contracts.inspect_contract, contracts.inspect_remote

    def dispatch():
        print(json.dumps({"operation": payload["operation"], "phase": "dispatch"}), flush=True)
    if payload["group"] in {"maverick.ts", "maverick.grpc"}:
        source = Path("/candidate/plugin" + payload["source_suffix"]).read_bytes()
        if hashlib.sha256(source).hexdigest() != payload["content_sha256"]:
            raise ValueError("Node source differs from the reviewed version")
        if payload.get("inspect_only") is True:
            result = inspect_remote(payload)
        else:
            result = execute_node(payload, dispatch) if payload["group"] == "maverick.ts" else execute_grpc(payload, dispatch)
    else:
        from importlib.metadata import version

        from maverick.plugin_lock import _dist_content_hash
        if version(payload["distribution"]) != payload["version"] or _dist_content_hash(payload["distribution"], portable_paths=True) != payload["content_sha256"]:
            raise ValueError("image does not contain the exact reviewed plugin bytes")
        module, _, attribute = payload["entry"].partition(":")
        target = importlib.import_module(module)
        for part in attribute.split("."):
            target = getattr(target, part)
        result = inspect_contract(payload["group"], target, payload["name"]) if payload.get("inspect_only") is True else execute(payload["group"], target, payload["sample"], dispatch, payload.get("input_schema_sha256"))
    if payload.get("inspect_only") is True:
        print(json.dumps({"operation": payload["operation"], "phase": "contract", "content_sha256": payload["content_sha256"], "contracts": result}, allow_nan=False))
        return
    encoded = json.dumps(result, sort_keys=True, allow_nan=False).encode()
    print(json.dumps({"operation": payload["operation"], "phase": "result", "schema_valid": True,
        "sample_valid": True, "completed": True, "content_sha256": payload["content_sha256"],
        "result_sha256": hashlib.sha256(encoded).hexdigest()}))


if __name__ == "__main__":
    main()
