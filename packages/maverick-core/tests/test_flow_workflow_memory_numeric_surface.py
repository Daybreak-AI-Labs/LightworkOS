"""Real local receipt histories pass through the CLI and governed native path.

The file-backed connector, capture, signed review/grant, package admission and
approval pauses are real. Review authority is the native fixture's local owner
callback; this test does not claim an external provider or OIDC acceptance.
"""
from __future__ import annotations

import json

from click.testing import CliRunner
from maverick.cli import main
from maverick.flow import Flow, store

from test_support.workflow_memory_native import ALLOWED, DOMAIN, decide
from test_support.workflow_memory_native import memory_native as memory_native
from test_support.workflow_memory_native import native as native


def test_numeric_signed_histories_cli_to_admitted_native_completion(memory_native, tmp_path):
    harness = memory_native
    paths = {}
    for name, value in {"bundles": harness.bundles, "trust": harness.trust(),
                        "domain": DOMAIN, "constants": [0]}.items():
        path = tmp_path / f"memory-{name}.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        paths[name] = path
    output = tmp_path / "numeric-memory-package.json"
    arguments = ["flow", "recipe", "learn-memory-verified", "--bundles", str(paths["bundles"]),
        "--trust", str(paths["trust"]), "--domain", str(paths["domain"]),
        "--tenant", harness.context.tenant, "--max-operations", "2", "--operators", "if,le,lt",
        "--constants", str(paths["constants"]), "--output", str(output)]
    for tool in ALLOWED:
        arguments.extend(["--allow-tool", tool])
    result = CliRunner().invoke(main, arguments)
    assert result.exit_code == 0, result.output
    assert "Not governed-admitted" in result.output and "live status not checked" in result.output
    package = json.loads(output.read_bytes())
    assert package["artifact"]["schema"] == "lightwork.workflow-memory.v1"
    assert package["artifact"] == harness.package["artifact"]
    assert len(package["manifest"]) == 6 and harness.counts() == 16
    assert package["artifact"]["model_count"] >= 1
    assert all(model["summary"]["kind"] == "integer" for model in package["artifact"]["models"])

    # The CLI package becomes executable only through a fresh governed check and
    # saved native draft; no generated teacher/history labels are added here.
    admitted = harness.lineage.admit(harness.context, package)
    assert admitted["id"] == harness.admission["id"]
    flow = Flow.from_dict(harness.lineage.draft(harness.context, admitted["id"],
        flow_id="numeric-cli-current", name="Numeric CLI current admission"))
    store.save_flow(flow)
    run = harness.start(flow, 7, [2, 2, 3])
    assert run.status == "paused_approval" and harness.counts() == 16
    for expected_calls in (17, 18, 19):
        run = decide(run.run_id)
        assert harness.counts() == expected_calls, run.error
    assert run.status == "completed", run.error
    assert [entry["result"]["quantity"] for entry in harness.calls()[-3:]] == [2, 2, 3]
    assert all(entry["arguments"] == {"target": 7} for entry in harness.calls()[-3:])
