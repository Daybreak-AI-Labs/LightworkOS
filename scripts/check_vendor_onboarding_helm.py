#!/usr/bin/env python3
"""Render the supported durable control-plane topology without cluster access.

Usage:
    python3 scripts/check_vendor_onboarding_helm.py --helm /path/to/helm
    python3 scripts/check_vendor_onboarding_helm.py --output work/helm-check.json

Uses an already installed Helm and the CI environment's PyYAML. Never downloads
charts, dependencies or images, contacts a cluster, or deploys resources.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

_STATE_HOME = "/home/maverick/.maverick"
_POSTGRES = ["--set", "worldModel.backend=postgres"]
_SCENARIOS = (
    ("default_sqlite", [], None),
    ("hosted_postgres_persistent_home", [
        *_POSTGRES, "--set-string", f"env.MAVERICK_HOME={_STATE_HOME}",
        "--set", "secret.create=false", "--set-string", "secret.name=synthetic-existing-secret",
    ], None),
    ("sqlite_without_persistence", ["--set", "persistence.enabled=false"],
     "persistence.enabled must be true"),
    ("postgres_without_persistence", [*_POSTGRES, "--set", "persistence.enabled=false"],
     "persistence.enabled must be true"),
    ("wrong_mount_path", ["--set-string", "persistence.mountPath=/tmp/unmounted-state"],
     "persistence.mountPath must be /home/maverick/.maverick"),
    ("home_outside_volume", ["--set-string", "env.MAVERICK_HOME=/tmp/unmounted-state"],
     "env.MAVERICK_HOME must match persistence.mountPath"),
    ("postgres_multiple_replicas", [*_POSTGRES, "--set", "replicaCount=2"],
     "replicaCount > 1 is not supported"),
    ("postgres_autoscaling", [*_POSTGRES, "--set", "autoscaling.enabled=true"],
     "autoscaling.enabled is not supported"),
)


def _one(resources, kind):
    matches = [resource for resource in resources if resource.get("kind") == kind]
    if len(matches) != 1:
        raise ValueError(f"expected one {kind}, found {len(matches)}")
    return matches[0]


def _validate_rendered(rendered: str, *, postgres: bool) -> int:
    resources = [row for row in yaml.safe_load_all(rendered) if isinstance(row, dict)]
    deployment = _one(resources, "Deployment")
    pvc = _one(resources, "PersistentVolumeClaim")
    spec = deployment["spec"]
    if spec.get("replicas") != 1 or spec.get("strategy", {}).get("type") != "Recreate":
        raise ValueError("supported control plane requires one replica and Recreate strategy")
    pod = spec["template"]["spec"]
    container, = pod["containers"]
    mounts = {mount["name"]: mount["mountPath"] for mount in container.get("volumeMounts", [])}
    if mounts.get("state") != _STATE_HOME:
        raise ValueError("durable state is not mounted at the application home")
    volumes = {volume["name"]: volume for volume in pod.get("volumes", [])}
    if volumes.get("state", {}).get("persistentVolumeClaim", {}).get("claimName") != pvc["metadata"]["name"]:
        raise ValueError("application state mount is not backed by the rendered PVC")
    if pvc["spec"].get("accessModes") != ["ReadWriteOnce"]:
        raise ValueError("supported persistence access mode changed")
    if any(resource.get("kind") == "HorizontalPodAutoscaler" for resource in resources):
        raise ValueError("supported control plane must not render an autoscaler")
    env = {entry["name"]: entry.get("value") for entry in container.get("env", [])}
    if env.get("MAVERICK_HOME", _STATE_HOME) != _STATE_HOME:
        raise ValueError("application home differs from the persistent volume")
    if postgres:
        if env.get("MAVERICK_WORLD_BACKEND") != "postgres" or env.get("MAVERICK_PG_RLS") != "1":
            raise ValueError("Postgres world-model configuration or RLS was omitted")
        if container.get("envFrom") != [{"secretRef": {"name": "synthetic-existing-secret"}}]:
            raise ValueError("hosted Postgres credential reference was not preserved")
    return len(resources)


def run_checks(helm: str, chart: Path, *, artifacts: Path | None = None) -> dict:
    if artifacts:
        artifacts.mkdir(parents=True, exist_ok=True)
    results = []
    for name, overrides, refusal in _SCENARIOS:
        command = [helm, "template", "vendor-recovery-check", str(chart), *overrides]
        rendered = subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                                  errors="replace", timeout=30, check=False)
        result = {"scenario": name, "helm_exit_code": rendered.returncode,
                  "expected": "rejected" if refusal else "rendered", "passed": False}
        if artifacts:
            (artifacts / f"{name}.yaml").write_text(rendered.stdout, encoding="utf-8")
            (artifacts / f"{name}.stderr.txt").write_text(rendered.stderr, encoding="utf-8")
        if refusal:
            result["passed"] = rendered.returncode != 0 and refusal in rendered.stderr
            result["required_diagnostic"] = refusal
        elif rendered.returncode == 0:
            try:
                result["resources"] = _validate_rendered(rendered.stdout, postgres=name.startswith("hosted_"))
                result["passed"] = True
            except (ValueError, KeyError, TypeError, yaml.YAMLError) as exc:
                result["error"] = str(exc)
        if not result["passed"]:
            result["helm_stderr"] = rendered.stderr
        results.append(result)
    digest = hashlib.sha256()
    for path in sorted(chart.rglob("*")):
        if path.is_file():
            digest.update(path.relative_to(chart).as_posix().encode("utf-8"))
            digest.update(path.read_bytes())
    return {"ok": all(result["passed"] for result in results), "chart": str(chart),
            "chart_sha256": digest.hexdigest(), "scenarios": results,
            "scope": "Local Helm rendering only; no cluster, volume recovery, live Postgres or deployment acceptance."}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helm", default=shutil.which("helm"), help="existing Helm executable")
    parser.add_argument("--chart", type=Path,
                        default=Path(__file__).resolve().parents[1] / "deploy/helm/maverick")
    parser.add_argument("--output", type=Path, help="optional JSON evidence file")
    parser.add_argument("--artifacts", type=Path, help="optional rendered manifests and refusal diagnostics")
    args = parser.parse_args(argv)
    if not args.helm or not args.chart.is_dir():
        parser.error("an installed Helm executable and an existing chart are required")
    try:
        report = run_checks(args.helm, args.chart.resolve(), artifacts=args.artifacts)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"Helm verification unavailable: {exc}", file=sys.stderr)
        return 2
    encoded = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
