"""Real publisher-rotation MSI acceptance, restricted to a disposable hosted job.

Uses two independently created fixture certificates and the existing compiled
updater key. It does not build or relabel another native executable.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import shutil
import sys
import time
import uuid
from pathlib import Path

from accept_signed_rollback_fixture import run_stage


def file_hash(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def make_policy(*, version: str, runtime_hash: str, old_native: str, new_native: str,
                old_publisher: str, new_publisher: str, public_key: str, installer_hash: str) -> dict:
    from maverick import release_identity_transition as bridge
    parts = [int(part) for part in version.split(".")]
    target = ".".join(map(str, [parts[0], parts[1], parts[2] + 1]))
    if old_native == new_native or old_publisher == new_publisher:
        raise ValueError("Publisher-transition acceptance needs distinct native builds and publisher identities.")
    source = {"version": version, "runtime_sha256": runtime_hash, "native_sha256": old_native,
              "publisher_thumbprint": old_publisher, "public_key": public_key}
    now = int(time.time())
    policy = {"schema": 1, "id": uuid.uuid4().hex, "issued_at": now - 30, "expires_at": now + 6 * 3600,
              "from": source, "to": {**source, "version": target, "native_sha256": new_native,
                                      "publisher_thumbprint": new_publisher},
              "new_installer_sha256": installer_hash, "rollback": "exact-retained-pair-only"}
    bridge.parse({"policy": policy, "from_signature": "pending", "to_signature": "pending"})
    return policy


def validate_report(report: dict, policy: dict, envelope_hash: str, old_installer_hash: str) -> None:
    required = ("actual_distinct_publisher_trust", "authenticated_administrator_api", "default_off_refusal",
                "tampered_policy_refused", "expired_admission_refused", "unrelated_publisher_rejected_before_execution",
                "pre_execution_process_resume", "protected_upgrade", "completed_upgrade_rollback",
                "exact_native_transition_and_return", "all_local_workspaces_restored", "runtime_bytes_unchanged")
    expected = {"schema": "lightwork.publisher-transition-acceptance.v1", "phase": "complete",
                "reviewed_transition_sha256": envelope_hash, "old_publisher_thumbprint": policy["from"]["publisher_thumbprint"],
                "new_publisher_thumbprint": policy["to"]["publisher_thumbprint"], "base_installer_sha256": old_installer_hash,
                "candidate_installer_sha256": policy["new_installer_sha256"], "old_native_sha256": policy["from"]["native_sha256"],
                "new_native_sha256": policy["to"]["native_sha256"], "initial_native_version": policy["from"]["version"],
                "upgraded_native_version": policy["to"]["version"], "rolled_back_native_version": policy["from"]["version"]}
    booleans = {"same_updater_key": True, "same_frozen_runtime_fixture": True, "synthetic_fixture_versions": True,
                "mid_msi_crash_tested": False, "publicly_recognized_publisher": False, "clean_virtual_machine": False}
    if (any(report.get(name) != value for name, value in expected.items())
            or any(report.get(name) is not value for name, value in booleans.items())
            or any(report.get(name) != "passed" for name in required)
            or type(report.get("cleanup_failures")) is not int or report["cleanup_failures"] != 0
            or report.get("acceptance_failed", False) is not False):
        raise RuntimeError("The actual publisher-transition acceptance report is incomplete or bound to different artifacts.")


def hosted_environment(workspace: Path, runner: Path) -> tuple[str, str]:
    expected = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
                "RUNNER_OS": "Windows", "GITHUB_JOB": "build-and-accept"}
    if os.name != "nt" or any(os.environ.get(key) != value for key, value in expected.items()):
        raise RuntimeError("Signing-transition acceptance requires the disposable GitHub-hosted Windows job.")
    if (runner.resolve() != Path(os.environ["RUNNER_TEMP"]).resolve()
            or workspace.resolve() != Path(os.environ["GITHUB_WORKSPACE"]).resolve()):
        raise RuntimeError("Transition acceptance inputs must belong to the current hosted job.")
    powershell, node = shutil.which("pwsh"), shutil.which("node")
    if not powershell or not node:
        raise RuntimeError("PowerShell 7 and the local Tauri signer are required.")
    return powershell, node


def read_payload_identity(report: Path, expected_msi_hash: str) -> str:
    payload = json.loads(report.read_text(encoding="utf-8"))
    if (payload.get("schema") != "lightwork.msi-native-payload.v1"
            or payload.get("msi_sha256") != expected_msi_hash):
        raise RuntimeError("Extracted native identity is not bound to the exact input MSI.")
    return payload["native_sha256"]


def accept(workspace: Path, runner: Path) -> None:
    powershell, node = hosted_environment(workspace, runner)
    from maverick import release_identity_transition as bridge
    inputs = {"base": workspace / "customer-artifacts/Lightwork.msi", "next": runner / "upgrade-fixture.msi"}
    originals = {name: file_hash(path) for name, path in inputs.items()}
    fixture = runner / ("identity-transition-" + uuid.uuid4().hex)
    fixture.mkdir()
    publishers = {name: runner / ("rollback-signed-" + uuid.uuid4().hex) for name in ("old", "new")}
    for directory in publishers.values():
        directory.mkdir()
    observed = {"schema": "lightwork.publisher-transition-fixture.v1", "same_updater_key": True,
                "same_frozen_runtime_fixture": True, "synthetic_publisher_certificates": True,
                "publicly_recognized_publisher": False, "completed_stages": [],
                "acceptance_passed": False, "cleanup_passed": False, "input_sha256": originals, "phase": "copy-inputs"}
    # Leave the 45-minute hosted step time for both certificate cleanups and
    # run_stage's bounded process-tree termination, even if work stalls late.
    work_deadline = time.monotonic() + 2220

    def record():
        (fixture / "stages.json").write_text(json.dumps(observed, indent=2), encoding="utf-8")

    def stage(name, command, timeout):
        observed["phase"] = name
        record()
        if not name.endswith("-cleanup"):
            remaining = work_deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("Transition acceptance reached its work deadline; cleaning both fixture identities.")
            timeout = min(timeout, remaining)
        run_stage(command, name, fixture, timeout=timeout, cwd=workspace)
        observed["completed_stages"].append(name)
        record()

    def publisher(name, phase):
        stage(name + "-" + phase, [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-File",
              str(workspace / "apps/installer-msi/fixture-publisher.ps1"), "-FixtureDirectory",
              str(publishers[name]), "-Phase", phase], 180 if phase.startswith("sign") else 60 if phase == "cleanup" else 90)

    primary = None
    try:
        # Bundle-time package markers change native bytes. Hash the payload in
        # each exact MSI, never Tauri's subsequently restored build executable.
        native_hashes = {}
        for name in ("base", "next"):
            payload_report = fixture / (name + "-payload.json")
            stage(name + "-payload", [sys.executable, str(workspace / "apps/installer-msi/msi_native_payload.py"),
                  "--msi", str(inputs[name]), "--report", str(payload_report)], 180)
            native_hashes[name] = read_payload_identity(payload_report, originals[name])
        observed["native_payload_sha256"] = native_hashes
        shutil.copyfile(inputs["base"], publishers["old"] / "base.msi")
        shutil.copyfile(inputs["next"], publishers["new"] / "next.msi")
        for name, label in (("old", "base"), ("new", "next")):
            for phase in ("create", "trust", "sign-" + label):
                publisher(name, phase)
        old_publisher, new_publisher = ((publishers[name] / "publisher-thumbprint.txt").read_text().strip().upper() for name in ("old", "new"))
        inventory = json.loads((workspace / "customer-artifacts/runtime-inventory.json").read_text(encoding="utf-8-sig"))
        public_key = Path(os.environ["ACCEPTANCE_PRIVATE_KEY"] + ".pub").read_text(encoding="utf-8").strip()
        policy = make_policy(version=inventory["version"], runtime_hash=inventory["runtime"]["sha256"],
            old_native=native_hashes["base"], new_native=native_hashes["next"], old_publisher=old_publisher,
            new_publisher=new_publisher, public_key=public_key, installer_hash=file_hash(publishers["new"] / "next.msi"))
        cli = workspace / "apps/installer-desktop/node_modules/@tauri-apps/cli/tauri.js"

        def sign_policy(value, name):
            document = fixture / (name + "-policy.json")
            document.write_text(bridge.canonical(value), encoding="utf-8", newline="")
            signatures = []
            for side in ("from", "to"):
                stage(name + "-" + side + "-signature", [node, str(cli), "signer", "sign", "--private-key-path",
                    os.environ["ACCEPTANCE_PRIVATE_KEY"], "--password", "", str(document)], 90)
                signatures.append(Path(str(document) + ".sig").read_text(encoding="utf-8").strip())
            envelope = {"policy": value, "from_signature": signatures[0], "to_signature": signatures[1]}
            bridge.verify(envelope, installed=policy["from"], admit=name != "expired")
            (fixture / (name + ".json")).write_text(json.dumps(envelope), encoding="utf-8")
            return envelope

        valid = sign_policy(policy, "bridge")
        unrelated = copy.deepcopy(policy)
        unrelated["to"]["publisher_thumbprint"] = next(char * 40 for char in "ABCDEF" if char * 40 not in (old_publisher, new_publisher))
        sign_policy(unrelated, "unrelated")
        expired = copy.deepcopy(policy)
        expired.update(issued_at=int(time.time()) - 120, expires_at=int(time.time()) - 30)
        sign_policy(expired, "expired")
        tampered = copy.deepcopy(valid)
        tampered["policy"]["id"] = uuid.uuid4().hex
        (fixture / "tampered.json").write_text(json.dumps(tampered), encoding="utf-8")
        observed.update(old_publisher=old_publisher, new_publisher=new_publisher,
                        envelope_sha256=bridge.digest(valid), native_hashes_distinct=True)
        stage("transition-rollback", [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-File",
            str(workspace / "apps/installer-msi/test-completed-rollback.ps1"),
            "-BaseMsi", str(publishers["old"] / "base.msi"), "-CandidateMsi", str(publishers["new"] / "next.msi"),
            "-PublicKeyFile", os.environ["ACCEPTANCE_PRIVATE_KEY"] + ".pub",
            "-Inventory", str(workspace / "customer-artifacts/runtime-inventory.json"),
            "-TransitionDirectory", str(fixture),
            "-Report", str(workspace / "customer-artifacts/publisher-transition-acceptance.json")], 2400)
        report = json.loads((workspace / "customer-artifacts/publisher-transition-acceptance.json").read_text(encoding="utf-8-sig"))
        validate_report(report, policy, bridge.digest(valid), file_hash(publishers["old"] / "base.msi"))
        if any(file_hash(path) != originals[name] for name, path in inputs.items()):
            raise RuntimeError("Transition acceptance changed an original build artifact.")
        observed["acceptance_passed"] = True
    except BaseException as error:
        primary = error
        observed["failed_phase"] = observed["phase"]
        raise
    finally:
        cleanup_errors = []
        for name in ("new", "old"):
            try:
                if (publishers[name] / "publisher-thumbprint.txt").is_file():
                    publisher(name, "cleanup")
            except Exception as error:
                cleanup_errors.append(error)
        observed["cleanup_passed"] = not cleanup_errors
        try:
            record()
        except Exception:
            if primary is None and not cleanup_errors:
                raise
        if primary is None and cleanup_errors:
            raise cleanup_errors[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--runner", type=Path, required=True)
    args = parser.parse_args()
    accept(args.workspace.resolve(), args.runner.resolve())


if __name__ == "__main__":
    main()
