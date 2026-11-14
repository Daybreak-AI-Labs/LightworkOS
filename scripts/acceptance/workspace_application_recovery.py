"""Portable synthetic fresh-target recovery through actual application readers.

Run with the Python installation containing all Lightwork packages. No provider,
server or scheduler is started. Evidence is published only after private cleanup.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import io
import json
import logging
import os
import subprocess
import sys
import tempfile
import time
import zipfile
from contextlib import contextmanager
from pathlib import Path

TENANT = "application-recovery-fixture"
CONTEXT = "a" * 64
SLOT = "b" * 64
BEFORE = "Synthetic accepted-before-snapshot"
AFTER = "Synthetic accepted-after-snapshot"


def source(directory):
    from maverick import crypto_at_rest as crypto
    from maverick import file_lock
    from maverick import workspace_recovery as recovery
    from maverick.paths import data_dir
    from maverick.recovery_rehearsal import _deny_external
    from maverick.world_model import WorldModel
    from maverick_dashboard.draft_store import DraftStore

    sys.addaudithook(_deny_external)

    home = Path(os.environ["MAVERICK_HOME"])
    file_lock.ensure_private_directory(home)
    file_lock.atomic_create_text(home / "config.toml", "[encryption]\nat_rest=true\n[kms]\nprovider='local'\n")
    crypto._KEY_PATH = home / "separate-key-custody" / "at_rest.key"
    root = file_lock.ensure_private_directory(data_dir())
    draft = DraftStore(CONTEXT)
    draft.save(SLOT, {"title": BEFORE}, expected_revision=0, operation_id="fixture-initial-write")
    world = WorldModel(root / "world.db")
    try:
        goal = world.create_goal(BEFORE, BEFORE, owner="user:recovery-fixture")
        artifact = world.add_artifact(goal, "text", "Fixture artifact", BEFORE)
        pre_acknowledged_at = time.time()
        recovery.configure_key()
        snapshot_started_at = time.time()
        selected = recovery.create()
        snapshot_completed_at = time.time()
        snapshot_completed_clock = time.perf_counter()
        custody = file_lock.ensure_private_directory(directory / "retained")
        file_lock.atomic_create_bytes(custody / "snapshot.tgz", file_lock.atomic_read_bytes(recovery._archive(selected["id"])))
        file_lock.atomic_create_bytes(custody / "custody.zip", recovery.export_encryption_keys())
        file_lock.atomic_create_text(custody / "recovery.key", recovery._key().hex())
        draft.save(SLOT, {"title": AFTER}, expected_revision=1, operation_id="fixture-later-draft")
        later_artifact = world.add_artifact(goal, "text", "Fixture artifact", AFTER)
        later_goal = world.create_goal(AFTER, owner="user:recovery-fixture")
        later_acknowledged_at = time.time()
        later_acknowledgement_interval = time.perf_counter() - snapshot_completed_clock
        if not (draft.read(SLOT)["payload"]["title"] == AFTER):
            raise RuntimeError("Source draft verification failed")
        if not (world.get_goal(later_goal).title == AFTER):
            raise RuntimeError("Source goal verification failed")
        if not (len(world.artifacts_for_goal(goal)) == 2):
            raise RuntimeError("Source artifacts verification failed")
    finally:
        world.close()
    crypto._KEY_PATH.unlink()
    evidence = {"goal": goal, "artifact": artifact, "later_goal": later_goal, "later_artifact": later_artifact,
                "pre_snapshot_acknowledged_writes": 3, "post_snapshot_acknowledged_writes": 3,
                "pre_acknowledged_at": pre_acknowledged_at, "snapshot_started_at": snapshot_started_at,
                "snapshot_completed_at": snapshot_completed_at, "last_post_snapshot_acknowledged_at": later_acknowledged_at,
                "post_snapshot_acknowledgement_interval_seconds": later_acknowledgement_interval,
                "application_identity": recovery.application_identity(), "application_version": recovery.version(),
                "archive_sha256": hashlib.sha256((custody / "snapshot.tgz").read_bytes()).hexdigest(),
                "custody_sha256": hashlib.sha256((custody / "custody.zip").read_bytes()).hexdigest(),
                "original_synthetic_primary_absent": not crypto._KEY_PATH.exists(), "source_pid": os.getpid()}
    file_lock.atomic_create_text(directory / "source-evidence.json", json.dumps(evidence))


def target(job, fixture):
    started = time.perf_counter()
    stage = "worker"
    app_reads = False
    from maverick import backup, file_lock
    from maverick import recovery_rehearsal as worker
    result = {"schema": 1, "kind": "synthetic-application-recovery-rehearsal", "target_pid": os.getpid(),
              "outcome": "failed", "application_reads_started": False, "network_or_provider_actions": 0,
              "external_stores_tested": False, "live_workspace_changed": False, "coverage_complete": False}
    try:
        scan = worker._run(backup._filesystem_path(job))
        result["envelope_scan_outcome"] = scan["outcome"]
        if scan["outcome"] != "verified_supported_formats":
            raise ValueError("supported record decryption did not pass")
        stage = "application-readers"
        app_reads = True
        from maverick.paths import data_dir
        from maverick.world_model import WorldModel
        from maverick_dashboard.draft_store import DraftStore
        draft = DraftStore(CONTEXT).read(SLOT)
        world = WorldModel(data_dir("world.db"))
        try:
            goal = world.get_goal(fixture["goal"])
            artifacts = world.artifacts_for_goal(fixture["goal"])
            checks = {
                "draft_current_binding_valid": draft["context"] == CONTEXT and draft["slot"] == SLOT,
                "draft_prior_revision_read": draft["revision"] == 1 and draft["payload"]["title"] == BEFORE,
                "goal_fields_read": goal.title == BEFORE and goal.description == BEFORE and goal.owner == "user:recovery-fixture",
                "artifact_reference_and_content_read": len(artifacts) == 1 and artifacts[0]["id"] == fixture["artifact"]
                    and artifacts[0]["goal_id"] == goal.id and artifacts[0]["content"] == BEFORE and artifacts[0]["version"] == 1,
                "later_goal_absent": world.get_goal(fixture["later_goal"]) is None,
                "later_artifact_revision_absent": all(row["id"] != fixture["later_artifact"] for row in artifacts),
                "later_draft_revision_absent": draft["revision"] != 2 and draft["payload"]["title"] != AFTER,
            }
            if not (all(checks.values())):
                raise RuntimeError("Restored application-reader verification failed")
        finally:
            world.close()
        request = json.loads((job / "request.json").read_text())
        result.update(outcome="verified_fixture_application_reads", application_checks=checks,
                      application_identity=scan["application_identity"], application_version=request["application_version"],
                      archive_sha256=request["archive_sha256"], custody_sha256=request["custody_sha256"], tenant=TENANT,
                      known_pre_snapshot_writes_restored=3, known_post_snapshot_writes_not_restored=3,
                      first_successful_application_reads_seconds=round(time.perf_counter() - started, 6),
                      limits=["Known synthetic draft/goal/artifact fixture only; no other application invariants or stores are established.",
                              "The three later writes were acknowledged after the selected snapshot and intentionally are not restored.",
                              "No production RTO/RPO or data-loss guarantee; no application server, scheduler, runner or provider started."])
    except Exception:
        result["failure_stage"] = stage
    result["application_reads_started"] = app_reads
    key = bytes.fromhex((job / "recovery.key").read_text())
    file_lock.atomic_create_text(job / "application-result.json", json.dumps(backup._authenticate_for_write(result, key)))


def digest_tree(root):
    from maverick import backup

    root = backup._filesystem_path(root)
    return {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in root.rglob("*") if path.is_file()}


@contextmanager
def _temporary_workspace():
    temporary = tempfile.TemporaryDirectory(prefix="lw-app-recovery-")
    directory = Path(temporary.name)
    inherited = {key: value for key, value in os.environ.items() if key.startswith(("MAVERICK_", "LIGHTWORK_"))}
    for key in inherited:
        os.environ.pop(key)
    os.environ.update(MAVERICK_HOME=str(directory / "controller"),
                      MAVERICK_CONFIG=str(directory / "controller" / "config.toml"), MAVERICK_CLIENT_ID=TENANT)
    try:
        from maverick import backup, file_lock

        file_lock.ensure_private_directory(directory)
        temporary.name = str(backup._filesystem_path(directory))
        yield directory
    finally:
        try:
            temporary.cleanup()
        finally:
            for key in tuple(os.environ):
                if key.startswith(("MAVERICK_", "LIGHTWORK_")):
                    os.environ.pop(key)
            os.environ.update(inherited)


def _run_fixture(directory):
    from maverick import workspace_recovery as recovery

    script = Path(__file__).resolve()
    python = sys.executable
    allowed = {"SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "SYSTEMDRIVE", "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS", "LANG", "LC_ALL", "TZ"}
    base = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    home = directory / "source"
    environment = {**base, "MAVERICK_HOME": str(home), "MAVERICK_CONFIG": str(home / "config.toml"),
                   "MAVERICK_CLIENT_ID": TENANT, "MAVERICK_ENCRYPT_AT_REST": "1", "MAVERICK_ENCRYPT_PER_TENANT": "0",
                   "TEMP": str(directory), "TMP": str(directory), "HOME": str(directory / "source-profile"),
                   "USERPROFILE": str(directory / "source-profile"), "APPDATA": str(directory / "source-profile"),
                   "PYTHONUTF8": "1"}
    if not getattr(sys, "frozen", False):
        # Source and target must read the same application bytes even when a
        # different Lightwork checkout is installed on the host.
        environment["PYTHONPATH"] = os.pathsep.join(recovery._application_roots())
    subprocess.run([python, str(script), "--_source", str(directory)], env=environment, check=True, capture_output=True, timeout=60)
    fixture = json.loads((directory / "source-evidence.json").read_text())
    retained = directory / "retained"
    original_hashes, custody_hashes = digest_tree(home), digest_tree(retained)
    from maverick import backup, file_lock
    key = bytes.fromhex((retained / "recovery.key").read_text())
    with backup.recovery_scope(retained, TENANT, key):
        manifest = backup.read_manifest(retained / "snapshot.tgz")
    if not (manifest["client_id"] == TENANT):
        raise RuntimeError("Snapshot client verification failed")
    if not (manifest["recovery"]["tenant_id"] == TENANT):
        raise RuntimeError("Snapshot tenant verification failed")
    if not (manifest["recovery"]["application_identity"] == fixture["application_identity"]):
        raise RuntimeError("Snapshot application identity verification failed")
    if not (manifest["recovery"]["application_version"] == fixture["application_version"]):
        raise RuntimeError("Snapshot application version verification failed")
    reports = []
    for variant in ("complete", "missing-custody", "wrong-primary"):
        job = file_lock.ensure_private_directory(directory / variant)
        child_env = recovery._custody_environment(job, TENANT)
        archive = (retained / "snapshot.tgz").read_bytes()
        custody = (retained / "custody.zip").read_bytes()
        if variant == "wrong-primary":
            with zipfile.ZipFile(io.BytesIO(custody)) as archive_zip:
                members = {name: archive_zip.read(name) for name in archive_zip.namelist()}
            manifest = json.loads(members["manifest.json"])
            wrong = b"00" * 32
            members["keys/at_rest.key"] = wrong
            manifest["files"]["at_rest.key"] = {"sha256": hashlib.sha256(wrong).hexdigest(), "size": len(wrong)}
            members["manifest.json"] = json.dumps(backup._authenticate_for_write(manifest, key)).encode()
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w") as archive_zip:
                for name, raw in members.items():
                    archive_zip.writestr(name, raw)
            custody = output.getvalue()
        request = {"schema": 1, "tenant": TENANT, "archive_sha256": hashlib.sha256(archive).hexdigest(),
                   "custody_sha256": hashlib.sha256(custody).hexdigest(), "application_identity": fixture["application_identity"],
                   "application_version": fixture["application_version"]}
        for name, raw in (("snapshot.tgz", archive), ("recovery.key", key.hex().encode()), ("request.json", json.dumps(request).encode())):
            file_lock.atomic_create_bytes(job / name, raw)
        if variant != "missing-custody":
            file_lock.atomic_create_bytes(job / "custody.zip", custody)
        launch = time.perf_counter()
        child = subprocess.run([python, str(script), "--_target", str(job), "--_fixture", str(directory / "source-evidence.json")],
                               env=child_env, cwd=job, capture_output=True, timeout=90)
        launch_through_exit_seconds = time.perf_counter() - launch
        if not (child.returncode == 0):
            raise RuntimeError("Synthetic target process did not return evidence")
        signed = json.loads((job / "application-result.json").read_text())
        signature = signed["authentication"]["signature"]
        if not (hmac.compare_digest(signature, hmac.new(key, backup._canonical_body(signed), hashlib.sha256).hexdigest())):
            raise RuntimeError("Target evidence signature verification failed")
        if not ((signed["outcome"] == "verified_fixture_application_reads") == (variant == "complete")):
            raise RuntimeError("Target outcome verification failed")
        if not (signed["application_reads_started"] == (variant == "complete")):
            raise RuntimeError("Target application-read admission verification failed")
        if variant == "complete":
            if not (signed["archive_sha256"] == fixture["archive_sha256"] and signed["custody_sha256"] == fixture["custody_sha256"]):
                raise RuntimeError("Target archive and custody verification failed")
            if not (signed["application_identity"] == fixture["application_identity"]):
                raise RuntimeError("Target application identity verification failed")
        if not (digest_tree(home) == original_hashes and digest_tree(retained) == custody_hashes):
            raise RuntimeError("Source and custody preservation verification failed")
        reports.append({"variant": variant, "parent_launch_through_exit_seconds": round(launch_through_exit_seconds, 6),
                        "signed_report": signed, "signature_verified": True})
    evidence = {"fixture": "synthetic-local-application-readers", "source": fixture,
                "signed_snapshot_application_binding_verified": True,
                "observed_post_snapshot_acknowledgement_window_seconds": round(fixture["post_snapshot_acknowledgement_interval_seconds"], 6),
                "source_and_retained_custody_unchanged_during_targets": True, "reports": reports,
                "scope": "Same-build temporary restore only; no production data-loss/RTO/RPO, external system or mixed-state recovery claim."}
    return evidence

def rehearse():
    with _temporary_workspace() as directory:
        evidence = _run_fixture(directory)
    # A retained result means every disposable key copy was cleaned first.
    return {**evidence, "temporary_state_cleaned_before_publication": True}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Also atomically save the JSON evidence to this file.")
    parser.add_argument("--_source", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--_target", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--_fixture", type=Path, help=argparse.SUPPRESS)
    arguments = parser.parse_args(argv)
    logging.disable(logging.CRITICAL)
    try:
        if arguments._source is not None:
            if arguments._target is not None or arguments._fixture is not None or arguments.output is not None:
                raise ValueError("invalid source arguments")
            source(arguments._source)
            return 0
        if arguments._target is not None:
            if arguments._fixture is None or arguments.output is not None:
                raise ValueError("invalid target arguments")
            target(arguments._target, json.loads(arguments._fixture.read_text()))
            return 0
        if arguments._fixture is not None:
            raise ValueError("invalid fixture arguments")
        evidence = rehearse()
        encoded = json.dumps(evidence, allow_nan=False, indent=2) + "\n"
        if arguments.output is not None:
            from maverick.file_lock import atomic_write_text

            atomic_write_text(arguments.output.absolute(), encoded)
        sys.stdout.write(encoded)
        return 0
    except Exception:
        sys.stderr.write("The temporary application recovery rehearsal could not complete safely. Previous evidence was kept.\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
