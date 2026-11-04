"""Time-bounded signing and rollback acceptance on a disposable hosted Windows VM."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

from collect_acceptance_diagnostics import scrub


def run_stage(command: list[str], name: str, directory: Path, *, timeout: float, cwd: Path) -> None:
    """Keep a stage log even when a native trust dialog or child process hangs."""
    log = directory / (name + ".log")
    print(f"Rollback acceptance: {name} (limit {timeout:g} seconds).", flush=True)
    try:
        with log.open("wb") as output:
            process = subprocess.Popen(command, cwd=cwd, stdout=output, stderr=subprocess.STDOUT,
                                       stdin=subprocess.DEVNULL)
            try:
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                try:
                    if os.name == "nt" and process.poll() is None:
                        subprocess.run([str(Path(os.environ["SystemRoot"]) / "System32/taskkill.exe"),
                                        "/PID", str(process.pid), "/T", "/F"],
                                       capture_output=True, timeout=15, check=False)
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=15)
                raise RuntimeError(f"{name} exceeded {timeout:g} seconds; retained stage diagnostics.") from None
        if code:
            raise RuntimeError(f"{name} failed with exit code {code}; retained stage diagnostics.")
    finally:
        if log.is_file():
            with log.open("rb") as source:
                source.seek(max(0, log.stat().st_size - 65536))
                print(scrub(source.read(65536).decode("utf-8", errors="replace")), flush=True)


def accept(workspace: Path, runner: Path) -> None:
    expected = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
                "RUNNER_OS": "Windows", "GITHUB_JOB": "build-and-accept"}
    if os.name != "nt" or any(os.environ.get(key) != value for key, value in expected.items()):
        raise RuntimeError("Fixture acceptance requires the disposable GitHub-hosted Windows job.")
    if runner.resolve() != Path(os.environ["RUNNER_TEMP"]).resolve():
        raise RuntimeError("Fixture directory must belong to the current disposable runner.")
    powershell = shutil.which("pwsh")
    if not powershell:
        raise RuntimeError("PowerShell 7 is required for fixture acceptance.")
    fixture = runner / ("rollback-signed-" + uuid.uuid4().hex)
    fixture.mkdir()
    helper = workspace / "apps/installer-msi/fixture-publisher.ps1"
    command = [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(helper),
               "-FixtureDirectory", str(fixture)]
    observed = {"schema": "lightwork.rollback-fixture.v1", "synthetic_fixture": True,
                "completed_stages": [], "acceptance_passed": False, "cleanup_passed": False}

    def record() -> None:
        (fixture / "stages.json").write_text(json.dumps(observed, indent=2), encoding="utf-8")

    def stage(name: str, arguments: list[str], timeout: int) -> None:
        observed["phase"] = name
        record()
        run_stage(arguments, name, fixture, timeout=timeout, cwd=workspace)
        observed["completed_stages"].append(name)
        record()

    primary = None
    try:
        observed["phase"] = "copy-installers"
        record()
        shutil.copyfile(workspace / "customer-artifacts/Lightwork.msi", fixture / "base.msi")
        shutil.copyfile(runner / "upgrade-fixture.msi", fixture / "next.msi")
        for name, timeout in (("create", 90), ("trust", 60), ("sign-base", 180), ("sign-next", 180)):
            stage(name, command + ["-Phase", name], timeout)
        rollback = workspace / "apps/installer-msi/test-completed-rollback.ps1"
        stage("completed-rollback", [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(rollback),
            "-BaseMsi", str(fixture / "base.msi"), "-CandidateMsi", str(fixture / "next.msi"),
            "-PublicKeyFile", os.environ["ACCEPTANCE_PRIVATE_KEY"] + ".pub",
            "-Inventory", str(workspace / "customer-artifacts/runtime-inventory.json"),
            "-Report", str(workspace / "customer-artifacts/completed-rollback-acceptance.json")], 2400)
        stage("native-webview", [sys.executable, str(workspace / "apps/installer-msi/native_webview_journey.py"),
            "--workspace", str(workspace), "--runner", str(runner), "--base", str(fixture / "base.msi"),
            "--candidate", str(fixture / "next.msi")], 1200)
        observed["acceptance_passed"] = True
    except BaseException as error:
        primary = error
        observed["failed_phase"] = observed["phase"]
        raise
    finally:
        try:
            if (fixture / "publisher-thumbprint.txt").is_file():
                stage("cleanup", command + ["-Phase", "cleanup"], 60)
            observed["cleanup_passed"] = True
        except Exception as cleanup_error:
            observed["cleanup_passed"] = False
            if primary is None:
                primary = cleanup_error
                raise
        finally:
            try:
                record()
            except Exception:
                if primary is None:
                    raise
                print("The final stage report could not be saved; retaining the original acceptance error.", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--runner", required=True, type=Path)
    args = parser.parse_args()
    try:
        accept(args.workspace.resolve(), args.runner.resolve())
    except (OSError, RuntimeError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
