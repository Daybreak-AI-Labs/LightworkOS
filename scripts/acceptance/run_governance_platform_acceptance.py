"""Run a fixed, local-only Lightwork governance-platform acceptance scope.

This runner intentionally cannot accept arbitrary pytest paths or arguments.
It executes only the reviewed allowlist below with the current interpreter,
streams child output into a SHA-256 digest with a bounded in-memory tail, and
writes a machine-readable report containing counts and digests rather than raw
test output.  It is local test evidence, not live customer, provider, tenant,
scale, penetration-test, certification, or regulator acceptance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO

SCHEMA = "lightwork.governance-platform-acceptance.v1"
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TIMEOUT_SECONDS = 120
MAX_TIMEOUT_SECONDS = 180
OUTPUT_TAIL_BYTES = 64 * 1024
_READ_CHUNK_BYTES = 8192
_GIT_OUTPUT_BYTES = 8 * 1024 * 1024
_SOURCE_MANIFEST_FILES = 20_000
_SOURCE_MANIFEST_BYTES = 512 * 1024 * 1024
SOURCE_BINDING_PATHS = (
    "packages",
    "apps",
    "scripts/acceptance",
    "conftest.py",
    "pyproject.toml",
    "uv.lock",
)
_COUNT_RE = re.compile(
    r"(?P<count>[0-9]+) (?P<kind>passed|failed|skipped|xfailed|xpassed|errors?|warnings?)"
)


@dataclass(frozen=True)
class AcceptanceSuite:
    category: str
    test_paths: tuple[str, ...]


# Fixed review scope.  Every entry is a local unit/integration test file; live
# Postgres, Qdrant, provider, cloud and customer-estate suites are deliberately
# excluded and reported as not run.
SUITES: tuple[AcceptanceSuite, ...] = (
    AcceptanceSuite(
        category="fresh-tenant-usability",
        test_paths=(
            "packages/maverick-core/tests/test_onboard_noninteractive.py",
            "packages/maverick-dashboard/tests/test_admin_tenants_api.py",
            "packages/maverick-dashboard/tests/test_tenants_console.py",
        ),
    ),
    AcceptanceSuite(
        category="cross-tenant-adversarial",
        test_paths=(
            "packages/maverick-core/tests/test_multitenant_isolation.py",
            "packages/maverick-core/tests/test_tenant_cache_vault_isolation.py",
            "packages/maverick-dashboard/tests/test_tenant_pinning.py",
        ),
    ),
    AcceptanceSuite(
        category="recovery",
        test_paths=(
            "packages/maverick-core/tests/test_audit_durability.py",
            "packages/maverick-core/tests/test_durable_checkpoint.py",
            "packages/maverick-core/tests/test_orphan_reclaim_tenants.py",
            "packages/maverick-core/tests/test_job_reclaim.py",
            "packages/maverick-dashboard/tests/test_external_gateway_runtime.py",
        ),
    ),
    AcceptanceSuite(
        category="concurrency-scale",
        test_paths=(
            "packages/maverick-core/tests/test_tenant_concurrency.py",
            "packages/maverick-core/tests/test_world_model_concurrency.py",
            "packages/maverick-core/tests/test_world_model_concurrent_open.py",
            "packages/maverick-core/tests/test_job_queue.py",
            "packages/maverick-core/tests/test_runner_fair_concurrency.py",
            "packages/maverick-core/tests/test_bounded_growth.py",
        ),
    ),
    AcceptanceSuite(
        category="audit-export",
        test_paths=(
            "packages/maverick-core/tests/test_audit_export.py",
            "packages/maverick-core/tests/test_audit_verify_cli.py",
        ),
    ),
)
_SUITE_BY_CATEGORY = {suite.category: suite for suite in SUITES}


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _git_output(repo_root: Path, arguments: Sequence[str]) -> bytes:
    try:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=str(repo_root),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            shell=False,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("Git source-state binding is unavailable") from exc
    if completed.returncode != 0:
        raise ValueError("Git source-state binding failed closed")
    if len(completed.stdout) > _GIT_OUTPUT_BYTES:
        raise ValueError("Git source-state metadata exceeds its byte bound")
    return completed.stdout


def _application_test_binding(repo_root: Path) -> dict[str, object]:
    """Bind evidence to HEAD, index state and bounded working-tree contents."""

    root = repo_root.resolve()
    head_raw = _git_output(root, ("rev-parse", "--verify", "HEAD")).strip()
    try:
        head_commit = head_raw.decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Git HEAD is not a canonical object id") from exc
    if re.fullmatch(r"[0-9a-f]{40,64}", head_commit) is None:
        raise ValueError("Git HEAD is not a canonical object id")

    path_arguments = ("--", *SOURCE_BINDING_PATHS)
    listed = _git_output(
        root,
        (
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            *path_arguments,
        ),
    )
    raw_paths = [item for item in listed.split(b"\0") if item]
    if len(raw_paths) > _SOURCE_MANIFEST_FILES:
        raise ValueError("source-state manifest exceeds its file-count bound")
    if len(set(raw_paths)) != len(raw_paths):
        raise ValueError("source-state manifest contains duplicate paths")

    manifest = hashlib.sha256()
    total_bytes = 0
    missing_files = 0
    for raw_path in sorted(raw_paths):
        relative = Path(os.fsdecode(raw_path))
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("source-state manifest contains an invalid path")
        candidate = root / relative
        try:
            candidate.parent.resolve().relative_to(root)
        except ValueError:
            raise ValueError("source-state manifest escaped its bounded root") from None

        kind: bytes
        content = hashlib.sha256()
        size = 0
        if candidate.is_symlink():
            kind = b"symlink"
            target = os.fsencode(os.readlink(candidate))
            content.update(target)
            size = len(target)
        elif candidate.is_file():
            kind = b"file"
            with candidate.open("rb") as handle:
                while chunk := handle.read(_READ_CHUNK_BYTES):
                    total_bytes += len(chunk)
                    size += len(chunk)
                    if total_bytes > _SOURCE_MANIFEST_BYTES:
                        raise ValueError(
                            "source-state manifest exceeds its content byte bound"
                        )
                    content.update(chunk)
        elif not candidate.exists():
            kind = b"missing"
            missing_files += 1
        else:
            raise ValueError("source-state manifest contains an unsupported entry")

        manifest.update(len(raw_path).to_bytes(8, "big"))
        manifest.update(raw_path)
        manifest.update(len(kind).to_bytes(2, "big"))
        manifest.update(kind)
        manifest.update(size.to_bytes(8, "big"))
        manifest.update(content.digest())

    status = _git_output(
        root,
        (
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            *path_arguments,
        ),
    )
    index = _git_output(
        root,
        ("ls-files", "--stage", "-z", *path_arguments),
    )
    return {
        "schema": "lightwork.application-test-source-binding.v1",
        "scope_ref": "bounded-application-tests-and-acceptance-v1",
        "scope_sha256": _sha256(SOURCE_BINDING_PATHS),
        "head_commit": head_commit,
        "dirty": bool(status),
        "git_status_sha256": hashlib.sha256(status).hexdigest(),
        "git_index_sha256": hashlib.sha256(index).hexdigest(),
        "worktree_manifest_sha256": manifest.hexdigest(),
        "file_count": len(raw_paths),
        "missing_file_count": missing_files,
        "content_bytes": total_bytes,
    }


def _selected_suites(categories: Sequence[str] | None) -> tuple[AcceptanceSuite, ...]:
    if not categories:
        return SUITES
    selected = set(categories)
    unknown = selected - set(_SUITE_BY_CATEGORY)
    if unknown:
        raise ValueError("acceptance category is not allowlisted")
    return tuple(suite for suite in SUITES if suite.category in selected)


def _suite_manifest(repo_root: Path, suite: AcceptanceSuite) -> str:
    root = repo_root.resolve()
    digest = hashlib.sha256()
    for relative in suite.test_paths:
        candidate = (root / relative).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            raise ValueError("allowlisted test escaped the repository root") from None
        if candidate.suffix != ".py" or not candidate.is_file():
            raise ValueError("allowlisted test is unavailable")
        digest.update(relative.replace("\\", "/").encode("utf-8"))
        digest.update(b"\0")
        with candidate.open("rb") as handle:
            while chunk := handle.read(_READ_CHUNK_BYTES):
                digest.update(chunk)
        digest.update(b"\0")
    return digest.hexdigest()


class _DigestingOutput:
    """Drain a child pipe fully while retaining only a bounded diagnostic tail."""

    def __init__(self, maximum_tail_bytes: int = OUTPUT_TAIL_BYTES) -> None:
        self._maximum = maximum_tail_bytes
        self._digest = hashlib.sha256()
        self._tail = bytearray()
        self.total_bytes = 0

    def drain(self, stream: BinaryIO) -> None:
        while True:
            chunk = stream.read(_READ_CHUNK_BYTES)
            if not chunk:
                break
            self.total_bytes += len(chunk)
            self._digest.update(chunk)
            self._tail.extend(chunk)
            overflow = len(self._tail) - self._maximum
            if overflow > 0:
                del self._tail[:overflow]

    @property
    def sha256(self) -> str:
        return self._digest.hexdigest()

    @property
    def truncated(self) -> bool:
        return self.total_bytes > self._maximum

    def counts(self) -> dict[str, int]:
        text = bytes(self._tail).decode("utf-8", errors="replace")
        counts: dict[str, int] = {}
        for match in _COUNT_RE.finditer(text):
            kind = match.group("kind")
            if kind == "error":
                kind = "errors"
            counts[kind] = int(match.group("count"))
        return counts


PopenFactory = Callable[..., subprocess.Popen[bytes]]


def _run_suite(
    suite: AcceptanceSuite,
    *,
    repo_root: Path,
    environment: Mapping[str, str],
    timeout_seconds: int,
    popen_factory: PopenFactory = subprocess.Popen,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, object]:
    manifest_sha256 = _suite_manifest(repo_root, suite)
    command = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "--tb=short",
        "-p",
        "no:cacheprovider",
        *suite.test_paths,
    ]
    started = monotonic()
    capture = _DigestingOutput()
    timed_out = False
    spawn_error = ""
    return_code: int | None = None
    reader: threading.Thread | None = None
    process: subprocess.Popen[bytes] | None = None
    try:
        process = popen_factory(
            command,
            cwd=str(repo_root),
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
        )
        if process.stdout is None:
            raise RuntimeError("pytest output pipe was unavailable")
        reader = threading.Thread(
            target=capture.drain,
            args=(process.stdout,),
            name=f"acceptance-output-{suite.category}",
            daemon=True,
        )
        reader.start()
        try:
            return_code = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.terminate()
            try:
                return_code = process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                return_code = process.wait(timeout=5)
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        spawn_error = type(exc).__name__
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    finally:
        if reader is not None:
            reader.join(timeout=5)
        if process is not None and process.stdout is not None:
            process.stdout.close()
    duration = max(0.0, monotonic() - started)
    counts = capture.counts()
    if spawn_error:
        status = "error"
    elif timed_out:
        status = "timed_out"
    elif return_code == 0 and counts.get("passed", 0) > 0 and not (
        counts.get("failed", 0) or counts.get("errors", 0)
    ):
        status = "passed"
    else:
        status = "failed"
    return {
        "category": suite.category,
        "status": status,
        "file_count": len(suite.test_paths),
        "test_manifest_sha256": manifest_sha256,
        "command_sha256": _sha256(command),
        "output_sha256": capture.sha256,
        "output_bytes": capture.total_bytes,
        "output_truncated": capture.truncated,
        "duration_seconds": round(duration, 6),
        "timeout_seconds": timeout_seconds,
        "timed_out": timed_out,
        "return_code": return_code,
        "spawn_error_category": spawn_error or None,
        "pytest_counts": counts,
    }


def _scope_manifest(suites: Sequence[AcceptanceSuite], repo_root: Path) -> str:
    return _sha256([
        {
            "category": suite.category,
            "file_count": len(suite.test_paths),
            "test_manifest_sha256": _suite_manifest(repo_root, suite),
        }
        for suite in suites
    ])


def run_acceptance(
    *,
    categories: Sequence[str] | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    repo_root: Path = REPO_ROOT,
    base_environment: Mapping[str, str] | None = None,
    popen_factory: PopenFactory = subprocess.Popen,
    source_binding_factory: Callable[[Path], dict[str, object]] = (
        _application_test_binding
    ),
) -> dict[str, object]:
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int)
        or not 10 <= timeout_seconds <= MAX_TIMEOUT_SECONDS
    ):
        raise ValueError("timeout must be between 10 and 180 seconds")
    suites = _selected_suites(categories)
    root = repo_root.resolve()
    started_at = datetime.now(timezone.utc)
    source_binding_at_start = source_binding_factory(root)
    results: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="lightwork-platform-acceptance-") as temp:
        temp_root = Path(temp)
        for suite in suites:
            suite_home = temp_root / suite.category
            suite_home.mkdir(parents=True, exist_ok=True)
            environment = dict(base_environment or os.environ)
            environment.update({
                "MAVERICK_HOME": str(suite_home),
                "MAVERICK_CONFIG": str(suite_home / "config.toml"),
                "MAVERICK_ENCRYPT_AT_REST": "0",
                "PYTHONDONTWRITEBYTECODE": "1",
            })
            environment.pop("MAVERICK_TENANT", None)
            environment.pop("PYTEST_ADDOPTS", None)
            results.append(_run_suite(
                suite,
                repo_root=root,
                environment=environment,
                timeout_seconds=timeout_seconds,
                popen_factory=popen_factory,
            ))
    source_binding_at_end = source_binding_factory(root)
    source_state_stable = source_binding_at_start == source_binding_at_end
    status_counts = {
        status: sum(1 for result in results if result["status"] == status)
        for status in ("passed", "failed", "timed_out", "error")
    }
    test_counts: dict[str, int] = {}
    for result in results:
        for kind, count in dict(result["pytest_counts"]).items():
            test_counts[kind] = test_counts.get(kind, 0) + int(count)
    report = {
        "schema": SCHEMA,
        "run_id": "GPA-" + _sha256({
            "started_at": started_at.isoformat(),
            "scope": _scope_manifest(suites, root),
            "source_binding": source_binding_at_start,
        })[:24],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope_manifest_sha256": _scope_manifest(suites, root),
        "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "interpreter_ref": "PY-" + hashlib.sha256(
            sys.executable.encode("utf-8")
        ).hexdigest()[:24],
        "python_version": ".".join(str(item) for item in sys.version_info[:3]),
        "local_test_only": True,
        "live_acceptance_status": "not_run",
        "external_credentials_requested": False,
        "application_test_source_binding": source_binding_at_end,
        "source_binding_at_start_sha256": _sha256(source_binding_at_start),
        "source_state_stable_during_run": source_state_stable,
        "runtime_gateway_acceptance": {
            "scope": "isolated_local_fastapi_test_estate",
            "real_external_gateway_routes_exercised": True,
            "authentication_approval_and_execution_ledger_exercised": True,
            "connector_and_runtime_policy_dependencies": "controlled_test_doubles",
            "external_or_customer_gateway_run": False,
            "external_credentials_used": False,
        },
        "suites": results,
        "summary": {
            "suite_counts": status_counts,
            "pytest_counts": test_counts,
            "all_selected_test_suites_passed": bool(results)
            and status_counts["passed"] == len(results),
            "all_selected_suites_passed": bool(results)
            and status_counts["passed"] == len(results)
            and source_state_stable,
        },
        "limits": [
            "This report covers fixed local pytest suites only; it is not fresh customer-tenant usability acceptance.",
            "Cross-tenant findings are local adversarial regression tests, not an external penetration test or live hosted-tenant exercise.",
            "Concurrency coverage uses bounded local test loads and is not production capacity, soak, latency or horizontal-scale evidence.",
            "Recovery coverage uses controlled local fault/restart cases and is not disaster-recovery or infrastructure failover acceptance.",
            "Runtime-policy coverage exercises the real local FastAPI external-gateway routes, authentication, approval and execution ledger in an isolated test estate with controlled connector and policy doubles; no external or customer gateway and no external credentials were used.",
            "Audit export coverage verifies local code paths and fixtures; auditor, customer, regulator and off-host custody acceptance were not run.",
            "Raw pytest output is not retained in this report; only its SHA-256 digest, byte count and parsed aggregate counts are recorded.",
            "This evidence is valid only for the recorded Git HEAD, index and bounded application/test working-tree manifest; source changes require a new run and source-state changes during the run invalidate acceptance.",
            "The JSON report is unsigned local evidence and must be correlated with CI, audit-ledger and environment-specific records.",
        ],
    }
    report["report_sha256"] = _sha256(report)
    return report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run fixed local Lightwork governance-platform acceptance suites."
    )
    parser.add_argument(
        "--category",
        action="append",
        choices=tuple(_SUITE_BY_CATEGORY),
        help="Run one allowlisted category; repeat to select more. Default: all.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="Per-category timeout (10-180 seconds).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Evidence JSON path (default: proof/governance-platform-acceptance-YYYY-MM-DD.json).",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        report = run_acceptance(
            categories=args.category,
            timeout_seconds=args.timeout_seconds,
        )
    except (OSError, ValueError) as exc:
        sys.stderr.write(
            f"governance platform acceptance: {type(exc).__name__}\n"
        )
        return 2
    output = args.output or Path(
        "proof",
        f"governance-platform-acceptance-{datetime.now(timezone.utc).date()}.json",
    )
    if not output.is_absolute():
        output = REPO_ROOT / output
    from maverick.file_lock import atomic_write_text

    atomic_write_text(
        output,
        json.dumps(report, sort_keys=True, indent=2) + "\n",
    )
    summary = {
        "artifact": str(output.resolve()),
        "all_selected_suites_passed": report["summary"][
            "all_selected_suites_passed"
        ],
        "report_sha256": report["report_sha256"],
    }
    sys.stdout.write(json.dumps(summary, sort_keys=True) + "\n")
    return 0 if report["summary"]["all_selected_suites_passed"] else 1


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    raise SystemExit(main())


__all__ = [
    "AcceptanceSuite",
    "DEFAULT_TIMEOUT_SECONDS",
    "MAX_TIMEOUT_SECONDS",
    "REPO_ROOT",
    "SCHEMA",
    "SUITES",
    "main",
    "run_acceptance",
]
