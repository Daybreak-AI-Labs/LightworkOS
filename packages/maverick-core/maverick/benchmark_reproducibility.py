"""Benchmark reproducibility audits — manifests for recorded benchmark runs.

``maverick.continuous_benchmark`` records ``{name, score, commit, t}`` rows;
that tells you *what* a run scored, not whether two runs were measuring the
same thing. This module wraps that REAL recording path
(:func:`record_with_manifest` calls ``continuous_benchmark.record_result`` +
``save_history`` unchanged) and writes an audit manifest next to each new
result::

    {"schema": "maverick-bench-repro/1", "suite", "started",
     "host": {"python", "platform", "cpu_count"},
     "config_digest":  sha256 of the resolved benchmark config (canonical JSON),
     "inputs_digest":  sha256 over the task fixture files,
     "results":        {"score", "commit", ...},
     "env_fingerprint": relevant env keys PRESENT/ABSENT only — never values}

Opt-in hook semantics: manifests are ON by default **for new runs only**
(``[benchmark] reproducibility = false`` or ``MAVERICK_BENCH_REPRO=0`` turns
them off). Existing history is never rewritten and no manifest is ever
back-filled for a historical row — a manifest only attests to a run it
actually observed.

:func:`verify_reproduction` compares two manifests and names exactly which
digests differ. Two runs are **"comparable" only when suite, config_digest,
and inputs_digest all match** — a score delta across differing digests is a
different experiment, and this module will never call it comparable.
:func:`audit_report` summarizes the stored manifests per suite.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import re
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)

SCHEMA = "maverick-bench-repro/1"
_MAX_MANIFESTS = 1000
_MAX_INPUT_FILES = 10_000

# Env keys whose PRESENCE (never value) plausibly changes benchmark behaviour.
# Any other MAVERICK_* key present in the environment is also fingerprinted.
_RELEVANT_ENV = (
    "PYTHONHASHSEED",
    "MAVERICK_CONFIG",
    "MAVERICK_HOME",
    "MAVERICK_TENANT",
    "MAVERICK_LANGUAGE",
)


def enabled() -> bool:
    """Manifest hook state: default ON; ``MAVERICK_BENCH_REPRO`` env overrides
    ``[benchmark] reproducibility`` in config."""
    env = os.environ.get("MAVERICK_BENCH_REPRO")
    if env is not None:
        return env.strip().lower() in {"1", "true", "yes", "on"}
    try:
        from .config import load_config
        return bool(((load_config() or {}).get("benchmark") or {})
                    .get("reproducibility", True))
    except Exception:  # pragma: no cover - config never blocks recording
        return True


def digest_config(config: dict | None) -> str:
    """SHA-256 of the resolved benchmark config (canonical JSON, key-order free)."""
    return hashlib.sha256(
        json.dumps(config or {}, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def digest_inputs(paths: list | tuple) -> str:
    """SHA-256 over the task fixture files (files or directories).

    Deterministic: files are hashed in sorted relative order, name + content.
    A missing path raises ``ValueError`` — a manifest must not silently claim
    inputs it could not read.
    """
    files: list[tuple[str, Path]] = []
    for raw in paths:
        p = Path(raw)
        if p.is_file():
            files.append((p.name, p))
        elif p.is_dir():
            for sub in sorted(p.rglob("*")):
                if sub.is_file():
                    files.append((str(sub.relative_to(p)), sub))
        else:
            raise ValueError(f"benchmark input not found: {p}")
    if len(files) > _MAX_INPUT_FILES:
        raise ValueError(f"too many input files ({len(files)} > {_MAX_INPUT_FILES})")
    h = hashlib.sha256()
    for rel, p in sorted(files):
        h.update(rel.encode("utf-8", "replace"))
        h.update(b"\x00")
        h.update(hashlib.sha256(p.read_bytes()).digest())
    return h.hexdigest()


def env_fingerprint(environ: dict | None = None) -> dict:
    """``{"present": [...], "absent": [...]}`` over the relevant env keys.

    Presence only — values never enter the manifest (they may hold secrets).
    """
    env = os.environ if environ is None else environ
    keys = sorted(set(_RELEVANT_ENV) | {k for k in env if k.startswith("MAVERICK_")})
    return {
        "present": [k for k in keys if k in env],
        "absent": [k for k in keys if k not in env],
    }


def host_info() -> dict:
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "cpu_count": os.cpu_count() or 0,
    }


def build_manifest(
    suite: str,
    results: dict,
    *,
    config: dict | None = None,
    input_paths: list | tuple = (),
    started: float | None = None,
    environ: dict | None = None,
) -> dict:
    ts = time.time() if started is None else started
    return {
        "schema": SCHEMA,
        "suite": str(suite),
        "started": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
        "host": host_info(),
        "config_digest": digest_config(config),
        "inputs_digest": digest_inputs(input_paths),
        "results": results,
        "env_fingerprint": env_fingerprint(environ),
    }


def _manifest_dir(history_path: Path) -> Path:
    return history_path.parent / "manifests"


def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:80] or "suite"


def _write_json_0600(path: Path, data: dict) -> None:
    from .file_lock import atomic_write_text, prepare_private_directory

    prepare_private_directory(path.parent)
    atomic_write_text(path, json.dumps(data, indent=2, sort_keys=True))


def record_with_manifest(
    name: str,
    score: float,
    *,
    commit: str = "",
    config: dict | None = None,
    input_paths: list | tuple = (),
    history_path: Path | None = None,
    write_manifest: bool | None = None,
    now: float | None = None,
) -> Path | None:
    """Record a run through the real ``continuous_benchmark`` path, plus manifest.

    History recording is byte-identical to ``continuous_benchmark`` (append +
    ``save_history``; prior rows untouched). When the hook is enabled
    (``write_manifest`` overrides :func:`enabled`), the manifest lands next to
    the history at ``<history dir>/manifests/<suite>-<ms>.json`` (atomic,
    0600). Returns the manifest path, or ``None`` when disabled.
    """
    from . import continuous_benchmark as cb
    path = Path(history_path) if history_path is not None else cb._store_path()
    history = cb.load_history(path)
    cb.record_result(history, name, score, commit)
    cb.save_history(path, history)

    if write_manifest is None:
        write_manifest = enabled()
    if not write_manifest:
        return None
    ts = time.time() if now is None else now
    manifest = build_manifest(
        name,
        {"score": float(score), "commit": str(commit or "")},
        config=config,
        input_paths=input_paths,
        started=ts,
    )
    # Add a pid+random suffix so two runs of the same suite within one
    # millisecond don't collide and silently overwrite each other's manifest.
    out = (_manifest_dir(path)
           / f"{_safe_name(name)}-{int(ts * 1000)}-{os.getpid()}-{secrets.token_hex(3)}.json")
    _write_json_0600(out, manifest)
    return out


# ---------------------------------------------------------------------------
# Verification / audit
# ---------------------------------------------------------------------------

_COMPARABILITY_FIELDS = ("suite", "config_digest", "inputs_digest")


def verify_reproduction(manifest_a: object, manifest_b: object) -> dict:
    """Compare two manifests. ``{"comparable", "verdict", "differs",
    "informational_differs"}``.

    ``comparable`` is True ONLY when suite, config_digest, and inputs_digest
    all match. Host/env fingerprint differences are reported as informational
    (they explain variance) but never grant comparability on their own.
    """
    for label, m in (("a", manifest_a), ("b", manifest_b)):
        if not isinstance(m, dict) or m.get("schema") != SCHEMA:
            return {
                "comparable": False,
                "verdict": f"manifest {label} is not a {SCHEMA} manifest",
                "differs": ["schema"],
                "informational_differs": [],
            }
    assert isinstance(manifest_a, dict) and isinstance(manifest_b, dict)
    differs = [f for f in _COMPARABILITY_FIELDS
               if manifest_a.get(f) != manifest_b.get(f)]
    informational = [f for f in ("host", "env_fingerprint")
                     if manifest_a.get(f) != manifest_b.get(f)]
    if differs:
        verdict = "not comparable: " + ", ".join(f"{f} differs" for f in differs)
    else:
        verdict = "comparable: same suite, config, and inputs"
        if informational:
            verdict += " (note: " + ", ".join(
                f"{f} differs" for f in informational) + ")"
    return {
        "comparable": not differs,
        "verdict": verdict,
        "differs": differs,
        "informational_differs": informational,
    }


def audit_report(manifest_dir: Path | None = None,
                 history_path: Path | None = None) -> dict:
    """Summarize stored manifests per suite.

    A suite is flagged ``mixed`` when its recorded runs carry more than one
    config or inputs digest — those runs are NOT mutually comparable and any
    cross-run score comparison within that suite is suspect.
    """
    if manifest_dir is None:
        if history_path is None:
            from . import continuous_benchmark as cb
            history_path = cb._store_path()
        manifest_dir = _manifest_dir(Path(history_path))
    manifest_dir = Path(manifest_dir)
    suites: dict[str, dict] = {}
    malformed = 0
    files = sorted(manifest_dir.glob("*.json"))[:_MAX_MANIFESTS]
    for f in files:
        try:
            m = json.loads(f.read_text(encoding="utf-8"))
            if not isinstance(m, dict) or m.get("schema") != SCHEMA:
                raise ValueError("not a manifest")
        except (OSError, ValueError):
            malformed += 1
            continue
        s = suites.setdefault(str(m.get("suite")), {
            "runs": 0, "config_digests": set(), "inputs_digests": set()})
        s["runs"] += 1
        s["config_digests"].add(str(m.get("config_digest")))
        s["inputs_digests"].add(str(m.get("inputs_digest")))
    report: dict = {"manifests": len(files), "malformed": malformed, "suites": {}}
    for name, s in sorted(suites.items()):
        mixed = len(s["config_digests"]) > 1 or len(s["inputs_digests"]) > 1
        report["suites"][name] = {
            "runs": s["runs"],
            "distinct_config_digests": len(s["config_digests"]),
            "distinct_inputs_digests": len(s["inputs_digests"]),
            "comparable": not mixed,
        }
    return report


__all__ = [
    "SCHEMA",
    "enabled",
    "digest_config",
    "digest_inputs",
    "env_fingerprint",
    "host_info",
    "build_manifest",
    "record_with_manifest",
    "verify_reproduction",
    "audit_report",
]
