"""Reliability certification run.

For a self-hosted enterprise deployment there is no hosted status page to
point at; the honest equivalent is a **reproducible, evidence-backed
self-certification**: run the resilience drills the repo already ships, on
this machine, against this install — and emit a certificate JSON carrying
each check's verdict, the environment fingerprint, and (when the
audit-signing key is available) an Ed25519 signature over the canonical
payload so the artifact is tamper-evident.

Checks composed (each already exists; this is the certification harness):

* **chaos game-day** (``chaos_gameday.main``) — retry-layer absorption of
  transient faults, bounded exhaustion on total outage;
* **plugin reliability drill** (``plugin_reliability.run_drill`` self-drill)
  — crash recovery / isolation / error-rate / leak properties;
* **WAL contention** — 16 concurrent writers, zero lock errors (inlined
  probe mirroring the CI audit).

(``DEFAULT_CHECKS`` has no query-plan / EXPLAIN index check.)

``python -m maverick.reliability_cert`` writes
``data_dir("reliability_cert.json")`` and exits non-zero when any check
fails — a cert is only issued for a passing run. Checks are injectable so
the harness itself is unit-tested without re-running every drill.
"""
from __future__ import annotations

import json
import logging
import platform
import time
from collections.abc import Callable
from pathlib import Path

log = logging.getLogger(__name__)


def _check_chaos() -> tuple[bool, str]:
    from . import chaos_gameday
    rc = chaos_gameday.main()
    return rc == 0, f"chaos game-day exit {rc}"


def _check_plugin_reliability() -> tuple[bool, str]:
    from random import Random

    from .plugin_reliability import FaultRates, _self_drill_plugin, run_drill
    rep = run_drill(_self_drill_plugin(), iterations=1500,
                    rates=FaultRates(crash=0.02, timeout=0.03, error=0.05),
                    rng=Random(0))
    return rep.ok, (f"{rep.calls} calls, {rep.success_rate:.1%} success"
                    + ("" if rep.ok else f"; problems: {rep.problems}"))


def _check_wal_contention(writers: int = 16, rows_each: int = 25) -> tuple[bool, str]:
    import tempfile
    import threading

    from .world_model import WorldModel
    with tempfile.TemporaryDirectory() as d:
        world = WorldModel(Path(d) / "world.db")
        gid = world.create_goal("cert", "")
        errors: list[str] = []

        def writer(n: int) -> None:
            try:
                for i in range(rows_each):
                    world.append_event(gid, f"w{n}", "cert", f"row {i}")
            except Exception as e:  # noqa: BLE001 -- the audit counts ANY failure
                errors.append(f"w{n}: {type(e).__name__}: {e}")

        threads = [threading.Thread(target=writer, args=(n,)) for n in range(writers)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        count = len(world.goal_events(gid, limit=writers * rows_each + 10))
        world.close()
    ok = not errors and count >= writers * rows_each
    return ok, (f"{writers} writers x {rows_each} rows: {count} written, "
                f"{len(errors)} error(s)")


DEFAULT_CHECKS: dict[str, Callable[[], tuple[bool, str]]] = {
    "chaos_gameday": _check_chaos,
    "plugin_reliability": _check_plugin_reliability,
    "wal_contention": _check_wal_contention,
}


def _fingerprint() -> dict:
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
    }


def certify(checks: dict[str, Callable[[], tuple[bool, str]]] | None = None,
            *, now: float | None = None) -> dict:
    """Run every check; return the certificate dict (unsigned).

    ``passed`` is True iff every check passed; a failing run still returns the
    full evidence (so the operator sees what failed) but the CLI refuses to
    write a cert file for it.
    """
    checks = checks if checks is not None else DEFAULT_CHECKS
    results: dict[str, dict] = {}
    for name, fn in checks.items():
        try:
            ok, detail = fn()
        except Exception as e:  # a crashing check is a failing check
            ok, detail = False, f"check raised {type(e).__name__}: {e}"
        results[name] = {"passed": bool(ok), "detail": detail}
    return {
        "kind": "maverick-reliability-cert",
        "version": 1,
        "issued_at": float(now if now is not None else time.time()),
        "environment": _fingerprint(),
        "checks": results,
        "passed": all(r["passed"] for r in results.values()),
    }


def sign_cert(cert: dict) -> dict:
    """Attach an Ed25519 signature over the canonical payload when the audit
    signing key is available; unsigned otherwise (the cert says which)."""
    payload = json.dumps({k: v for k, v in cert.items() if k != "signature"},
                         sort_keys=True, separators=(",", ":")).encode("utf-8")
    try:
        from .audit.signing import _load_or_create_keypair
        priv, pub, key_id = _load_or_create_keypair()
        from cryptography.hazmat.primitives.asymmetric import ed25519
        signer = ed25519.Ed25519PrivateKey.from_private_bytes(priv)
        cert["signature"] = {
            "alg": "ed25519", "key_id": key_id,
            "pubkey": pub.hex(), "sig": signer.sign(payload).hex(),
        }
    except Exception:
        cert["signature"] = None  # honest: unsigned cert
    return cert


def write_cert(cert: dict, path: Path | None = None) -> Path:
    if path is None:
        from .paths import data_dir
        path = data_dir("reliability_cert.json")
    path = Path(path)
    # Unique temp + os.replace (0600): a fixed ".tmp" collides if two CLI
    # invocations write the cert concurrently (one os.replace moves it out from
    # under the other).
    from .file_lock import atomic_write_text
    atomic_write_text(path, json.dumps(cert, indent=2, sort_keys=True))
    return path


def main(argv: list[str] | None = None) -> int:  # pragma: no cover -- CLI shell
    import argparse
    p = argparse.ArgumentParser(prog="maverick.reliability_cert",
                                description="Run the reliability certification.")
    p.add_argument("--out", default=None, help="cert output path")
    args = p.parse_args(argv)
    cert = certify()
    for name, r in cert["checks"].items():
        print(f"  {'PASS' if r['passed'] else 'FAIL'}  {name}: {r['detail']}")
    if not cert["passed"]:
        print("reliability cert: FAILED — no certificate issued")
        return 1
    path = write_cert(sign_cert(cert), Path(args.out) if args.out else None)
    signed = "signed" if cert.get("signature") else "UNSIGNED"
    print(f"reliability cert: PASSED — {signed} certificate at {path}")
    return 0


__all__ = ["certify", "sign_cert", "write_cert", "DEFAULT_CHECKS"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
