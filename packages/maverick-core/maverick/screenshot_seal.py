"""Tamper-evident screenshots.

A screenshot used as evidence ("the agent saw this page before clicking") is
only evidence if it can't be quietly swapped. This seals captures the moment
they land: each file gets a ledger entry carrying its sha256, capture
metadata, an HMAC signature over the entry, and the previous entry's hash —
an append-only hash chain with an externally anchored signed tip, so replacing
a file, editing an entry, deleting one, truncating the tail, or reordering them
is detectable.

Key from ``[safety] screenshot_key`` / ``MAVERICK_SCREENSHOT_KEY``; sealing
without a key refuses (an unsigned seal proves nothing). The ledger is one
JSONL per directory (``.seals.jsonl`` next to the captures), crash-friendly
(append + fsync via the same discipline as ``crash_only_log``).

  seal(path, key=...)      -> SealEntry (writes the ledger line)
  verify_file(path, key)   -> "VALID" | "TAMPERED" | "UNSEALED"
  verify_ledger(dir, key)  -> chain report (count, broken_at, missing files, anchor)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path

LEDGER_NAME = ".seals.jsonl"
ANCHOR_VERSION = 1


class SealKeyMissing(RuntimeError):
    """Sealing/verifying needs the deployment screenshot key."""


def _key(explicit: str | None) -> str:
    if explicit:
        return explicit
    env = os.environ.get("MAVERICK_SCREENSHOT_KEY", "").strip()
    if env:
        return env
    try:
        from .config import load_config
        key = str(((load_config() or {}).get("safety") or {}).get("screenshot_key") or "")
        if key.strip():
            return key.strip()
    except Exception:  # pragma: no cover -- config never blocks
        pass
    raise SealKeyMissing(
        "no screenshot sealing key: set [safety] screenshot_key or "
        "MAVERICK_SCREENSHOT_KEY (an unsigned seal proves nothing)")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass(frozen=True)
class SealEntry:
    file: str            # basename within the ledger's directory
    sha256: str
    sealed_at: float
    prev: str            # sha256 of the previous ledger LINE ("" for first)
    sig: str             # HMAC over the canonical entry minus sig

    def canonical(self) -> bytes:
        d = asdict(self)
        d.pop("sig")
        return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def _ledger_path(file_path: Path) -> Path:
    return file_path.parent / LEDGER_NAME


def _ledger_state(ledger: Path) -> tuple[int, str]:
    try:
        lines = [ln for ln in ledger.read_bytes().splitlines() if ln.strip()]
    except OSError:
        return 0, ""
    return len(lines), hashlib.sha256(lines[-1]).hexdigest() if lines else ""


def _anchor_path(directory: Path) -> Path:
    resolved = str(directory.resolve())
    name = hashlib.sha256(resolved.encode()).hexdigest()
    return directory.parent / f".seals.{name}.tip.json"


def _anchor_payload(directory: Path, count: int, tip: str) -> dict:
    return {
        "version": ANCHOR_VERSION,
        "directory": str(directory.resolve()),
        "entries": count,
        "tip": tip,
    }


def _anchor_canonical(payload: dict) -> bytes:
    d = dict(payload)
    d.pop("sig", None)
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def _write_anchor(directory: Path, count: int, tip: str, key: str) -> None:
    anchor = _anchor_path(directory)
    payload = _anchor_payload(directory, count, tip)
    payload["sig"] = hmac.new(key.encode(), _anchor_canonical(payload), hashlib.sha256).hexdigest()
    tmp = anchor.with_name(f".{anchor.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, (json.dumps(payload, sort_keys=True) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, anchor)
    try:
        dir_fd = os.open(anchor.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        pass


def _read_anchor(directory: Path, key: str) -> tuple[dict | None, str | None]:
    anchor = _anchor_path(directory)
    try:
        payload = json.loads(anchor.read_text())
    except FileNotFoundError:
        return None, "missing"
    except (OSError, ValueError, TypeError):
        return None, "invalid"
    if not isinstance(payload, dict):
        return None, "invalid"
    sig = str(payload.get("sig", ""))
    expected = hmac.new(key.encode(), _anchor_canonical(payload), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected.encode(), sig.encode()):
        return payload, "bad_signature"
    if payload.get("version") != ANCHOR_VERSION:
        return payload, "invalid"
    if not isinstance(payload.get("entries"), int) or not isinstance(payload.get("tip"), str):
        return payload, "invalid"
    if payload.get("directory") != str(directory.resolve()):
        return payload, "wrong_directory"
    return payload, None


def seal(path: str | Path, *, key: str | None = None, now: float | None = None) -> SealEntry:
    """Seal one captured file into its directory's hash-chained ledger."""
    k = _key(key)
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(p)
    ledger = _ledger_path(p)
    previous_count, prev = _ledger_state(ledger)
    entry = SealEntry(
        file=p.name,
        sha256=_sha256_file(p),
        sealed_at=now if now is not None else time.time(),
        prev=prev,
        sig="",
    )
    sig = hmac.new(k.encode(), entry.canonical(), hashlib.sha256).hexdigest()
    entry = SealEntry(**{**asdict(entry), "sig": sig})
    line = json.dumps(asdict(entry), sort_keys=True)
    fd = os.open(ledger, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, (line + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    _write_anchor(p.parent, previous_count + 1, hashlib.sha256(line.encode()).hexdigest(), k)
    return entry


def _entries(ledger: Path) -> list[tuple[SealEntry, str]]:
    """(entry, line_hash) per intact ledger line."""
    out: list[tuple[SealEntry, str]] = []
    try:
        raw = ledger.read_bytes()
    except OSError:
        return out
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            d = json.loads(line)
            out.append((SealEntry(**d), hashlib.sha256(line).hexdigest()))
        except (ValueError, TypeError):
            out.append((None, hashlib.sha256(line).hexdigest()))  # type: ignore[arg-type]
    return out


def verify_file(path: str | Path, *, key: str | None = None) -> str:
    """VALID (latest seal matches the bytes + signature), TAMPERED, or UNSEALED."""
    k = _key(key)
    p = Path(path)
    ledger_report = verify_ledger(p.parent, key=k)
    if not ledger_report["ok"]:
        return "TAMPERED"
    entries = [e for e, _ in _entries(_ledger_path(p)) if e is not None and e.file == p.name]
    if not entries:
        return "UNSEALED"
    latest = entries[-1]
    expected_sig = hmac.new(k.encode(), latest.canonical(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig.encode(), str(latest.sig).encode()):
        return "TAMPERED"
    if not p.is_file() or _sha256_file(p) != latest.sha256:
        return "TAMPERED"
    return "VALID"


def verify_ledger(directory: str | Path, *, key: str | None = None) -> dict:
    """Chain verification for a capture directory.

    Returns ``{entries, ok, broken_at, bad_signatures, missing_files,
    modified_files}`` — ``broken_at`` is the 0-based index where the
    prev-hash chain or a corrupt line breaks (None when intact).
    """
    k = _key(key)
    d = Path(directory)
    rows = _entries(d / LEDGER_NAME)
    report = {"entries": len(rows), "ok": True, "broken_at": None,
              "bad_signatures": [], "missing_files": [], "modified_files": [],
              "anchor": None}
    anchor, anchor_error = _read_anchor(d, k)
    if rows and anchor_error is not None:
        report["ok"] = False
        report["anchor"] = anchor_error
    # Only the LATEST seal for a file pins its current bytes (a re-capture
    # legitimately supersedes earlier seals of the same name).
    latest_index: dict[str, int] = {}
    for i, (entry, _) in enumerate(rows):
        if entry is not None:
            latest_index[entry.file] = i
    prev = ""
    for i, (entry, line_hash) in enumerate(rows):
        if entry is None or entry.prev != prev:
            report["ok"] = False
            report["broken_at"] = i
            break
        sig = hmac.new(k.encode(), entry.canonical(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig.encode(), str(entry.sig).encode()):
            report["ok"] = False
            report["bad_signatures"].append(entry.file)
        if latest_index.get(entry.file) == i:
            f = d / entry.file
            if not f.is_file():
                report["ok"] = False
                report["missing_files"].append(entry.file)
            elif _sha256_file(f) != entry.sha256:
                report["ok"] = False
                report["modified_files"].append(entry.file)
        prev = line_hash
    if anchor_error is None and anchor is not None:
        if anchor.get("entries") != len(rows) or anchor.get("tip") != prev:
            report["ok"] = False
            report["anchor"] = "mismatch"
    return report


__all__ = ["seal", "verify_file", "verify_ledger", "SealEntry",
           "SealKeyMissing", "LEDGER_NAME"]
