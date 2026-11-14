"""Workspace mutation journal: pre-images of file-tool writes, with revert.

Opt-in (``[workspace] journal = true``, default OFF). Every workspace write
that goes through the file tools' one shared chokepoint
(:func:`maverick.tools.fs.write_text_contained` — ``write_file``,
``str_replace_editor``, SEARCH/REPLACE and ``ast_edit`` all funnel there)
first records what the file looked like BEFORE the mutation: existed or not,
prior bytes (blob), size, and sha256. ``maverick journal revert --goal N``
then restores every journaled file to its pre-run state, newest entry first,
so an operator can undo an agent's file edits without having planned ahead
with a ``workspace_snapshot`` — the journal is harness-enforced, not
model-invoked. Shell-driven mutations (``rm``/``mv``/redirects) are NOT
journaled; the audit chain still records the commands, but revert cannot
undo them. Deliberate boundary, stated in the CLI output.

Failure posture: recording is fail-open by default — a broken journal must
not stop the agent's write, but it logs loudly. ``[workspace] journal_strict
= true`` inverts that for regulated deployments: a write whose pre-image
cannot be journaled is REFUSED, so "every mutation is reversible" holds as a
guarantee rather than a best effort. Caps (per-file bytes, per-goal total
bytes and entry count) bound disk use; once a cap trips, the journal marks
itself incomplete and a later full revert refuses unless ``--partial`` —
an incomplete rollback must never masquerade as a complete one.

Revert re-validates what it reads back: entry paths must be relative, free of
traversal, and resolve inside the entry's recorded workdir, and restores
refuse to write through a symlink (the target, or a planted temp file). The
recorded workdir itself is taken from the journal, so the journal store is
created owner-only (directories 0700, entries and pre-image blobs 0600):
only the operator's own account can edit it. Each non-dry revert emits one signed
``workspace_revert`` audit row and archives the journal directory so a
second revert cannot silently replay. A revert in which a write or delete
failed keeps the journal so it can be retried; other skips (unsafe path,
symlink, missing pre-image) are reported and the journal is archived.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import logging
import os
import tempfile
import threading
import time
from pathlib import Path

from ._envparse import env_int
from .paths import data_dir

log = logging.getLogger(__name__)

_lock = threading.Lock()
# Per-goal-dir (count, total_blob_bytes) seeded by one scan, then maintained
# in-process. A concurrent worker process may undercount briefly; the caps are
# disk-usage bounds, not a security boundary, so approximate is acceptable.
_usage: dict[str, tuple[int, int]] = {}

_CAP_MARKER = "CAPPED"
_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}

_DEFAULT_MAX_FILE_MB = 8
_DEFAULT_MAX_TOTAL_MB = 256
_DEFAULT_MAX_ENTRIES = 2000


def _workspace_cfg() -> dict:
    try:
        from .config import load_config
        cfg = (load_config() or {}).get("workspace") or {}
        return cfg if isinstance(cfg, dict) else {}
    except Exception:  # pragma: no cover -- config never blocks a write
        return {}


def _cfg_bool(value: object, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        v = value.strip().lower()
        if v in _TRUE:
            return True
        if v in _FALSE or v == "":
            return False
    return default


def enabled() -> bool:
    """Journal on? ``MAVERICK_WORKSPACE_JOURNAL`` (1/0) beats ``[workspace]
    journal`` so an operator can force it either way per-process."""
    env = os.environ.get("MAVERICK_WORKSPACE_JOURNAL", os.environ.get("LIGHTWORK_WORKSPACE_JOURNAL", "")).strip().lower()
    if env in _TRUE:
        return True
    if env in _FALSE and env != "":
        return False
    return _cfg_bool(_workspace_cfg().get("journal"), False)


def strict() -> bool:
    """Strict mode: a journal failure refuses the write instead of warning."""
    env = os.environ.get("MAVERICK_WORKSPACE_JOURNAL_STRICT", os.environ.get("LIGHTWORK_WORKSPACE_JOURNAL_STRICT", "")).strip().lower()
    if env in _TRUE:
        return True
    if env in _FALSE and env != "":
        return False
    return _cfg_bool(_workspace_cfg().get("journal_strict"), False)


def _max_file_bytes() -> int:
    cfg = _workspace_cfg().get("journal_max_file_mb", _DEFAULT_MAX_FILE_MB)
    try:
        mb = float(cfg)
    except (TypeError, ValueError):
        mb = _DEFAULT_MAX_FILE_MB
    mb = env_int("MAVERICK_WORKSPACE_JOURNAL_MAX_FILE_MB", int(mb))
    return max(1, int(mb)) * 1024 * 1024


def _max_total_bytes() -> int:
    cfg = _workspace_cfg().get("journal_max_total_mb", _DEFAULT_MAX_TOTAL_MB)
    try:
        mb = float(cfg)
    except (TypeError, ValueError):
        mb = _DEFAULT_MAX_TOTAL_MB
    return max(1, int(mb)) * 1024 * 1024


def _max_entries() -> int:
    cfg = _workspace_cfg().get("journal_max_entries", _DEFAULT_MAX_ENTRIES)
    try:
        n = int(cfg)
    except (TypeError, ValueError):
        n = _DEFAULT_MAX_ENTRIES
    return max(1, n)


def journal_root() -> Path:
    """Journal store root: ``[workspace] journal_dir`` or the (tenant-scoped)
    ``~/.maverick/journal``."""
    jd = str(_workspace_cfg().get("journal_dir") or "").strip()
    return Path(jd).expanduser() if jd else data_dir("journal")


def goal_dir(goal_id: object = None) -> Path:
    """Directory holding one goal's journal entries.

    ``goal_id=None`` resolves the CURRENT goal from the logging trace context
    (bound by the orchestrator for every nested call of a run); writes outside
    any goal — an operator using the file tools ad hoc — land in ``adhoc``.
    """
    gid = goal_id
    if gid is None:
        try:
            from .logging_config import current_goal_id
            gid = current_goal_id()
        except Exception:  # pragma: no cover -- attribution never blocks
            gid = None
    # The literal "adhoc" addresses the no-goal bucket explicitly (the CLI's
    # default when no --goal is given must land on the same directory that
    # context-free writes recorded into).
    if gid is None or str(gid) == "adhoc":
        return journal_root() / "adhoc"
    return journal_root() / f"goal-{gid}"


def _seed_usage(gdir: Path) -> tuple[int, int]:
    key = str(gdir)
    got = _usage.get(key)
    if got is not None:
        return got
    count = 0
    total = 0
    if gdir.exists():
        count = sum(1 for _ in gdir.glob("*.json"))
        for p in gdir.glob("*.pre"):
            try:
                total += p.stat().st_size
            except OSError:
                pass
    _usage[key] = (count, total)
    return count, total


def _next_seq(gdir: Path, count_hint: int) -> int:
    # count_hint is usually right; verify against the store so a concurrent
    # writer (another worker process on the same goal) can't be overwritten —
    # the entry file itself is created O_EXCL and retried on collision.
    seq = count_hint + 1
    existing = sorted(gdir.glob("*.json"))
    if existing:
        try:
            seq = max(seq, int(existing[-1].name.split(".")[0]) + 1)
        except ValueError:
            pass
    return seq


def record_pre_image(workdir: Path, target: Path) -> None:
    """Journal ``target``'s pre-write state. Called BEFORE the file tool's
    ``O_CREAT`` open, so a created-by-this-write file is recorded as
    ``existed = false`` (revert then deletes it).

    Fail-open by default (log + continue); under :func:`strict`, any failure
    raises ``ValueError`` so the file tools' standard error contract refuses
    the write. Never raises anything else.
    """
    if not enabled():
        return
    try:
        _record_inner(Path(workdir), Path(target))
    except ValueError:
        raise
    except Exception:
        if strict():
            raise ValueError(
                "workspace journal (strict) could not record the pre-image; "
                "refusing the write"
            ) from None
        log.warning("workspace journal: pre-image record failed for %s",
                    target, exc_info=True)


def _mkdir_private(path: Path) -> None:
    # Pre-images can hold secrets (``.env``, keys): the journal root and goal
    # directory are owner-only, whatever the umask.
    for d in (path.parent, path):
        d.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.chmod(d, 0o700)
        except OSError:  # pragma: no cover -- e.g. a non-POSIX filesystem
            pass


def _write_private(path: Path, data: bytes) -> None:
    fd = os.open(str(path), os.O_CREAT | os.O_TRUNC | os.O_WRONLY
                 | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def _default_file_mode(directory: Path) -> int:
    """``0o666 & ~umask`` -- the mode a plain ``open()`` would create.

    Setting the umask to probe it would briefly change it for every thread in
    the process, so it is read from /proc where available, and elsewhere by
    creating a throwaway file with mode 0o666 in ``directory`` and reading
    back the mode the kernel gave it. 0o644 is the last resort only when
    neither works.
    """
    try:
        with open("/proc/self/status", encoding="ascii") as fh:
            for line in fh:
                if line.startswith("Umask:"):
                    return 0o666 & ~int(line.split()[1], 8)
    except (OSError, ValueError, IndexError):
        pass
    probe = directory / f".journal-umask-probe.{os.getpid()}.{time.time_ns()}"
    try:
        fd = os.open(str(probe), os.O_CREAT | os.O_EXCL | os.O_WRONLY
                     | getattr(os, "O_NOFOLLOW", 0), 0o666)
        try:
            return os.fstat(fd).st_mode & 0o777
        finally:
            os.close(fd)
            os.unlink(probe)
    except OSError:
        return 0o644


def _entry_mode(entry: dict) -> int | None:
    mode = entry.get("mode")
    if type(mode) is int and 0 <= mode <= 0o777:
        return mode
    return None


def _restore_bytes(target: Path, blob: bytes, mode: int | None = None) -> None:
    """Atomically replace ``target`` with ``blob``. The temp file is created
    with ``mkstemp`` (O_EXCL, unpredictable name) so a file or symlink an
    agent planted beside the target can never receive the bytes. ``mode`` is
    the recorded pre-image mode; without one the current file's mode is kept,
    or a missing file gets the umask default."""
    target.parent.mkdir(parents=True, exist_ok=True)
    if mode is None:
        try:
            mode = target.stat().st_mode & 0o777 if target.exists() else None
        except OSError:
            mode = None
    if mode is None:
        mode = _default_file_mode(target.parent)
    fd, tmp = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".journal-revert.tmp",
                               dir=str(target.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(blob)
        os.chmod(tmp, mode)
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _record_inner(workdir: Path, target: Path) -> None:
    gdir = goal_dir()
    with _lock:
        count, total = _seed_usage(gdir)
        if (gdir / _CAP_MARKER).exists():
            # Already marked incomplete. Fail-open mode stops accumulating;
            # strict mode must keep refusing EVERY subsequent write, or the
            # guarantee quietly lapses after the first cap trip.
            if strict():
                raise ValueError(
                    "workspace journal (strict) is full; refusing the write "
                    "(raise [workspace] journal_max_* or revert/clear the goal)"
                )
            return
        if count >= _max_entries() or total >= _max_total_bytes():
            _mkdir_private(gdir)
            (gdir / _CAP_MARKER).write_text(
                f"cap reached at {count} entries / {total} bytes; later writes "
                "are NOT journaled — full revert will refuse without --partial\n",
                encoding="utf-8")
            log.warning(
                "workspace journal for %s hit its cap (%d entries / %d bytes); "
                "further writes are not journaled", gdir.name, count, total)
            if strict():
                raise ValueError(
                    "workspace journal (strict) is full; refusing the write "
                    "(raise [workspace] journal_max_* or revert/clear the goal)"
                )
            return

        try:
            rel = target.relative_to(workdir).as_posix()
        except ValueError:
            # The file tools always pass a workdir-contained target; a caller
            # that doesn't gets recorded by absolute path only if we refused —
            # instead skip: journal scope is the workspace.
            return

        existed = target.exists()
        blob: bytes | None = None
        skipped_reason = ""
        size = 0
        mode: int | None = None
        if existed:
            try:
                st = target.stat()
                size = st.st_size
                mode = st.st_mode & 0o777
            except OSError:
                size = -1
            if 0 <= size <= _max_file_bytes():
                try:
                    blob = target.read_bytes()
                except OSError:
                    skipped_reason = "unreadable"
            else:
                skipped_reason = "too_large"
        if skipped_reason and strict():
            raise ValueError(
                f"workspace journal (strict): pre-image of {rel!r} "
                f"{skipped_reason.replace('_', ' ')}; refusing the write")

        _mkdir_private(gdir)
        seq = _next_seq(gdir, count)
        for _ in range(5):
            meta_path = gdir / f"{seq:06d}.json"
            entry = {
                "seq": seq,
                "ts": int(time.time()),
                "path": rel,
                "workdir": str(workdir),
                "existed": existed,
                "pre_bytes": (len(blob) if blob is not None
                              else (size if existed and size >= 0 else 0)),
                "pre_sha256": (hashlib.sha256(blob).hexdigest()
                               if blob is not None else ""),
                "blob": blob is not None,
                "skipped_reason": skipped_reason,
                "mode": mode,
            }
            try:
                fd = os.open(str(meta_path),
                             os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                seq += 1
                continue
            # Blob first, then metadata through the already-claimed fd: a blob
            # without its .json is ignorable garbage, but a .json referencing a
            # missing blob would break revert.
            try:
                if blob is not None:
                    _write_private(gdir / f"{seq:06d}.pre", blob)
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(entry, fh)
            except BaseException:
                try:
                    os.close(fd)
                except OSError:
                    pass
                raise
            _usage[str(gdir)] = (count + 1,
                                 total + (len(blob) if blob is not None else 0))
            return
        raise ValueError("workspace journal: could not allocate an entry slot")


def list_entries(goal_id: object = None) -> list[dict]:
    """This goal's journal entries, oldest first. ``[]`` when none."""
    gdir = goal_dir(goal_id)
    out: list[dict] = []
    if not gdir.exists():
        return out
    for p in sorted(gdir.glob("*.json")):
        try:
            entry = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            log.warning("workspace journal: unreadable entry %s", p)
            continue
        if isinstance(entry, dict):
            out.append(entry)
    out.sort(key=lambda e: int(e.get("seq") or 0))
    return out


def is_capped(goal_id: object = None) -> bool:
    return (goal_dir(goal_id) / _CAP_MARKER).exists()


def _safe_rel(entry: dict) -> str | None:
    """Validate an entry's recorded path: relative, no traversal. The journal
    file is operator-writable state — treat it as untrusted at revert time."""
    rel = str(entry.get("path") or "")
    if not rel or rel.startswith(("/", "\\")):
        return None
    parts = [p for p in rel.replace("\\", "/").split("/") if p]
    if not parts or any(p == ".." for p in parts) or any(":" in p for p in parts):
        return None
    return "/".join(parts)


def _resolve_target(entry: dict) -> Path | None:
    rel = _safe_rel(entry)
    if rel is None:
        return None
    workdir = Path(str(entry.get("workdir") or "")).expanduser()
    if not str(workdir):
        return None
    candidate = workdir / rel
    try:
        candidate.resolve(strict=False).relative_to(workdir.resolve(strict=False))
    except ValueError:
        return None
    return candidate


def _blob_for(gdir: Path, entry: dict) -> bytes | None:
    if not entry.get("blob"):
        return None
    try:
        return (gdir / f"{int(entry['seq']):06d}.pre").read_bytes()
    except (OSError, ValueError, KeyError):
        return None


def diff_goal(goal_id: object = None, *, max_bytes: int = 200_000) -> str:
    """Unified diff of every journaled file: pre-image vs what's on disk NOW.

    Text-lossy by design (``errors="replace"``); binary files diff as noise
    but never crash the view. Output capped at ``max_bytes``.
    """
    gdir = goal_dir(goal_id)
    chunks: list[str] = []
    seen: set[str] = set()
    # Oldest entry per file: the diff an operator wants is pre-run vs now.
    for entry in list_entries(goal_id):
        rel = _safe_rel(entry)
        if rel is None or rel in seen:
            continue
        seen.add(rel)
        target = _resolve_target(entry)
        if target is None:
            continue
        pre = _blob_for(gdir, entry) if entry.get("existed") else b""
        if pre is None:
            chunks.append(f"--- {rel}: pre-image not captured "
                          f"({entry.get('skipped_reason') or 'missing blob'})\n")
            continue
        try:
            now = target.read_bytes() if target.exists() else b""
        except OSError:
            now = b""
        if pre == now:
            continue
        diff = difflib.unified_diff(
            pre.decode("utf-8", errors="replace").splitlines(keepends=True),
            now.decode("utf-8", errors="replace").splitlines(keepends=True),
            fromfile=f"a/{rel}", tofile=f"b/{rel}")
        chunks.append("".join(diff))
        if sum(len(c) for c in chunks) > max_bytes:
            chunks.append("\n... [diff truncated]\n")
            break
    return "".join(chunks) or "(no journaled changes)"


def _apply_revert(gdir: Path, entries: list[dict], *, dry_run: bool) -> dict:
    """One pass over ``entries`` newest-first: restore pre-images / delete
    created files (or just count, when ``dry_run``). Shared by the audit
    pre-pass and the real application so the audited plan and the applied
    change come from the same logic."""
    reverted = 0
    deleted = 0
    skipped = 0
    # Write/unlink errors may succeed on a later run; the other skip reasons
    # (unsafe path, symlink, missing blob) never will.
    retryable = 0
    reasons: dict[str, int] = {}

    def _skip(reason: str) -> None:
        nonlocal skipped
        skipped += 1
        reasons[reason] = reasons.get(reason, 0) + 1

    for entry in sorted(entries, key=lambda e: int(e.get("seq") or 0),
                        reverse=True):
        target = _resolve_target(entry)
        if target is None:
            _skip("unsafe_path")
            log.warning("workspace journal: refusing entry with unsafe path %r",
                        entry.get("path"))
            continue
        if target.is_symlink():
            _skip("symlink")
            log.warning("workspace journal: refusing to restore through "
                        "symlink %s", target)
            continue
        if not entry.get("existed"):
            if dry_run:
                deleted += 1
            elif target.exists():
                try:
                    target.unlink()
                    deleted += 1
                except OSError:
                    _skip("delete_failed")
                    retryable += 1
            continue
        blob = _blob_for(gdir, entry)
        if blob is None:
            _skip(entry.get("skipped_reason") or "missing_blob")
            continue
        if dry_run:
            reverted += 1
            continue
        try:
            _restore_bytes(target, blob, _entry_mode(entry))
            reverted += 1
        except OSError:
            _skip("write_failed")
            retryable += 1
    return {"reverted": reverted, "deleted": deleted, "skipped": skipped,
            "retryable": retryable, "skip_reasons": reasons,
            "entries": len(entries), "dry_run": dry_run}


def revert_goal(goal_id: object = None, *, partial: bool = False,
                dry_run: bool = False) -> dict:
    """Restore every journaled file to its pre-run state, newest entry first
    (so a file written N times lands on its pre-FIRST-write bytes).

    Raises ``ValueError`` when the journal is incomplete (cap marker or any
    skipped pre-image) unless ``partial=True`` — an incomplete rollback must
    be an explicit choice, never a silent one. ``dry_run`` reports what would
    happen without touching the workspace. A real revert first writes one
    signed ``workspace_revert`` audit row (an audit REFUSAL aborts the revert
    before any file changes), then applies, then archives the journal
    directory so it cannot be replayed by accident -- unless a write or delete
    failed, in which case the journal stays so revert can be retried.
    """
    gdir = goal_dir(goal_id)
    entries = list_entries(goal_id)
    if not entries:
        return {"reverted": 0, "deleted": 0, "skipped": 0, "entries": 0,
                "complete": not is_capped(goal_id), "dry_run": dry_run}
    incomplete = is_capped(goal_id) or any(
        e.get("skipped_reason") for e in entries)
    if incomplete and not partial:
        raise ValueError(
            "journal is incomplete (cap reached or unreadable/oversized "
            "pre-images): a full revert is impossible. Re-run with --partial "
            "to restore what was captured.")

    if not dry_run:
        # Signed evidence FIRST, mutation second: audit_event lets a refusal
        # (AuditRefused — the deployment mandates a signed chain and the
        # signer will not start) propagate, and an unrecordable revert must
        # not run at all — the alternative is exactly the "recorded nothing
        # and did it anyway" failure the audit contract exists to prevent.
        # Counts come from the dry pass below, so the row states the plan the
        # refusal would have blocked. Non-refusal audit failures are logged
        # (not raised) inside audit_event itself.
        plan = _apply_revert(gdir, entries, dry_run=True)
        from .audit import EventKind, audit_event
        audit_event(EventKind.WORKSPACE_REVERT,
                    goal_id=goal_id if isinstance(goal_id, int) else None,
                    journal=gdir.name,
                    complete=not incomplete and not plan["skipped"],
                    **{k: plan[k] for k in ("reverted", "deleted", "skipped",
                                            "entries")})

    result = _apply_revert(gdir, entries, dry_run=dry_run)
    # A skipped entry (unsafe path, symlink, missing blob, write error) means
    # the workspace is NOT back at its pre-run state.
    result["complete"] = not incomplete and not result["skipped"]
    if dry_run:
        return result

    if result["retryable"]:
        # A write or unlink failed: keep the journal so running revert again
        # can retry it. Permanent skips (unsafe path, symlink, missing or
        # uncaptured pre-image) never succeed on a retry, so they are only
        # reported, and the journal is archived as usual: replaying it would
        # overwrite edits made since this revert.
        log.warning("workspace journal: %d write(s) failed; %s kept for retry",
                    result["retryable"], gdir)
        return result
    with _lock:
        _usage.pop(str(gdir), None)
        archived = gdir.with_name(f"{gdir.name}.reverted-{int(time.time())}")
        try:
            os.replace(gdir, archived)
            result["archived"] = str(archived)
        except OSError:
            log.warning("workspace journal: could not archive %s", gdir,
                        exc_info=True)
    return result


def _reset_for_tests() -> None:
    """Drop the in-process usage cache (test isolation only)."""
    with _lock:
        _usage.clear()


__all__ = [
    "enabled", "strict", "journal_root", "goal_dir", "record_pre_image",
    "list_entries", "is_capped", "diff_goal", "revert_goal",
]
