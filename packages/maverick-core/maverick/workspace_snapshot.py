"""Workspace snapshot / restore: point-in-time tar.gz of a directory.

A cheap, dependency-free checkpoint of a working directory so a long run can roll
back a bad edit or compare states. Snapshots are gzip tarballs under
``~/.maverick/snapshots/`` (or ``[workspace] snapshot_dir``). Extraction is
path-traversal-safe — no archive member may escape the destination directory
(the classic "tarbomb"/``../`` write). The ``_*`` helpers take explicit paths so
they're unit-testable against a tmpdir.
"""
from __future__ import annotations

import logging
import os
import re
import tarfile
import time
from pathlib import Path

from .paths import data_dir

log = logging.getLogger(__name__)

_DEFAULT_STORE = data_dir("snapshots")
_ID_RE = re.compile(r"^snap-(\d{4})(?:-.*)?$")
# Per-snapshot ceiling so a runaway workspace can't fill the disk silently.
_MAX_FILES = 20_000
_MAX_BYTES = 512 * 1024 * 1024  # 512 MiB uncompressed


def store_dir() -> Path:
    from .config import load_config
    try:
        cfg = (load_config() or {}).get("workspace") or {}
        sd = str(cfg.get("snapshot_dir") or "").strip()
    except Exception:  # pragma: no cover -- config never blocks snapshots
        sd = ""
    return Path(sd).expanduser() if sd else _DEFAULT_STORE


def _slug(label: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9_-]+", "-", (label or "").strip()).strip("-")
    return s[:40].lower()


def _next_id(store: Path) -> str:
    n = 0
    if store.exists():
        for p in store.glob("snap-*.tar.gz"):
            m = _ID_RE.match(p.name[: -len(".tar.gz")])
            if m:
                n = max(n, int(m.group(1)))
    return f"{n + 1:04d}"


def create_snapshot(src: Path, store: Path, label: str = "") -> dict:
    """Tar+gzip ``src`` into ``store`` and return its manifest.

    Raises ``ValueError`` if ``src`` doesn't exist or exceeds the size/file
    ceilings.
    """
    src = Path(src)
    if not src.exists() or not src.is_dir():
        raise ValueError(f"not a directory: {src}")
    store.mkdir(parents=True, exist_ok=True)
    num = _next_id(store)
    slug = _slug(label)
    name = f"snap-{num}-{slug}.tar.gz" if slug else f"snap-{num}.tar.gz"
    target = store / name

    files = 0
    total = 0
    for p in src.rglob("*"):
        # Count only what restore can actually recreate: restore_snapshot skips
        # link members, so a symlink counted here (``is_file`` follows the link)
        # would inflate the manifest above the number restore reports back.
        if p.is_file() and not p.is_symlink():
            files += 1
            try:
                total += p.stat().st_size
            except OSError:
                pass
            if files > _MAX_FILES or total > _MAX_BYTES:
                raise ValueError(
                    f"workspace too large to snapshot ({files} files, "
                    f"{total} bytes); raise the limit or narrow the path")

    # Build the archive into a temp sibling and atomically rename it into
    # place. Writing tarfile.open(target) directly meant a tar.add() that
    # failed partway (an unreadable file, a full disk, an interrupt) left a
    # TRUNCATED .tar.gz at the discoverable snap-*.tar.gz name -- list_snapshots
    # would list it and a later restore would fail to extract a corrupt
    # checkpoint. With temp+os.replace the final name only ever appears once
    # the archive is complete; a failure unlinks the temp and leaves the store
    # with no half-written snapshot.
    tmp = target.with_name(target.name + ".tmp")
    try:
        with tarfile.open(tmp, "w:gz") as tar:
            tar.add(src, arcname=".", recursive=True)
        os.replace(tmp, target)
    except BaseException:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass
        raise
    return {
        "id": f"snap-{num}",
        "label": label,
        "path": str(target),
        "files": files,
        "bytes": total,
        "created": int(time.time()),
    }


def list_snapshots(store: Path) -> list[dict]:
    """Newest-first list of ``{id, label, archive, size_bytes, mtime}``."""
    if not store.exists():
        return []
    out: list[dict] = []
    for p in sorted(store.glob("snap-*.tar.gz")):
        stem = p.name[: -len(".tar.gz")]
        m = _ID_RE.match(stem)
        if not m:
            continue
        label = stem[len(f"snap-{m.group(1)}"):].lstrip("-")
        try:
            st = p.stat()
        except OSError:
            continue
        out.append({
            "id": f"snap-{m.group(1)}",
            "label": label,
            "archive": p.name,
            "size_bytes": st.st_size,
            "mtime": int(st.st_mtime),
        })
    out.sort(key=lambda r: r["id"], reverse=True)
    return out


def _resolve_archive(store: Path, snap_id: str) -> Path:
    snap_id = (snap_id or "").strip()
    m = re.match(r"^(?:snap-)?(\d{4})$", snap_id)
    if not m:
        raise ValueError(f"invalid snapshot id {snap_id!r} (expected e.g. snap-0001)")
    num = m.group(1)
    matches = sorted(store.glob(f"snap-{num}*.tar.gz"))
    if not matches:
        raise ValueError(f"no such snapshot {snap_id!r}")
    return matches[0]


def _is_within(base: Path, target: Path) -> bool:
    # Lexical containment: normalize away any ``..`` in the archive member name
    # WITHOUT resolving symlinks. Link archive members are skipped before this
    # check, so an outward symlink already present in ``dest`` does not abort an
    # in-place rollback merely because the skipped link itself points outside.
    base_s = os.path.normpath(str(base))
    target_s = os.path.normpath(str(target))
    return target_s == base_s or target_s.startswith(base_s + os.sep)


def _resolved_within(base: Path, target: Path) -> bool:
    base_r = base.resolve(strict=False)
    target_r = target.resolve(strict=False)
    try:
        target_r.relative_to(base_r)
    except ValueError:
        return False
    return True


def restore_snapshot(store: Path, snap_id: str, dest: Path) -> dict:
    """Extract a snapshot into ``dest`` with path-traversal protection."""
    archive = _resolve_archive(store, snap_id)
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    restored = 0
    skipped_links = 0
    members_seen: set[str] = set()
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar.getmembers():
            # Record EVERY member's normalised path (files, dirs, even skipped
            # links) so the reconciliation pass below only deletes destination
            # entries the snapshot never contained.
            members_seen.add(os.path.normpath(member.name))
            if member.issym() or member.islnk():
                # Refuse links — a symlink member could later redirect a write
                # outside dest even though the link file itself is "within".
                # Skip BEFORE the containment check: a link is never extracted,
                # so there is nothing to confine, and an outward-pointing
                # symlink already present in dest would otherwise abort the
                # whole in-place rollback and leave later members unrestored.
                skipped_links += 1
                continue
            if not (member.isfile() or member.isdir()):
                raise ValueError(
                    f"unsafe archive member type for restore: {member.name!r}")
            out_path = dest / member.name
            if not _is_within(dest, out_path):
                raise ValueError(
                    f"unsafe archive member escapes destination: {member.name!r}")
            if not _resolved_within(dest, out_path):
                raise ValueError(
                    f"unsafe archive member follows a link outside destination: "
                    f"{member.name!r}")
            if member.isfile() and not _resolved_within(dest, out_path.parent):
                raise ValueError(
                    f"unsafe archive member parent escapes destination: "
                    f"{member.name!r}")
            # ``filter="data"`` is the safe extraction policy (rejects absolute
            # paths / traversal / device files) and the future default; the
            # kwarg only exists on 3.12+.  On 3.10/3.11 the resolved checks
            # above also prevent writes through pre-existing symlink components.
            try:
                tar.extract(member, path=dest, filter="data")
            except TypeError:
                tar.extract(member, path=dest)
            if member.isfile():
                restored += 1
    if skipped_links:
        log.warning(
            "restore_snapshot: skipped %d link member(s) not recreated in %s",
            skipped_links, dest)
    # Reconcile the destination against the snapshot: delete files (and
    # now-empty dirs) present in dest but ABSENT from the archive. Extraction
    # alone only overwrites/creates members, so reverting an ADDITIVE change (a
    # file the patch created) would otherwise leave the added file behind while
    # revert reports success -- the rollback silently no-ops the add. Confined
    # by the SAME guards as extraction: never delete outside dest, never through
    # a symlink that escapes it. os.walk does not descend into symlinked dirs
    # (followlinks defaults off) so the walk itself cannot leave the snapshot
    # root; symlink entries are left untouched (never followed, never removed).
    removed = 0
    for cur, dirnames, filenames in os.walk(dest, topdown=False):
        base = Path(cur)
        for name in filenames:
            fpath = base / name
            if fpath.is_symlink():
                continue
            rel = os.path.normpath(os.path.relpath(fpath, dest))
            if rel in members_seen:
                continue
            if not _is_within(dest, fpath) or not _resolved_within(dest, fpath):
                continue  # would escape dest -- refuse to delete
            fpath.unlink()
            removed += 1
        for name in dirnames:
            dpath = base / name
            if dpath.is_symlink():
                continue  # a symlinked dir was never recursed into
            rel = os.path.normpath(os.path.relpath(dpath, dest))
            if rel in members_seen:
                continue
            if not _is_within(dest, dpath) or not _resolved_within(dest, dpath):
                continue
            try:
                dpath.rmdir()  # succeeds only if already empty
                removed += 1
            except OSError:
                pass  # still holds a kept file -- leave it in place
    return {"id": f"snap-{archive.name[5:9]}", "restored": restored,
            "skipped_links": skipped_links, "removed": removed, "dest": str(dest)}


# --- tool surface ----------------------------------------------------------

_SCHEMA = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["snapshot", "list", "restore"]},
        "path": {"type": "string",
                 "description": "directory to snapshot (snapshot op; default cwd)"},
        "label": {"type": "string", "description": "human label for a snapshot"},
        "id": {"type": "string", "description": "snapshot id, e.g. snap-0001 (restore)"},
        "dest": {"type": "string", "description": "directory to restore into (restore)"},
    },
    "required": ["op"],
}


def _run(args: dict, sandbox=None) -> str:
    import json as _json

    # Confine the snapshot SOURCE and the restore DESTINATION to the sandbox
    # workspace. Unconfined, `snapshot path=~/.maverick` would tar up the
    # operator's API keys + world.db, and `restore dest=...` could write those
    # bytes anywhere -- a secret-exfiltration / arbitrary-write primitive.
    from .tools.ffmpeg_tool import _safe_path
    op = args.get("op")
    store = store_dir()
    try:
        if op == "snapshot":
            src = Path(_safe_path(sandbox, args.get("path") or "."))
            man = create_snapshot(src, store, args.get("label") or "")
            return (f"created {man['id']} ({man['files']} files, "
                    f"{man['bytes']} bytes) -> {man['path']}")
        if op == "list":
            snaps = list_snapshots(store)
            return _json.dumps(snaps, indent=2) if snaps else "(no snapshots)"
        if op == "restore":
            dest = args.get("dest")
            if not dest:
                return "ERROR: restore requires dest"
            res = restore_snapshot(store, args.get("id") or "",
                                   Path(_safe_path(sandbox, dest)))
            return f"restored {res['restored']} files from {res['id']} -> {res['dest']}"
    except (ValueError, OSError, tarfile.TarError) as e:
        return f"ERROR: {e}"
    return f"ERROR: unknown op {op!r}"


def workspace_snapshot(sandbox=None):
    from .tools import Tool
    return Tool(
        name="workspace_snapshot",
        description=(
            "Snapshot / restore a working directory as a gzip tarball. ops: "
            "snapshot (path, label), list, restore (id, dest). Snapshots live "
            "under ~/.maverick/snapshots; the source/destination are confined "
            "to the workspace and restore is path-traversal-safe."
        ),
        input_schema=_SCHEMA,
        fn=lambda args: _run(args, sandbox),
    )


__all__ = [
    "store_dir", "create_snapshot", "list_snapshots", "restore_snapshot",
    "workspace_snapshot",
]
