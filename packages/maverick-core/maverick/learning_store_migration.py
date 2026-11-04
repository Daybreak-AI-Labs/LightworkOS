"""One-way move of this host's FILE learning stores into the shared WORLD store.

The work behind ``maverick self-harness migrate-store`` (for
``[self_harness] store = "world"``), shared with the dashboard's Settings > Maintenance control.
Idempotent and fleet-safe: existing world entries win, file-only keys import,
and a conflicting addenda block merges line-by-line under the normal cap. The
routed store is verified to serve every imported key before the files are
renamed to ``*.migrated`` backups. Every write happens under the learning
store's own read-modify-write lock, so it is safe while Lightwork is running.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class MigrationRefused(RuntimeError):
    """The move cannot run (wrong store setting) or failed its verification."""


def _raw(path: Path, keep) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError, OSError):
        return {}
    return {str(k): v for k, v in data.items() if keep(v)} if isinstance(data, dict) else {}


def _file_stores() -> tuple[Path, dict, dict, dict]:
    from . import self_harness as sh
    src = sh._store_path()
    addenda = _raw(src, lambda v: isinstance(v, str) and v.strip())
    meta = _raw(sh._meta_path(src), lambda v: isinstance(v, dict))
    tried = {k: float(v) for k, v in
             _raw(sh._transfer_tried_path(src),
                  lambda v: isinstance(v, (int, float))).items()}
    return src, addenda, meta, tried


def world_store_selected() -> bool:
    from . import self_harness as sh
    return sh.settings().get("store") == "world"


def require_world_store() -> None:
    if not world_store_selected():
        raise MigrationRefused(
            'set [self_harness] store = "world" first -- the migration '
            "imports into the configured world database.")


def preview() -> dict[str, Any]:
    """What a move would import right now (read-only)."""
    from . import self_harness as sh
    _src, addenda, meta, tried = _file_stores()
    return {"world_store": world_store_selected(), "addenda": len(addenda),
            "provenance": len(meta), "tried": len(tried),
            "corpus_configured": bool(sh.settings().get("eval_corpus"))}


def migrate_learning_files() -> dict[str, int] | None:
    """Import the learning files; None when there are none on this host.

    Raises :class:`MigrationRefused` when verification finds an imported key
    missing (the file stores are then left untouched)."""
    from . import learning_store
    from . import self_harness as sh
    src, addenda, meta, tried = _file_stores()
    if not (addenda or meta or tried):
        return None
    merged = 0
    with learning_store.rmw_lock():
        db_add = learning_store.load_addenda_db()
        for k, block in addenda.items():
            if k not in db_add:
                db_add[k] = block
            elif db_add[k] != block:
                cur = db_add[k]
                have = {sh._norm_line(x) for x in sh._bullets(cur)}
                for ln in sh._bullets(block):
                    if sh._norm_line(ln) not in have:
                        cur = sh._compose_addendum(k, cur, ln)
                db_add[k] = cur
                merged += 1
        learning_store.write_addenda_db(db_add)
        db_meta = learning_store.load_line_meta_db()
        for lid, rec in meta.items():
            db_meta.setdefault(lid, rec)
        learning_store.write_line_meta_db(db_meta)
        db_tried = learning_store.load_transfer_tried_db()
        for lid, ts in tried.items():
            db_tried.setdefault(lid, ts)
        learning_store.write_transfer_tried_db(db_tried)
    routed = sh.load_addenda()
    missing = [k for k in addenda if k not in routed]
    if missing:
        raise MigrationRefused(
            f"verification failed -- keys missing after import: {missing[:3]}"
            " (file stores left untouched)")
    for p in (src, sh._meta_path(src), sh._transfer_tried_path(src)):
        if p.exists():
            p.rename(p.with_name(p.name + ".migrated"))
    return {"addenda": len(addenda), "provenance": len(meta), "tried": len(tried),
            "merged": merged}


def migrate_corpus() -> dict[str, int] | None:
    """The eval corpus family rides the same move when configured."""
    from . import self_harness as sh
    cpath = sh.settings().get("eval_corpus")
    if not cpath:
        return None
    from . import self_harness_eval as ev
    return ev.migrate_corpus_files(cpath)


__all__ = ["MigrationRefused", "world_store_selected", "require_world_store", "preview",
           "migrate_learning_files", "migrate_corpus"]
