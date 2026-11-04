"""Obsidian vault tool: read / write / search a local Markdown vault.

File-based (no external service, no auth) — an Obsidian vault is just a folder of
``.md`` notes. ops: list, read, create, append, search. The vault path comes
from ``[obsidian] vault_path`` in ``~/.maverick/config.toml``; every path is
confined to the vault (no traversal). The ``_op_*`` helpers take an explicit
vault so they're unit-testable against a tmpdir.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from . import Tool

_OBSIDIAN_SCHEMA = {
    "type": "object",
    "properties": {
        "op": {"type": "string",
               "enum": ["list", "read", "create", "append", "search"]},
        "note": {"type": "string", "description": "vault-relative note path, e.g. 'ideas/agents.md'"},
        "body": {"type": "string", "description": "full note body (create)"},
        "text": {"type": "string", "description": "text to append (append)"},
        "query": {"type": "string", "description": "substring to search names + content (search)"},
        "limit": {"type": "integer", "default": 50},
    },
    "required": ["op"],
}


def _vault() -> Path:
    from ..config import load_config
    cfg = (load_config() or {}).get("obsidian") or {}
    vp = str(cfg.get("vault_path") or "").strip()
    if not vp:
        raise RuntimeError(
            "no Obsidian vault configured; set [obsidian] vault_path in "
            "~/.maverick/config.toml")
    return Path(vp).expanduser()


def _resolve(vault: Path, note: str) -> Path:
    """Resolve a vault-relative note path, refusing anything outside the vault."""
    if not note or not note.strip():
        raise ValueError("note path is required")
    note = note.strip()
    if not note.endswith(".md"):
        note += ".md"
    vault_root = vault.resolve()
    p = (vault_root / note).resolve()
    if p != vault_root and vault_root not in p.parents:
        raise ValueError(f"note path escapes the vault: {note!r}")
    return p


def _op_list(vault: Path, limit: int = 50) -> str:
    root = vault.resolve()
    notes = sorted(str(p.relative_to(root)).replace("\\", "/")
                   for p in root.rglob("*.md"))
    if not notes:
        return "(vault has no .md notes)"
    return "\n".join(notes[:limit])


def _op_read(vault: Path, note: str) -> str:
    p = _resolve(vault, note)
    if not p.exists():
        return f"ERROR: no such note {note!r}"
    return p.read_text(encoding="utf-8")


def _op_create(vault: Path, note: str, body: str) -> str:
    p = _resolve(vault, note)
    if p.exists():
        return f"ERROR: note {note!r} already exists (use append or a new name)"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body or "", encoding="utf-8")
    return f"created {note}"


def _op_append(vault: Path, note: str, text: str) -> str:
    p = _resolve(vault, note)
    if not text:
        return "ERROR: append requires text"
    p.parent.mkdir(parents=True, exist_ok=True)
    existing = p.read_text(encoding="utf-8") if p.exists() else ""
    sep = "" if (not existing or existing.endswith("\n")) else "\n"
    p.write_text(existing + sep + text, encoding="utf-8")
    return f"appended to {note}"


def _op_search(vault: Path, query: str, limit: int = 50) -> str:
    q = (query or "").strip().lower()
    if not q:
        return "ERROR: search requires query"
    root = vault.resolve()
    hits: list[str] = []
    for p in sorted(root.rglob("*.md")):
        rel = str(p.relative_to(root)).replace("\\", "/")
        try:
            in_body = q in p.read_text(encoding="utf-8").lower()
        except OSError:
            in_body = False
        if q in rel.lower() or in_body:
            hits.append(rel)
        if len(hits) >= limit:
            break
    return "\n".join(hits) if hits else f"(no notes match {query!r})"


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        vault = _vault()
    except RuntimeError as e:
        return f"ERROR: {e}"
    try:
        if op == "list":
            return _op_list(vault, int(args.get("limit") or 50))
        if op == "read":
            return _op_read(vault, args.get("note") or "")
        if op == "create":
            return _op_create(vault, args.get("note") or "", args.get("body") or "")
        if op == "append":
            return _op_append(vault, args.get("note") or "", args.get("text") or "")
        if op == "search":
            return _op_search(vault, args.get("query") or "", int(args.get("limit") or 50))
    except (ValueError, OSError) as e:
        return f"ERROR: {e}"
    return f"ERROR: unknown op {op!r}"


def obsidian() -> Tool:
    return Tool(
        name="obsidian",
        description=(
            "Read / write / search a local Obsidian Markdown vault. ops: list, "
            "read (note), create (note + body), append (note + text), search "
            "(query). Vault from [obsidian] vault_path; paths are confined to "
            "the vault."
        ),
        input_schema=_OBSIDIAN_SCHEMA,
        fn=_run,
    )
