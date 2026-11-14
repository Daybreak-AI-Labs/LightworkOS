"""Adopt an evolution archive's best config into a domain pack.

Closes the loop from offline search to live behavior: ``evolve_continuous``
finds winning configs, and this flows them back into the packs the agent
factory actually spawns from. ``adopt_best`` takes the archive's
best candidate, overlays the chosen keys onto a pack, and writes the result
as an OPERATOR pack (user domains dir overrides built-ins) — never editing
the source pack in place, always leaving a ``.bak`` of any pack it replaces.

Deliberately gated: this is an explicit operator action (CLI ``--adopt``
prints the diff and requires ``--yes``), not an automatic step of any loop —
a config that won offline still deserves a human glance before it changes a
department's live persona.
"""
from __future__ import annotations

import shutil
import threading
from pathlib import Path

from .archive import Archive

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover -- Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

# Keys adoption may overlay onto a pack. Capability scopes (allow_*, max_risk)
# are deliberately excluded: evolution must never widen a security envelope.
ADOPTABLE_KEYS = frozenset({"persona", "description", "models"})
_adopt_lock = threading.Lock()


def _toml_value(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return _toml_string(value)
    if isinstance(value, list):
        return "[" + ", ".join(_toml_value(v) for v in value) + "]"
    raise TypeError(f"unsupported TOML value: {type(value).__name__}")


def _toml_string(value: str) -> str:
    """A TOML basic string. Every control character is escaped (a bare CR, BEL
    or NUL made the written pack unparseable), not only newlines."""
    out = []
    for ch in value:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append(f"\\u{ord(ch):04X}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _toml_key(key) -> str:
    """A bare key when it is one, else a quoted key: ``a.b`` emitted bare
    re-parsed as a nested table, and a key with a space was invalid TOML."""
    key = str(key)
    if key and all(c.isascii() and (c.isalnum() or c in "-_") for c in key):
        return key
    return _toml_string(key)


def _is_table_array(value) -> bool:
    """A non-empty list whose items are all dicts -> a TOML array-of-tables."""
    return (
        isinstance(value, list)
        and len(value) > 0
        and all(isinstance(item, dict) for item in value)
    )


def _emit_table_body(lines: list[str], table: dict) -> None:
    """Emit ``k = v`` rows for one table's scalar/list-of-scalar entries.

    Real packs nest only scalars and lists-of-scalars inside ``[output]`` and
    each ``[[workflow]]`` item; a dict/array-of-tables nested a further level
    deep still raises via :func:`_toml_value`, matching the "raise rather than
    write a corrupt pack" contract.
    """
    for k, v in table.items():
        lines.append(f"{_toml_key(k)} = {_toml_value(v)}")


def render_pack(data: dict) -> str:
    """Serialize a domain-pack dict back to TOML.

    Covers the shapes a :class:`DomainProfile` uses: top-level strings, lists
    of scalars, and numbers; ``[table]`` blocks for dict values (e.g.
    ``models``, ``output``); and ``[[array_of_tables]]`` blocks for lists of
    dicts (e.g. the ``workflow`` step list every shipped domain pack carries).
    Raises on anything deeper rather than writing a corrupt pack.

    Top-level scalars/lists are emitted first so the tables and table-arrays
    they precede are not accidentally captured as members of an earlier
    ``[table]`` header (TOML scopes bare keys under the most recent header).
    """
    lines: list[str] = []
    tables: list[tuple[str, dict]] = []
    table_arrays: list[tuple[str, list]] = []
    for key, value in data.items():
        if isinstance(value, dict):
            tables.append((key, value))
            continue
        if _is_table_array(value):
            table_arrays.append((key, value))
            continue
        lines.append(f"{_toml_key(key)} = {_toml_value(value)}")
    for key, table in tables:
        lines.append("")
        lines.append(f"[{_toml_key(key)}]")
        _emit_table_body(lines, table)
    for key, items in table_arrays:
        for item in items:
            lines.append("")
            lines.append(f"[[{_toml_key(key)}]]")
            _emit_table_body(lines, item)
    return "\n".join(lines) + "\n"


def plan_adoption(
    archive_path: str | Path, pack_path: str | Path, *,
    keys: list[str] | None = None,
) -> tuple[dict, dict[str, tuple[object, object]]]:
    """Compute the adopted pack dict + a ``{key: (old, new)}`` change map.

    Pure (no writes), so the CLI can show the diff before asking for
    confirmation and tests can assert the overlay without touching disk.
    Only :data:`ADOPTABLE_KEYS` are considered; a key absent from the best
    config is left untouched.
    """
    archive = Archive.load(archive_path)
    best = archive.confirmed_best()
    if best is None:
        if archive.best() is None:
            raise ValueError(f"archive {archive_path} has no candidates")
        raise ValueError(
            f"archive {archive_path} has no promotion-confirmed candidate")
    with open(pack_path, "rb") as f:
        pack = tomllib.load(f)
    wanted = set(keys) if keys else set(ADOPTABLE_KEYS)
    illegal = wanted - ADOPTABLE_KEYS
    if illegal:
        raise ValueError(
            f"refusing to adopt non-adoptable key(s): {sorted(illegal)} "
            f"(capability scopes never widen via evolution)"
        )
    changes: dict[str, tuple[object, object]] = {}
    for key in sorted(wanted):
        if key not in best.config:
            continue
        new = best.config[key]
        old = pack.get(key)
        if new != old:
            changes[key] = (old, new)
            pack[key] = new
    return pack, changes


def adopt_best(
    archive_path: str | Path, pack_path: str | Path, *,
    keys: list[str] | None = None, out_dir: str | Path | None = None,
) -> Path | None:
    """Write the adopted pack into ``out_dir`` (default: alongside the pack).

    Returns the written path, or ``None`` when the best config changes
    nothing. The destination's PRISTINE pack is preserved to ``.bak`` -- written
    ONCE and never clobbered -- so adoption is always reversible to the original
    with a rename, even after adopting repeatedly into the same destination.
    """
    pack_path = Path(pack_path)
    dest_dir = Path(out_dir) if out_dir is not None else pack_path.parent
    dest = dest_dir / pack_path.name
    dest_dir.mkdir(parents=True, exist_ok=True)
    # Serialize the whole back-up + write across processes: the .bak guard
    # (dest.exists() and not bak.exists()) is a TOCTOU, and the write used a
    # fixed ".tmp" -- two concurrent adoptions of the same dest would race both.
    from maverick.file_lock import atomic_write_text, cross_process_lock
    # ``cross_process_lock`` is advisory and older Windows runtimes may not
    # provide the platform byte-range implementation. The local lock closes the
    # same-process gap (CLI/tests/embedded workers) while the sidecar covers
    # cooperating processes where supported.
    with (_adopt_lock, cross_process_lock(dest),
          cross_process_lock(archive_path)):
        # Re-read both authority inputs and recompute the complete plan only
        # after serialization. A pre-lock plan can overwrite a newer pack or
        # adopt a champion whose confirmation was concurrently revoked.
        base = dest if dest.exists() else pack_path
        adopted, changes = plan_adoption(archive_path, base, keys=keys)
        if not changes:
            return None
        body = render_pack(adopted)
        # Back up the PRISTINE pack once and never clobber it. With the default
        # out_dir (dest == pack_path), a second adoption used to copy the
        # already-adopted V1 over the .bak, destroying the original pack -- so the
        # docstring's "reversible with a rename" silently held for only one
        # adoption. Writing .bak once keeps the shipped pack recoverable forever.
        bak = dest.with_suffix(dest.suffix + ".bak")
        if dest.exists() and not bak.exists():
            shutil.copy2(dest, bak)
        # Atomic write: a crash or short write mid-replace must not leave a
        # department's live pack half-written/corrupt -- the dest is always
        # either the old pack (recoverable from .bak) or the complete new one.
        atomic_write_text(dest, body)
    return dest


__all__ = ["ADOPTABLE_KEYS", "render_pack", "plan_adoption", "adopt_best"]
