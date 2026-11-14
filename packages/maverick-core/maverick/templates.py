"""Goal templates: pre-built goal bodies with variable substitution.

A template is a markdown file with optional YAML frontmatter that
captures a reusable goal pattern. Variables like ``{{ topic }}`` are
substituted from ``--param key=value`` on the CLI (or programmatically
from a dict).

Lookup order:
  1. ``~/.maverick/templates/<name>.md`` (user-installed)
  2. ``benchmarks/example-templates/<name>.md`` (bundled with the repo)

File format::

    ---
    title: Research and compare AI agent frameworks
    budget_dollars: 2.0
    budget_wall_seconds: 1200
    params:
      - topic
      - depth
    ---
    Compare {{ topic }} across {{ depth }} dimensions. Write the
    output to report.md.

The title can also contain ``{{ vars }}``.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from .paths import data_dir

# ``data_dir`` is tenant-sensitive.  Keep the historical constant as an
# explicit test/embedding override, but never use its import-time value as the
# production runtime path: a long-lived dashboard serves many tenant contexts
# in one process.
_IMPORT_USER_TEMPLATES = data_dir("templates")
USER_TEMPLATES = _IMPORT_USER_TEMPLATES
log = logging.getLogger(__name__)

# Bundled templates ship in the repo; locate via relative path from the
# installed package. The agent kernel intentionally has no notion of the
# repo layout, so we try a few candidate roots.
_BUNDLED_CANDIDATES = [
    Path(__file__).parent.parent.parent.parent / "benchmarks" / "example-templates",
    Path.cwd() / "benchmarks" / "example-templates",
]


def user_templates_dir() -> Path:
    """Return the active tenant's user-template directory.

    ``USER_TEMPLATES`` remains a supported explicit override for tests and
    embedders.  When it still has its original import-time object, resolve the
    path again so the current tenant and ``MAVERICK_HOME`` are honored.
    """
    if USER_TEMPLATES is not _IMPORT_USER_TEMPLATES:
        return Path(USER_TEMPLATES)
    return data_dir("templates")


@dataclass
class Template:
    name: str
    title: str
    body: str
    budget_dollars: float | None = None
    budget_wall_seconds: float | None = None
    params: list[str] = field(default_factory=list)
    path: Path | None = None
    sig: str | None = None
    pubkey: str | None = None
    verified: bool = False
    owner: str = ""
    generation: int = 0
    parameter_schema: dict = field(default_factory=dict)

    @classmethod
    def parse(cls, text: str, name: str, path: Path | None = None) -> Template:
        """Parse a template file. YAML frontmatter is optional."""
        # Normalize CRLF/CR so the LF-anchored frontmatter regex matches files
        # authored on Windows or served over HTTP with CRLF endings -- otherwise
        # their frontmatter (title/params AND budgets) is silently ignored.
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        m = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.DOTALL)
        if m:
            front, body = m.group(1), m.group(2)
            meta = _parse_frontmatter(front)
        else:
            meta, body = {}, text

        def _num(key: str) -> float | None:
            # A user-authored template with a non-numeric budget must not raise a
            # raw ValueError traceback out of float(); give a clear, catchable
            # message the CLI can surface instead.
            raw = meta.get(key)
            if raw is None:
                return None
            try:
                value = float(raw)
                if not math.isfinite(value) or value < 0:
                    raise ValueError
                return value
            except (TypeError, ValueError):
                raise ValueError(
                    f"template {name!r}: [{key}] must be a number, got {raw!r}"
                ) from None

        try:
            generation = int(meta.get("generation", 0))
        except (TypeError, ValueError):
            raise ValueError(
                f"template {name!r}: [generation] must be an integer"
            ) from None
        if generation < 0:
            raise ValueError(f"template {name!r}: [generation] cannot be negative")

        from .template_parameters import normalize_schema

        names = meta.get("params", []) if isinstance(meta.get("params"), list) else []
        return cls(
            name=name,
            title=str(meta.get("title", name)),
            body=body.strip(),
            budget_dollars=_num("budget_dollars"),
            budget_wall_seconds=_num("budget_wall_seconds"),
            params=meta.get("params", []) if isinstance(meta.get("params"), list) else [],
            path=path,
            sig=meta.get("sig") if isinstance(meta.get("sig"), str) else None,
            pubkey=meta.get("pubkey") if isinstance(meta.get("pubkey"), str) else None,
            owner=meta.get("owner") if isinstance(meta.get("owner"), str) else "",
            generation=generation,
            parameter_schema=normalize_schema(meta.get("parameter_schema"), names),
        )

    def render(self, **params: str) -> tuple[str, str]:
        """Return (title, body) with variables substituted.

        Missing required params raise ValueError.
        """
        from .connections import current_principal
        return self.render_for(current_principal(), **params)

    def render_for(self, actor, **params: str) -> tuple[str, str]:
        from .template_connections import parameters
        resolved, _ = parameters(self, actor, params)
        return _substitute(self.title, resolved), _substitute(self.body, resolved)



def _parse_frontmatter(front: str) -> dict:
    meta: dict = {}
    current_key = None
    for line in front.splitlines():
        line = line.rstrip()
        if not line:
            continue
        if line.startswith("  - ") and current_key:
            meta.setdefault(current_key, []).append(line[4:].strip())
        elif ":" in line:
            k, _, v = line.partition(":")
            k = k.strip()
            v = v.strip()
            current_key = k
            if v:
                # Try numeric coercion for budget fields. The pattern must
                # match a real number -- the old `^[\d.]+$` accepted things
                # like "1.2.3" / "." / "5." that float() then choked on,
                # raising an uncaught ValueError out of template parse.
                if k.startswith("budget_") and re.match(r"^\d+(\.\d+)?$", v):
                    meta[k] = float(v)
                else:
                    meta[k] = v
            else:
                meta[k] = []
    return meta


_VAR = re.compile(r"\{\{\s*(\w+)\s*\}\}")


def _substitute(text: str, params: dict[str, str]) -> str:
    return _VAR.sub(lambda m: str(params.get(m.group(1), m.group(0))), text)


def _candidate_dirs() -> list[Path]:
    # De-dup by resolved path: the two bundled candidates (package-relative
    # and cwd-relative) point at the same directory when run from a repo
    # checkout, which otherwise lists it twice -- including in the
    # "not found. Searched: [...]" error.
    out: list[Path] = []
    seen: set[Path] = set()
    for d in [user_templates_dir(), *(c for c in _BUNDLED_CANDIDATES if c.exists())]:
        rd = d.resolve()
        if rd in seen:
            continue
        seen.add(rd)
        out.append(d)
    return out


def list_templates() -> list[str]:
    """Return template names found across user + bundled dirs."""
    seen: set[str] = set()
    out: list[str] = []
    for d in _candidate_dirs():
        if not d.exists():
            continue
        for p in sorted(d.glob("*.md")):
            if p.stem == "README":
                continue
            if p.stem in seen:
                continue
            seen.add(p.stem)
            out.append(p.stem)
    return out


def _validate_template_name(name: str) -> None:
    """Only allow safe template IDs like ``trip-plan`` or ``research_v2``."""
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9_-]*$", name):
        raise ValueError(
            f"invalid template name {name!r}; use only letters, numbers, _ and -"
        )


def load_template(name: str) -> Template:
    """Find ``name.md`` in candidate dirs and parse it."""
    _validate_template_name(name)
    for d in _candidate_dirs():
        p = d / f"{name}.md"
        if p.exists():
            return Template.parse(p.read_text(encoding="utf-8"), name, path=p)
    raise FileNotFoundError(
        f"template {name!r} not found. Searched: {[str(d) for d in _candidate_dirs()]}"
    )


def can_read_template(template: Template, principal: str | None) -> bool:
    """Content permission is exact ownership or verifiable publication.

    Unknown user-installed ownership is retained for migration, never inferred
    from an administrator role or from the absence of owner frontmatter.
    """
    if template.owner and template.owner == (principal or "local"):
        return True
    if template.path is None:
        return False
    try:
        path = template.path.resolve()
        if not template.owner and any(path.parent == directory.resolve() for directory in _BUNDLED_CANDIDATES):
            return True
        if path.parent != user_templates_dir().resolve():
            return False
        receipt = json.loads((path.parent / (template.name + ".publication.json")).read_text(encoding="utf-8"))
        return (receipt.get("schema") == "lightwork.catalog-template-publication.v1"
                and receipt.get("name") == template.name
                and receipt.get("sha256") == hashlib.sha256(path.read_bytes()).hexdigest())
    except (OSError, ValueError, TypeError):
        return False


def _optional_template_budget(value: float | None) -> float | None:
    if value is None:
        return None
    try:
        amount = float(value)
    except (TypeError, ValueError):
        raise ValueError("template budgets must be numbers") from None
    if isinstance(value, bool) or not math.isfinite(amount) or amount < 0:
        raise ValueError("template budgets must be finite non-negative numbers")
    return amount


def _template_parameters(params, title, body):
    clean_params: list[str] = []
    for p in (str(p).strip() for p in (params or [])):
        if re.match(r"^[A-Za-z_]\w*$", p) and p not in clean_params:
            clean_params.append(p)
    # Reconcile declared params with the {{placeholders}} the title/body actually
    # use: an undeclared placeholder would render as a literal "{{x}}" in the
    # goal, and the scheduler/trigger UI (which prompts from tpl.params) would
    # never ask the operator to fill it. Fold any used-but-undeclared placeholder
    # into params so every slot is fillable.
    for m in _VAR.finditer(f"{title}\n{body}"):
        placeholder = m.group(1)
        if placeholder not in clean_params:
            clean_params.append(placeholder)
    return clean_params


def _template_owner(value):
    owner = str(value or "local").strip()
    if not owner or len(owner) > 256 or any(ord(char) < 32 or ord(char) == 127 for char in owner):
        raise ValueError("template owner must be a bounded printable principal")
    return owner


def save_user_template(
    name: str,
    *,
    title: str,
    body: str,
    params: list[str] | None = None,
    budget_dollars: float | None = None,
    budget_wall_seconds: float | None = None,
    overwrite: bool = True,
    owner: str | None = None,
    expected_generation: int | None = None,
    admin_override: bool = False,
    parameter_schema: dict | None = None,
    effect_guard: Callable[[], None] | None = None,
) -> Template:
    """Persist a user-authored (or AI-drafted) workflow as a user template.

    Writes ``~/.maverick/templates/<name>.md`` with frontmatter that
    :meth:`Template.parse` round-trips, then returns the parsed Template. This
    is the local write path behind the dashboard's "save workflow" — the
    counterpart to ``install_template_from_catalog`` (remote, hash-pinned),
    here for content the operator authored or drafted from their own brief.

    Validates the name, requires a non-empty body, collapses the title to a
    single line (frontmatter is line-oriented), and keeps only identifier-like
    param names. Refuses to clobber an existing file when ``overwrite`` is
    False.
    """
    _validate_template_name(name)
    owner = _template_owner(owner)
    if expected_generation is not None:
        try:
            expected_generation = int(expected_generation)
        except (TypeError, ValueError):
            raise ValueError("expected_generation must be an integer") from None
        if expected_generation < 0:
            raise ValueError("expected_generation cannot be negative")
    title = " ".join((title or name).split()) or name
    body = (body or "").strip()
    if not body:
        raise ValueError("template body must not be empty")
    clean_params = _template_parameters(params, title, body)
    from .template_parameters import normalize_schema

    schema = normalize_schema(parameter_schema, clean_params)
    bd = _optional_template_budget(budget_dollars)
    bw = _optional_template_budget(budget_wall_seconds)

    dest = user_templates_dir() / f"{name}.md"
    from .file_lock import (
        atomic_write_text,
        cross_process_lock,
        ensure_private_directory,
    )

    # Make the existence check and publication one serialized operation.
    # ``atomic_write_text`` also avoids following a planted destination symlink
    # and publishes a private, whole-file snapshot to concurrent readers.
    ensure_private_directory(dest.parent)
    with cross_process_lock(dest, strict=True):
        if dest.exists() and not overwrite:
            raise FileExistsError(f"template {name!r} already exists")
        generation = 1
        previous_content = None
        if dest.exists():
            from .file_lock import atomic_read_text, ensure_private_file

            ensure_private_file(dest)
            previous_content = atomic_read_text(dest, encoding="utf-8")
            existing = Template.parse(previous_content, name, path=dest)
            if not admin_override:
                if existing.owner and existing.owner != owner:
                    raise PermissionError(
                        f"template {name!r} is owned by another principal"
                    )
                if not existing.owner and owner != "local":
                    raise PermissionError(
                        f"legacy template {name!r} requires an administrator migration"
                    )
            if (
                expected_generation is not None
                and existing.generation != expected_generation
            ):
                raise FileExistsError(
                    f"template {name!r} changed since generation "
                    f"{expected_generation}; current generation is {existing.generation}"
                )
            generation = existing.generation + 1
        elif expected_generation not in (None, 0):
            raise FileExistsError(
                f"template {name!r} does not exist at generation "
                f"{expected_generation}"
            )
        front = [
            f"title: {title}",
            f"owner: {owner}",
            f"generation: {generation}",
        ]
        if bd is not None:
            front.append(f"budget_dollars: {bd}")
        if bw is not None:
            front.append(f"budget_wall_seconds: {bw}")
        if schema:
            front.append("parameter_schema: " + json.dumps(schema, ensure_ascii=True, separators=(",", ":")))
        if clean_params:
            front.append("params:")
            front.extend(f"  - {p}" for p in clean_params)
        content = "---\n" + "\n".join(front) + "\n---\n" + body + "\n"
        from .workflow_versions import before_save

        if effect_guard is None:
            before_save(name, content, previous_content)
            atomic_write_text(dest, content)
        else:
            before_save(name, content, previous_content, effect_guard=effect_guard)
            atomic_write_text(dest, content, effect_guard=effect_guard)
    return Template.parse(content, name, path=dest)



# ---- v2 community registry (federated catalog) ------------------------------
#
# Goal templates v2: discover + install templates by name from a self-hostable
# `<base>/templates/index.json` (the same federated `catalog` the skills + MCP
# registries use). A template is content (frontmatter + body), so an entry is
# fetched from `source` and verified against `sha256`, exactly like skills.


def _configured_template_indexes() -> list[str]:
    """Registry base URLs from ``[template_registries] indexes``, else the
    shared catalog default."""
    from . import catalog
    try:
        from .config import load_config
        cfg = (load_config() or {}).get("template_registries") or {}
        indexes = cfg.get("indexes")
        if isinstance(indexes, list) and indexes:
            return [str(i).rstrip("/") for i in indexes]
    except Exception:  # pragma: no cover -- never block discovery on config
        pass
    return [i.rstrip("/") for i in catalog.DEFAULT_INDEXES]


def browse_templates(*, indexes: list[str] | None = None):
    """Return the template entries available across the configured registries."""
    from . import catalog
    return catalog.load_catalog(
        "templates",
        indexes=indexes if indexes is not None else _configured_template_indexes())


def _strip_registry_budget_frontmatter(content: str) -> str:
    """Drop run-budget fields from untrusted registry template content.

    Local/user-authored templates may still declare budgets, but catalog
    templates are remote prompt content. Persisting catalog-supplied budgets
    would let an index raise spend/time limits later when the user runs the
    template, so remote installs are normalized to the parser defaults unless
    the user passes explicit CLI flags or edits the local file themselves.
    """
    # Normalize line endings first: a CRLF-served template would otherwise slip
    # past the LF-anchored regex and keep its remote budget_* lines (which
    # Template.parse, also normalized, would then honor) -- defeating the strip.
    content = content.replace("\r\n", "\n").replace("\r", "\n")
    m = re.match(r"^---\n(.*?)\n---\n(.*)$", content, re.DOTALL)
    if not m:
        return content
    front, body = m.group(1), m.group(2)
    # ``owner`` and ``generation`` are local publication state, outside the
    # signature: a catalog entry must not name who may overwrite the template.
    budget_keys = {"budget_dollars", "budget_wall_seconds", "owner", "generation"}
    kept: list[str] = []
    for line in front.splitlines():
        key = line.partition(":")[0].strip() if ":" in line else ""
        if key in budget_keys:
            continue
        kept.append(line)
    return "---\n" + "\n".join(kept).rstrip() + "\n---\n" + body


def _canonical_template_signed_bytes(template: Template) -> bytes:
    """Stable bytes for signed registry template prompt content."""
    return json.dumps(
        {
            "title": template.title,
            "body": template.body,
            "params": list(template.params),
            **({"parameter_schema": template.parameter_schema} if template.parameter_schema else {}),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _verify_registry_template_signature(
    template: Template, *, require_signature: bool = False
) -> bool:
    """Enforce trusted-publisher signatures for catalog template installs.

    Reuses the same operator trust anchors as catalog skills. Remote templates
    require an Ed25519 signature from a configured trusted publisher.
    """
    from . import config as _config
    from .catalog_trust import verify_signed_catalog_item

    cfg = _config.get_skills()
    trusted = cfg["trusted_pubkeys"]
    return verify_signed_catalog_item(
        item="template",
        sig=template.sig,
        pubkey=template.pubkey,
        canonical_bytes_fn=lambda: _canonical_template_signed_bytes(template),
        trusted=trusted,
        must_verify=True,
        require_anchor=True,
        fields="title/params/body",
    )


def install_template_from_catalog(
    name: str, *, indexes: list[str] | None = None, dest: Path | None = None
) -> Template:
    """Install a template by name from the registry into ``~/.maverick/templates``.

    Resolves the entry, fetches its ``source`` (gh:/https:), verifies the pinned
    ``sha256``, strips remote budget frontmatter, enforces trusted-publisher
    signatures when configured, Shield-scans the prompt surface when Shield is
    installed, validates it parses as a Template, then writes ``<name>.md``.
    Returns the parsed Template. Raises ValueError on unknown name, hash
    mismatch, signature policy failure, or Shield rejection."""
    from . import catalog
    from .skills import _fetch_skill_source_bytes  # generic gh:/https: fetcher

    _validate_template_name(name)
    entry = catalog.resolve(
        name, "templates",
        indexes=indexes if indexes is not None else _configured_template_indexes())
    if entry is None:
        raise ValueError(f"no template named {name!r} in the registry")
    # The pin covers the published file's wire bytes; decode only after the
    # check (errors="replace" would change the bytes being verified).
    raw = _fetch_skill_source_bytes(entry.source)
    if not catalog.verify_sha256(raw, entry.sha256):
        raise ValueError(
            f"content hash mismatch for {name!r}: the fetched template does not "
            "match the registry's pinned sha256. Refusing to install.")
    content = raw.decode("utf-8", errors="replace")
    # Catalog templates are untrusted remote prompt content. Validate and scan
    # the rendered prompt surface before persisting, and do not persist remote
    # budget fields as future explicit run overrides.
    content = _strip_registry_budget_frontmatter(content)
    template = Template.parse(content, name)  # validate it parses before writing
    template.verified = _verify_registry_template_signature(template)
    from .catalog_trust import shield_scan

    shield_scan(
        f"Template title: {template.title}\n\nTemplate body:\n{template.body}",
        label="template",
    )
    target_dir = dest if dest is not None else user_templates_dir()
    from .file_lock import (
        atomic_write_text,
        cross_process_lock,
        ensure_private_directory,
    )

    ensure_private_directory(target_dir)
    target = target_dir / f"{name}.md"
    with cross_process_lock(target, strict=True):
        if target.exists():
            # Installing catalog content may not silently replace a privately
            # authored workflow or an unknown legacy record with the same slug.
            existing = Template.parse(target.read_text(encoding="utf-8"), name, path=target)
            if existing.owner or not can_read_template(existing, "user:catalog-publication-check"):
                raise ValueError("A private or unverified template already uses this name. Review it in the workflow builder before installing.")
        atomic_write_text(target, content)
        atomic_write_text(target_dir / (name + ".publication.json"), json.dumps({
            "schema": "lightwork.catalog-template-publication.v1", "name": name,
            "sha256": hashlib.sha256(target.read_bytes()).hexdigest()}))
    template.path = target
    return template
