"""Self-learning: acquire new capabilities on demand, mid-run.

When the agent hits a capability gap ("I need to send an SMS but have no
tool for it"), this module is the machinery that lets it close the gap
without a human editing config:

  1. SEARCH the federated catalog (skills / mcp / plugins) for an
     existing capability that matches the need.
  2. ACQUIRE safe in-loop capabilities:
       - skills  -> install_from_catalog (hash-pinned, safe).
       - tools   -> GENERATE a Python tool module, validate it, and
                    register it into the live run.
       - apis    -> route through the built-in openapi_runner.
     MCP servers must be added by an operator in config; the agent-facing
     learn_capability tool never persists or hot-starts model-supplied
     subprocess commands.
  3. PERSIST what was learned to ~/.maverick/learned.ndjson and, for
     generated tools, to ~/.maverick/generated_tools/<name>.py so the
     NEXT run already has the capability.

Two entry points exercise this:
  - ``preflight()``       — orchestrator pre-acquisition before a run.
  - the ``learn_capability`` tool (maverick.tools.learn) — in-loop, the
    agent calls it when it realizes it is missing something.

SAFETY / KERNEL RULES
---------------------
Governed local learning is ON by default and can be disabled with
``MAVERICK_SELF_LEARNING=0`` or ``[self_learning] enable = false``. Because
"create a tool" means running fresh model-authored code, that sub-capability
remains a separate explicit trust decision, as do MCP and auxiliary provider
egress.
Generated source is AST-constrained to stdlib-only, scanned through the Shield
(when installed), and bound to tenant/name/digest consent before it is executed
or persisted. Both shape validation and every later ``fn`` call run in
an isolated sandbox; the kernel process only handles bounded JSON metadata and
string results. The generation LLM call is metered against the run Budget
(kernel rule 3).
"""
from __future__ import annotations

import ast
import base64
import hashlib
import json
import logging
import math
import re
import secrets
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, fields, is_dataclass, replace
from pathlib import Path
from typing import Any

from .config import governed_learning_env_flag
from .file_lock import (
    atomic_read_text,
    atomic_write_text,
    cross_process_lock,
    ensure_private_directory,
    ensure_private_file,
)
from .learning_guard import check_learning_halt
from .paths import data_dir

log = logging.getLogger(__name__)

def learned_path() -> Path:
    """The active tenant's learned-capability ledger.

    Resolve this at each operation rather than at module import: dashboard and
    worker processes serve several tenant contexts without re-importing this
    module, so a frozen path can otherwise send one tenant's capability history
    to whichever tenant happened to import the module first.
    """
    override = globals().get("LEARNED_PATH")
    return Path(override) if override is not None else data_dir("learned.ndjson")


def generated_tools_dir() -> Path:
    """The active tenant's persisted generated-tool directory."""
    override = globals().get("GENERATED_TOOLS_DIR")
    return Path(override) if override is not None else data_dir("generated_tools")


def __getattr__(name: str) -> Path:
    """Backward-compatible, dynamically resolved legacy path attributes."""
    if name == "LEARNED_PATH":
        return learned_path()
    if name == "GENERATED_TOOLS_DIR":
        return generated_tools_dir()
    raise AttributeError(name)

# A generated tool module must be addressable as a plain identifier and
# must not shadow a stdlib / kernel module name when imported.
_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,40}$")
_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")
_lock = threading.Lock()
_VALID_LEARNED_KINDS = frozenset({"skill", "mcp", "tool", "api"})
_VALID_LEARNED_OUTCOMES = frozenset({"acquired", "failed"})
_MAX_LEARNED_TEXT = {
    "need": 300,
    "name": 512,
    "source": 2048,
}
_LEARNED_FIELDS = frozenset({"ts", "need", "kind", "name", "source", "outcome",
                              "content_version", "owner", "goal_id"})
_MAX_LEARNED_LEDGER_BYTES = 16 * 1024 * 1024


class GeneratedToolRemovalError(RuntimeError):
    """A generated tool could not be removed with durable revocation proof."""


# --------------------------------------------------------------------------
# config / gating
# --------------------------------------------------------------------------
def enabled() -> bool:
    """Whether the governed self-learning loop is active. On by default."""
    _v = governed_learning_env_flag("MAVERICK_SELF_LEARNING")
    if _v is not None:
        return _v
    try:
        from .config import get_self_learning
        return bool(get_self_learning()["enable"])
    except Exception:  # pragma: no cover -- config never blocks a run
        return False


def settings() -> dict:
    """Resolved ``[self_learning]`` settings with defaults filled in."""
    try:
        from .config import get_self_learning
        return get_self_learning()
    except Exception:  # pragma: no cover
        return {
            "enable": False, "preflight": True, "create_tools": False,
            "provision_packs": True, "allow_mcp_acquisition": False,
            "distill_local": True,
            "max_acquisitions": 5,
        }


def skill_acquisition_readiness() -> dict:
    """Current prerequisites for automatic signed catalog-skill preparation.

    No catalog request, publisher key disclosure or provider call is needed.
    Being configured means Lightwork can check a match, not that a suitable
    signed catalog entry exists. The final installer still verifies it.
    """
    from . import config
    from .audit import signing
    from .learning_guard import Halted

    config.load_config()
    notice = ("Automatic skill preparation accepts only signatures from publishers you trust. "
              "A matching, correctly signed skill must still be available and pass the installation checks. "
              "This check adds nothing and does not contact an AI service or the catalog.")
    result = {"ready": False, "trusted_publishers": 0, "notice": notice}

    def blocked(status, message, setting=None):
        return {**result, "status": status, "message": message,
                "remedy": {"href": "/settings/all?id=" + setting,
                           "label": "Review trusted skill publishers" if setting == "skills.trusted_pubkeys" else "Review skill preparation settings"}
                if setting else {"href": "/help", "label": "Open Help"}}

    if config.config_source_errors(include_tenant=True):
        return blocked("Settings need attention", "Current learning settings could not be checked. Ask your administrator to review them.")
    cfg = settings()
    if not enabled():
        return blocked("Automatic learning is off", "Automatic catalog-skill preparation is off. Existing skills are kept.", "self_learning.enable")
    if not cfg["preflight"]:
        return blocked("Skill preparation is off", "New tasks are not checked for catalog skills before they start.", "self_learning.preflight")
    trusted = config.get_skills()["trusted_pubkeys"]
    result["trusted_publishers"] = sum(bool(re.fullmatch(r"[a-fA-F0-9]{64}", key)) for key in set(trusted))
    if not result["trusted_publishers"]:
        return blocked("Choose trusted skill publishers", "Automatic skill preparation cannot install a catalog skill until you choose a trusted publisher. Upload the publisher's public key in Trusted skill publishers.", "skills.trusted_pubkeys")
    if not signing._have_crypto():
        return blocked("Signature checking is unavailable", "This installation cannot verify publisher signatures. Ask your administrator to repair signature checking before automatic skill preparation can run.")
    try:
        check_learning_halt("self_learning", "skill_readiness")
    except Halted:
        return blocked("Learning is stopped", "Automatic skill preparation is paused by the current learning stop. Existing skills are kept.")
    return {**result, "ready": True, "status": "Ready to check signed matches",
            "message": "Lightwork can check for matching skills signed by your trusted publishers. Availability and the final signature are checked when a skill is added.",
            "remedy": {"href": "/settings/all?id=skills.trusted_pubkeys", "label": "Review trusted skill publishers"}}


# --------------------------------------------------------------------------
# learned-capability ledger
# --------------------------------------------------------------------------
@dataclass
class Learned:
    ts: float
    need: str
    kind: str          # skill | mcp | tool | api
    name: str
    source: str = ""
    outcome: str = "acquired"   # acquired | failed
    content_version: int = 0
    owner: str | None = None
    goal_id: int | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def _redact(text: str) -> str | None:
    try:
        from .safety.secret_detector import redact
        return redact(str(text or ""))[0]
    except Exception:  # pragma: no cover
        # This is durable cross-run state. If the redaction boundary is missing,
        # drop the row rather than persist potentially sensitive model/tool text.
        return None


def _safe_learned_text(value: object, field: str, *, required: bool) -> str | None:
    try:
        raw = str(value or "")
    except Exception:
        return None
    redacted = _redact(raw)
    if not isinstance(redacted, str):
        return None
    text = redacted.strip()
    if required and not text:
        return None
    if len(text) > _MAX_LEARNED_TEXT[field]:
        return None
    # Ledger fields are rendered in CLI/dashboard surfaces. Keep each on one
    # printable line so a poisoned row cannot forge another record or label.
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        return None
    return text


def _validated_learned(
    *, ts: object, need: object, kind: object, name: object,
    source: object, outcome: object,
) -> Learned | None:
    if isinstance(ts, bool):
        return None
    try:
        safe_ts = float(ts)
    except (TypeError, ValueError):
        return None
    try:
        safe_kind = str(kind or "")
        safe_outcome = str(outcome or "")
    except Exception:
        return None
    safe_need = _safe_learned_text(need, "need", required=True)
    safe_name = _safe_learned_text(name, "name", required=True)
    safe_source = _safe_learned_text(source, "source", required=False)
    if (
        not math.isfinite(safe_ts) or safe_ts < 0
        or safe_kind not in _VALID_LEARNED_KINDS
        or safe_outcome not in _VALID_LEARNED_OUTCOMES
        or safe_need is None or safe_name is None or safe_source is None
    ):
        return None
    return Learned(
        ts=safe_ts, need=safe_need, kind=safe_kind, name=safe_name,
        source=safe_source, outcome=safe_outcome,
    )


def _record_impl(
    need: str, kind: str, name: str, *,
    source: str = "", outcome: str = "acquired",
    path: Path | None = None,
    before_write: Callable[[], None] | None = None,
) -> bool:
    path = path if path is not None else learned_path()
    entry = _validated_learned(
        ts=time.time(), need=need, kind=kind, name=name,
        source=source, outcome=outcome,
    )
    if entry is None:
        return False
    from .learning_content import allowed, lineage
    content = lineage()
    entry = replace(entry, **content)
    with _lock:
        try:
            ensure_private_directory(path.parent)
            with cross_process_lock(path):
                if path.exists():
                    ensure_private_file(path, 0o600)
                    if path.stat().st_size > _MAX_LEARNED_LEDGER_BYTES:
                        raise ValueError("learned ledger exceeds the size limit")
                previous = atomic_read_text(path) if path.exists() else ""
                if previous and not previous.endswith("\n"):
                    previous += "\n"
                if not allowed(content):
                    return False
                if before_write is not None:
                    before_write()
                atomic_write_text(
                    path,
                    previous + json.dumps(entry.to_dict(), sort_keys=True) + "\n",
                    mode=0o600,
                )
            return True
        except (OSError, RuntimeError, ValueError) as e:
            log.warning("self_learning: ledger write failed: %s", e)
            return False


def record(
    need: str, kind: str, name: str, *,
    source: str = "", outcome: str = "acquired",
    path: Path | None = None,
) -> bool:
    """Atomically append a validated, redacted learned-capability entry."""
    check_learning_halt("self_learning", "record_start")
    return _record_impl(
        need,
        kind,
        name,
        source=source,
        outcome=outcome,
        path=path,
        before_write=lambda: check_learning_halt(
            "self_learning", "record_persistence",
        ),
    )


def _record_committed(
    need: str, kind: str, name: str, *, source: str = "", outcome: str = "acquired",
) -> bool:
    """Finish bookkeeping for authority that is already durably committed.

    Like a promotion COMMIT, this tail must not turn a completed installation
    into a reported failure merely because HALT arrived after publication.  It
    grants no new authority and remains best-effort; new standalone records
    always go through the guarded public :func:`record` boundary.
    """
    return _record_impl(
        need, kind, name, source=source, outcome=outcome,
    )


def history(*, limit: int = 50, path: Path | None = None, owner: str | None = None) -> list[Learned]:
    """Current-owner learned capabilities, filtered before limiting results."""
    from .learning_content import allowed
    path = path if path is not None else learned_path()
    if not path.exists():
        return []
    out: list[tuple[int, Learned]] = []
    try:
        ensure_private_directory(path.parent)
        with cross_process_lock(path):
            ensure_private_file(path, 0o600)
            if path.stat().st_size > _MAX_LEARNED_LEDGER_BYTES:
                return []
            rows = atomic_read_text(path).splitlines()
        for append_index, raw in enumerate(rows):
            try:
                def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
                    result: dict[str, object] = {}
                    for key, value in pairs:
                        if key in result:
                            raise ValueError(f"duplicate key {key!r}")
                        result[key] = value
                    return result

                d = json.loads(raw, object_pairs_hook=_object)
                if not isinstance(d, dict) or frozenset(d) != _LEARNED_FIELDS:
                    continue
                entry = _validated_learned(
                    ts=d.get("ts"), need=d.get("need"), kind=d.get("kind"),
                    name=d.get("name"), source=d.get("source"),
                    outcome=d.get("outcome"),
                )
                if entry is not None and allowed(d, owner=owner):
                    out.append((append_index, replace(entry, content_version=1,
                        owner=d["owner"], goal_id=d["goal_id"])))
            except (json.JSONDecodeError, TypeError, ValueError):
                continue
    except (OSError, RuntimeError):
        return []
    # The locked writer serializes publication, so physical append order is the
    # authoritative tie-breaker when the wall clock returns the same timestamp.
    out.sort(key=lambda item: (item[1].ts, item[0]), reverse=True)
    return [entry for _, entry in out[: max(1, limit)]]


# --------------------------------------------------------------------------
# catalog search
# --------------------------------------------------------------------------
def _tokens(s: str) -> set[str]:
    return {t.lower() for t in _TOKEN_RE.findall(s or "")}


@dataclass
class Candidate:
    kind: str          # singular: skill | mcp | plugin | persona
    name: str
    summary: str
    source: str
    score: float


_KIND_SINGULAR = {
    "skills": "skill", "mcp": "mcp", "plugins": "plugin", "personas": "persona",
}


_EMBED_MIN_SCORE = 0.25  # cosine floor so semantic search doesn't return noise


def _entry_text(e: Any) -> str:
    return f"{e.name} {e.summary}"


def _gather_entries(kinds: tuple[str, ...], indexes: list[str] | None):
    """Collect ``(kind_singular, CatalogEntry)`` across ``kinds``.

    Per-kind load failures are logged and skipped so an unreachable catalog
    degrades to "fewer candidates" rather than breaking a gap-search.
    """
    from . import catalog as _catalog

    out: list[tuple[str, Any]] = []
    for kind in kinds:
        if kind not in _catalog.VALID_KINDS:
            continue
        try:
            entries = _catalog.load_catalog(kind, indexes=indexes)
        except Exception as e:  # pragma: no cover -- catalog never blocks
            log.debug("self_learning: catalog %s load failed: %s", kind, e)
            continue
        for entry in entries:
            out.append((_KIND_SINGULAR.get(kind, kind), entry))
    return out


def _rank_lexical(need: str, entries: list, max_n: int) -> list[Candidate]:
    want = _tokens(need)
    scored: list[Candidate] = []
    for kind, e in entries:
        hay = _tokens(_entry_text(e))
        if not hay:
            continue
        overlap = len(want & hay)
        if overlap == 0:
            continue
        scored.append(Candidate(
            kind=kind, name=e.name, summary=e.summary, source=e.source,
            score=overlap / len(want | hay),
        ))
    scored.sort(key=lambda c: -c.score)
    return scored[: max(1, max_n)]


def _rank_embed(need: str, entries: list, max_n: int) -> list[Candidate] | None:
    """Cosine-rank ``entries`` against ``need`` using fastembed.

    Returns None (signal "fall back to lexical") when fastembed isn't
    installed or the embed call fails; otherwise a ranked list (possibly
    empty if nothing clears ``_EMBED_MIN_SCORE``).
    """
    try:
        from .skill.embeddings import (
            _cosine,
            _have_fastembed,
            cached_corpus_vectors,
            embed,
            embedding_identity,
            validate_vectors,
        )

        if not _have_fastembed() or not entries or len(need) > 8192:
            return None
        identity = embedding_identity()
        qv = validate_vectors(embed([need]), 1)[0]
        keys = [hashlib.sha256(json.dumps(
            [kind, e.name, e.source, getattr(e, "version", ""), getattr(e, "sha256", "")],
            separators=(",", ":"), ensure_ascii=True,
        ).encode()).hexdigest() for kind, e in entries]
        if len(set(keys)) != len(keys):
            return None
        cache = cached_corpus_vectors(
            {key: _entry_text(e) for key, (_, e) in zip(keys, entries, strict=True)},
            namespace="capabilities", dimension=len(qv), identity=identity,
        )
        if cache is None or len(cache) != len(entries) or embedding_identity() != identity:
            return None
        scored: list[Candidate] = []
        for key, (kind, e) in zip(keys, entries, strict=True):
            score = _cosine(qv, cache[key].vector)
            if score < _EMBED_MIN_SCORE:
                continue
            scored.append(Candidate(
                kind=kind, name=e.name, summary=e.summary, source=e.source,
                score=score,
            ))
        scored.sort(key=lambda c: (-c.score, c.kind, c.name, c.source))
        return scored[: max(1, max_n)]
    except Exception as e:  # pragma: no cover -- defensive optional path
        log.debug("self_learning: embedding rank failed: %s", e)
        return None


def search_capabilities(
    need: str, *, kinds: tuple[str, ...] = ("skills", "mcp", "plugins"),
    max_n: int = 5, indexes: list[str] | None = None,
) -> list[Candidate]:
    """Rank catalog entries across ``kinds`` by relevance to ``need``.

    Uses embedding-based (semantic) ranking when ``fastembed`` is installed
    — so a need can match a skill that shares no surface tokens — and falls
    back to lexical token-overlap otherwise. Degrades to an empty list when
    the catalog is unreachable, so a gap-search never breaks a run.
    """
    entries = _gather_entries(kinds, indexes)
    if not entries:
        return []
    ranked = _rank_embed(need, entries, max_n)
    if ranked is None:
        ranked = _rank_lexical(need, entries, max_n)
    return ranked


# --------------------------------------------------------------------------
# acquire: skills
# --------------------------------------------------------------------------
def acquire_skill(name: str, *, need: str = "") -> str:
    """Install a trusted catalog skill by name and return its body.

    Returns the SKILL.md body so the caller can inject the steps into the
    live context immediately. Raises ValueError on failure (propagated to
    the agent as a tool-result string). Autonomous acquisition requires an
    Ed25519 signature anchored in ``[skills].trusted_pubkeys``; a catalog hash
    alone is same-host TOFU and cannot safely authorize persistent prompt text.
    """
    from .skills import install_from_catalog

    check_learning_halt("self_learning", "skill_acquisition_start")
    skill = install_from_catalog(
        name,
        require_signature=True,
        before_save=lambda: check_learning_halt(
            "self_learning", "skill_persistence",
        ),
    )
    # The ledger keeps ``need`` on one bounded line. Preflight passes the whole
    # redacted goal, which is often longer or multi-line; fold it to fit rather
    # than let the ledger drop the row for the skill just installed.
    need_line = "".join(ch for ch in " ".join(str(need or "").split())
                        if ord(ch) >= 32 and ord(ch) != 127)
    _record_committed(need_line[:_MAX_LEARNED_TEXT["need"]].strip() or name, "skill",
                      skill.name, source=str(skill.path))
    return skill.body


# --------------------------------------------------------------------------
# acquire: MCP servers
# --------------------------------------------------------------------------
def _toml_value(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, list):
        return "[" + ", ".join(_toml_value(x) for x in v) + "]"
    if isinstance(v, dict):
        inner = ", ".join(f"{k} = {_toml_value(val)}" for k, val in v.items())
        return "{ " + inner + " }"
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def add_mcp_server(
    name: str, command: str, *,
    args: list[str] | None = None, env: dict[str, str] | None = None,
    pin_sha256: str | None = None, need: str = "",
    path: Path | None = None,
    authority_check: Callable[[], None] | None = None,
) -> Any:
    """Validate + persist an ``[mcp_servers.<name>]`` block to config.toml.

    Returns the validated ``MCPServerSpec``. The block is only written
    AFTER validation succeeds (the same supply-chain / shell-meta input
    checks the static config loader enforces), so a malformed spec never
    lands on disk. ``pin_sha256`` (a catalog-supplied executable/package
    digest) is persisted so ``MCPClient.start()`` verifies the binary on
    every launch (CVE-2026-30615). Hot-starting the client is the caller's
    job (it needs the running event loop).

    NOTE: this is the low-level persistence primitive. It is NOT the
    agent-facing entry point — catalog acquisition is currently disabled.
    """
    from .config import config_path
    from .file_lock import atomic_write_text, cross_process_lock, ensure_private_file
    from .mcp_client import MCPServerSpec

    check_learning_halt("self_learning", "mcp_config_start")
    if not _NAME_RE.fullmatch(name):
        raise ValueError(
            f"mcp server name {name!r} must be lowercase id (a-z0-9_), "
            "2-41 chars, starting with a letter"
        )
    spec = MCPServerSpec(
        name=name, command=command, args=list(args or []),
        env={k: str(v) for k, v in (env or {}).items()},
        pin_sha256=pin_sha256 or None,
    )  # __post_init__ runs the CVE-2026-30615 input validation.

    path = path if path is not None else config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    # Serialize the complete read/validate/write transaction.  Without this,
    # concurrent capability acquisitions can both read the same predecessor and
    # silently discard one another's server block.
    with cross_process_lock(path):
        if authority_check is not None:
            authority_check()
        if path.exists():
            # Config can contain provider credentials.  ``chmod`` is not an ACL
            # boundary on Windows, so tighten legacy files before reading them.
            ensure_private_file(path, 0o600)
        existing = path.read_text(encoding="utf-8") if path.exists() else ""
        header = f"[mcp_servers.{name}]"
        if header in existing:
            raise ValueError(f"mcp server {name!r} already configured")

        block = [header, f"command = {_toml_value(command)}"]
        if spec.args:
            block.append(f"args = {_toml_value(spec.args)}")
        if spec.env:
            block.append(f"env = {_toml_value(spec.env)}")
        if spec.pin_sha256:
            block.append(f"pin_sha256 = {_toml_value(spec.pin_sha256)}")
        body = ("" if existing.endswith("\n") or not existing else "\n") + \
            "\n" + "\n".join(block) + "\n"

        # Unique private staging + handle-bound atomic publication.  This keeps
        # credential bytes out of a predictable temp path and leaves the live
        # TOML either wholly old or wholly new on any failure.
        check_learning_halt("self_learning", "mcp_config_persistence")
        if authority_check is not None:
            authority_check()
        atomic_write_text(path, existing + body, mode=0o600)
    _record_committed(need or name, "mcp", name, source=command)
    return spec


def mcp_acquisition_enabled() -> bool:
    """Catalog acquisition remains disabled pending publisher authentication."""
    return False


def provider_egress_enabled() -> bool:
    """Whether learning may make additional task/result-bearing model calls."""
    return settings().get("allow_provider_egress") is True


def acquire_mcp_server(name: str, *, need: str = "") -> Any:
    """Refuse unauthenticated catalog server configurations."""
    raise ValueError(
        "Catalog MCP server acquisition is unavailable until publisher authentication is implemented; "
        "an operator can independently review and configure a server."
    )


# --------------------------------------------------------------------------
# acquire: generated tools
# --------------------------------------------------------------------------
TOOL_AUTHOR_SYSTEM = """You author a single self-contained Lightwork tool module in Python.

Output ONLY the module source (no markdown fences, no prose). The module MUST define:

    def make_tool():
        from maverick.tools import Tool
        return Tool(
            name="<snake_case_name>",
            description="<what it does, when to use it>",
            input_schema={"type": "object", "properties": {...}, "required": [...]},
            fn=<callable taking a dict, returning a str>,
        )

Hard rules:
- Standard library only. For HTTP use urllib.request. No third-party imports.
- fn(args: dict) -> str. Catch your own errors and return an "ERROR: ..." string; never raise out of fn.
- NEVER read environment variables, credentials, ~/.maverick, or files outside the working directory.
- NEVER run shell commands, spawn processes, delete files, or perform destructive actions.
- Be small and correct. The whole module should read like the example above."""


# Static audit of generated tool source. The TOOL_AUTHOR_SYSTEM prompt
# *asks* for stdlib-only, no subprocess/file/env access — this ENFORCES it
# before the module is ever imported, so a generated (LLM-authored) module
# that strays from the contract is rejected instead of executed. This is a
# guardrail, not a security boundary: it bounds the obvious escape surface
# (dangerous imports, eval/exec, the dunder introspection chain) but a determined
# adversary may still find a Python introspection path around an AST allowlist.
# The actual boundary is therefore process isolation: source is never imported
# in the kernel interpreter, and both validation and every invocation execute
# through the sandbox protocol below.
_SAFE_IMPORT_TOP = frozenset({
    "__future__", "json", "re", "math", "datetime", "urllib", "base64",
    "hashlib", "hmac", "time", "random", "string", "collections", "itertools",
    "functools", "typing", "decimal", "html", "textwrap", "statistics",
    "uuid", "csv", "io", "dataclasses", "enum", "zoneinfo",
})
_BANNED_CALLS = frozenset({
    "eval", "exec", "compile", "__import__", "open", "FileIO", "urlretrieve",
    "input", "breakpoint",
})
_BANNED_ATTRS = frozenset({
    "__globals__", "__subclasses__", "__bases__", "__mro__", "__builtins__",
    "__code__", "__closure__", "__dict__", "__class__", "__base__",
    "__getattribute__", "__reduce__", "__reduce_ex__", "open", "FileIO",
    "urlretrieve",
})


def _safe_stdlib_module(mod: str) -> bool:
    return mod.split(".")[0] in _SAFE_IMPORT_TOP


def _import_from_allowed(mod: str, names: list[ast.alias]) -> bool:
    # The tool factory legitimately does ``from maverick.tools import Tool``;
    # allow exactly that symbol, not arbitrary globals re-exported by the
    # maverick.tools package (for example its module-scope ``os`` import).
    if mod == "maverick.tools":
        return all(alias.name == "Tool" for alias in names)
    return _safe_stdlib_module(mod)


def audit_generated_source(source: str) -> None:
    """Reject generated tool source that breaks the stdlib-only contract.

    Raises ValueError on a disallowed import, a banned builtin call
    (eval/exec/open/...), or access to a known sandbox-escape dunder. A
    SyntaxError surfaces as a ValueError too (it's an invalid tool either way).
    """
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        raise ValueError(f"generated tool has a syntax error: {e}") from e
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if not _safe_stdlib_module(alias.name):
                    raise ValueError(
                        f"generated tool imports disallowed module {alias.name!r}"
                    )
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if node.level or not _import_from_allowed(mod, node.names):
                raise ValueError(
                    "generated tool imports disallowed module "
                    f"{mod or '<relative import>'!r}"
                )
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in _BANNED_CALLS:
                raise ValueError(
                    f"generated tool calls disallowed builtin {node.func.id!r}"
                )
        elif isinstance(node, ast.Attribute):
            if node.attr in _BANNED_ATTRS:
                raise ValueError(
                    f"generated tool accesses disallowed attribute {node.attr!r}"
                )


def _shield_ok(source: str) -> tuple[bool, str]:
    """Scan generated source through the Shield. Fail-open if absent."""
    try:
        from maverick_shield import Shield  # type: ignore
    except ImportError:
        return True, ""
    try:
        verdict = Shield.from_config().scan_input(source)
    except Exception:  # pragma: no cover -- fail-open per kernel rule 1
        return True, ""
    if getattr(verdict, "allowed", True):
        return True, ""
    return False, "; ".join(getattr(verdict, "reasons", []) or ["blocked by Shield"])


def _shield_generated_output(output: str) -> None:
    """Fail closed on blocked/erroring Shield scans for generated-code output."""
    try:
        from maverick_shield import Shield  # type: ignore
    except ImportError:
        return
    try:
        verdict = Shield.from_config().scan_output(output)
    except Exception as e:
        raise ValueError("generated tool output safety scan failed") from e
    if not getattr(verdict, "allowed", True):
        raise ValueError("generated tool output was blocked by the safety scanner")


# Generated-code protocol. Source and arguments are embedded as base64 in a
# POSIX-shell-quoted probe, so no host staging path is exposed to a container or
# remote backend. Generated stdout is redirected to stderr. The only accepted
# stdout is one nonce-bound, base64-encoded JSON control record plus ``\n``.
_IMPORT_CHECK_TIMEOUT = 20.0
_RUNTIME_TIMEOUT = 30.0
_MAX_GENERATED_SOURCE_BYTES = 8 * 1024
_MAX_GENERATED_SCHEMA_BYTES = 16 * 1024
_MAX_GENERATED_INPUT_BYTES = 8 * 1024
_MAX_GENERATED_OUTPUT_BYTES = 32 * 1024
_MAX_GENERATED_DESCRIPTION_CHARS = 2048
_MAX_CONTROL_BYTES = 64 * 1024
_MAX_SANDBOX_ERROR_CHARS = 2000
_IMPORT_CHECK_OK = "__MAVERICK_TOOL_META_V1__"
_RUNTIME_OK = "__MAVERICK_TOOL_RESULT_V1__"
_SAFE_GENERATED_BACKENDS = frozenset({
    "maverick.sandbox.docker.DockerBackend",
    "maverick.sandbox.podman.PodmanBackend",
    "maverick.sandbox.firecracker.FirecrackerBackend",
})
_REJECTED_GENERATED_BACKENDS = frozenset({
    "maverick.sandbox.devcontainer.DevcontainerBackend",
    "maverick.sandbox.local.LocalBackend",
    "maverick.sandbox.modal_backend.ModalBackend",
    "maverick.sandbox.ssh.SSHBackend",
    "maverick.sandbox.kubernetes.KubernetesBackend",
})
_PRIVATE_WORKDIR_BACKENDS = frozenset({
    "maverick.sandbox.docker.DockerBackend",
    "maverick.sandbox.podman.PodmanBackend",
    "maverick.sandbox.firecracker.FirecrackerBackend",
})

_PROBE_BOOTSTRAP = r'''
import base64 as _b64, contextlib as _ctx, hashlib as _hashlib, json as _json, sys as _sys, types as _types
class _Tool:
    def __init__(self, name, description, input_schema, fn, parallel_safe=False):
        self.name = name
        self.description = description
        self.input_schema = input_schema
        self.fn = fn
        self.parallel_safe = parallel_safe
_tools = _types.ModuleType("maverick.tools")
_tools.Tool = _Tool
_maverick = _types.ModuleType("maverick")
_maverick.tools = _tools
_sys.modules["maverick"] = _maverick
_sys.modules["maverick.tools"] = _tools
_b64decode = _b64.b64decode
_b64encode = _b64.b64encode
_sha256 = _hashlib.sha256
_json_encode = _json.JSONEncoder(
    allow_nan=False, check_circular=True, ensure_ascii=True,
    separators=(",", ":"), sort_keys=True,
).encode
'''

_IMPORT_CHECK_PROBE = _PROBE_BOOTSTRAP + r'''
_source = _b64decode(__SOURCE_B64__).decode("utf-8", errors="strict")
_mod = _types.ModuleType("maverick_generated_probe")
with _ctx.redirect_stdout(_sys.stderr):
    exec(compile(_source, "<maverick-generated-tool>", "exec"), _mod.__dict__)
    if not callable(getattr(_mod, "make_tool", None)):
        raise SystemExit("module does not define make_tool()")
    _tool = _mod.make_tool()
    if type(_tool) is not _Tool or not callable(_tool.fn):
        raise SystemExit("make_tool() did not return a valid Tool")
    if _tool.name != __EXPECTED_NAME__:
        raise SystemExit("make_tool() returned an unexpected tool name")
    _metadata = {
        "description": _tool.description,
        "input_schema": _tool.input_schema,
        "name": _tool.name,
    }
    _payload = _json_encode(_metadata).encode("utf-8")
    if len(_payload) > __MAX_CONTROL_BYTES__:
        raise SystemExit("generated tool metadata is too large")
print(__CONTROL_PREFIX__ + _b64encode(_payload).decode("ascii"))
'''

_RUNTIME_PROBE = _PROBE_BOOTSTRAP + r'''
_source = _b64decode(__SOURCE_B64__).decode("utf-8", errors="strict")
_args_raw = _b64decode(__ARGS_B64__)
_args = _json.loads(_args_raw.decode("utf-8", errors="strict"))
_mod = _types.ModuleType("maverick_generated_runtime")
with _ctx.redirect_stdout(_sys.stderr):
    exec(compile(_source, "<maverick-generated-tool>", "exec"), _mod.__dict__)
    if not callable(getattr(_mod, "make_tool", None)):
        raise SystemExit("module does not define make_tool()")
    _tool = _mod.make_tool()
    if type(_tool) is not _Tool or not callable(_tool.fn):
        raise SystemExit("make_tool() did not return a valid Tool")
    _actual_metadata = {
        "description": _tool.description,
        "input_schema": _tool.input_schema,
        "name": _tool.name,
    }
    _actual_metadata_raw = _json_encode(_actual_metadata).encode("utf-8")
    if _sha256(_actual_metadata_raw).hexdigest() != __METADATA_DIGEST__:
        raise SystemExit("generated tool metadata changed after validation")
    _result = _tool.fn(_args)
    if type(_result) is not str:
        raise SystemExit("generated tool fn must return str")
    _payload = _result.encode("utf-8")
    if len(_payload) > __MAX_OUTPUT_BYTES__:
        raise SystemExit("generated tool result exceeds the output limit")
print(__CONTROL_PREFIX__ + _b64encode(_payload).decode("ascii"))
'''


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant {value!r}")


def _reject_duplicate_json_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON key {key!r}")
        out[key] = value
    return out


def _strict_json_loads(raw: str) -> Any:
    return json.loads(
        raw,
        parse_constant=_reject_json_constant,
        object_pairs_hook=_reject_duplicate_json_keys,
    )


def _safe_generated_error(value: object) -> str:
    redacted = _redact(str(value or "").strip())
    if not isinstance(redacted, str):
        return "error details could not be safely redacted"
    return redacted[:_MAX_SANDBOX_ERROR_CHARS]


def _require_secret_free(text: str, *, label: str) -> None:
    """Keep detected credentials out of sandbox command-line transport."""
    try:
        from .safety.secret_detector import scan

        matches = scan(text)
    except Exception as e:
        raise ValueError(f"could not scan {label} for secrets") from e
    if matches:
        raise ValueError(f"{label} contains secret-like material")


def _sandbox_error_detail(result: Any) -> str:
    stderr = getattr(result, "stderr", "")
    stdout = getattr(result, "stdout", "")
    detail = stderr if isinstance(stderr, str) and stderr.strip() else stdout
    if not isinstance(detail, str):
        return "sandbox returned malformed output"
    return _safe_generated_error(detail)


def _assert_safe_generated_sandbox(sandbox: Any) -> None:
    """Require an explicitly supported/attested, non-host-visible boundary."""
    from .sandbox import fs_is_host_visible

    if sandbox is None or fs_is_host_visible(sandbox):
        raise ValueError(
            "generated tool execution requires a non-host-visible sandbox; "
            "None and LocalBackend are not safe execution boundaries"
        )
    backend = f"{sandbox.__class__.__module__}.{sandbox.__class__.__name__}"
    if backend in _REJECTED_GENERATED_BACKENDS:
        raise ValueError(
            f"sandbox backend {sandbox.__class__.__name__} cannot isolate generated tools from its "
            "normal workspace and network"
        )
    if (
        backend not in _SAFE_GENERATED_BACKENDS
        and not bool(getattr(sandbox, "generated_tool_safe", False))
    ):
        raise ValueError(
            f"sandbox backend {sandbox.__class__.__name__} has not attested "
            "generated-tool isolation"
        )
    if not callable(getattr(sandbox, "exec", None)):
        raise ValueError("generated tool sandbox does not implement exec()")


def _clone_generated_sandbox(sandbox: Any, private_workdir: Path | None) -> Any:
    """Clone a dataclass backend with generated-code-specific security floors."""
    available = {field.name for field in fields(sandbox)}
    changes: dict[str, Any] = {}
    if private_workdir is not None:
        if "workdir" not in available:
            raise ValueError("bind-mounted sandbox cannot accept a private workdir")
        changes["workdir"] = private_workdir
    if "allow_network" in available:
        changes["allow_network"] = False
    if "network" in available:
        changes["network"] = "egress-deny"
    if "reuse_container" in available:
        changes["reuse_container"] = False
    if "warm" in available:
        changes["warm"] = False
    try:
        return replace(sandbox, **changes)
    except Exception as e:
        raise ValueError(
            "could not construct isolated generated-tool sandbox: "
            f"{type(e).__name__}: {_safe_generated_error(e)}"
        ) from e


@contextmanager
def _generated_sandbox(sandbox: Any) -> Iterator[Any]:
    """Yield a network-denied boundary with no normal host-workspace mount."""
    _assert_safe_generated_sandbox(sandbox)
    backend = f"{sandbox.__class__.__module__}.{sandbox.__class__.__name__}"
    bind_mount = bool(getattr(sandbox, "generated_tool_bind_mount", False))
    private = bind_mount or backend in _PRIVATE_WORKDIR_BACKENDS
    network_needs_floor = (
        bool(getattr(sandbox, "allow_network", False))
        or getattr(sandbox, "network", "egress-deny") != "egress-deny"
        or bool(getattr(sandbox, "reuse_container", False))
        or bool(getattr(sandbox, "warm", False))
    )
    if not private and not network_needs_floor:
        yield sandbox
        return
    if not is_dataclass(sandbox):
        raise ValueError(
            "generated tool sandbox cannot be safely cloned to remove workspace/network access"
        )
    temp = tempfile.TemporaryDirectory(prefix="maverick-generated-") if private else None
    clone: Any = None
    try:
        private_path = Path(temp.name) if temp is not None else None
        clone = _clone_generated_sandbox(sandbox, private_path)
        yield clone
    finally:
        if clone is not None:
            close = getattr(clone, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:
                    pass
        if temp is not None:
            temp.cleanup()


def _sandbox_probe(sandbox: Any, probe: str, *, timeout: float) -> Any:
    import shlex

    # Bound BOTH streams before they cross the sandbox/host boundary. Generated
    # code can deliberately print forever or bypass Python's stdout redirect;
    # a shell file-size limit prevents capture_output from accumulating an
    # attacker-sized buffer, while head keeps returned diagnostics bounded.
    command = (
        "_mav_tmp=$(mktemp -d) || exit 125; "
        "trap 'rm -rf \"$_mav_tmp\"' EXIT HUP INT TERM; "
        f"(ulimit -f 256 || exit 125; python3 -c {shlex.quote(probe)} ) "
        ' >"$_mav_tmp/out" 2>"$_mav_tmp/err"; '
        "_mav_status=$?; "
        f'head -c {_MAX_CONTROL_BYTES} "$_mav_tmp/out"; '
        f'head -c {_MAX_SANDBOX_ERROR_CHARS} "$_mav_tmp/err" >&2; '
        "exit $_mav_status"
    )
    try:
        with _generated_sandbox(sandbox) as isolated:
            return isolated.exec(command, timeout=timeout)
    except ValueError:
        raise
    except Exception as e:
        raise ValueError(
            "generated tool sandbox could not run: "
            f"{type(e).__name__}: {_safe_generated_error(e)}"
        ) from e


def _control_payload(result: Any, *, marker: str, nonce: str) -> bytes:
    exit_code = getattr(result, "exit_code", 1)
    stdout = getattr(result, "stdout", None)
    prefix = f"{marker}:{nonce}:"
    if exit_code != 0 or not isinstance(stdout, str):
        raise ValueError(
            "generated tool sandbox failed: "
            f"{_sandbox_error_detail(result) or 'probe failed'}"
        )
    if not stdout.endswith("\n") or stdout.count("\n") != 1 or not stdout.startswith(prefix):
        raise ValueError("generated tool sandbox returned an invalid control record")
    encoded = stdout[len(prefix):-1]
    if not encoded or len(encoded) > ((_MAX_CONTROL_BYTES * 4 // 3) + 8):
        raise ValueError("generated tool sandbox control record is too large")
    try:
        payload = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as e:
        raise ValueError("generated tool sandbox control record is not valid base64") from e
    if len(payload) > _MAX_CONTROL_BYTES:
        raise ValueError("generated tool sandbox control payload is too large")
    return payload


def _validate_tool_metadata(metadata: Any, *, expected_name: str) -> dict[str, Any]:
    if not isinstance(metadata, dict) or set(metadata) != {
        "description", "input_schema", "name",
    }:
        raise ValueError("generated tool returned invalid metadata fields")
    name = metadata.get("name")
    description = metadata.get("description")
    schema = metadata.get("input_schema")
    if name != expected_name:
        raise ValueError(
            f"make_tool() returned {name!r}; expected exactly {expected_name!r}"
        )
    if (
        not isinstance(description, str)
        or not description.strip()
        or len(description) > _MAX_GENERATED_DESCRIPTION_CHARS
        or any(ord(ch) < 32 and ch not in "\n\t" for ch in description)
    ):
        raise ValueError("generated tool description is invalid")
    if not isinstance(schema, dict) or schema.get("type") != "object":
        raise ValueError("generated tool input_schema must be a JSON object schema")
    properties = schema.get("properties", {})
    required = schema.get("required", [])
    if not isinstance(properties, dict) or not isinstance(required, list):
        raise ValueError("generated tool input_schema properties/required are invalid")
    if any(not isinstance(item, str) for item in required) or len(set(required)) != len(required):
        raise ValueError("generated tool input_schema required must contain unique strings")
    if any(item not in properties for item in required):
        raise ValueError("generated tool input_schema requires an undeclared property")
    try:
        schema_raw = json.dumps(
            schema, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as e:
        raise ValueError("generated tool input_schema is not bounded JSON") from e
    if len(schema_raw) > _MAX_GENERATED_SCHEMA_BYTES:
        raise ValueError("generated tool input_schema exceeds the size limit")
    return {"name": name, "description": description, "input_schema": schema}


def _validate_import_isolated(
    source: str, *, expected_name: str, sandbox: Any,
) -> dict[str, Any]:
    """Execute/shape-check source in isolation and return bounded metadata."""
    nonce = secrets.token_hex(16)
    prefix = f"{_IMPORT_CHECK_OK}:{nonce}:"
    encoded = base64.b64encode(source.encode("utf-8")).decode("ascii")
    probe = (
        _IMPORT_CHECK_PROBE
        .replace("__SOURCE_B64__", repr(encoded))
        .replace("__EXPECTED_NAME__", repr(expected_name))
        .replace("__MAX_CONTROL_BYTES__", str(_MAX_CONTROL_BYTES))
        .replace("__CONTROL_PREFIX__", repr(prefix))
    )
    result = _sandbox_probe(sandbox, probe, timeout=_IMPORT_CHECK_TIMEOUT)
    payload = _control_payload(result, marker=_IMPORT_CHECK_OK, nonce=nonce)
    try:
        metadata = _strict_json_loads(payload.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError, RecursionError) as e:
        raise ValueError("generated tool returned invalid metadata JSON") from e
    return _validate_tool_metadata(metadata, expected_name=expected_name)


def _reserved_tool_names() -> frozenset[str]:
    """Return every kernel/live tool name a generated tool must not shadow."""
    from .capability import COORDINATION_TOOLS
    from .tools import base_tool_names

    names = base_tool_names()
    if names is None:
        raise ValueError("could not establish the live tool namespace")
    return frozenset(names) | frozenset(COORDINATION_TOOLS) | {"learn_capability"}


def _generated_consent_scope(tenant: str, name: str, digest: str) -> str:
    return f"{tenant}:{name}:{digest}"


def _generated_consent_granted(
    *, tenant: str, name: str, digest: str,
) -> bool:
    """Check the durable digest grant for this tenant without prompting."""
    try:
        from .paths import current_tenant_id
        from .safety.consent import list_grants

        if (current_tenant_id() or "shared") != tenant:
            return False
        scope = _generated_consent_scope(tenant, name, digest)
        return ("register-generated-tool", scope) in set(list_grants())
    except Exception:
        return False


def _execute_generated_tool(
    *, source: str, metadata: dict[str, Any], args: dict[str, Any], sandbox: Any,
) -> str:
    """Run one generated tool call through the nonce-bound sandbox protocol."""
    if not isinstance(args, dict):
        raise ValueError("generated tool input must be an object")
    try:
        args_raw = json.dumps(
            args, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True,
        ).encode("utf-8")
        metadata_raw = json.dumps(
            metadata, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as e:
        raise ValueError("generated tool input is not bounded JSON") from e
    if len(args_raw) > _MAX_GENERATED_INPUT_BYTES:
        raise ValueError("generated tool input exceeds the size limit")
    _require_secret_free(source, label="generated tool source")
    _require_secret_free(args_raw.decode("utf-8"), label="generated tool input")

    nonce = secrets.token_hex(16)
    prefix = f"{_RUNTIME_OK}:{nonce}:"
    probe = (
        _RUNTIME_PROBE
        .replace(
            "__SOURCE_B64__",
            repr(base64.b64encode(source.encode("utf-8")).decode("ascii")),
        )
        .replace(
            "__ARGS_B64__",
            repr(base64.b64encode(args_raw).decode("ascii")),
        )
        .replace("__METADATA_DIGEST__", repr(hashlib.sha256(metadata_raw).hexdigest()))
        .replace("__MAX_OUTPUT_BYTES__", str(_MAX_GENERATED_OUTPUT_BYTES))
        .replace("__CONTROL_PREFIX__", repr(prefix))
    )
    result = _sandbox_probe(sandbox, probe, timeout=_RUNTIME_TIMEOUT)
    payload = _control_payload(result, marker=_RUNTIME_OK, nonce=nonce)
    if len(payload) > _MAX_GENERATED_OUTPUT_BYTES:
        raise ValueError("generated tool result exceeds the output limit")
    try:
        output = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as e:
        raise ValueError("generated tool result is not valid UTF-8") from e
    redacted = _redact(output)
    if not isinstance(redacted, str):
        raise ValueError("generated tool result could not be safely redacted")
    _shield_generated_output(redacted)
    return redacted


def _generated_tool_proxy(
    *, source: str, metadata: dict[str, Any], sandbox: Any,
    tenant: str, digest: str,
) -> Any:
    """Build a host-safe Tool containing metadata and a sandbox-call closure."""
    from .tools import Tool

    name = str(metadata["name"])
    from .learning_content import source_allowed_now
    target = generated_tools_dir() / f"{name}.py"

    def _run(args: dict[str, Any]) -> str:
        if not source_allowed_now(target, digest):
            return "ERROR: generated tool source content is unavailable"
        if not _generated_consent_granted(
            tenant=tenant, name=name, digest=digest,
        ):
            return (
                "ERROR: generated tool execution blocked because its "
                "tenant/name/digest consent is missing or revoked"
            )
        try:
            result = _execute_generated_tool(
                source=source, metadata=metadata, args=args, sandbox=sandbox,
            )
            if not source_allowed_now(target, digest):
                return "ERROR: generated tool source content is unavailable"
            return result
        except Exception as e:
            return (
                f"ERROR: generated tool {name!r} sandbox execution failed: "
                f"{_safe_generated_error(e)}"
            )

    return Tool(
        name=name,
        description=str(metadata["description"]),
        input_schema=dict(metadata["input_schema"]),
        fn=_run,
        parallel_safe=False,
    )


def _read_generated_source(path: Path) -> str:
    ensure_private_file(path, 0o600)
    if path.stat().st_size > _MAX_GENERATED_SOURCE_BYTES:
        raise ValueError("generated tool source exceeds the size limit")
    source = atomic_read_text(path)
    if len(source.encode("utf-8")) > _MAX_GENERATED_SOURCE_BYTES:
        raise ValueError("generated tool source exceeds the size limit")
    return source


def generated_tool_names(*, owner: str | None = None) -> set[str]:
    """Discover authorized consented names without importing/executing source."""
    from .learning_content import source_allowed_now
    from .paths import current_tenant_id

    directory = generated_tools_dir()
    if not directory.exists():
        return set()
    tenant = current_tenant_id() or "shared"
    names: set[str] = set()
    try:
        ensure_private_directory(directory)
    except (OSError, PermissionError, RuntimeError):
        return set()
    for path in sorted(directory.glob("*.py")):
        if path.name.startswith((".", "_")) or not _NAME_RE.fullmatch(path.stem):
            continue
        try:
            with cross_process_lock(path):
                source = _read_generated_source(path)
            _require_secret_free(source, label="generated tool source")
            audit_generated_source(source)
            ok, _reason = _shield_ok(source)
            if not ok:
                continue
            digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
            if source_allowed_now(path, digest, owner=owner) and _generated_consent_granted(
                tenant=tenant, name=path.stem, digest=digest,
            ):
                names.add(path.stem)
        except (OSError, PermissionError, RuntimeError, ValueError):
            continue
    return names


def delete_generated_tool(name: str, *, actor: str = "system", owner: str | None = None,
                          expected_digest: str | None = None, metadata_stop: bool = False,
                          allow_absent: bool = False, before_delete: Callable[[], None] | None = None,
                          effect_guard: Callable[[], None] | None = None,
                          owned_absence_guard: Callable[[], None] | None = None,
                          after_revoke: Callable[[], None] | None = None) -> dict[str, Any]:
    """Revoke and remove one persisted generated tool, fail-closed.

    Deletion is an authority lifecycle transition, not merely ``Path.unlink``:
    the exact tenant/name/source-digest grant is first invalidated with a
    signed consent-ledger tombstone. A durable audit row recording that
    revocation must then land before source removal can proceed. A live proxy
    rechecks the same grant on every call, so revocation immediately disables
    already-loaded instances as well as future discovery.

    Returns a source-free evidence summary. Raises ``FileNotFoundError`` when
    the file does not exist and leaves the source in place when revocation or
    audit evidence cannot be made durable.
    """
    if not _NAME_RE.fullmatch(name):
        raise ValueError(
            f"tool name {name!r} must be lowercase id (a-z0-9_), 2-41 chars"
        )

    from .audit import EventKind, audit_event
    from .paths import current_tenant_id
    from .safety.consent import revoke

    tenant = current_tenant_id() or "shared"
    target = generated_tools_dir() / f"{name}.py"
    with cross_process_lock(target, strict=True):
        if not target.is_file():
            if not allow_absent or not metadata_stop or expected_digest is None:
                raise FileNotFoundError(target)
            digest = expected_digest
        else:
            source = _read_generated_source(target)
            digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
        if expected_digest is not None and digest != expected_digest:
            raise GeneratedToolRemovalError("The reviewed generated source changed; review it again")
        from .learning_content import source_allowed_now
        if metadata_stop:
            from .generated_tool_removal import require_owned
            try:
                require_owned(target, digest, owner)
            except FileNotFoundError:
                if not allow_absent or target.exists() or owned_absence_guard is None:
                    raise
                owned_absence_guard()
        elif not source_allowed_now(target, digest, owner=owner):
            raise PermissionError("Generated source content is unavailable")
        scope = _generated_consent_scope(tenant, name, digest)

        if before_delete is not None:
            before_delete()
        if effect_guard is not None:
            effect_guard()

        consent_revoked = revoke(
            "register-generated-tool",
            scope=scope,
            strict=True,
            write_tombstone=True,
            effect_guard=effect_guard,
            all_matching_bindings=True,
        )
        from .generated_tool_removal import runtime_permission
        if runtime_permission(tenant, name, digest):
            raise GeneratedToolRemovalError(
                "generated-tool authority remained active after revocation"
            )

        recorded = audit_event(
            EventKind.LEARNING_UPDATE,
            agent="self_learning",
            operation="generated_tool_authority_revoked",
            name_sha256=hashlib.sha256(name.encode("utf-8")).hexdigest(),
            tenant=tenant,
            source_sha256=digest,
            consent_revoked=consent_revoked,
            actor=str(actor or "system")[:256],
        )
        if not recorded:
            raise GeneratedToolRemovalError(
                "generated-tool revocation could not be recorded in the audit log"
            )
        if after_revoke is not None:
            after_revoke()

        # Revocation and its audit evidence are durable before this point. If
        # unlink now fails, the source remains present but cannot execute; the
        # caller can safely retry removal without resurrecting authority.
        if effect_guard is not None:
            effect_guard()
        target.unlink(missing_ok=allow_absent)
        from .learning_content import metadata_path
        if effect_guard is not None:
            effect_guard()
        metadata_path(target).unlink(missing_ok=True)

    return {
        "name": name,
        "tenant": tenant,
        "source_sha256": digest,
        "consent_revoked": consent_revoked,
    }


def write_generated_tool(
    name: str, source: str, *, need: str = "",
    sandbox: Any = None, require_approval: bool = True,
) -> Any:
    """Consent, validate, and atomically persist a generated tool.

    Static checks and namespace checks run first. Consent is bound to the active
    tenant, requested tool name, and exact source digest *before* source runs in
    the isolated shape probe. The host never imports the source. After atomic
    persistence, the returned Tool is a metadata-only proxy whose every call
    rechecks consent and executes the same bytes in an isolated boundary.

    ``require_approval`` remains for API compatibility but can no longer bypass
    this security boundary: generated code always requires digest-bound consent.
    """
    from .learning_content import lineage, publish
    from .paths import current_tenant_id
    from .safety.consent import (
        consume_operation_consent,
        grant_persistent,
        require_operation_consent,
    )
    content_lineage = lineage()
    check_learning_halt("self_learning", "generated_tool_start")
    if not _NAME_RE.fullmatch(name):
        raise ValueError(
            f"tool name {name!r} must be lowercase id (a-z0-9_), 2-41 chars"
        )
    source = _strip_fences(source)
    if len(source.encode("utf-8")) > _MAX_GENERATED_SOURCE_BYTES:
        raise ValueError("generated tool source exceeds the size limit")
    _require_secret_free(source, label="generated tool source")
    # Enforce the stdlib-only contract before source reaches any interpreter.
    audit_generated_source(source)
    ok, reason = _shield_ok(source)
    if not ok:
        raise ValueError(f"generated tool rejected by Shield: {reason}")

    if name in _reserved_tool_names():
        raise ValueError(f"generated tool name {name!r} collides with a live tool")
    _assert_safe_generated_sandbox(sandbox)

    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
    tenant = current_tenant_id() or "shared"
    scope = _generated_consent_scope(tenant, name, digest)
    target = generated_tools_dir() / f"{name}.py"
    existed_before_consent = target.exists()

    def current_target() -> dict[str, Any]:
        current_path = generated_tools_dir() / f"{name}.py"
        return {
            "tenant": current_tenant_id() or "shared",
            "name": name,
            "path": str(current_path),
            "already_exists": current_path.exists(),
        }

    def sandbox_credentials() -> dict[str, str]:
        from .approval_cards import digest as approval_digest

        backend = type(sandbox)
        return {
            "kind": "generated-tool-sandbox",
            "generation_sha256": approval_digest({
                "backend": f"{backend.__module__}.{backend.__qualname__}",
                "workdir": str(getattr(sandbox, "workdir", "")),
                "host_visible_fs": getattr(sandbox, "host_visible_fs", None),
                "generated_tool_safe": getattr(
                    sandbox, "generated_tool_safe", None,
                ),
            }),
        }

    if not require_approval:
        log.warning(
            "require_approval=False no longer bypasses generated-tool consent"
        )
    permit = require_operation_consent(
        "register-generated-tool",
        risk="high",
        scope=scope,
        detail=(
            f"Register LLM-generated tool {name!r} for tenant {tenant!r}; "
            f"sha256={digest}. It is stdlib-only; validation and every runtime "
            "call execute in an isolated, network-denied sandbox."
        ),
        provenance=f"self-learning:{tenant}:{name}:sha256={digest}",
        target=current_target(),
        parameters={"name": name, "source": source, "need": need or name},
        parameter_summary=[
            f"Validate and persist the exact {len(source.encode('utf-8'))}-byte source committed by SHA-256."
        ],
        known_effects=[
            "Executes the reviewed source in a network-denied shape probe and persists it for this tenant."
        ],
        unresolved_assumptions=[
            "Static checks cannot prove every semantic behavior of generated code."
        ],
        before="The source has not executed and no generated-tool file or grant exists.",
        after="The reviewed source is persisted with a tenant/name/digest runtime grant.",
        irreversible=False,
        target_provider=current_target,
        parameters_provider=lambda: {
            "name": name,
            "source": source,
            "need": need or name,
        },
        input_versions_provider=lambda: {
            "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
            "static_policy": "generated-tool-ast-v1",
        },
        credential_versions_provider=sandbox_credentials,
        budget_provider=lambda: {
            "source_bytes": len(source.encode("utf-8")),
            "probe_timeout_seconds": _IMPORT_CHECK_TIMEOUT,
        },
        allow_auto_approve=False,
        consult_ledger=False,
    )

    # Spend the permit before the first execution of generated bytes and retain
    # the authority fence through persistence of both source and runtime grant.
    with consume_operation_consent(permit):
        metadata = _validate_import_isolated(
            source, expected_name=name, sandbox=sandbox,
        )

        tools_dir = generated_tools_dir()
        ensure_private_directory(tools_dir)
        target = tools_dir / f"{name}.py"
        with cross_process_lock(target):
            if target.exists():
                raise ValueError(
                    f"generated tool {name!r} already exists; refusing to overwrite it"
                )
            if existed_before_consent:
                raise ValueError(
                    f"generated tool {name!r} changed during approval; "
                    "retry to obtain a fresh digest-bound decision"
                )
            check_learning_halt("self_learning", "generated_tool_persistence")
            atomic_write_text(target, source, mode=0o600)
            try:
                publish(target, source, content_lineage)
                # A later process must distinguish these approved bytes from an
                # AST-safe file swapped in after registration.
                check_learning_halt(
                    "self_learning", "generated_tool_consent_persistence",
                )
                grant_persistent("register-generated-tool", scope=scope)
                if not _generated_consent_granted(
                    tenant=tenant, name=name, digest=digest,
                ):
                    raise ValueError(
                        "could not persist generated-tool digest consent"
                    )
            except Exception:
                target.unlink(missing_ok=True)
                raise
        tool = _generated_tool_proxy(
            source=source,
            metadata=metadata,
            sandbox=sandbox,
            tenant=tenant,
            digest=digest,
        )
        _record_committed(need or name, "tool", name, source=str(target))
        return tool


def _strip_fences(text: str) -> str:
    t = (text or "").strip()
    if t.startswith("```"):
        t = t.split("\n", 1)[1] if "\n" in t else ""
        if t.rstrip().endswith("```"):
            t = t.rstrip()[:-3]
    return t.strip()


def load_generated_tools(*, sandbox: Any = None) -> list[Any]:
    """Load persisted tools as sandbox proxies; never host-import their source.

    A module that fails audit, consent, or isolated validation is logged and
    skipped without taking down registry assembly. Only consulted when
    self-learning is enabled (see base_registry).
    """
    from .learning_content import source_allowed_now
    from .paths import current_tenant_id
    from .tools import Tool

    tools_dir = generated_tools_dir()
    if not tools_dir.exists():
        return []
    try:
        ensure_private_directory(tools_dir)
        _assert_safe_generated_sandbox(sandbox)
        reserved = _reserved_tool_names()
    except Exception as e:
        log.warning("generated tools unavailable: %s", e)
        return []
    tenant = current_tenant_id() or "shared"
    out: list[Tool] = []
    for p in sorted(tools_dir.glob("*.py")):
        if (
            p.name.startswith((".", "_"))
            or not _NAME_RE.fullmatch(p.stem)
            or p.stem in reserved
        ):
            continue
        try:
            with cross_process_lock(p):
                source = _read_generated_source(p)
            _require_secret_free(source, label="generated tool source")
            audit_generated_source(source)
            ok, reason = _shield_ok(source)
            if not ok:
                raise ValueError(f"rejected by Shield: {reason}")
            digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
            if not source_allowed_now(p, digest):
                continue
            if not _generated_consent_granted(
                tenant=tenant, name=p.stem, digest=digest,
            ):
                raise ValueError("tenant/name/digest consent is missing or revoked")
            metadata = _validate_import_isolated(
                source, expected_name=p.stem, sandbox=sandbox,
            )
            out.append(_generated_tool_proxy(
                source=source,
                metadata=metadata,
                sandbox=sandbox,
                tenant=tenant,
                digest=digest,
            ))
        except Exception as e:
            log.warning("generated tool %s failed to load: %s", p.name, e)
    return out


# --------------------------------------------------------------------------
# discover: REST APIs (OpenAPI specs)
# --------------------------------------------------------------------------
# Well-known locations a service tends to publish its OpenAPI/Swagger doc.
WELL_KNOWN_SPEC_PATHS = (
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/v3/api-docs",
    "/api-docs", "/swagger/v1/swagger.json", "/.well-known/openapi.json",
)
SPEC_FETCH_TIMEOUT = 10.0
MAX_SPEC_BYTES = 5_000_000
_URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+")


def _default_opener(url: str, *, timeout: float):
    # Route through the shared SSRF guard so a model-supplied URL can't be
    # pointed at an internal/metadata address.
    from .tools.http_fetch import guarded_urlopen
    return guarded_urlopen(url, timeout=timeout)


def _fetch_text(url: str, *, opener=None, timeout: float = SPEC_FETCH_TIMEOUT) -> str | None:
    opener = opener or _default_opener
    try:
        with opener(url, timeout=timeout) as resp:
            if getattr(resp, "status", 200) != 200:
                return None
            return resp.read(MAX_SPEC_BYTES).decode("utf-8", errors="replace")
    except Exception as e:  # pragma: no cover -- network/parse never blocks
        log.debug("self_learning: fetch %s failed: %s", url, e)
        return None


def _is_openapi_text(text: str | None) -> bool:
    """True iff ``text`` is an OpenAPI/Swagger document.

    Matches what ``openapi_runner`` will actually accept: a JSON object with
    an ``openapi``/``swagger`` key AND ``paths``. YAML specs are detected by
    a cheap structural check on the head (openapi_runner parses them when
    pyyaml is installed).
    """
    if not text:
        return False
    try:
        data = json.loads(text)
        return (
            isinstance(data, dict)
            and ("openapi" in data or "swagger" in data)
            and "paths" in data
        )
    except (json.JSONDecodeError, ValueError):
        head = text[:2000]
        return bool(re.search(r"^\s*(openapi|swagger)\s*:", head, re.MULTILINE))


def validate_spec_url(url: str, *, opener=None) -> str | None:
    """Return ``url`` if it serves an OpenAPI/Swagger doc, else None."""
    if not url.startswith(("http://", "https://")):
        return None
    return url if _is_openapi_text(_fetch_text(url, opener=opener)) else None


def probe_openapi_spec(base_url: str, *, opener=None) -> str | None:
    """Probe well-known spec locations under ``base_url``; return the first hit.

    Tries the URL itself first (it may already be a spec doc), then the
    well-known paths under both the given URL and its bare origin.
    """
    from urllib.parse import urlsplit, urlunsplit

    base = (base_url or "").rstrip("/")
    if not base:
        return None
    direct = validate_spec_url(base, opener=opener)
    if direct:
        return direct
    parts = urlsplit(base)
    roots = [base]
    if parts.scheme and parts.netloc:
        origin = urlunsplit((parts.scheme, parts.netloc, "", "", ""))
        if origin not in roots:
            roots.append(origin)
    for root in roots:
        for path in WELL_KNOWN_SPEC_PATHS:
            hit = validate_spec_url(root + path, opener=opener)
            if hit:
                return hit
    return None


def _extract_urls(text: str, *, limit: int = 10) -> list[str]:
    seen: list[str] = []
    for u in _URL_RE.findall(text or ""):
        u = u.rstrip(".,);")
        if u not in seen:
            seen.append(u)
    return seen[:limit]


def discover_openapi_spec(
    *, base_url: str = "", search_text: str = "", opener=None, max_candidates: int = 6,
) -> str | None:
    """Find an OpenAPI spec URL from a base URL and/or web-search result text.

    1. If ``base_url`` is given, probe its well-known spec locations.
    2. Otherwise scan ``search_text`` for URLs and accept the first that
       serves a spec; failing that, probe the first candidate's origin.

    Returns the spec URL or None. Every fetch goes through the SSRF guard.
    Request count is bounded by ``max_candidates`` + the well-known probe.
    """
    if base_url:
        hit = probe_openapi_spec(base_url, opener=opener)
        if hit:
            return hit
    candidates = _extract_urls(search_text)[:max_candidates]
    for u in candidates:
        if validate_spec_url(u, opener=opener):
            return u
    if candidates:
        return probe_openapi_spec(candidates[0], opener=opener)
    return None


# --------------------------------------------------------------------------
# pre-flight gap analysis (orchestrator-driven)
# --------------------------------------------------------------------------
_NEEDS_SYSTEM = """You analyse a task and list capabilities a general assistant might LACK to do it.

Output a JSON array of short capability phrases (3-6 words each), e.g.
["send an sms message", "query a postgres database"]. List only NON-obvious,
specialised capabilities (external services, niche APIs, domain tools). If the
task needs nothing special, output []. Output ONLY the JSON array."""


def _parse_needs(text: str) -> list[str]:
    t = _strip_fences(text)
    m = re.search(r"\[.*\]", t, re.DOTALL)
    if not m:
        return []
    try:
        data = json.loads(m.group(0))
    except json.JSONDecodeError:
        return []
    return [str(x).strip() for x in data if isinstance(x, str) and str(x).strip()][:10]


async def preflight(
    llm: Any, goal_text: str, budget: Any, blackboard: Any | None = None,
    *, max_acquisitions: int = 5,
) -> list[str]:
    """Before a run, map the goal to capability needs and pre-acquire skills.

    Uses one cheap LLM call to extract needs, then installs the best
    catalog SKILL match for each (hash-pinned, safe — MCP/tool creation
    stays agent-driven via the in-loop tool). Returns the names acquired.
    A failed analysis or acquisition degrades to "acquired nothing"; the
    learning HALT check, the readiness check and the local skill and catalog
    reads are not wrapped and can raise.
    """
    check_learning_halt("self_learning", "preflight_start")
    acquired: list[str] = []
    readiness = skill_acquisition_readiness()
    if not readiness["ready"]:
        message = readiness["message"] + " No catalog skill was added. Review skill preparation on the Learning page."
        log.info("Automatic skill preparation unavailable: %s", readiness["status"])
        if blackboard is not None:
            blackboard.post("orchestrator", "observation", message)
        return acquired
    try:
        from .safety.secret_detector import redact
        safe_goal, _ = redact(str(goal_text or "")[:8_000])
    except Exception as e:
        log.debug("self_learning preflight redaction unavailable: %s", e)
        return acquired

    if provider_egress_enabled():
        from .budget import BudgetExceeded, UsageAccountingError

        try:
            from .llm import model_for_role
            resp = await llm.complete_async(
                system=_NEEDS_SYSTEM,
                messages=[{"role": "user", "content": f"Task:\n{safe_goal}"}],
                budget=budget, max_tokens=256,
                model=model_for_role("summarizer"),
            )
            needs = _parse_needs(resp.text or "")
        except (BudgetExceeded, UsageAccountingError):
            raise  # a budget or accounting stop ends the run, not just preflight
        except Exception as e:  # pragma: no cover -- preflight never blocks a run
            log.debug("self_learning preflight analysis skipped: %s", e)
            return acquired
    else:
        # Local first pass: match the redacted task directly against the
        # catalog. This preserves default-on skill readiness without creating a
        # second provider disclosure path.
        needs = [safe_goal] if safe_goal.strip() else []

    from .skills import load_skills
    have = {s.name for s in load_skills()}
    for need in needs:
        if len(acquired) >= max(1, max_acquisitions):
            break
        # The catalog host is never on a run's critical path: serve the cached
        # index (any age) and refresh it in the background.
        from . import catalog as _catalog
        with _catalog.cached_first():
            cands = [c for c in search_capabilities(need, kinds=("skills",)) if c.score >= 0.2]
        if not cands or cands[0].name in have:
            continue
        try:
            acquire_skill(cands[0].name, need=need)
            acquired.append(cands[0].name)
            have.add(cands[0].name)
            if blackboard is not None:
                blackboard.post(
                    "orchestrator", "observation",
                    f"self-learning: pre-acquired skill {cands[0].name!r} for {need!r}",
                )
        except Exception as e:
            log.debug("preflight acquire %s failed: %s", cands[0].name, e)
    return acquired


__all__ = [
    "enabled", "settings", "Learned", "record", "history",
    "learned_path", "generated_tools_dir",
    "Candidate", "search_capabilities", "acquire_skill", "add_mcp_server",
    "acquire_mcp_server", "mcp_acquisition_enabled",
    "provider_egress_enabled",
    "write_generated_tool", "delete_generated_tool", "load_generated_tools",
    "GeneratedToolRemovalError", "audit_generated_source",
    "preflight", "skill_acquisition_readiness",
    "validate_spec_url", "probe_openapi_spec", "discover_openapi_spec",
    "LEARNED_PATH", "GENERATED_TOOLS_DIR",  # noqa: F822 - dynamic __getattr__ API
    "TOOL_AUTHOR_SYSTEM",
]
