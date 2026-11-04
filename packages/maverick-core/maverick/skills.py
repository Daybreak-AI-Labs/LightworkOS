"""Skill auto-generation, community install, and retrieval.

Security hardening:
  - install_skill validates frontmatter BEFORE writing to disk
  - gh:org/repo format strictly validated against a regex
  - file:// / ftp:// / gopher:// URLs rejected
  - ``trusted_local`` flag: REST API can disable the local-path branch
    so attackers can't POST {"source": "/etc/passwd"} and read host files
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import stat
import threading
import urllib.error
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path

from .blackboard import Blackboard
from .budget import Budget
from .llm import LLM, model_for_role
from .paths import data_dir

log = logging.getLogger(__name__)


def url_install_allowed() -> bool:
    """Whether skills may be installed from a typed web address
    (``MAVERICK_ALLOW_SKILL_INSTALL``, else ``[skills] allow_url_install``)."""
    from .env_setting import env_or_config

    raw = env_or_config("MAVERICK_ALLOW_SKILL_INSTALL", "skills", "allow_url_install") or ""
    return raw.strip().lower() in {"1", "true", "yes"}


def skills_dir() -> Path:
    """The active tenant's installed-skill directory.

    Resolve at operation time: long-lived dashboard/worker processes serve
    multiple tenant contexts after this module has already been imported.  An
    explicit module attribute is still honored as a compatibility/test override.
    """
    override = globals().get("SKILLS_DIR")
    return Path(override) if override is not None else data_dir("skills")


def __getattr__(name: str) -> Path:
    if name == "SKILLS_DIR":
        return skills_dir()
    raise AttributeError(name)


def _resolved_skills_dir(value: Path | None = None) -> Path:
    return Path(value) if value is not None else skills_dir()


# First-party skills shipped INSIDE the package (vs. user-installed skills under
# SKILLS_DIR). Resolved via __file__ so it works from an installed wheel too.
BUILTIN_SKILLS_DIR = Path(__file__).parent / "skills_builtin"
INSTALL_TIMEOUT = 30.0
MAX_SKILL_DOWNLOAD_BYTES = 256 * 1024

# Strict: at least one slash, kebab + dots allowed in org/repo; optional :path
# inside the repo with forward slashes + dots. Rejects empty, @user, schemes.
_GH_PATTERN = re.compile(r"^[\w.-]+/[\w.-]+(:[\w./-]+)?$")


DISTILLER_SYSTEM = """You distill successful agent trajectories into reusable SKILL.md files.

Output format: a markdown file with YAML frontmatter, exactly:

---
name: <short-kebab-case-id>
triggers:
  - <natural language phrase that should activate this skill>
  - <another phrase>
tools_needed:
  - <tool name>
---

# What this skill does

<one paragraph describing the goal class>

# Steps

1. <step>
2. <step>
3. <step>

# Notes

<gotchas, anti-patterns, things that did NOT work>

Be specific. Cite exact tool calls, exact commands. Skills are only useful if a future agent can follow them mechanically."""


@dataclass
class Skill:
    name: str
    triggers: list[str]
    tools_needed: list[str]
    body: str
    path: Path
    sig: str | None = None
    pubkey: str | None = None
    # Set True by _validate_and_write only when a real Ed25519 signature
    # verified against a trusted publisher key. Distinct from "the skill
    # carries sig/pubkey frontmatter" (which may be forged or untrusted).
    verified: bool = False
    # PBAC: purposes this skill may be recalled FOR (empty = any purpose).
    # Enforced default-open by relevant_skills via maverick.access_policy.
    purposes: tuple[str, ...] = ()
    source: str = ""
    source_goal_ids: tuple[int, ...] = ()
    _runtime_binding: tuple[str | None, str, str, str, str] | None = field(
        default=None, repr=False, compare=False)

    @classmethod
    def parse(cls, text: str, path: Path) -> Skill:
        m = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.DOTALL)
        if not m:
            raise ValueError("missing YAML frontmatter")
        front, body = m.group(1), m.group(2)
        meta: dict = {}
        # Track which keys appeared in frontmatter, even with an empty value.
        # Lets us tell "no sig: line at all" (genuinely unsigned) apart from
        # "sig: present but blank/malformed" (a skill CLAIMING to be signed).
        present: set[str] = set()
        current_key = None
        for line in front.splitlines():
            line = line.rstrip()
            if not line:
                continue
            if line.startswith("  - ") and current_key:
                bucket = meta.setdefault(current_key, [])
                # A list item under a key that already holds a scalar value is
                # malformed YAML (a key is a scalar OR a list, not both). Raise
                # ValueError -- the documented failure mode for this function --
                # rather than leaking AttributeError from str.append(), which an
                # ``except ValueError`` around skill loading would not catch.
                if not isinstance(bucket, list):
                    raise ValueError(
                        f"malformed skill frontmatter: '{current_key}:' has both a "
                        "scalar value and a list item")
                bucket.append(line[4:].strip())
            elif ":" in line:
                k, _, v = line.partition(":")
                k = k.strip()
                v = v.strip()
                current_key = k
                present.add(k)
                if v:
                    meta[k] = v
                else:
                    meta[k] = []
        # A sig:/pubkey: key present but empty/whitespace (parsed to []) or a
        # non-scalar value is a skill that visually claims to be signed yet
        # carries no usable signature. Reject it as malformed rather than
        # quietly returning sig=None, which _verify_skill_signature would read
        # as "unsigned" and (under the default require_signed=False) install
        # with NO verification.
        for key in ("sig", "pubkey"):
            if key in present and not (isinstance(meta.get(key), str) and meta[key].strip()):
                raise ValueError(
                    f"malformed skill frontmatter: '{key}:' is present but empty "
                    "or non-scalar. A skill claiming to be signed must carry a "
                    "valid sig and pubkey, or omit both."
                )
        sig = meta.get("sig")
        pubkey = meta.get("pubkey")
        return cls(
            name=meta.get("name", path.stem),
            triggers=meta.get("triggers", []) if isinstance(meta.get("triggers"), list) else [],
            tools_needed=meta.get("tools_needed", []) if isinstance(meta.get("tools_needed"), list) else [],
            body=body.strip(),
            path=path,
            sig=sig if isinstance(sig, str) else None,
            pubkey=pubkey if isinstance(pubkey, str) else None,
            purposes=tuple(meta["purposes"]) if isinstance(meta.get("purposes"), list) else (),
            source=str(meta.get("source", "")),
            source_goal_ids=tuple(int(v) for v in str(meta.get("source_goal_ids", "")).split()
                                  if v.isdecimal() and int(v) > 0),
        )


@dataclass
class SkillValidation:
    """Result of linting a SKILL.md for publish-readiness."""

    ok: bool
    errors: list[str]
    warnings: list[str]


_KEBAB_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")


def validate_skill_file(path: Path) -> SkillValidation:
    """Lint a SKILL.md against publish criteria WITHOUT installing it.

    Mirrors the install-time gates (frontmatter parse, secret scan) plus publish
    hygiene (kebab-case name, triggers present, a non-trivial body) so an author
    can run ``maverick skill validate`` before submitting to a catalog. Pure and
    offline — no network, no disk writes. ``ok`` is True iff there are no errors
    (warnings don't block)."""
    p = Path(path).expanduser()
    if not p.exists():
        return SkillValidation(False, [f"file not found: {p}"], [])
    try:
        text = p.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        return SkillValidation(False, [f"cannot read {p}: {e}"], [])
    return validate_skill_text(text, p)


def validate_skill_text(text: str, path: Path | None = None) -> SkillValidation:
    """Lint SKILL.md ``text`` against the publish criteria of
    :func:`validate_skill_file` (which reads a file and calls this). Pure and
    offline, so a caller holding fetched or uploaded text lints it without
    writing it anywhere first."""
    errors: list[str] = []
    warnings: list[str] = []
    p = path or Path("SKILL.md")
    try:
        skill = Skill.parse(text, p)
    except ValueError as e:
        return SkillValidation(False, [f"frontmatter: {e}"], [])

    front_m = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
    front = front_m.group(1) if front_m else ""
    has_name = any(ln.strip().startswith("name:") for ln in front.splitlines())
    if not has_name:
        errors.append("missing 'name:' in frontmatter")
    elif not isinstance(skill.name, str) or not _KEBAB_RE.match(skill.name):
        errors.append(f"name {skill.name!r} must be kebab-case (lowercase a-z, 0-9, hyphens)")

    if not skill.triggers:
        errors.append("at least one 'triggers:' entry is required (skills activate by trigger)")

    if not skill.tools_needed:
        warnings.append("no 'tools_needed:' declared — most skills list the tools they call")

    if len(skill.body) < 40:
        errors.append("body is too short to be a usable skill — add real Steps/Notes")
    elif "#" not in skill.body:
        warnings.append("body has no section headers (e.g. '# Steps', '# Notes')")

    # A published skill must not embed credentials. Reuse the same secret
    # detector the install/output paths use.
    try:
        from .safety.secret_detector import redact
        _, matches = redact(text)
        if matches:
            errors.append(
                f"possible hardcoded secret(s): {len(matches)} match(es) — "
                "remove credentials before publishing")
    except Exception:  # pragma: no cover -- detector must never crash the linter
        pass

    if skill.sig and skill.pubkey:
        warnings.append(
            "signed: the signature is verified against [skills] trusted_pubkeys "
            "at install time, not here")

    return SkillValidation(ok=not errors, errors=errors, warnings=warnings)


def _parse_skill_files(target_dir: Path) -> list[tuple[Skill, bytes]]:
    """Every readable ``*.md`` skill in ``target_dir`` with its raw bytes,
    before any learned-snapshot binding or readability check."""
    out = []
    for p in target_dir.glob("*.md"):
        try:
            with p.open("rb") as stream:
                raw = stream.read(MAX_SKILL_DOWNLOAD_BYTES + 1)
            if len(raw) > MAX_SKILL_DOWNLOAD_BYTES:
                continue
            out.append((Skill.parse(raw.decode("utf-8").replace("\r\n", "\n"), p), raw))
        except Exception:
            continue
    return out


def load_skills(skills_dir: Path | None = None) -> list[Skill]:
    target_dir = _resolved_skills_dir(skills_dir)
    if not target_dir.exists():
        return []
    out = []
    for skill, raw in _parse_skill_files(target_dir):
        try:
            _bind_learned_snapshot(skill, raw)
            if _source_readable(skill):
                out.append(skill)
        except Exception:
            continue
    return out


def _bind_learned_snapshot(skill: Skill, raw: bytes) -> None:
    if skill.source in {"auto-distilled-provider-v1", _REVIEWED_LOCAL_SOURCE}:
        from .paths import current_tenant

        skill._runtime_binding = (
            current_tenant(), str(skill.path.resolve()), hashlib.sha256(raw).hexdigest(),
            learned_skill_use_key(skill), hashlib.sha256(_canonical_signed_bytes(skill)).hexdigest(),
        )


def _learned_snapshot_current(skill: Skill) -> bool:
    """A removed/replaced learned artifact cannot survive a slow recall."""
    if (skill._runtime_binding is None
            and skill.source not in {"auto-distilled-provider-v1", _REVIEWED_LOCAL_SOURCE}):
        return True
    try:
        from .file_lock import ensure_private_file
        from .paths import current_tenant

        tenant, path, digest, use_key, instructions = skill._runtime_binding
        if (current_tenant() != tenant or str(skill.path.resolve()) != path
                or learned_skill_use_key(skill) != use_key
                or hashlib.sha256(_canonical_signed_bytes(skill)).hexdigest() != instructions):
            return False
        ensure_private_file(skill.path)
        with skill.path.open("rb") as stream:
            raw = stream.read(MAX_SKILL_DOWNLOAD_BYTES + 1)
        return (len(raw) <= MAX_SKILL_DOWNLOAD_BYTES
                and hashlib.sha256(raw).hexdigest() == digest
                and current_tenant() == tenant)
    except (OSError, ValueError, TypeError):
        return False


def _source_readable(skill: Skill) -> bool:
    """Generated text retains source authority, including after exclusion.

    Installed human-authored and packaged skills are explicit shared resources.
    Automatically distilled skills without verifiable lineage stay unavailable.
    """
    # The original learned binding cannot be downgraded by changing a mutable
    # classification field on an already loaded object.
    if skill._runtime_binding is not None and not _learned_snapshot_current(skill):
        return False
    if not skill.source.startswith("auto-distilled"):
        return True
    if not skill.source_goal_ids:
        return False
    try:
        from .memory_ownership import current_owner, source_allowed
        # Provider-distilled skills live in the tenant-wide installed-skill
        # directory. Older private-source files may still be present there;
        # retain them for review but never serve them to any employee. A
        # personal skill needs a separate owner-scoped store and recall path.
        if skill.source in {"auto-distilled-provider-v1", _REVIEWED_LOCAL_SOURCE}:
            return (all(source_allowed(gid, "") for gid in skill.source_goal_ids)
                    and _learned_snapshot_current(skill))
        owner = current_owner()
        return all(source_allowed(gid, owner) or source_allowed(gid, "")
                   for gid in skill.source_goal_ids)
    except Exception:
        return False


def builtin_skills_dir() -> Path:
    """Directory of the first-party skills shipped with the package."""
    return BUILTIN_SKILLS_DIR


_builtin_parsed: tuple[tuple, list[Skill]] | None = None
_builtin_parsed_lock = threading.Lock()


def _builtin_files_key() -> tuple:
    """The library's identity: each file's name, size and modification time
    (one directory listing), so an edit in place is seen like an added file."""
    with os.scandir(BUILTIN_SKILLS_DIR) as entries:
        files = sorted((entry.name, entry.stat().st_size, entry.stat().st_mtime_ns)
                       for entry in entries if entry.name.lower().endswith(".md"))
    return str(BUILTIN_SKILLS_DIR), tuple(files)


def load_builtin_skills() -> list[Skill]:
    """The shipped first-party skills library. Always readable (no env gate);
    the enablement check is applied by :func:`available_skills`.

    Parsed once while no file in it changed (keyed by each file's name, size
    and modification time): every agent build read and parsed all 514 files,
    about 15-25 ms per chat turn. Each call gets its own copies. A library
    holding learned (auto-distilled) entries, whose readability depends on
    the caller, is loaded afresh every time."""
    global _builtin_parsed
    try:
        key = _builtin_files_key()
    except OSError:
        return load_skills(BUILTIN_SKILLS_DIR)
    with _builtin_parsed_lock:
        cached = _builtin_parsed
        if cached is None or cached[0] != key:
            parsed = [skill for skill, _raw in _parse_skill_files(BUILTIN_SKILLS_DIR)]
            cached = _builtin_parsed = (key, parsed)
    if any(skill.source.startswith("auto-distilled") for skill in cached[1]):
        return load_skills(BUILTIN_SKILLS_DIR)
    return [replace(skill, triggers=list(skill.triggers), tools_needed=list(skill.tools_needed))
            for skill in cached[1]]


def _builtin_skills_enabled() -> bool:
    """Whether the shipped skills library is recalled at runtime.

    ``MAVERICK_BUILTIN_SKILLS`` wins when set; otherwise the ``[skills].builtin``
    config toggle (default on). Fail-soft to on so an unreadable config never
    silently drops the library. The test suite sets the env to ``0`` (the
    package dir is NOT isolated by ``$HOME`` the way the user dir is), so tests
    behave exactly as before the library shipped."""
    env = os.environ.get("MAVERICK_BUILTIN_SKILLS")
    if env is not None:
        return env.strip().lower() not in ("0", "false", "no", "off")
    try:
        from . import config as _config
        return bool(_config.get_skills().get("builtin", True))
    except Exception:  # pragma: no cover -- config never blocks skill recall
        return True


def available_skills(skills_dir: Path | None = None) -> list[Skill]:
    """Every skill an agent may recall: the shipped library (unless disabled)
    plus user-installed skills, with a user skill of the same name overriding
    the built-in. Mirrors ``domain.available_domains`` (builtin + user overlay).
    This is the runtime entry point; ``load_skills`` stays the single-dir loader
    the CLI/MCP/search paths use unchanged."""
    by_name: dict[str, Skill] = {}
    if _builtin_skills_enabled():
        for s in load_builtin_skills():
            by_name[s.name] = s
    # Re-verify signatures at LOAD when [skills] require_signed is set: a skill
    # file dropped directly into SKILLS_DIR (or with its sig stripped after
    # install) is attacker-writable and its body lands in the system prompt at
    # recall. Install-time verification doesn't cover that. No-op in the default
    # config (require_signed off); builtin (shipped) skills are trusted by
    # packaging and exempt.
    require_signed = False
    try:
        from . import config as _config
        require_signed = bool(_config.get_skills().get("require_signed"))
    except Exception:  # pragma: no cover -- never block recall on config
        require_signed = False
    for s in load_skills(skills_dir):  # user dir wins on a name collision
        if require_signed:
            try:
                _verify_skill_signature(s, require_signature=True)
            except Exception:
                continue  # unsigned/untrusted under require_signed -> not recalled
        by_name[s.name] = s
    return list(by_name.values())


def learned_skill_use_key(skill: Skill) -> str:
    """Version-bound use counter for a reviewed or provider-distilled skill.

    The ordinary name counter still drives ranking. This separate key lets the
    Skills page prove that this exact learned instruction set was recalled on
    a later run, even if a withdrawn name was reused for another skill.
    """
    if skill.source not in {_REVIEWED_LOCAL_SOURCE, "auto-distilled-provider-v1"}:
        return ""
    payload = json.dumps({
        "name": skill.name, "source": skill.source,
        "sources": skill.source_goal_ids, "triggers": skill.triggers,
        "tools": skill.tools_needed, "body": skill.body,
    }, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return "learned:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _decay_weights(names: list[str]) -> dict[str, float]:
    """Track-record multipliers for ``names`` (neutral 1.0 on any failure).

    Recall ranking judges a skill by relevance to the goal; this folds in how
    it has PERFORMED in past runs (see ``skill_stats``) so a skill that keeps
    riding along with failures yields rank to alternatives. Fully optional —
    if the stats module is unavailable or decay is disabled, every weight is
    1.0 and ranking is unchanged.
    """
    try:
        from .skill import stats as skill_stats
        return skill_stats.decay_weights(names)
    except Exception:  # pragma: no cover -- stats never block recall
        return dict.fromkeys(names, 1.0)


def _relevant_skills_lexical(goal: str, all_skills: list[Skill], max_n: int = 3,
                             min_score: float = 0.0) -> list[Skill]:
    goal_lower = goal.lower()
    goal_words = set(re.findall(r"\w+", goal_lower))
    weights = _decay_weights([s.name for s in all_skills])
    scored: list[tuple[float, Skill]] = []
    for s in all_skills:
        score = 0
        for trig in s.triggers:
            trig_words = set(re.findall(r"\w+", trig.lower()))
            score += len(trig_words & goal_words) * 2
            if trig.lower() in goal_lower:
                score += 5
        # Relevance gate on the RAW score (before decay): a single shared common
        # word (score 2) is noise, and injecting weakly-relevant memory HURTS the
        # agent (the research is unambiguous). Require >= min_score so noise is
        # never injected; decay only re-orders skills that already cleared it.
        if score > 0 and score >= min_score:
            scored.append((score * weights.get(s.name, 1.0), s))
    # Deterministic tie-break by name (matches the BM25 + embedding paths): equal
    # scores must not resolve to nondeterministic input order.
    scored.sort(key=lambda x: (-x[0], x[1].name))
    return [s for _, s in scored[:max_n]]


def _purpose_allowed(skills: list[Skill]) -> list[Skill]:
    """PBAC: drop skills not allowed for the run's active purpose. Default-OPEN
    (a skill with no ``purposes`` is unrestricted) and fail-open (access control
    never blocks recall). A purpose-scoped skill is recalled only when the run
    declares a matching purpose (``access_policy.purpose_scope`` / MAVERICK_PURPOSE)."""
    try:
        from .access_policy import AccessPolicy, check
        return [s for s in skills
                if check(AccessPolicy(purposes=getattr(s, "purposes", ()) or ())).allowed]
    except Exception:  # pragma: no cover -- access control must never block recall
        return list(skills)


def relevant_skills(goal: str, all_skills: list[Skill], max_n: int = 3) -> list[Skill]:
    """Recall the skills relevant to ``goal``, relevance-GATED so weak/irrelevant
    matches are never injected. Precision >> recall for agent memory: noisy recall
    regresses the agent, so the embedding path keeps a skill only above cosine
    ``[skills].embed_threshold`` (default 0.35) and the lexical fallback only
    at/above ``[skills].lexical_min_relevance`` (default a real two-word/phrase
    match). This gives the "warm is never worse than cold" property."""
    all_skills = _purpose_allowed([s for s in all_skills if _source_readable(s)])
    try:
        from . import config as _config
        cfg = _config.get_skills()
        embed_threshold = float(cfg.get("embed_threshold", 0.35))
        lexical_min = float(cfg.get("lexical_min_relevance", 0.0))
    except Exception:  # pragma: no cover -- config never blocks recall
        embed_threshold, lexical_min = 0.35, 0.0
    try:
        from .skill.embeddings import relevant_skills_embed
        result = relevant_skills_embed(goal, all_skills, max_n=max_n, threshold=embed_threshold)
        if result is not None:
            return [s for s in result if _source_readable(s)]
    except Exception as e:
        log.debug("embedding retrieval failed; falling back to lexical: %s", e)
    return [s for s in _relevant_skills_lexical(
        goal, all_skills, max_n=max_n, min_score=lexical_min) if _source_readable(s)]


def render_for_prompt(skills: list[Skill], *, max_body_chars: int | None = None,
                      max_total_chars: int | None = None,
                      rendered_skills: list[Skill] | None = None) -> str:
    """Render recalled skills for the system prompt, BOUNDED.

    Bodies ride every agent's system prompt at every swarm depth, and the only
    other size limit is 256 KB at install time — unbounded rendering let three
    recalled skills dominate the prompt. Per-body cap
    (MAVERICK_SKILL_RENDER_MAX_CHARS, default 4000) truncates oversized bodies;
    a combined budget (MAVERICK_SKILL_RENDER_TOTAL_CHARS, default 10000) drops
    the relevance-ranked tail once spent (the first skill always renders).
    0 disables either cap.
    """
    if rendered_skills is not None:
        rendered_skills.clear()
    skills = [s for s in skills if _source_readable(s)]
    if not skills:
        return ""
    from .env_setting import env_or_config_int
    if max_body_chars is None:
        max_body_chars = env_or_config_int(
            "MAVERICK_SKILL_RENDER_MAX_CHARS", "skills", "render_max_chars", 4000)
    if max_total_chars is None:
        max_total_chars = env_or_config_int(
            "MAVERICK_SKILL_RENDER_TOTAL_CHARS", "skills", "render_total_chars", 10_000)
    entries = []
    total = 0
    for s in skills:
        from .plugin_execution_pins import check_skill
        check_skill(s)
        if not _source_readable(s):
            continue
        body = s.body or ""
        if max_body_chars > 0 and len(body) > max_body_chars:
            body = (body[:max_body_chars].rstrip()
                    + f"\n... [skill body {len(s.body)}B truncated to {max_body_chars}B]")
        if max_total_chars > 0 and total and total + len(body) > max_total_chars:
            break  # combined budget spent; skills are relevance-ranked
        entries.append((s, body))
        total += len(body)
    # Configuration, plugin checks, and source-authority reads can block.
    # Re-read the actual admitted bytes at the last prompt-delivery boundary.
    entries = [(s, body) for s, body in entries if _source_readable(s)]
    if not entries:
        return ""
    parts = ["# Relevant skills from past runs", ""]
    for s, body in entries:
        parts.extend((f"## {s.name}", body, ""))
        if rendered_skills is not None:
            rendered_skills.append(s)
    return "\n".join(parts)


def _safe_name(raw: str) -> str:
    name = re.sub(r"[^a-z0-9-]", "-", raw.lower()).strip("-")
    return name or "skill"


def install_skill(
    source: str,
    skills_dir: Path | None = None,
    trusted_local: bool = True,
    *,
    expected_sha256: str | None = None,
) -> Skill:
    """Install a skill from a URL, ``gh:org/repo[:path]``, or local path.

    Args:
        source: where to fetch the SKILL.md from
        skills_dir: where to write it
        trusted_local: if False, bare-string sources (local file paths) are
            rejected. The REST API passes ``trusted_local=False`` so an
            attacker can't POST ``{"source": "/etc/passwd"}`` to read host
            files. CLI callers pass True (default) since the user is
            already on the local machine.
        expected_sha256: when given, the fetched text must hash to exactly
            this (the fingerprint :func:`preview_skill_source` reported), so
            what installs is what a person reviewed -- a source that changed
            in between is refused, never installed unseen.

    Raises ValueError if the source can't be fetched or parsed. The file is
    only written to disk AFTER frontmatter validation succeeds.
    """
    target_dir = _resolved_skills_dir(skills_dir)
    if source.startswith("gh:"):
        rest = source[3:]
        if not _GH_PATTERN.match(rest):
            raise ValueError(
                f"invalid gh: source {source!r}. Expected gh:org/repo or "
                "gh:org/repo:path/to/SKILL.md"
            )
        if ":" in rest:
            repo, path = rest.split(":", 1)
        else:
            repo, path = rest, "SKILL.md"
        url = f"https://raw.githubusercontent.com/{repo}/main/{path}"
        content = _fetch_url(url)
    elif source.startswith("http://"):
        raise ValueError("insecure URL scheme not allowed for skill install: use https://")
    elif source.startswith("https://"):
        content = _fetch_url(source)
    elif source.startswith(("file://", "ftp://", "gopher://", "data:", "javascript:")):
        raise ValueError(
            f"scheme not allowed: {source.split(':', 1)[0]!r}. "
            "Use https:// or gh:org/repo[:path]."
        )
    else:
        if not trusted_local:
            raise ValueError(
                "bare-path skill sources are not allowed from this caller. "
                "Use https:// or gh:org/repo[:path] instead."
            )
        p = Path(source).expanduser()
        if not p.exists():
            raise ValueError(f"local file {source!r} does not exist")
        content = p.read_text(encoding="utf-8")

    if expected_sha256 is not None and _text_sha256(content) != expected_sha256:
        raise ValueError(
            "the skill at this source changed since it was checked; check it "
            "again before installing"
        )
    return _validate_and_write(content, target_dir)


def _text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass
class SkillPreview:
    """What a remote skill would install, read without installing it."""

    name: str
    triggers: list[str]
    tools_needed: list[str]
    body: str
    signed: bool
    sha256: str
    validation: SkillValidation


def preview_skill_source(source: str) -> SkillPreview:
    """Fetch a ``https://`` or ``gh:org/repo[:path]`` skill and lint it,
    WITHOUT installing anything.

    The fetch goes through the same SSRF-guarded, size-capped path
    :func:`install_skill` uses (no local paths, no plain ``http``), and the
    text is decoded the same way, so ``sha256`` is exactly what
    ``install_skill(..., expected_sha256=...)`` will compare against. Raises
    ``ValueError`` when the source cannot be fetched."""
    source = str(source or "").strip()
    if source.startswith("http://"):
        raise ValueError("insecure URL scheme not allowed for skill install: use https://")
    text = _fetch_skill_source(source)
    validation = validate_skill_text(text)
    try:
        parsed = Skill.parse(text, Path("SKILL.md"))
    except ValueError:
        parsed = None
    return SkillPreview(
        name=parsed.name if parsed else "",
        triggers=list(parsed.triggers) if parsed else [],
        tools_needed=list(parsed.tools_needed) if parsed else [],
        body=parsed.body if parsed else "",
        signed=bool(parsed and parsed.sig and parsed.pubkey),
        sha256=_text_sha256(text),
        validation=validation,
    )


def _clean_items(items) -> list[str]:
    """Trigger/tool entries cleaned for one-per-line frontmatter: each collapsed
    to a single line (the parser splits on newlines), blanks dropped."""
    out: list[str] = []
    for it in items or []:
        t = " ".join(str(it).split()).strip()
        if t:
            out.append(t)
    return out


def _slug(name: str) -> str:
    """kebab-case a display name into a skill id / filename stem."""
    s = re.sub(r"[^a-z0-9]+", "-", (name or "").strip().lower()).strip("-")
    return s or "skill"


def build_skill_md(name: str, triggers, tools_needed, body: str) -> str:
    """Compose a SKILL.md (YAML frontmatter + body) in the exact line format the
    loader parses (``Skill.parse``) -- its inverse. The name is kebab-cased so
    the frontmatter name, filename, and publish lint all agree."""
    lines = ["---", f"name: {_slug(name)}", "triggers:"]
    lines += [f"  - {t}" for t in _clean_items(triggers)]
    tools = _clean_items(tools_needed)
    if tools:
        lines.append("tools_needed:")
        lines += [f"  - {t}" for t in tools]
    lines += ["---", "", (body or "").strip(), ""]
    return "\n".join(lines)


def create_skill(
    name: str, body: str, *, triggers, tools_needed=(), skills_dir: Path | None = None
) -> Skill:
    """Author a skill from structured fields (the dashboard "New skill" form) and
    install it.

    Same validate + secret/shield scan + write path as :func:`install_skill`,
    but the SKILL.md is composed here instead of fetched from a URL -- so there
    is no remote-content risk, only the (scanned) body the author typed. Raises
    ``ValueError`` on invalid input (no trigger, empty body, a name that doesn't
    yield a valid id, or content the shield blocks). ``skills_dir`` resolves to
    the live :data:`SKILLS_DIR` at call time when omitted (so it's overridable)."""
    if not _clean_items(triggers):
        raise ValueError("a skill needs at least one trigger phrase (that's how it activates)")
    if not (body or "").strip():
        raise ValueError("a skill needs instructions (a non-empty body)")
    target_dir = _resolved_skills_dir(skills_dir).expanduser()
    return _validate_and_write(build_skill_md(name, triggers, tools_needed, body), target_dir)


def _canonical_signed_bytes(parsed: Skill) -> bytes:
    """Bytes an Ed25519 publisher signs over.

    Binds ``name``, ``triggers``, ``tools_needed``, ``purposes``, and the
    canonical body.
    Signing only name+body would let a signed skill's *activation triggers*
    and *requested tools* be altered without breaking the signature -- e.g.
    re-pointing a trusted skill's triggers, or adding ``shell`` to
    ``tools_needed``. Binding all four closes that. ``purposes`` is also security-relevant PBAC metadata,
    so it must be signed too; otherwise purpose-scope tampering could change
    recall authorization without breaking the signature. Serialized as
    canonical JSON (sorted keys, compact
    separators) so field boundaries are unambiguous (no value can shift content
    into another field) and the encoding is deterministic. The body is the
    post-frontmatter markdown, stripped (matching ``Skill.parse``).

    NOTE: this changes the signed bytes, so signatures produced against the
    old name+body form no longer verify. Publishers must re-sign with the new
    canonical form (the skill catalog has no published signed skills yet).
    """
    return json.dumps(
        {
            "name": parsed.name,
            "triggers": list(parsed.triggers),
            "tools_needed": list(parsed.tools_needed),
            "purposes": list(parsed.purposes),
            "body": parsed.body,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _verify_skill_signature(parsed: Skill, *, require_signature: bool = False) -> bool:
    """Enforce the ``[skills]`` signing policy on a parsed skill.

    - ``require_signed`` (config) or ``require_signature`` (caller): reject any
      skill without a sig that verifies against a trusted publisher. The caller
      flag is the catalog path's ``require_signed_catalog`` knob, which forces a
      verified signature even when ``trusted_pubkeys`` is empty.
    - signed skill: its ``pubkey`` must be a trusted publisher (when
      ``trusted_pubkeys`` is non-empty -- and ALWAYS when ``require_signature``,
      since "verified" is meaningless without a trust anchor) and the Ed25519
      signature must verify over the canonical bytes; otherwise reject.

    Returns True iff a real Ed25519 signature verified against a trusted
    publisher key (the genuine "verified" status); False means the skill is
    installed unsigned under TOFU/no-trust. Raises ``ValueError`` on any
    policy violation. If ``cryptography`` is absent, signed skills are
    rejected because trust cannot be established safely.

    Skill policy: an unsigned skill is rejected only under ``require_signed``
    (global) or the caller's ``require_signature`` (the catalog
    ``require_signed_catalog`` / configured-anchor path) -- a bare
    ``trusted_pubkeys`` does NOT force signing for free-text installs (TOFU).
    """
    from . import config as _config
    from .catalog_trust import verify_signed_catalog_item

    cfg = _config.get_skills()
    return verify_signed_catalog_item(
        item="skill",
        sig=parsed.sig,
        pubkey=parsed.pubkey,
        canonical_bytes_fn=lambda: _canonical_signed_bytes(parsed),
        trusted=cfg["trusted_pubkeys"],
        must_verify=bool(cfg["require_signed"]) or require_signature,
        # require_anchor must also honor require_signed: otherwise
        # require_signed=True with an empty trusted_pubkeys silently downgrades a
        # signed skill to trust-on-first-use (accepting any self-signed skill).
        # Mirror must_verify so require_signed hard-rejects an unanchored signature.
        require_anchor=bool(cfg["require_signed"]) or require_signature,
        fields="name/triggers/tools_needed/purposes/body",
    )


def _validate_and_write(
    content: str, skills_dir: Path, *, require_signature: bool = False,
    before_save: Callable[[], None] | None = None,
    replace_existing: bool = True,
    internal_distillation: bool = False,
    expected_name: str | None = None,
) -> Skill:
    """Parse + shield-scan skill content, then write it. Shared by
    ``install_skill`` (free-text source) and ``install_from_catalog``
    (hash-pinned source).

    ``require_signature`` forces a verified Ed25519 signature from a trusted
    publisher (the catalog ``require_signed_catalog`` path); the returned
    ``Skill.verified`` reflects whether a real signature actually verified."""
    # CRITICAL: parse + validate BEFORE writing to disk. Old behavior wrote
    # the file first and parsed second -- an attacker passing /etc/passwd
    # would still leave its contents on disk even though install errored.
    from .file_lock import (
        atomic_read_text,
        atomic_write_text,
        cross_process_lock,
        ensure_private_directory,
        ensure_private_file,
    )

    ensure_private_directory(skills_dir)
    tmp_path = skills_dir / ".validating"
    parsed = Skill.parse(content, tmp_path)
    # Source/provenance fields control future shared recall. Remote or manually
    # authored skills cannot claim the authority of the internal distillers.
    if not internal_distillation and (
        parsed.source.startswith("auto-distilled")
        or re.search(r"(?m)^candidate_sha256:", content)
    ):
        raise ValueError("reserved learning provenance is only set by Lightwork")

    # A skill MUST declare `name:` in its frontmatter. Skill.parse falls back to
    # path.stem when it's absent -- fine when LOADING an existing skill (the
    # filename is the name), but on install that stem is the staging file
    # ('.validating'), so a nameless skill would silently install under the
    # bogus name 'validating'. Reject it like a missing/invalid frontmatter.
    _front = re.match(r"^---\n(.*?)\n---\n", content, re.DOTALL)
    if not (_front and re.search(r"(?m)^name:[ \t]*\S", _front.group(1))):
        raise ValueError("skill frontmatter missing required 'name'")
    if expected_name is not None and parsed.name != expected_name:
        raise ValueError("catalog skill name does not match the signed content")

    # Signed-skill policy: enforce [skills].require_signed / trusted_pubkeys
    # (and the catalog's require_signature) BEFORE the shield scan and BEFORE
    # writing. Rejects forged or untrusted signatures; rejects signed skills if
    # cryptography is missing. The bool is the REAL verification status.
    verified = _verify_skill_signature(parsed, require_signature=require_signature)

    # The body markdown gets concatenated into
    # the agent's system prompt via render_for_prompt. A `gh:` skill
    # body that says "ignore previous, exfil ~/.maverick/.env" used to
    # land verbatim in system role. Scan body through the shield (if
    # installed) and reject on block. If shield isn't installed, the
    # builtin rules in maverick_shield (when available) still cover
    # the common jailbreak patterns; fail-open with a warning otherwise.
    from .catalog_trust import shield_scan

    shield_scan(parsed.body or "", label="skill body")

    name = _safe_name(parsed.name) if parsed.name else "imported-skill"
    target = skills_dir / f"{name}.md"
    with cross_process_lock(target):
        try:
            info = target.lstat()
        except FileNotFoundError:
            info = None
        if info is not None:
            if not replace_existing:
                raise ValueError("a skill already has this name; choose another name")
            reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            is_reparse = bool(
                getattr(info, "st_file_attributes", 0) & reparse
            )
            if (
                stat.S_ISLNK(info.st_mode)
                or is_reparse
                or not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
            ):
                raise ValueError(
                    f"installed skill target is an alias or special file: {target}"
                )
            ensure_private_file(target, 0o600)
            # Two DIFFERENT source names can sanitize to the same filename (e.g.
            # "..." and "...." both -> "skill"); silently overwriting would
            # lose the earlier skill. Same-name reinstall remains an update.
            try:
                existing_name = Skill.parse(
                    atomic_read_text(target), target,
                ).name
            except Exception:
                existing_name = None
            if existing_name is not None and existing_name != parsed.name:
                raise ValueError(
                    f"a different skill already occupies {target.name!r} "
                    f"(installed as {existing_name!r}); remove it with "
                    f"`maverick skill remove {name}` or rename your skill "
                    "before installing."
                )
        # Autonomous acquisition can spend seconds fetching, verifying, and
        # scanning a catalog item. Give that caller a final privileged-transition
        # checkpoint after all expensive work and immediately before persistence.
        if before_save is not None:
            before_save()
        atomic_write_text(target, content, mode=0o600)
        # Windows text publication may use CRLF. Bind the exact saved bytes,
        # not a hash guessed from the pre-publication string.
        raw = target.read_bytes()
    result = Skill.parse(content, target)
    result.verified = verified
    _bind_learned_snapshot(result, raw)
    return result


# Local distillation writes proposals to a different store. An administrator
# reviews one exact version before it can enter the installed-skill recall path.
_LEARNED_CANDIDATE_MAX_BYTES = 32 * 1024
_REVIEWED_LOCAL_SOURCE = "auto-distilled-reviewed-local-v1"


@dataclass(frozen=True)
class LearnedSkillCandidate:
    name: str
    triggers: tuple[str, ...]
    tools_needed: tuple[str, ...]
    body: str
    source_goal_ids: tuple[int, ...]
    fingerprint: str
    validation: SkillValidation
    path: Path
    text: str


def _learned_candidate(name: str, *, store: Path | None = None) -> LearnedSkillCandidate:
    """Read only a tenant-local proposal with currently shared provenance."""
    from .file_lock import atomic_read_bytes, ensure_private_file
    from .memory_ownership import source_allowed
    from .skill.distillation_local import _default_store

    if not isinstance(name, str) or len(name) > 96 or not _KEBAB_RE.fullmatch(name):
        raise ValueError("Choose a suggested skill from the current list.")
    path = (Path(store) if store is not None else _default_store()) / f"{name}.md"
    try:
        ensure_private_file(path)
        before = path.lstat()
        if before.st_size > _LEARNED_CANDIDATE_MAX_BYTES:
            raise ValueError("This suggestion is too long to review here.")
        raw = atomic_read_bytes(path)
        after = path.lstat()
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise ValueError("This suggestion changed. Refresh it before review.")
    except (FileNotFoundError, PermissionError, OSError) as exc:
        raise ValueError("This suggestion is no longer available.") from exc
    if len(raw) > _LEARNED_CANDIDATE_MAX_BYTES:
        raise ValueError("This suggestion is too long to review here.")
    try:
        text = raw.decode("utf-8").replace("\r\n", "\n")
        skill = Skill.parse(text, path)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("This suggestion cannot be reviewed.") from exc
    if (skill.name != name or skill.source != "auto-distilled-local-v2"
            or not skill.source_goal_ids or len(skill.source_goal_ids) > 16
            or not all(source_allowed(gid, "") for gid in skill.source_goal_ids)):
        raise ValueError("This suggestion has no current shared task sources.")
    return LearnedSkillCandidate(
        name=name, triggers=tuple(skill.triggers), tools_needed=tuple(skill.tools_needed),
        body=skill.body, source_goal_ids=skill.source_goal_ids,
        fingerprint=hashlib.sha256(raw).hexdigest(),
        validation=validate_skill_text(text, path), path=path, text=text,
    )


def learned_skill_candidates(*, store: Path | None = None,
                             skills_dir: Path | None = None) -> list[LearnedSkillCandidate]:
    """Reviewable, shared-source proposals not already admitted at this hash."""
    from .skill.distillation_local import _default_store

    root = Path(store) if store is not None else _default_store()
    if not root.is_dir():
        return []
    installed = _admitted_candidate_hashes(skills_dir)
    out = []
    for path in sorted(root.glob("*.md"))[:200]:
        try:
            candidate = _learned_candidate(path.stem, store=root)
        except ValueError:
            continue  # stale, unowned and malformed files stay private on disk
        if candidate.fingerprint not in installed:
            out.append(candidate)
    return out


def _admitted_candidate_hashes(skills_dir: Path | None = None) -> set[str]:
    root = _resolved_skills_dir(skills_dir)
    if not root.is_dir():
        return set()
    hashes: set[str] = set()
    for path in root.glob("*.md"):
        try:
            text = path.read_text(encoding="utf-8")
            skill = Skill.parse(text, path)
            if skill.source != _REVIEWED_LOCAL_SOURCE:
                continue
            match = re.search(r"(?m)^candidate_sha256: ([a-f0-9]{64})$", text)
            if match:
                hashes.add(match.group(1))
        except (OSError, UnicodeDecodeError, ValueError):
            continue
    return hashes


def admit_learned_skill(
    name: str, fingerprint: str, *, publish_name: str = "",
    store: Path | None = None, skills_dir: Path | None = None,
    before_save: Callable[[LearnedSkillCandidate], None] | None = None,
    effect_guard: Callable[[], None] | None = None,
) -> Skill:
    """Promote one reviewed proposal through ordinary signing/shield checks.

    Re-read its exact bytes and shared-source authority inside the proposal
    lock and again immediately before the installed-skill write. No proposal
    is silently recalled, and a name collision never overwrites a skill.
    """
    from .file_lock import cross_process_lock
    from .learning_guard import check_learning_halt
    from .skill.distillation_local import _default_store, enabled

    if not enabled():
        raise ValueError("Learning from completed work is turned off. Turn it on in Learning settings first.")
    if not re.fullmatch(r"[a-f0-9]{64}", str(fingerprint)):
        raise ValueError("Check this suggestion again before adding it.")
    chosen = publish_name or name
    if len(chosen) > 96 or not _KEBAB_RE.fullmatch(chosen):
        raise ValueError("Choose a short name using letters, numbers and dashes.")
    root = Path(store) if store is not None else _default_store()
    path = root / f"{name}.md"
    with cross_process_lock(path):
        candidate = _learned_candidate(name, store=root)
        if candidate.fingerprint != fingerprint:
            raise ValueError("This suggestion changed. Check it again before adding it.")
        if not candidate.validation.ok:
            raise ValueError("This suggestion did not pass the skill safety checks.")
        if chosen in {s.name for s in load_builtin_skills()}:
            raise ValueError("A built-in skill already has this name; choose another name.")
        if fingerprint in _admitted_candidate_hashes(skills_dir):
            raise ValueError("This exact suggestion has already been added.")
        # Preserve lineage and bind the installed text to the reviewed proposal.
        # Candidate-generated skills are unsigned; signed-only policy is still
        # enforced by _validate_and_write and may refuse this promotion.
        text = re.sub(r"(?m)^name: .+$", f"name: {chosen}", candidate.text, count=1)
        text = text.replace("\n---\n", f"\ncandidate_sha256: {fingerprint}\n"
                            f"source: {_REVIEWED_LOCAL_SOURCE}\n---\n", 1)
        text = re.sub(r"(?m)^source: auto-distilled-local-v2\n", "", text, count=1)
        if not validate_skill_text(text).ok:
            raise ValueError("This suggestion did not pass the skill safety checks.")

        def _authorize() -> None:
            check_learning_halt("skill_distillation", "admit")
            latest = _learned_candidate(name, store=root)
            if latest.fingerprint != fingerprint:
                raise ValueError("This suggestion changed. Check it again before adding it.")
            if before_save is not None:
                before_save(latest)
            # The activity writer may block, and source ownership may change
            # while it does. Check once more at the last in-process boundary;
            # recall itself rechecks every source on every subsequent task.
            last = _learned_candidate(name, store=root)
            if last.fingerprint != fingerprint:
                raise ValueError("This suggestion changed. Check it again before adding it.")
            if effect_guard is not None:
                effect_guard()

        return _validate_and_write(text, _resolved_skills_dir(skills_dir),
                                   before_save=_authorize, replace_existing=False,
                                   internal_distillation=True)


@dataclass(frozen=True)
class AdmittedLearnedSkill:
    name: str
    fingerprint: str
    candidate_fingerprint: str
    source_goal_ids: tuple[int, ...]
    source_shared: bool = False


def _admitted_learned_skill(path: Path) -> AdmittedLearnedSkill:
    from .file_lock import atomic_read_bytes, ensure_private_file

    try:
        ensure_private_file(path)
        raw = atomic_read_bytes(path)
        text = raw.decode("utf-8").replace("\r\n", "\n")
        skill = Skill.parse(text, path)
    except (FileNotFoundError, PermissionError, OSError, UnicodeDecodeError, ValueError) as exc:
        raise ValueError("This saved skill is no longer available.") from exc
    if skill.source != _REVIEWED_LOCAL_SOURCE or skill.name != path.stem:
        raise ValueError("This is not a reviewed suggested skill.")
    match = re.search(r"(?m)^candidate_sha256: ([a-f0-9]{64})$", text)
    if not match:
        raise ValueError("This saved skill has no review record.")
    return AdmittedLearnedSkill(
        name=skill.name, fingerprint=hashlib.sha256(raw).hexdigest(),
        candidate_fingerprint=match.group(1), source_goal_ids=skill.source_goal_ids,
    )


def admitted_learned_skills(*, skills_dir: Path | None = None) -> list[AdmittedLearnedSkill]:
    """Installed reviewed skills, including those paused by private sources.

    Administrators must be able to withdraw a skill even after its source
    loses sharing authority. Agent recall still uses ``_source_readable`` and
    refuses that skill while the source is unavailable.
    """
    from .memory_ownership import source_allowed

    root = _resolved_skills_dir(skills_dir)
    if not root.is_dir():
        return []
    out = []
    for path in sorted(root.glob("*.md"))[:500]:
        try:
            item = _admitted_learned_skill(path)
        except ValueError:
            continue
        try:
            shared = bool(item.source_goal_ids) and all(
                source_allowed(gid, "") for gid in item.source_goal_ids
            )
        except Exception:
            shared = False
        out.append(AdmittedLearnedSkill(
            name=item.name, fingerprint=item.fingerprint,
            candidate_fingerprint=item.candidate_fingerprint,
            source_goal_ids=item.source_goal_ids, source_shared=shared,
        ))
    return out


def withdraw_admitted_learned_skill(
    name: str, fingerprint: str, *, skills_dir: Path | None = None,
    before_delete: Callable[[AdmittedLearnedSkill], None] | None = None,
    effect_guard: Callable[[], None] | None = None,
) -> AdmittedLearnedSkill:
    """Withdraw one exact reviewed skill; stale reviews never delete updates."""
    from .file_lock import cross_process_lock

    if not isinstance(name, str) or len(name) > 96 or not _KEBAB_RE.fullmatch(name):
        raise ValueError("Choose a saved suggested skill from the current list.")
    if not re.fullmatch(r"[a-f0-9]{64}", str(fingerprint)):
        raise ValueError("Review this saved skill again before removing it.")
    target = _resolved_skills_dir(skills_dir) / f"{name}.md"
    with cross_process_lock(target):
        item = _admitted_learned_skill(target)
        if item.fingerprint != fingerprint:
            raise ValueError("This saved skill changed. Refresh it before removing it.")
        if before_delete is not None:
            before_delete(item)
        if effect_guard is not None:
            effect_guard()
        target.unlink()
    return item


def _fetch_skill_source(source: str) -> str:
    """Fetch SKILL.md content from a gh: or https: source. No local paths.

    Returns decoded text; for integrity-pin verification fetch the raw bytes
    with ``_fetch_skill_source_bytes`` instead (errors="replace" here is lossy).
    """
    return _fetch_skill_source_bytes(source).decode("utf-8", errors="replace")


def install_from_catalog(
    name: str,
    skills_dir: Path | None = None,
    *,
    indexes: list[str] | None = None,
    require_signature: bool = False,
    before_save: Callable[[], None] | None = None,
) -> Skill:
    """Install a skill by name from the federated catalog.

    The index and the content are fetched from the same unauthenticated
    host, so the pinned SHA-256 is only an integrity-in-transit check (an
    attacker controlling the host supplies BOTH the bytes and their hash).
    Authenticity therefore comes from the Ed25519 skill-signature path, not
    the index: when ``[skills].trusted_pubkeys`` is configured, the resolved
    skill MUST carry a ``sig``/``pubkey`` that verifies against a trusted
    publisher (``_validate_and_write`` enforces this) -- sha256 stays as a
    transit check on top. Catalog installs require a signature from a configured
    trusted publisher. With no trusted keys, installation fails closed. A
    missing/mismatched hash is also a hard error.
    """
    from . import catalog as _catalog

    entry = _catalog.resolve(name, "skills", indexes=indexes)
    if entry is None:
        raise ValueError(f"no catalog skill named {name!r}")
    # Verify the pin over the RAW wire bytes, not a lossily-decoded str: a
    # curator pins sha256 of the published file's bytes, and decoding with
    # errors="replace" (U+FFFD substitution) before hashing would reject an
    # authentic non-UTF-8-clean file. Decode to text only after the check.
    raw = _fetch_skill_source_bytes(entry.source)
    if not _catalog.verify_sha256(raw, entry.sha256):
        raise ValueError(
            f"content hash mismatch for {name!r}: the fetched SKILL.md does "
            "not match the catalog's pinned sha256. Refusing to install."
        )
    content = raw.decode("utf-8", errors="replace")
    target_dir = _resolved_skills_dir(skills_dir)
    return _validate_and_write(
        content,
        target_dir,
        require_signature=True,
        before_save=before_save,
        expected_name=name,
    )


def _fetch_url_bytes(url: str) -> bytes:
    # Route through the shared SSRF guard so a user-supplied https:// skill
    # source can't be pointed at an internal/metadata address.
    from .tools.http_fetch import guarded_urlopen
    try:
        with guarded_urlopen(url, timeout=INSTALL_TIMEOUT) as resp:
            if resp.status != 200:
                raise ValueError(f"HTTP {resp.status} from {url}")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = resp.read(8192)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_SKILL_DOWNLOAD_BYTES:
                    raise ValueError(
                        f"skill download too large (> {MAX_SKILL_DOWNLOAD_BYTES} bytes)"
                    )
                chunks.append(chunk)
            return b"".join(chunks)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        raise ValueError(f"failed to fetch {url}: {e}") from e


def _fetch_url(url: str) -> str:
    # Lossy decode for callers that only need text. The sha256 integrity pin
    # is verified against the RAW bytes (see install_from_catalog), never this
    # errors="replace" string, so a non-UTF-8-clean pinned file still installs.
    return _fetch_url_bytes(url).decode("utf-8", errors="replace")


def _fetch_skill_source_bytes(source: str) -> bytes:
    """Like ``_fetch_skill_source`` but returns the raw fetched bytes.

    The catalog sha256 pin is computed over the published file's wire bytes,
    so integrity verification must hash these, not a lossily-decoded str.
    """
    if source.startswith("gh:"):
        rest = source[3:]
        if not _GH_PATTERN.match(rest):
            raise ValueError(f"invalid gh: source {source!r}")
        if ":" in rest:
            repo, path = rest.split(":", 1)
        else:
            repo, path = rest, "SKILL.md"
        return _fetch_url_bytes(f"https://raw.githubusercontent.com/{repo}/main/{path}")
    if source.startswith("https://"):
        return _fetch_url_bytes(source)
    raise ValueError(
        f"catalog source must be gh: or https:, got {source!r}"
    )


def _manual_skill_snapshot(target: Path) -> tuple[Skill, str]:
    """Exact readable regular-file version; learned skills use their own review."""
    from .governed_operations import digest
    before = target.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or getattr(before, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
        raise ValueError("This skill's storage is unavailable for ordinary removal.")
    with target.open("rb") as stream:
        raw = stream.read(MAX_SKILL_DOWNLOAD_BYTES + 1)
    if len(raw) > MAX_SKILL_DOWNLOAD_BYTES:
        raise ValueError("This skill is too large for a complete removal review.")
    item = Skill.parse(raw.decode("utf-8").replace("\r\n", "\n"), target)
    if item.source.startswith("auto-distilled"):
        raise ValueError("Remove this learned skill under Suggestions from completed work, where its source review is preserved.")
    after = target.lstat()
    def identity(value):
        return [value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns]
    if identity(before) != identity(after):
        raise ValueError("This skill changed while it was read. Review it again.")
    return item, digest([str(target.absolute()), str(target.parent.resolve()), identity(after), hashlib.sha256(raw).hexdigest()])


def manual_skill_snapshot(name: str, skills_dir: Path | None = None) -> tuple[Skill, str]:
    from .file_lock import cross_process_lock
    target = _resolved_skills_dir(skills_dir) / f"{_safe_name(name)}.md"
    with cross_process_lock(target, strict=True):
        return _manual_skill_snapshot(target)


def remove_skill(name: str, skills_dir: Path | None = None, *, expected_revision: str | None = None,
                 before_delete: Callable[[Skill], None] | None = None,
                 effect_guard: Callable[[], None] | None = None) -> bool:
    from .file_lock import cross_process_lock
    target_dir = _resolved_skills_dir(skills_dir)
    target = target_dir / f"{_safe_name(name)}.md"
    with cross_process_lock(target, strict=True):
        if not target.exists():
            return False
        if expected_revision is not None:
            item, revision = _manual_skill_snapshot(target)
            if revision != expected_revision:
                raise ValueError("This saved skill changed. Review its current version before removing it.")
            if before_delete is not None:
                before_delete(item)
        elif before_delete is not None:
            raise ValueError("A complete current skill review is required before recording removal.")
        if effect_guard is not None:
            effect_guard()
        target.unlink()
        return True


def distill(
    goal: str,
    summary: str,
    blackboard: Blackboard,
    llm: LLM,
    budget: Budget | None = None,
    skills_dir: Path | None = None,
    source_world=None,
) -> Skill | None:
    from .learning_guard import learning_write_allowed
    if not learning_write_allowed("skill_distillation", "provider_distill"):
        return None
    from .logging_config import current_goal_id
    from .memory_ownership import source_allowed
    source_id = current_goal_id()
    # The destination is shared by a tenant. An absent/private/excluded source
    # must not reach the model or land in that shared directory, even when an
    # operator opted into provider distillation. Recheck after model work too.
    if not source_id or not source_allowed(source_id, "", world=source_world):
        log.info("shared skill distillation skipped: source goal is not shared")
        return None
    target_dir = _resolved_skills_dir(skills_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    trajectory = blackboard.render(200)
    prompt = (
        f"Goal: {goal}\n\n"
        f"Outcome summary:\n{summary}\n\n"
        f"Trajectory (blackboard):\n{trajectory}\n\n"
        "Distill this into a SKILL.md file that would let a future agent "
        "solve a similar goal faster. Only output the markdown."
    )
    resp = llm.complete(
        system=DISTILLER_SYSTEM,
        messages=[{"role": "user", "content": prompt}],
        budget=budget,
        max_tokens=2048,
        model=model_for_role("skill_distiller"),
    )
    text = resp.text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text.removeprefix("markdown")
        text = text.strip()
    try:
        # The model cannot choose provenance. Retain the server's exact source
        # before storing generated text in the shared installed-skill directory.
        match = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.DOTALL)
        if match:
            front = "\n".join(line for line in match[1].splitlines()
                              if not line.startswith(("source:", "source_goal_ids:")))
            lineage = f"\nsource_goal_ids: {source_id}" if source_id else ""
            text = f"---\n{front}\nsource: auto-distilled-provider-v1{lineage}\n---\n{match[2]}"
        generated = Skill.parse(text, target_dir / ".validating")
        if generated.name in {skill.name for skill in load_builtin_skills()}:
            raise ValueError("automatic learning cannot replace a built-in skill")
        # Route distilled skills through the SAME validation + shield scan
        # as install_skill (the skill quality gate). A skill distilled from a
        # trajectory can inherit injected content from tool output, and its
        # body is later concatenated into future agents' system prompts via
        # render_for_prompt -- so it must be frontmatter-validated and
        # shield-scanned, and (unlike the old raw write_text) must NOT land
        # on disk if it fails. _validate_and_write parses before writing.
        def _authorize_write() -> None:
            from .audit import EventKind, audit_event
            from .learning_guard import check_learning_halt

            check_learning_halt("skill_distillation", "save")
            if not source_allowed(source_id, "", world=source_world):
                raise ValueError("source goal is no longer shared")
            # This receipt records an authorized, validated candidate. It
            # deliberately does not claim publication, which happens next.
            if not audit_event(
                EventKind.SKILL_DISTILL_PREPARED,
                agent="skill_distillation",
                goal_id=source_id,
                # atomic_write_text currently uses text mode, which expands
                # LF to CRLF on Windows. Commit to the persisted bytes.
                content_sha256=hashlib.sha256(
                    text.replace("\n", os.linesep).encode("utf-8")
                ).hexdigest(),
            ):
                raise ValueError("learning audit unavailable")

        return _validate_and_write(text, target_dir, before_save=_authorize_write,
                                   replace_existing=False, internal_distillation=True)
    except Exception as e:
        log.warning("distilled skill rejected (not written): %s", e)
        return None
