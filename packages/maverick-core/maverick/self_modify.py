"""Governed code self-modification: the editable-surface boundary + code rung.

This is the boundary of a governed Darwin-Gödel-Machine-style capability (DGM,
arXiv:2505.22954): a system that proposes changes to *its own code* and validates
them empirically. The DGM insight is empirical validation instead of proof; we
run it **under a reference monitor**. The current operable posture is research:
the agent may propose, sandbox-test, and archive a constrained patch, but cannot
promote or apply live code.

The load-bearing safety primitive is the **editable-surface boundary**, and it
lives here. The reference-monitor principle: the control plane must live outside
the surface the agent can rewrite. So a proposed patch is **structurally
refused** if it touches ANY protected path — the self-improvement gate, the
approval verifier, the calibration interlock, the FINAL verifier, the capability
algebra, the sandbox, the audit chain, the config loader, or THIS module. That
refusal happens before any evaluation or deployment integration.

A candidate that clears the boundary is still not authorized for deployment.
The legacy code approval payload omits evaluator evidence, base revision,
surface/policy, tenant, nonce, and expiry, so this module never forwards code to
that promotion gate.

Posture: **OFF by default and fail-closed.** The engine is a no-op unless
``[self_modify] enable`` is set, the editable allowlist is EMPTY by default (so
every path is ``unknown`` → refused), and malformed or ambiguous paths are
treated as protected. This module never applies or promotes a patch.
"""
from __future__ import annotations

import fnmatch
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)


# --- the boundary: the control plane, which self-modification may NEVER touch --

# Top-level modules under the ``maverick`` package that ARE the reference
# monitor. Editing any of these is the one move that could unravel the whole
# governance stack, so it is refused structurally regardless of evidence.
_PROTECTED_FILES = frozenset({
    "__init__.py",              # package import surface
    "self_modify.py",            # this boundary itself
    "self_improvement.py",       # the promotion gate
    "self_improvement_runner.py",
    "killswitch.py",             # global emergency stop
    "learning_guard.py",         # learning-job emergency-stop boundary
    "pilot_learning.py",         # frozen pilot learning-exclusion authority
    "release_identity_transition.py",  # dual-signed native update trust admission
    "release_manifest_signing.py",  # update-bundle signatures and their trust anchor
    "learning_proof.py",         # proof/evidence authority
    "factory_learning.py",       # factory promotion/evidence consumer
    "approval_signing.py",       # cryptographic human approval
    "approval_delegation.py",    # approval routing / quorum
    "calibration.py",            # the drift / reward-laundering interlock
    "verifier.py",               # the FINAL correctness gate
    "verifier_head.py",
    "capability.py",             # the capability algebra (non-escalation proof)
    "capability_boot.py",
    "budget.py",                 # cost caps (kernel rule 3)
    "promotion_effect.py",       # the evidence gate's causal input
    "evaluator_evolution.py",    # anchor-gated judge promotion
    "migration_governance.py",   # released-migration immutability gate
    "llm.py",                    # ROLE_MODELS / model routing
    "secret_provider.py",        # provider-secret custody
    "tool_token.py",             # delegated tool authority
    "governed_tools.py",         # governed tool dispatch
    "mcp_tools.py",              # MCP authority bridge
    "config.py",                 # resolves every gate's settings
    "migrate.py",                # the config-section registry
    "sigstore_signing.py",       # signing primitives
    "erasure_verify.py",
    # Agent/fleet identity, routing, and authenticated handoff control plane.
    "agent_bus.py", "bus_handoff.py", "agent_trust.py", "handoff.py",
    "swarm.py", "federation.py", "federation_envelope.py",
    "emergent_protocol.py", "grpc_tls.py",
    "grpc_dispatcher.py", "grpc_plugin_host.py", "proxy_auth.py",
    "oauth_vault.py", "browser_auth_vault.py", "mcp_oauth.py",
    "workflow.py",
    # Secret/DLP, transport, isolation, and agent/fleet authorities.  The
    # boundary must protect the helpers it relies on as well as the boundary
    # itself; otherwise a candidate can first weaken the detector or identity
    # plane and then submit an apparently clean follow-up patch.
    "secrets.py", "provable_redaction.py", "security_defaults.py",
    "access_policy.py", "containment.py", "a2a.py", "a2a_tasks.py",
    "agent.py", "agent_autonomy.py", "agent_framework_adapters.py",
    "fleet.py", "fleet_memory.py", "self_learning.py",
    "server.py", "catalog_trust.py", "shield_policy.py", "web_session.py",
    "webhooks.py",
})
# Whole packages under ``maverick`` that are off-limits (any file within).
_PROTECTED_DIRS = frozenset({
    "audit", "automation_import", "cli", "evaluator_anchors", "flow",
    "grpc_api", "providers", "safety", "sandbox", "tenant", "tools",
    "training",
})
# Case-folded copies: the boundary must hold on case-insensitive filesystems
# (macOS/Windows), where ``Self_Improvement.py`` IS ``self_improvement.py``.
_PROTECTED_FILES_CF = frozenset(f.casefold() for f in _PROTECTED_FILES)
_PROTECTED_DIRS_CF = frozenset(d.casefold() for d in _PROTECTED_DIRS)
# Every ``self_modify*`` module is part of the reference monitor: boundary,
# proposer/runner, evaluator, corpus, archive, apply/rollback, and any future
# helper added to that family.  Keep this as a prefix rule instead of an
# enumerated list so adding a new control-plane module cannot silently make it
# editable under a broad ``**`` surface.
_PROTECTED_FILE_PREFIXES_CF = (
    "approval_", "self_harness", "self_improvement", "self_modify",
)
# Authority-bearing outer packages (channels, operator UI, evaluator, knowledge
# ingestion, MCP transport, and Shield) remain outside the editable universe
# even though their import package is not named exactly ``maverick``.
_PROTECTED_REPO_PREFIXES_CF = (
    ".devcontainer/",
    "apps/",
    "build/",
    "deploy/",
    "extensions/",
    "go/",
    "packages/maverick-channels/",
    "packages/maverick-dashboard/",
    "packages/maverick-evolve/",
    "packages/maverick-knowledge/",
    "packages/maverick-mcp/",
    "packages/maverick-shield/",
    "rust/",
    "scripts/",
    "sdks/",
    "test_support/",
    "vendor/",
    "web/",
)
# Candidate-controlled tests/proofs can launder a score without improving the
# product.  These artifacts must be mounted read-only by an external evaluator,
# never edited as part of the candidate.
_PROTECTED_PATH_COMPONENTS_CF = frozenset({
    ".codex", ".git", ".github", "benchmarks", "proof", "test", "tests",
})
_PROTECTED_BASENAMES_CF = frozenset({
    ".coveragerc", ".gitattributes", ".pre-commit-config.yaml",
    ".secrets.baseline", "agents.md", "conftest.py", "makefile",
    "pyproject.toml", "pytest.ini", "release-cohort.toml", "ruff.toml",
    "sitecustomize.py", "tox.ini", "usercustomize.py",
})
_WINDOWS_RESERVED_STEMS_CF = frozenset({
    "aux", "clock$", "con", "conin$", "conout$", "nul", "prn",
})
_WINDOWS_DEVICE_DIGITS = frozenset({
    "1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³",
})
_MAX_REVIEW_PATCH_CHARS = 512 * 1024

# git C-style single-char escapes inside a quoted path (see quote_c_style).
_C_ESCAPES = {
    "a": "\a", "b": "\b", "t": "\t", "n": "\n", "v": "\v",
    "f": "\f", "r": "\r", '"': '"', "\\": "\\",
}


def _unquote_git(path: str) -> str | None:
    """Decode a git C-quoted path (``"a/na\\303\\251me"`` etc.) to the real
    filename, or return the input unchanged if it isn't quoted. Returns None on
    malformed quoting so the caller can fail closed.

    git quotes any path with special/high bytes and ``git apply`` un-quotes it,
    so the boundary MUST decode octal (``\\NNN``) and ``\\t``/``\\n``/... escapes
    before matching -- otherwise ``"a/maverick/self_improvement.py"`` (or an
    octal-escaped spelling) slips past a raw-string comparison."""
    if not (len(path) >= 2 and path[0] == '"' and path[-1] == '"'):
        return path
    body = path[1:-1]
    out = bytearray()
    i = 0
    try:
        while i < len(body):
            ch = body[i]
            if ch != "\\":
                out.extend(ch.encode("utf-8"))
                i += 1
                continue
            nxt = body[i + 1]
            if nxt in "01234567":
                j = 0
                while j < 3 and i + 1 + j < len(body) and body[i + 1 + j] in "01234567":
                    j += 1
                value = int(body[i + 1:i + 1 + j], 8)
                if value > 0xFF:
                    return None
                out.append(value)
                i += 1 + j
            elif nxt in _C_ESCAPES:
                out.extend(_C_ESCAPES[nxt].encode("utf-8"))
                i += 2
            else:
                return None
        return out.decode("utf-8", errors="strict")
    except (UnicodeDecodeError, ValueError, IndexError):
        return None


def _canonical(raw: str) -> str | None:
    """Return one unambiguous, repo-relative spelling of a patch path.

    Besides traversal and absolute paths, reject filesystem spellings that can
    alias a different target on Windows: drive/ADS colons, device names, 8.3
    aliases, trailing dots/spaces, control characters, and empty/dot segments.
    The reference monitor is cross-platform, so a path unsafe on any supported
    filesystem fails closed even when the current evaluator runs on POSIX.
    """
    try:
        s = str(raw)
    except Exception:
        return None
    if not s or s != s.strip():
        return None
    if s.startswith('"'):
        s = _unquote_git(s)
        if s is None:
            return None
    s = s.replace("\\", "/")
    if s.startswith(("a/", "b/")):
        s = s[2:]
    if not s or s.startswith("/"):
        return None  # absolute/UNC -> reaches outside the repo tree

    parts = s.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return None
    for part in parts:
        # NTFS strips a terminal dot/space and interprets ':' as an alternate
        # data stream.  The other characters and controls are likewise invalid
        # or device-path syntax on Windows and therefore ambiguous here.
        if (part.endswith((".", " "))
                or any(ord(ch) < 32 for ch in part)
                or any(ch in '<>:"|?*' for ch in part)):
            return None
        stem = part.split(".", 1)[0].casefold()
        is_numbered_device = (
            stem[:3] in {"com", "lpt"}
            and stem[3:] in _WINDOWS_DEVICE_DIGITS
        )
        if stem in _WINDOWS_RESERVED_STEMS_CF or is_numbered_device:
            return None
        # DOS short names can resolve to a protected long filename without the
        # protected spelling appearing in the patch (e.g. ``SELF_I~1.PY``).
        if re.search(r"~[1-9][0-9]*(?:\.|$)", part, flags=re.IGNORECASE):
            return None
    return "/".join(parts)


def _maverick_tails(parts: list[str]) -> list[list[str]]:
    """Components after EVERY case-folded ``maverick`` package occurrence.

    Inspecting only the last occurrence lets a path such as
    ``maverick/audit/maverick/writer.py`` hide the protected ``audit`` component
    behind a nested directory named ``maverick``.
    """
    # Package components are case-insensitive on Windows/macOS.  Matching only
    # the literal lower-case spelling lets ``MAVERICK/SELF_MODIFY.PY`` evade the
    # reference monitor and then match a permissive ``**`` allowlist.
    idxs = [i for i, p in enumerate(parts) if p.casefold() == "maverick"]
    return [parts[i + 1:] for i in idxs]


def is_protected(path: str) -> bool:
    """Whether ``path`` is part of the reference monitor and may never be edited.

    Canonicalizes first (:func:`_canonical`) so a quoted / ``//`` / ``\\`` /
    ``..`` / absolute spelling can't dodge the check, and matches case-insensitively
    so a re-cased path can't dodge it on macOS/Windows. Fail-closed: a path that
    can't be canonicalized (traversal, absolute, malformed quoting) is treated as
    protected."""
    c = _canonical(path)
    if c is None:
        return True
    c_cf = c.casefold()
    if any(c_cf.startswith(prefix) for prefix in _PROTECTED_REPO_PREFIXES_CF):
        return True
    parts = c.split("/")
    parts_cf = [part.casefold() for part in parts]
    if any(part in _PROTECTED_PATH_COMPONENTS_CF for part in parts_cf):
        return True
    basename = parts_cf[-1] if parts_cf else ""
    if (basename in _PROTECTED_BASENAMES_CF
            or basename.startswith("requirements")
            or basename.startswith("test_")
            or basename.endswith("_test.py")):
        return True

    for tail in _maverick_tails(parts):
        if not tail:
            continue
        tail_cf = [part.casefold() for part in tail]
        head = tail_cf[0]
        # Positive mutable zone: only domain assets live inside the code
        # package's candidate-editable surface. Enumerating every future
        # orchestrator/security module is not a sustainable reference monitor.
        if head != "domains":
            return True
        if head in _PROTECTED_DIRS_CF:
            return True
        if any(head.startswith(prefix) for prefix in _PROTECTED_FILE_PREFIXES_CF):
            return True
        if len(tail_cf) == 1 and head in _PROTECTED_FILES_CF:
            return True
    return False


@dataclass(frozen=True)
class EditableSurface:
    """The allowlist of paths self-modification MAY touch.

    ``editable_globs`` are repo-relative fnmatch patterns (e.g.
    ``packages/maverick-core/maverick/domains/*.toml``). A path is ``protected``
    (control plane) > ``editable`` (matches the allowlist) > ``unknown``
    (matches nothing) — and ``unknown`` is refused, so an EMPTY allowlist (the
    default) makes the whole engine inert even when enabled."""

    editable_globs: tuple[str, ...] = ()

    def classify(self, path: str) -> str:
        """Return ``"protected"`` | ``"editable"`` | ``"unknown"``.

        Matching is against the canonicalized path, so a quoted/`//`/`..` spelling
        can't slip a control-plane file past the protected check into the
        allowlist. Note: ``editable_globs`` use fnmatch, where ``*`` spans ``/`` --
        keep them as narrow as possible, since the allowlist is what turns
        ``unknown`` (refused) into ``editable`` (appliable)."""
        if is_protected(path):
            return "protected"
        c = _canonical(path)
        if c is None:  # defensive: is_protected already fails these closed
            return "protected"
        for g in self.editable_globs:
            if fnmatch.fnmatch(c, g):
                return "editable"
        return "unknown"


@dataclass(frozen=True)
class PatchReview:
    """The boundary's verdict on a proposed patch."""

    ok: bool
    reason: str = ""
    touched: tuple[str, ...] = ()
    protected: tuple[str, ...] = ()
    unknown: tuple[str, ...] = ()


def _diff_paths(patch: str) -> list[str]:
    """Extract every file path a unified diff touches (a/ and b/ sides, renames),
    ``/dev/null`` excluded. Deliberately permissive at extraction so the
    classifier — not the parser — is what decides; an unparseable-but-nonempty
    patch yields no paths and is refused by :func:`review_patch`."""
    paths: list[str] = []
    seen: set[str] = set()

    def _add(raw: str) -> None:
        # git's ---/+++ headers separate the path from an optional timestamp with
        # a TAB; git apply ignores everything from the tab on. Mirror that, or a
        # "--- a/config.py\t2024-..." header parses as a different path than the
        # one actually patched and slips past the protected-path classifier.
        # Preserve spaces: on Windows a terminal space aliases the spelling
        # without it, and :func:`_canonical` must see and reject that ambiguity.
        # Git timestamps are delimited by a TAB, so removing only that suffix is
        # sufficient and does not rewrite the filename being classified.
        p = raw.split("\t", 1)[0]
        if p.startswith(("a/", "b/")):
            p = p[2:]
        if not p or p == "/dev/null":
            return
        if p not in seen:
            seen.add(p)
            paths.append(p)

    for line in _patch_lines(patch):
        # A CRLF patch ends each header with "\r"; git does not read it as
        # part of the path. Only header lines are inspected here.
        line = line.removesuffix("\r")
        if line.startswith("diff --git "):
            # diff --git a/X b/Y
            bits = line.split()
            for tok in bits[2:]:
                _add(tok)
        elif line.startswith(("--- ", "+++ ")):
            _add(line[4:])
        elif line.startswith(("rename from ", "rename to ",
                              "copy from ", "copy to ")):
            _add(line.split(" ", 2)[2])
    return paths


def _patch_lines(patch: str) -> list[str]:
    """Split a patch into lines exactly as ``git apply`` does: on ``\n`` only.

    ``str.splitlines`` also breaks on U+2028, U+0085, ``\x0b``, ``\x0c`` and
    ``\x1c``-``\x1e``; git keeps those inside the line. Splitting differently
    from git would let a header such as ``+++ b/x.toml<U+2028>y.py`` be
    reviewed as ``x.toml`` while git writes the longer name.
    """
    return patch.split("\n")


def _split_diff_git_paths(line: str) -> tuple[str, str] | None:
    """Return the two raw path tokens from one ``diff --git`` header.

    Git C-quotes paths containing whitespace, so a plain ``str.split`` cannot
    distinguish the two operands safely.  Keep the tokens quoted here; the
    existing canonicalizer is the single authority that decodes them.
    """
    prefix = "diff --git "
    if not line.startswith(prefix):
        return None
    text = line[len(prefix):]
    tokens: list[str] = []
    i = 0
    while i < len(text):
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            break
        start = i
        if text[i] == '"':
            i += 1
            closed = False
            while i < len(text):
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == '"':
                    i += 1
                    closed = True
                    break
                i += 1
            if not closed:
                return None
        else:
            while i < len(text) and not text[i].isspace():
                i += 1
        tokens.append(text[start:i])
        if len(tokens) > 2:
            return None
    if len(tokens) != 2:
        return None
    return tokens[0], tokens[1]


def _unsafe_apply_prefix(patch: str) -> str | None:
    """Reject a patch whose reviewed paths differ from ``git apply -p1`` paths.

    ``-p1`` strips *any* first path component, not only the conventional ``a``
    and ``b`` components.  Accepting ``x/apps/...`` during review would therefore
    classify that spelling while git later writes ``apps/...``.  Require the
    standard prefixes on every file header so review and mutation address the
    exact same repository-relative target.  Rename/copy metadata is already
    repository-relative and is classified separately by :func:`_diff_paths`.
    """
    for line in _patch_lines(patch or ""):
        line = line.removesuffix("\r")  # CRLF header; see _diff_paths
        if line.startswith("diff --git "):
            pair = _split_diff_git_paths(line)
            if pair is None:
                return "malformed diff --git path header"
            decoded = tuple(_unquote_git(raw) for raw in pair)
            if (decoded[0] is None or decoded[1] is None
                    or not decoded[0].startswith("a/")
                    or not decoded[1].startswith("b/")
                    or len(decoded[0]) <= 2 or len(decoded[1]) <= 2):
                return "non-standard diff path prefix is unsafe with git apply -p1"
        elif line.startswith(("--- ", "+++ ")):
            marker = line[:3]
            raw = line[4:].split("\t", 1)[0]
            decoded = _unquote_git(raw)
            expected = "a/" if marker == "---" else "b/"
            if decoded == "/dev/null":
                continue
            if (decoded is None or not decoded.startswith(expected)
                    or len(decoded) <= 2):
                return "non-standard file-header prefix is unsafe with git apply -p1"
    return None


def _unsafe_diff_artifact(patch: str) -> str | None:
    """Return the first unsafe diff artifact kind, if any.

    Self-modification is text-source only. Git symlink (120000), gitlink
    (160000), device/special modes, and binary patches can make an apparently
    allowlisted path resolve or execute outside the reviewed source artifact.
    """
    regular_modes = {"100644", "100755"}
    for raw in _patch_lines(patch or ""):
        line = raw.strip()
        # A text patch may edit an existing regular executable, but it may not
        # create one or change mode bits.  Executability is a capability change
        # that source review alone does not capture.
        if line.startswith(("old mode ", "new mode ")):
            return "unsafe git file mode change"
        new_file_mode = re.match(r"^new file mode\s+(\d{6})$", line)
        if new_file_mode and new_file_mode.group(1) != "100644":
            return f"unsafe new git file mode {new_file_mode.group(1)}"
        deleted_file_mode = re.match(r"^deleted file mode\s+(\d{6})$", line)
        if deleted_file_mode and deleted_file_mode.group(1) not in regular_modes:
            return f"unsafe git file mode {deleted_file_mode.group(1)}"
        if (line.startswith(("new file mode ", "deleted file mode "))
                and not (new_file_mode or deleted_file_mode)):
            return "unsafe malformed git file mode"
        index_mode = re.match(r"^index\s+\S+\.\.\S+\s+(\d{6})$", line)
        if index_mode and index_mode.group(1) not in regular_modes:
            return f"unsafe git index mode {index_mode.group(1)}"
        if line.startswith("index ") and not re.match(
                r"^index\s+\S+\.\.\S+(?:\s+\d{6})?$", line):
            return "unsafe malformed git index metadata"
        content = line[1:] if line.startswith(("+", "-")) else line
        if line == "GIT binary patch" or content.startswith("Subproject commit "):
            return f"unsafe diff artifact {content!r}"
        if line.startswith("Binary files ") and line.endswith(" differ"):
            return "unsafe binary diff"
    return None


def review_patch(patch: str, surface: EditableSurface | None = None) -> PatchReview:
    """Classify every path a patch touches against the surface. ``ok`` iff at
    least one path was found and ALL touched paths are ``editable``.

    This is the structural refusal: it runs before the promotion gate and does
    not depend on it, so a control-plane edit is rejected even if every other
    gate were somehow satisfied."""
    if type(patch) is not str:
        return PatchReview(False, reason="patch must be text")
    if surface is None:
        surface = EditableSurface()
    elif type(surface) is not EditableSurface:
        return PatchReview(False, reason="invalid editable surface authority")
    if (type(surface.editable_globs) is not tuple
            or any(type(glob) is not str for glob in surface.editable_globs)):
        return PatchReview(False, reason="invalid editable surface allowlist")
    if len(patch) > _MAX_REVIEW_PATCH_CHARS:
        return PatchReview(False, reason="patch exceeds review size limit")
    prefix_error = _unsafe_apply_prefix(patch)
    if prefix_error:
        return PatchReview(False, reason=prefix_error)
    from .safety.self_modify_dlp import contains_secret_material
    if contains_secret_material(patch or "", unified_diff=True):
        return PatchReview(False, reason="patch contains detected secret material")
    unsafe = _unsafe_diff_artifact(patch or "")
    if unsafe:
        return PatchReview(False, reason=unsafe)
    paths = _diff_paths(patch or "")
    if not paths:
        return PatchReview(False, reason="no file paths found in patch")
    protected: list[str] = []
    unknown: list[str] = []
    for p in paths:
        try:
            c = surface.classify(p)
        except Exception:
            return PatchReview(False, reason="editable surface classification failed")
        if c == "protected":
            protected.append(p)
        elif c != "editable":
            unknown.append(p)
    if protected:
        reason = f"patch touches protected control-plane paths: {sorted(protected)}"
    elif unknown:
        reason = f"patch touches paths outside the editable allowlist: {sorted(unknown)}"
    else:
        reason = f"all {len(paths)} touched paths are within the editable surface"
    return PatchReview(
        ok=not protected and not unknown, reason=reason,
        touched=tuple(paths), protected=tuple(protected), unknown=tuple(unknown),
    )


# --- capability-diff: a heuristic non-escalation SIGNAL -----------------------

def capability_diff(patch: str) -> tuple[bool, list[str]]:
    """Heuristic scan for capability-widening constructs a patch ADDS.

    Returns ``(widens, reasons)``. ``widens`` is True iff the patch's added lines
    evidence any capability class (process spawn, network, dynamic code,
    filesystem write, dynamic import, native FFI, deserialization, an explicit
    tool/entitlement grant). The construct taxonomy is defined ONCE in
    :mod:`maverick.self_modify_capability` (``classes_in``) and shared with the
    algebra screen, so the two detectors can never drift apart; ``reasons`` are
    that module's human labels for the detected classes.

    This is a **signal, not a proof**. It is deliberately one-directional --
    :func:`propose_code_change` uses a positive hit to force
    ``capability_widens=True`` (blocking the change), but never treats a clean
    scan as a standalone certificate of non-escalation; the code rung's human
    signature is the backstop for what a regex cannot catch."""
    from .self_modify_capability import _added_lines, classes_in_source, describe_classes
    hit = classes_in_source("\n".join(_added_lines(patch)))
    return bool(hit), describe_classes(hit)


# --- config / gate -----------------------------------------------------------

def _settings() -> dict:
    try:
        from .config import get_self_modify
        return get_self_modify()
    except Exception:  # pragma: no cover -- config never blocks
        return {"enable": False, "editable_paths": []}


def _production_control() -> dict:
    """Resolve the one canonical, deployment-global DGM request bit.

    Environment policy has highest precedence, followed by the optional
    operator-owned config overlay, the dashboard overlay and base config.
    Per-tenant config is deliberately excluded: DGM edits one shared source
    tree, so request context must never change its authority. Invalid boolean
    values and any unreadable global source fail closed.
    """
    blockers: list[dict[str, str]] = []
    try:
        from .config import (
            CONFIG_OVERLAY_ENV,
            config_source_errors,
            env_flag,
            load_config,
            load_global_config,
        )

        cfg = load_global_config() or {}
        errors = config_source_errors(include_tenant=False)
        section = cfg.get("self_modify", {})
        if not isinstance(section, dict):
            section = {}
            blockers.append({
                "code": "invalid_self_modify_config",
                "message": "[self_modify] must be a TOML table.",
            })

        raw_configured = section.get("enable", False)
        if "enable" in section and type(raw_configured) is not bool:
            blockers.append({
                "code": "invalid_self_modify_enable",
                "message": "[self_modify] enable must be a boolean.",
            })
        configured = raw_configured is True

        environment_managed = "MAVERICK_SELF_MODIFY" in os.environ
        env_override = env_flag("MAVERICK_SELF_MODIFY")
        if environment_managed and env_override is None:
            blockers.append({
                "code": "invalid_self_modify_environment",
                "message": "MAVERICK_SELF_MODIFY must be a recognized boolean.",
            })

        overlay_managed = False
        overlay_raw = os.environ.get(CONFIG_OVERLAY_ENV, "").strip()
        if overlay_raw:
            overlay_cfg = load_config(Path(overlay_raw).expanduser()) or {}
            if isinstance(overlay_cfg, dict) and "self_modify" in overlay_cfg:
                overlay_section = overlay_cfg.get("self_modify")
                overlay_managed = (
                    not isinstance(overlay_section, dict)
                    or "enable" in overlay_section
                )

        if errors:
            blockers.append({
                "code": "config_source_error",
                "message": "An active global configuration source is unreadable or invalid.",
            })

        invalid = any(item["code"].startswith("invalid_") for item in blockers)
        if errors or invalid:
            requested = False
        elif environment_managed:
            requested = bool(env_override)
        else:
            requested = configured

        managed_by = (
            "environment" if environment_managed
            else "config_overlay" if overlay_managed
            else None
        )
        return {
            "ok": True,
            "cfg": cfg,
            "section": section,
            "errors": errors,
            "configured": configured,
            "requested": requested,
            "managed_by_environment": environment_managed,
            "managed_by_config_overlay": overlay_managed,
            "control_managed": managed_by is not None,
            "managed_by": managed_by,
            "environment_override": env_override,
            "blockers": blockers,
        }
    except Exception:
        return {
            "ok": False,
            "cfg": {},
            "section": {},
            "errors": {"status": "unavailable"},
            "configured": False,
            "requested": False,
            "managed_by_environment": False,
            "managed_by_config_overlay": False,
            "control_managed": False,
            "managed_by": None,
            "environment_override": None,
            "blockers": [{
                "code": "status_unavailable",
                "message": "DGM configuration status is unavailable.",
            }],
        }


def enabled() -> bool:
    """Whether the governed code-modification engine may run. OFF by default.

    ``MAVERICK_SELF_MODIFY=1`` or ``[self_modify] enable``. Even when enabled it
    is inert until the editable allowlist is non-empty. Config uncertainty
    fails closed (stays off)."""
    return bool(_production_control()["requested"])


def improvement_enabled() -> bool:
    """Resolve the DGM dependency without tenant-scoped policy escalation."""
    try:
        from .config import (
            GOVERNED_LEARNING_DEFAULT,
            config_source_errors,
            env_flag,
            load_global_config,
        )
        cfg = load_global_config() or {}
        if config_source_errors(include_tenant=False):
            return False
        section = cfg.get("self_improvement", {})
        if not isinstance(section, dict):
            return False
        raw = section.get("enable", GOVERNED_LEARNING_DEFAULT)
        if type(raw) is not bool:
            return False
        if "MAVERICK_SELF_IMPROVEMENT" in os.environ:
            override = env_flag("MAVERICK_SELF_IMPROVEMENT")
            if override is None:
                return False
            base = override
        else:
            base = raw
        return bool(base)
    except Exception:  # pragma: no cover -- uncertainty cannot arm DGM
        return False


def production_status() -> dict:
    """Return a side-effect-free, fail-closed production control-plane view.

    ``requested`` answers whether the client turned the research harness on;
    ``effective`` additionally requires the governed self-improvement gate;
    ``ready`` means the static production prerequisites are configured.  A run
    still performs its own fresh Git, budget, HALT and sandbox attestation
    checks before any proposer is called.  Enabling never authorizes live code
    adoption: the stock runner can only propose, evaluate and archive.
    """
    control = _production_control()
    cfg = control["cfg"]
    section = control["section"]
    errors = control["errors"]
    configured = control["configured"]
    requested = control["requested"]
    blockers: list[dict[str, str]] = list(control["blockers"])
    sandbox = cfg.get("sandbox") or {}
    if not isinstance(sandbox, dict):
        sandbox = {}

    improvement_on = improvement_enabled()
    if not improvement_on:
        blockers.append({
            "code": "self_improvement_disabled",
            "message": "Governed self-improvement is disabled.",
        })

    paths = section.get("editable_paths")
    configured_surface = bool(
        isinstance(paths, list) and any(str(p).strip() for p in paths)
    )
    tiers = section.get("tiers")
    if isinstance(tiers, list):
        configured_surface = configured_surface or any(
            isinstance(tier, dict)
            and isinstance(tier.get("editable_paths"), list)
            and any(str(p).strip() for p in tier["editable_paths"])
            for tier in tiers
        )
    if not configured_surface:
        blockers.append({
            "code": "editable_surface_missing",
            "message": "Configure a narrow [self_modify] editable_paths allowlist.",
        })

    tests = section.get("eval_tests")
    configured_tests = (
        [str(test).strip() for test in tests if str(test).strip()]
        if isinstance(tests, list) else []
    )
    if len(configured_tests) < 2:
        blockers.append({
            "code": "challenge_corpus_missing",
            "message": "Configure at least two discriminating eval_tests.",
        })

    backend = str(sandbox.get("backend") or "local").strip().lower()
    if not backend.startswith("ep:"):
        blockers.append({
            "code": "attested_evaluator_missing",
            "message": (
                "Configure an external ep: sandbox backend that authenticates "
                "bounded test results; bundled backends are not DGM-attested."
            ),
        })

    if requested:
        try:
            from .learning_guard import check_learning_halt
            check_learning_halt("self_modify", "status")
        except Exception:
            blockers.append({
                "code": "learning_halt_active",
                "message": "The global learning HALT is active or unavailable.",
            })

    # De-duplicate codes defensively if two malformed inputs collapse to the
    # same refusal. Stable order makes API/UI snapshots and tests deterministic.
    blockers = list({item["code"]: item for item in blockers}.values())
    effective = bool(requested and improvement_on and not errors)
    ready = bool(effective and not blockers)
    # A corrupt active policy is operationally blocked, even if we cannot trust
    # it enough to recover the requested bit. Missing readiness prerequisites
    # alone do not make the normal default-off state look unhealthy.
    state = (
        "ready" if ready
        else "blocked" if requested or bool(errors)
        else "off"
    )
    return {
        "configured": configured,
        "requested": bool(requested),
        "effective": effective,
        "ready": ready,
        "state": state,
        "managed_by_environment": control["managed_by_environment"],
        "managed_by_config_overlay": control["managed_by_config_overlay"],
        "control_managed": control["control_managed"],
        "managed_by": control["managed_by"],
        "environment_override": control["environment_override"],
        "research_only": True,
        "live_adoption": False,
        "runtime_preflight_required": True,
        "blockers": blockers,
    }


def default_surface() -> EditableSurface:
    """The editable surface from ``[self_modify] editable_paths`` (empty by
    default → nothing is editable)."""
    try:
        globs = tuple(_settings().get("editable_paths") or ())
    except Exception:  # pragma: no cover
        globs = ()
    return EditableSurface(editable_globs=globs)


# --- the governed code-rung producer -----------------------------------------

@dataclass
class CodeChangeResult:
    """Outcome of reviewing a proposed code change at the deployment boundary.

    ``ok`` stays false while live code promotion is disabled. ``verdict`` is
    retained for API compatibility but is not populated by this module."""

    review: PatchReview
    verdict: object | None = None      # maverick.self_improvement.Verdict | None
    reason: str = ""

    @property
    def ok(self) -> bool:
        # getattr(None, "ok", False) is already False, so no explicit None guard.
        return bool(self.review.ok and getattr(self.verdict, "ok", False))


def propose_code_change(
    patch: str,
    *,
    summary: str,
    baseline_score: float,
    candidate_score: float,
    samples: int,
    rollback: object,
    surface: EditableSurface | None = None,
    capability_widens: bool | None = None,
    baseline_files: dict[str, str] | None = None,
    approval_signature: str | None = None,
    payload_sha256: str | None = None,
    candidate_id: str | None = None,
    controller: object | None = None,
    rung: str = "code",
) -> CodeChangeResult:
    """Review a code-rung change without promoting or applying it.

    Two independent gates must BOTH pass, in order:
      1. **Editable-surface boundary** (:func:`review_patch`) — the patch touches
         only allowlisted paths, never the control plane. Refused structurally
         here, before the promotion gate is even consulted.
      2. **Capability screen** — any potential widening is refused.

    The legacy code approval gate is intentionally unreachable because its
    payload is not bound to the evaluation evidence, base revision, editable
    policy, tenant, nonce, and expiry. This function never applies or promotes a
    patch; errors yield a refusal.

    This API is code-specific.  A caller cannot label a source patch as the
    lower ``prompt``/``policy`` rung to bypass code approval requirements; a
    non-code rung is rejected before configuration, boundary, or gate work.
    """
    if type(rung) is not str or rung != "code":
        reason = "code self-modification requires rung='code'"
        return CodeChangeResult(PatchReview(False, reason=reason), reason=reason)
    if not enabled():
        return CodeChangeResult(
            PatchReview(False, reason="self-modification disabled"),
            reason="self-modification disabled")
    try:
        review = review_patch(patch, surface or default_surface())
        if not review.ok:
            # The boundary refused: do NOT build a candidate or touch the gate.
            return CodeChangeResult(review, reason=review.reason)

        # Capability screen (one-directional): a syntactic hit FORCES
        # ``capability_widens=True`` so the gate refuses. A caller-supplied True
        # is honoured; a caller-supplied False is NOT allowed to override a
        # positive screen (a heuristic must be able to make the gate stricter,
        # never weaker). When the caller said nothing and the screen is clean we
        # leave it None, so the code rung still demands a real proof.
        widens_hit, widen_reasons = capability_diff(patch)
        if widens_hit:
            if capability_widens is False:
                log.info("self-modify: capability screen overrode "
                         "capability_widens=False: %s", widen_reasons)
            capability_widens = True
        if capability_widens:
            return CodeChangeResult(
                review,
                reason="code patch may widen a capability; refusing",
            )

        # The legacy approval object binds too little state to authorize a code
        # deployment: it omits evaluator evidence, base revision, editable
        # surface/policy, tenant, nonce, and expiry.  Never forward a code patch
        # to that gate. A future integration must use an external one-shot
        # evaluator plus the durable PREPARE/CAS/COMMIT transaction API.
        return CodeChangeResult(
            review,
            reason="live code promotion is disabled until a nonce-bound "
                   "transactional approval manifest is available",
        )
    except Exception:  # pragma: no cover -- a privileged path must never crash a run
        log.warning("self-modify: propose_code_change errored; refusing", exc_info=True)
        return CodeChangeResult(
            PatchReview(False, reason="self-modify controller error"),
            reason="self-modify controller error")


__all__ = [
    "EditableSurface",
    "PatchReview",
    "CodeChangeResult",
    "is_protected",
    "review_patch",
    "capability_diff",
    "propose_code_change",
    "enabled",
    "default_surface",
]
