"""Automated pre-publication moderation for marketplace submissions.

Before a community skill or plugin lands in the marketplace, it runs this
gauntlet of static, deterministic, offline checks so a human moderator reviews
a triaged verdict instead of a raw upload. It covers a submitted **skill**
package (a ``SKILL.md``) or **plugin** package (a dir with a
``maverick-plugin.toml`` + source), and reports:

  * **manifest completeness** -- required fields present (skill: name +
    triggers + a real body; plugin: name/version/api_version + author + repo).
  * **permission-escalation flags** -- does the package declare or use
    ``subprocess`` / ``network`` / sensitive env access? Declared-and-used is a
    FLAG (needs a human); *used-but-undeclared* is the dangerous case and a
    stronger flag.
  * **secret-in-body scan** -- reuse ``maverick.safety.secret_detector`` so an
    embedded credential is a hard REJECT (same detector the install path uses).
  * **prohibited-pattern scan** -- obvious malware/exfil tells (``os.system``,
    ``eval(`` / ``exec(`` on dynamic input, ``curl ... | sh``, reverse shells,
    fork bombs). Hard tells REJECT; softer ones FLAG.
  * **license presence** -- a published artifact must declare a license.

Verdicts follow the project's strictest-wins idiom (cf. ``governance.Verdict``):
``REJECT`` > ``FLAG`` > ``APPROVE``. Every finding carries a code, a severity,
and a human-readable reason so the moderator (or the author) sees exactly why.

Pure + offline: no network, no install, no code execution -- it only reads and
pattern-matches the submitted files. CLI::

    python -m maverick.marketplace.moderation path/to/skill-or-plugin
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Verdict(str, Enum):
    """Moderation outcome. Ordered strictest-first for ``escalate``."""

    REJECT = "reject"    # a hard blocker (secret, malware tell, broken manifest)
    FLAG = "flag"        # needs human review (permission escalation, soft tell)
    APPROVE = "approve"  # clean: no findings worse than advisory

    @property
    def _rank(self) -> int:
        return {"reject": 2, "flag": 1, "approve": 0}[self.value]

    def escalate(self, other: Verdict) -> Verdict:
        """Return the stricter of two verdicts (REJECT > FLAG > APPROVE)."""
        return self if self._rank >= other._rank else other


class Severity(str, Enum):
    REJECT = "reject"
    FLAG = "flag"
    INFO = "info"

    def as_verdict(self) -> Verdict:
        return {"reject": Verdict.REJECT, "flag": Verdict.FLAG, "info": Verdict.APPROVE}[self.value]


@dataclass(frozen=True)
class Finding:
    """One moderation finding: what tripped, how bad, and why."""

    code: str
    severity: Severity
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "severity": self.severity.value, "message": self.message}


@dataclass
class ModerationReport:
    """The full result of moderating one submission."""

    target: str
    kind: str  # "skill" | "plugin" | "unknown"
    verdict: Verdict
    findings: list[Finding] = field(default_factory=list)

    @property
    def reasons(self) -> list[str]:
        return [f.message for f in self.findings]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "kind": self.kind,
            "verdict": self.verdict.value,
            "findings": [f.to_dict() for f in self.findings],
        }


# ---- prohibited patterns ----------------------------------------------------

# (code, severity, regex, human message). Hard tells (reverse shells, piped
# installers, fork bombs) REJECT; softer ones (a bare os.system, dynamic eval)
# FLAG for a human -- legitimate skills occasionally shell out, but a moderator
# should look. Patterns are deliberately conservative to limit false positives.
_PROHIBITED: list[tuple[str, Severity, re.Pattern, str]] = [
    ("pipe_to_shell", Severity.REJECT,
     re.compile(r"curl\s+[^|]+\|\s*(?:sudo\s+)?(?:ba)?sh", re.IGNORECASE),
     "pipes a downloaded script straight into a shell (curl ... | sh)"),
    ("wget_to_shell", Severity.REJECT,
     re.compile(r"wget\s+[^|]+\|\s*(?:sudo\s+)?(?:ba)?sh", re.IGNORECASE),
     "pipes a downloaded script straight into a shell (wget ... | sh)"),
    ("reverse_shell", Severity.REJECT,
     re.compile(r"(?:bash\s+-i\s+>&|/dev/tcp/|nc\s+-e\b|ncat\s+-e\b)"),
     "contains a reverse-shell construct"),
    ("fork_bomb", Severity.REJECT,
     re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),
     "contains a shell fork bomb"),
    ("rm_rf_root", Severity.REJECT,
     re.compile(r"rm\s+-rf\s+(?:--no-preserve-root\s+)?/(?:\s|$|\*)"),
     "issues a destructive 'rm -rf /'"),
    ("os_system", Severity.FLAG,
     re.compile(r"\bos\.system\s*\("),
     "calls os.system (shells out; should go through the sandbox)"),
    ("dynamic_exec", Severity.FLAG,
     re.compile(r"\b(?:eval|exec)\s*\(", ),
     "uses eval()/exec() (dynamic code execution -- review the source)"),
    ("dynamic_import", Severity.FLAG,
     re.compile(r"\b__import__\s*\("),
     "uses __import__() (dynamic import -- review the source)"),
    ("base64_exec", Severity.REJECT,
     re.compile(r"(?:base64\.b64decode|codecs\.decode)\s*\([^)]*\)\s*\)?\s*(?:#.*)?$", re.MULTILINE),
     "decodes and is positioned to execute obfuscated payload"),
]

# Tells that a package TOUCHES a capability, used to detect undeclared use
# (used-but-not-declared in the manifest). Conservative substrings.
_SUBPROCESS_TELLS = re.compile(r"\b(?:subprocess\.|os\.system|os\.popen|pty\.spawn)")
_NETWORK_TELLS = re.compile(r"\b(?:socket\.socket|httpx\.|requests\.|urllib\.request|aiohttp\.)")
_ENV_TELLS = re.compile(r"os\.environ(?:\.get)?\s*[\[(]\s*['\"]([A-Z_][A-Z0-9_]*)['\"]")
# Env var names that read as sensitive even if not explicitly declared.
_SENSITIVE_ENV_RE = re.compile(r"(?:KEY|TOKEN|SECRET|PASSWORD|PASS|CREDENTIAL|PRIVATE)", re.IGNORECASE)


def scan_prohibited(text: str) -> list[Finding]:
    """Return findings for every prohibited pattern present in ``text``."""
    findings: list[Finding] = []
    for code, severity, pat, message in _PROHIBITED:
        if pat.search(text):
            findings.append(Finding(code, severity, f"prohibited pattern: {message}"))
    return findings


def scan_secrets(text: str, *, where: str = "body") -> list[Finding]:
    """REJECT findings for any embedded credential (reuses the shared detector).

    Uses ``maverick.safety.secret_detector`` so moderation agrees byte-for-byte
    with the install-time / output-time redactor. Each detected secret type is
    reported once. Never raises -- a detector hiccup degrades to no finding.
    """
    try:
        from ..safety.secret_detector import scan
    except Exception:  # pragma: no cover -- detector must not crash moderation
        return []
    seen: set[str] = set()
    findings: list[Finding] = []
    for match in scan(text):
        if match.name in seen:
            continue
        seen.add(match.name)
        findings.append(Finding(
            "embedded_secret", Severity.REJECT,
            f"possible {match.name} credential embedded in {where} -- remove before publishing",
        ))
    return findings


# ---- skill submissions ------------------------------------------------------

def _find_skill_md(path: Path) -> Path | None:
    if path.is_file() and path.suffix == ".md":
        return path
    if path.is_dir():
        direct = path / "SKILL.md"
        if direct.exists():
            return direct
        mds = sorted(path.glob("*.md"))
        return mds[0] if mds else None
    return None


def moderate_skill(skill_md: Path) -> ModerationReport:
    """Moderate a single ``SKILL.md`` submission.

    Reuses ``skills.validate_skill_file`` for manifest/secret hygiene (so the
    moderation gate and the publish-lint never drift), then layers the
    marketplace-specific checks: prohibited patterns over the whole file and an
    explicit license-presence requirement (the lint warns; moderation FLAGs).
    """
    report = ModerationReport(target=str(skill_md), kind="skill", verdict=Verdict.APPROVE)
    try:
        text = skill_md.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        return _single(report, Finding("unreadable", Severity.REJECT, f"cannot read submission: {e}"))

    from .. import skills as skills_mod

    validation = skills_mod.validate_skill_file(skill_md)
    for err in validation.errors:
        # Every publish-lint error blocks publication (a malformed manifest, a
        # too-short body, or an embedded secret the lint's own scan caught), so
        # surface each as a REJECT.
        _add(report, Finding("manifest", Severity.REJECT, f"manifest: {err}"))

    # Belt-and-suspenders secret scan over the raw file (covers anything the
    # lint's body-only view might miss, e.g. a secret in the frontmatter).
    for finding in scan_secrets(text, where="skill file"):
        _add(report, finding)

    for finding in scan_prohibited(text):
        _add(report, finding)

    if not _declares_license(text):
        _add(report, Finding(
            "license_missing", Severity.FLAG,
            "no license declared (add a 'license:' frontmatter key or a LICENSE)",
        ))
    return report


def _declares_license(text: str) -> bool:
    front = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
    if front and re.search(r"(?mi)^license\s*:", front.group(1)):
        return True
    return False


# ---- plugin submissions -----------------------------------------------------

def _find_plugin_manifest(path: Path) -> Path | None:
    if path.is_file() and path.name == "maverick-plugin.toml":
        return path
    if path.is_dir():
        candidate = path / "maverick-plugin.toml"
        if candidate.exists():
            return candidate
    return None


def _python_sources(root: Path) -> list[Path]:
    """All ``*.py`` under a plugin dir (the source we pattern-scan)."""
    if root.is_file():
        return [root] if root.suffix == ".py" else []
    return sorted(p for p in root.rglob("*.py") if p.is_file())


def moderate_plugin(manifest_path: Path) -> ModerationReport:
    """Moderate a plugin package (a ``maverick-plugin.toml`` + its source).

    Parses the manifest via ``plugin_manifest.parse`` (so schema rules stay in
    one place), checks completeness + license + author, then scans every Python
    source file for secrets, prohibited patterns, and -- the marketplace-
    specific bit -- **permission escalation**: a source that USES subprocess /
    network / sensitive-env access the manifest does NOT declare.
    """
    root = manifest_path.parent
    report = ModerationReport(target=str(root), kind="plugin", verdict=Verdict.APPROVE)

    from .. import plugin_manifest

    manifest = plugin_manifest.parse(manifest_path)
    if manifest is None:
        return _single(report, Finding(
            "manifest", Severity.REJECT,
            "maverick-plugin.toml is missing required fields or is invalid TOML",
        ))

    if not manifest.license:
        _add(report, Finding("license_missing", Severity.FLAG, "manifest declares no license"))
    if not manifest.author:
        _add(report, Finding("author_missing", Severity.FLAG, "manifest declares no author"))
    if not manifest.repo:
        _add(report, Finding("repo_missing", Severity.FLAG, "manifest declares no repo URL"))
    for warn in manifest.warnings:
        if "api_version" in warn:
            _add(report, Finding("api_version", Severity.FLAG, warn))

    _check_declared_permissions(report, manifest)
    _scan_plugin_sources(report, root, manifest)
    return report


def _check_declared_permissions(report: ModerationReport, manifest: Any) -> None:
    """FLAG each elevated permission the manifest *declares* (for human review).

    Declared escalation isn't a rejection -- a deploy tool legitimately needs
    subprocess + network -- but a human should sign off, so each declared
    elevated capability is surfaced.
    """
    perms = manifest.permissions
    if perms.subprocess:
        _add(report, Finding("perm_subprocess", Severity.FLAG, "declares subprocess permission"))
    if perms.network:
        _add(report, Finding("perm_network", Severity.FLAG, "declares network permission"))
    if perms.sensitive_envs:
        _add(report, Finding(
            "perm_sensitive_envs", Severity.FLAG,
            f"declares access to sensitive envs: {', '.join(perms.sensitive_envs)}",
        ))


def _scan_plugin_sources(report: ModerationReport, root: Path, manifest: Any) -> None:
    """Scan every source file; flag undeclared capability use most sharply."""
    perms = manifest.permissions
    for src in _python_sources(root):
        try:
            text = src.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        rel = src.relative_to(root) if src != root else src.name
        for finding in scan_secrets(text, where=str(rel)):
            _add(report, finding)
        for finding in scan_prohibited(text):
            _add(report, finding)
        _check_undeclared_use(report, text, perms, str(rel))


def _check_undeclared_use(report: ModerationReport, text: str, perms: Any, where: str) -> None:
    """The escalation case that matters: capability USED but NOT declared.

    A plugin that shells out / opens sockets / reads a sensitive env WITHOUT
    declaring the matching permission is exactly the supply-chain risk
    moderation exists to catch, so it's a stronger flag than a declared one.
    """
    if _SUBPROCESS_TELLS.search(text) and not perms.subprocess:
        _add(report, Finding(
            "undeclared_subprocess", Severity.REJECT,
            f"{where}: uses subprocess/os.system but the manifest does not declare it",
        ))
    if _NETWORK_TELLS.search(text) and not perms.network:
        _add(report, Finding(
            "undeclared_network", Severity.REJECT,
            f"{where}: makes network calls but the manifest does not declare network access",
        ))
    declared = {e.upper() for e in perms.sensitive_envs}
    for m in _ENV_TELLS.finditer(text):
        var = m.group(1)
        if _SENSITIVE_ENV_RE.search(var) and var.upper() not in declared:
            _add(report, Finding(
                "undeclared_sensitive_env", Severity.FLAG,
                f"{where}: reads sensitive env {var!r} not declared in sensitive_envs",
            ))


# ---- dispatch ---------------------------------------------------------------

def _single(report: ModerationReport, finding: Finding) -> ModerationReport:
    _add(report, finding)
    return report


def _add(report: ModerationReport, finding: Finding) -> None:
    report.findings.append(finding)
    report.verdict = report.verdict.escalate(finding.severity.as_verdict())


def moderate(path: Path) -> ModerationReport:
    """Moderate a submission at ``path`` (auto-detects skill vs plugin).

    A plugin (a ``maverick-plugin.toml`` present) is moderated as a plugin; a
    lone/dir-with ``.md`` is moderated as a skill. An ambiguous path that is
    neither returns a REJECT report rather than silently approving.
    """
    path = Path(path).expanduser()
    if not path.exists():
        return ModerationReport(
            str(path), "unknown", Verdict.REJECT,
            [Finding("not_found", Severity.REJECT, f"no such submission: {path}")],
        )
    manifest_path = _find_plugin_manifest(path)
    if manifest_path is not None:
        return moderate_plugin(manifest_path)
    skill_md = _find_skill_md(path)
    if skill_md is not None:
        return moderate_skill(skill_md)
    return ModerationReport(
        str(path), "unknown", Verdict.REJECT,
        [Finding(
            "unrecognized", Severity.REJECT,
            "submission is neither a SKILL.md nor a plugin (no maverick-plugin.toml)",
        )],
    )


# ---- CLI --------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    """Run moderation and print the report as JSON.

    Exit code maps the verdict so CI can gate on it: 0 approve, 1 flag (human
    review needed), 2 reject.
    """
    ap = argparse.ArgumentParser(
        prog="python -m maverick.marketplace.moderation",
        description="Static pre-publication moderation for a marketplace skill/plugin submission.",
    )
    ap.add_argument("path", help="path to a SKILL.md, a skill dir, or a plugin package dir")
    args = ap.parse_args(argv)

    report = moderate(Path(args.path))
    print(json.dumps(report.to_dict(), indent=2))
    return {Verdict.APPROVE: 0, Verdict.FLAG: 1, Verdict.REJECT: 2}[report.verdict]


__all__ = [
    "Verdict",
    "Severity",
    "Finding",
    "ModerationReport",
    "moderate",
    "moderate_skill",
    "moderate_plugin",
    "scan_prohibited",
    "scan_secrets",
    "main",
]


if __name__ == "__main__":
    sys.exit(main())
