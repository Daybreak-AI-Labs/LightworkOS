"""Self-reviewer agent (BugBot-style).

PR-review bots such as Cursor's BugBot review agent-generated diffs.
Lightwork has a verifier role for FINAL answers; this module repurposes
it for DIFF review specifically.

The reviewer is invoked AFTER the agent emits its FINAL answer when
the goal's working directory has uncommitted changes. It returns:

    ReviewVerdict(
        approves: bool,
        confidence: float,
        comments: list[ReviewComment],
    )

ReviewComment(path, line, severity, message). Severity is "blocker",
"warning", or "nit"; the orchestrator surfaces blockers as a revision
request, warnings/nits as advisory notes attached to the FINAL.
"""
from __future__ import annotations

import json
import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .budget import Budget, BudgetExceeded
from .git_safety import git_env_without_user_config, git_metadata_may_execute_filters
from .llm import LLM, model_for_role

log = logging.getLogger(__name__)


REVIEWER_SYSTEM = """You are a meticulous code reviewer reviewing a diff
another agent produced. You have no tools.

Review the diff for:
  1. Correctness: real bugs, off-by-one, missing null checks, wrong
     conditions, copy-paste errors, missing await/error handling.
  2. Security: injection sinks, secrets in code, unsafe deserialization,
     path traversal, SSRF.
  3. Test coverage: every new code path needs a test or a clear reason
     it can't be tested.
  4. Style: only flag if it actively hurts readability; otherwise skip.

Respond with a JSON object on a single line:

{
  "approves": true|false,
  "confidence": 0.0-1.0,
  "comments": [
    {"path": "...", "line": <int>, "severity": "blocker|warning|nit",
     "message": "<one sentence>"},
    ...
  ]
}

`approves` = true iff confidence >= 0.75 AND no `blocker` comments.
Output ONLY the JSON; no preamble; no markdown fence.
"""


@dataclass
class ReviewComment:
    path: str
    line: int
    severity: str
    message: str


@dataclass
class ReviewVerdict:
    approves: bool
    confidence: float
    comments: list[ReviewComment] = field(default_factory=list)
    raw: str = ""

    @classmethod
    def empty_pass(cls) -> ReviewVerdict:
        """Used when there's no diff to review (no changes since goal start)."""
        return cls(approves=True, confidence=1.0, comments=[])

    @classmethod
    def reject(cls, reason: str) -> ReviewVerdict:
        return cls(
            approves=False,
            confidence=0.0,
            comments=[ReviewComment(path="", line=0, severity="blocker",
                                    message=reason)],
        )

    @property
    def blockers(self) -> list[ReviewComment]:
        return [c for c in self.comments if c.severity == "blocker"]


_JSON_RE = re.compile(r"\{.*\}", re.DOTALL)


def _parse(text: str) -> ReviewVerdict:
    if not text:
        return ReviewVerdict.reject("reviewer returned empty response")
    m = _JSON_RE.search(text)
    if m is None:
        return ReviewVerdict.reject("no JSON in reviewer reply")
    try:
        data = json.loads(m.group(0))
    except json.JSONDecodeError as e:
        return ReviewVerdict.reject(f"reviewer JSON parse failed: {e}")

    try:
        confidence = float(data.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    confidence = max(0.0, min(1.0, confidence))

    approves_raw = data.get("approves", False)
    approves = (
        approves_raw.lower() in ("true", "yes", "1")
        if isinstance(approves_raw, str)
        else bool(approves_raw)
    )

    comments: list[ReviewComment] = []
    for c in data.get("comments", []) or []:
        if not isinstance(c, dict):
            continue
        sev = str(c.get("severity", "warning")).lower()
        if sev not in ("blocker", "warning", "nit"):
            sev = "warning"
        try:
            line = int(c.get("line", 0))
        except (TypeError, ValueError):
            line = 0
        comments.append(ReviewComment(
            path=str(c.get("path", "") or ""),
            line=line,
            severity=sev,
            message=str(c.get("message", "") or ""),
        ))

    return ReviewVerdict(
        approves=approves, confidence=confidence,
        comments=comments, raw=text,
    )


def get_diff(workdir: Path, *, max_bytes: int = 100_000) -> str:
    """Return `git diff HEAD` for the workdir, truncated to max_bytes.

    Used to assemble the reviewer's input. We don't call into the
    sandbox here because the reviewer is checking AGENT output -- it's
    a one-shot reviewer not a tool the agent uses.

    `workdir` is the agent's own working directory, which the agent can
    write freely (including `.git/config`), so a repo-local
    `core.fsmonitor` hook or filter smudge command would otherwise
    execute on the host with this process's full environment (provider
    API keys included) -- refuse when such metadata is present, and run
    under a scrubbed environment either way. See :mod:`maverick.git_safety`.
    """
    if not (workdir / ".git").exists():
        return ""
    if git_metadata_may_execute_filters(workdir):
        log.warning(
            "reviewer.get_diff skipped: unsafe git filter/fsmonitor metadata in %s",
            workdir,
        )
        return ""
    try:
        proc = subprocess.run(
            ["git", "-C", str(workdir), "-c", "diff.external=", "-c", "diff.textconv=false",
             "-c", "core.hooksPath=/dev/null", "diff", "--no-ext-diff", "--no-textconv", "HEAD"],
            capture_output=True, text=True, timeout=10,
            env=git_env_without_user_config(),
        )
        diff = proc.stdout or ""
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        log.warning("reviewer git diff failed: %s", e)
        return ""
    if len(diff) > max_bytes:
        diff = diff[:max_bytes] + f"\n... [diff truncated to {max_bytes}B]\n"
    return diff


async def review_diff(
    brief: str,
    diff: str,
    llm: LLM,
    budget: Budget | None = None,
    *,
    max_tokens: int = 2048,
    proposer_model: str | None = None,
) -> ReviewVerdict:
    """Run the reviewer over a diff. Conservative: any parsing failure
    -> reject (treats the failure as a blocker comment).

    Cross-family verifier guard applies here too (a same-family reviewer
    can be jailbroken in lockstep with the proposer per the alignment-
    faking research).
    """
    if not diff or not diff.strip():
        return ReviewVerdict.empty_pass()

    # Reuse verifier role's model selection + cross-family swap.
    from .verifier import _cross_family_fallback, _same_family

    model = model_for_role("reviewer") or model_for_role("verifier")
    if proposer_model and _same_family(proposer_model, model):
        cross = _cross_family_fallback(model)
        if cross is not None:
            model = cross

    user_msg = (
        f"GOAL BRIEF:\n{brief}\n\n"
        f"DIFF (unified, from `git diff HEAD`):\n```diff\n{diff}\n```\n\n"
        "Return the review JSON."
    )
    try:
        resp = await llm.complete_async(
            system=REVIEWER_SYSTEM,
            messages=[{"role": "user", "content": user_msg}],
            tools=None,
            budget=budget,
            max_tokens=max_tokens,
            model=model,
        )
    except BudgetExceeded:
        # Budget exhaustion must halt the run, never silently soft-pass:
        # soft-passing here auto-approves the diff when the cap is hit.
        raise
    except Exception as e:  # pragma: no cover -- network errors
        # Fail CLOSED, matching the verifier's contract (verify_proposal): a
        # reviewer that crashes must not silently auto-approve an unreviewed
        # diff. Return a `blocker` so the orchestrator surfaces it as a revision
        # request instead of soft-passing the change through ungated. (A flaky
        # reviewer can only make the system MORE careful, not less.)
        log.warning("reviewer LLM call failed: %s; rejecting (fail-closed)", e)
        return ReviewVerdict(
            approves=False, confidence=0.0,
            comments=[ReviewComment(path="", line=0, severity="blocker",
                                    message=f"reviewer call failed: {e}")],
        )
    return _parse(resp.text)


def format_for_human(verdict: ReviewVerdict) -> str:
    """Render the verdict as a markdown block for the FINAL answer."""
    if verdict.approves and not verdict.comments:
        return f"\n\n_reviewer: ✓ approved (confidence {verdict.confidence:.2f})_"
    lines = [f"\n\n_reviewer verdict (confidence {verdict.confidence:.2f}):_"]
    for c in verdict.comments:
        loc = f"{c.path}:{c.line}" if c.path else "(global)"
        icon = {"blocker": "🛑", "warning": "⚠️", "nit": "💡"}.get(c.severity, "•")
        lines.append(f"  {icon} **{c.severity}** [{loc}] {c.message}")
    return "\n".join(lines)
