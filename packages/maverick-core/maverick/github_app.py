"""Parse and authenticate GitHub App events.

Automated issue-to-PR processing is unavailable until an agent-controlled
checkout can be safely separated from host Git and publication credentials.
"""
from __future__ import annotations

import contextlib
import hashlib
import hmac
import logging
import os
import re
import subprocess
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)


# Default labels that trigger a Lightwork run.
DEFAULT_LABELS = ("maverick", "automate", "ai-fix")

# Slash-command that triggers a run from an issue comment.
SLASH_TRIGGER = "/maverick"

# A comment author must have write-ish access to trigger a run via the
# slash command. GitHub's author_association reflects the commenter's
# relationship to the repo; anything below COLLABORATOR (CONTRIBUTOR,
# FIRST_TIME_CONTRIBUTOR, NONE, ...) is the general public and must not be
# able to spend the operator's API budget by commenting "/maverick".
_PRIVILEGED_ASSOCIATIONS = {"OWNER", "MEMBER", "COLLABORATOR"}


@dataclass
class WebhookPayload:
    """Normalized event from GitHub's webhook surface."""
    event: str                # "issues" | "issue_comment"
    action: str               # "labeled" | "created" | ...
    repo_full_name: str       # "owner/name"
    issue_number: int
    issue_title: str
    issue_body: str
    trigger_label: str | None = None
    comment_body: str | None = None
    sender_login: str = ""


def webhook_secret() -> str:
    """The GitHub App webhook secret: ``MAVERICK_GH_APP_WEBHOOK_SECRET`` wins;
    otherwise ``[github] app_webhook_secret``, saved sealed on the All settings
    page and opened by ``load_config``. Empty means requests are refused."""
    env = os.environ.get("MAVERICK_GH_APP_WEBHOOK_SECRET", "").strip()
    if env:
        return env
    try:
        from .config import load_config
        value = ((load_config() or {}).get("github") or {}).get("app_webhook_secret")
    except Exception:  # pragma: no cover - unreadable config means "not set"
        return ""
    return value.strip() if isinstance(value, str) else ""


def verify_signature(
    body: bytes,
    signature_header: str | None,
    secret: str | None,
) -> bool:
    """HMAC-SHA256 verification of GitHub's X-Hub-Signature-256 header.

    Defends against webhook spoofing. Fails CLOSED: a missing/empty secret
    rejects the request, matching ``issue_webhooks`` and ``webhooks`` (which
    also fail closed). The receiver this guards clones repos and drives a
    swarm that runs shell, so an unsigned request must never be enough to
    trigger a run -- the previous fail-open branch accepted *every* request
    when the operator forgot to set MAVERICK_GH_APP_WEBHOOK_SECRET.
    """
    if not secret:
        log.warning(
            "GH webhook signature check FAILED CLOSED: no secret configured "
            "(set MAVERICK_GH_APP_WEBHOOK_SECRET or the GitHub app webhook "
            "secret in All settings). Rejecting the request."
        )
        return False
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(
        secret.encode("utf-8"), body, hashlib.sha256,
    ).hexdigest()
    # Compare as bytes: signature_header is attacker-controlled and
    # hmac.compare_digest raises TypeError on a str with any non-ASCII char,
    # which would 500 the webhook instead of cleanly failing closed.
    return hmac.compare_digest(expected.encode("utf-8"), signature_header.encode("utf-8"))


def parse_webhook(event: str, payload: dict) -> WebhookPayload | None:
    """Normalize the GitHub webhook payload.

    Returns None for events we don't care about (e.g., issues.opened
    without a trigger label).
    """
    action = payload.get("action", "")
    repo = payload.get("repository", {}).get("full_name", "")
    issue = payload.get("issue", {}) or {}
    sender = (payload.get("sender") or {}).get("login", "")

    if event == "issues" and action == "labeled":
        label_name = (payload.get("label") or {}).get("name", "")
        if label_name.lower() not in _trigger_labels():
            return None
        return WebhookPayload(
            event=event, action=action,
            repo_full_name=repo,
            issue_number=issue.get("number", 0),
            issue_title=issue.get("title", ""),
            issue_body=issue.get("body", "") or "",
            trigger_label=label_name,
            sender_login=sender,
        )

    if event == "issue_comment" and action == "created":
        comment_obj = payload.get("comment") or {}
        comment = comment_obj.get("body", "") or ""
        if SLASH_TRIGGER not in comment.lower():
            return None
        # Authorization: only repo-privileged commenters may trigger a run.
        # Without this, any public user can comment "/maverick" and spend
        # the operator's budget on a clone + swarm run.
        association = (comment_obj.get("author_association") or "").upper()
        if association not in _PRIVILEGED_ASSOCIATIONS:
            log.warning(
                "ignoring /maverick from unauthorized commenter %s "
                "(author_association=%s)", sender, association or "NONE",
            )
            return None
        return WebhookPayload(
            event=event, action=action,
            repo_full_name=repo,
            issue_number=issue.get("number", 0),
            issue_title=issue.get("title", ""),
            issue_body=issue.get("body", "") or "",
            comment_body=comment,
            sender_login=sender,
        )

    return None


def _trigger_labels() -> set[str]:
    """Issue labels that start a run: ``MAVERICK_GH_TRIGGER_LABELS`` (comma
    separated) wins, else ``[github] trigger_labels`` (the All settings page),
    else :data:`DEFAULT_LABELS`."""
    raw = os.environ.get("MAVERICK_GH_TRIGGER_LABELS", "")
    if raw:
        return {x.strip().lower() for x in raw.split(",") if x.strip()}
    try:
        from .config import load_config
        labels = ((load_config() or {}).get("github") or {}).get("trigger_labels")
    except Exception:  # pragma: no cover - config never blocks a webhook
        labels = None
    if isinstance(labels, list):
        chosen = {x.strip().lower() for x in labels if isinstance(x, str) and x.strip()}
        if chosen:
            return chosen
    return set(DEFAULT_LABELS)


def build_brief(payload: WebhookPayload) -> str:
    """Render the issue into a Lightwork goal brief."""
    return (
        f"GitHub issue: {payload.repo_full_name}#{payload.issue_number}\n"
        f"Title: {payload.issue_title}\n\n"
        f"Issue body:\n{payload.issue_body}\n\n"
        "Implement a minimal fix or feature satisfying the issue. "
        "Stage and commit your work; the harness will push and open a PR."
    )


def slugify(title: str, max_len: int = 40) -> str:
    """Issue title -> kebab-case branch slug."""
    s = title.lower()
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return s[:max_len] or "issue"


@dataclass
class PRResult:
    branch_name: str
    pr_url: str | None
    workdir: Path
    summary: str   # agent's FINAL output
    error: str | None = None


@contextlib.contextmanager
def _git_token_env(token: str | None) -> Iterator[dict]:
    """Yield an env that feeds ``token`` to git via ``GIT_ASKPASS``.

    Embedding the token in the clone URL (``https://x-access-token:TOKEN@``)
    leaked it three ways: into ``ps``/argv, into the cloned repo's persisted
    ``origin`` URL on disk, and into ``CalledProcessError`` messages on a
    failed clone (which we surface in ``PRResult.error``). Routing it through
    an ephemeral askpass helper keeps the token out of all three -- the URL
    carries only the ``x-access-token`` username, git asks the helper for the
    password, and the helper file is removed on exit.
    """
    if not token:
        yield dict(os.environ)
        return
    fd, path = tempfile.mkstemp(prefix="mvk-gh-askpass-", suffix=".sh")
    try:
        with os.fdopen(fd, "w") as f:
            f.write('#!/bin/sh\nexec printf "%s" "$MAVERICK_GH_TOKEN"\n')
        os.chmod(path, 0o700)
        yield {
            **os.environ,
            "GIT_ASKPASS": path,
            "GIT_TERMINAL_PROMPT": "0",
            "MAVERICK_GH_TOKEN": token,
        }
    finally:
        with contextlib.suppress(OSError):
            os.unlink(path)


def clone_repo(repo_full_name: str, token: str, dest: Path) -> Path:
    """Shallow-clone `owner/repo` to `dest`. Requires `git` on PATH.

    The token is supplied via ``GIT_ASKPASS`` (see ``_git_token_env``) so it
    never lands in argv, the persisted remote URL, or error output.
    """
    url = f"https://x-access-token@github.com/{repo_full_name}.git"
    with _git_token_env(token) as env:
        subprocess.run(
            ["git", "clone", "--depth", "10", url, str(dest)],
            check=True, capture_output=True, timeout=120, env=env,
        )
    return dest


def create_pr_via_gh(
    workdir: Path,
    branch_name: str,
    issue_number: int,
    pr_title: str,
    pr_body: str,
    *,
    draft: bool = True,
) -> str | None:
    """Refuse publication from an agent-controlled Git checkout."""
    # Keep the public call signature for existing integrations while this
    # unsafe publication path is disabled.
    _ = (workdir, branch_name, issue_number, pr_title, pr_body, draft)
    raise RuntimeError("GitHub issue automation is unavailable until checkout isolation is implemented")


async def process_issue(
    payload: WebhookPayload,
    *,
    token: str | None = None,
    max_dollars: float | None = None,
    max_wall_seconds: float | None = None,
    draft: bool = True,
) -> PRResult:
    """Fail closed before cloning or running an agent in an unsafe checkout."""
    return PRResult(
        branch_name="", pr_url=None, workdir=Path(), summary="",
        error="GitHub issue automation is unavailable until checkout isolation is implemented",
    )
