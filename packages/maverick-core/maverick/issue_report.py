"""Build a pre-filled GitHub "new issue" URL from a failed run.

Lets a user "claim as bug report": gather a goal's failed-turn context,
scrub secrets, and produce a ``github.com/<repo>/issues/new?title=&body=``
link they can open to file a report with the context already filled in.
No network calls -- it just builds a URL the user opens in a browser.
"""
from __future__ import annotations

from urllib.parse import quote

DEFAULT_REPO = "Daybreak-AI-Labs/LightworkOS"
# Keep the prefilled body well under GitHub's URL length limit so the link
# always opens; long error dumps are truncated.
_MAX_BODY_CHARS = 6000


def build_issue_url(
    repo: str, title: str, body: str, *, max_body: int = _MAX_BODY_CHARS,
) -> str:
    """Return a ``github.com/<repo>/issues/new`` prefill URL (title + body)."""
    if len(body) > max_body:
        body = body[:max_body] + "\n\n[... truncated]"
    return (
        f"https://github.com/{repo}/issues/new"
        f"?title={quote(title, safe='')}"
        f"&body={quote(body, safe='')}"
    )


def build_report_fields(
    goal, error_events, *, repo: str = DEFAULT_REPO, version: str | None = None,
    failure_cause: str | None = None,
) -> dict[str, str]:
    """Build the exact, bounded local draft before any external navigation.

    ``goal`` exposes ``.id`` / ``.title`` / ``.status``; ``error_events`` is a
    list of objects with ``.agent`` / ``.content``. ``failure_cause`` is
    explicit so the CLI URL does not silently gain the task's result. All
    free text is scrubbed of secrets before it leaves this builder.
    """
    from .secrets import scrub

    gtitle = scrub(str(getattr(goal, "title", "") or "")).strip()
    title = f"Agent run failed: {gtitle or 'goal'}"[:120]
    lines = [
        "_Reported from a stopped Lightwork task._",
        "",
        f"- Goal #{getattr(goal, 'id', '?')}: {gtitle}",
        f"- Status: {getattr(goal, 'status', '?')}",
    ]
    if version:
        lines.append(f"- Version: {scrub(str(version)).strip()[:80]}")
    lines += ["", "### Errors", ""]
    reason = ""
    if failure_cause:
        from .safety.secret_detector import redact

        try:
            reason, _ = redact(scrub(str(failure_cause)[:4000]))
            reason = " ".join(reason.split())[:800]
        except Exception:
            reason = "(The failure details could not be safely prepared.)"
        if reason:
            lines.append(f"- Recorded failure: {reason}")
    if error_events:
        for e in error_events:
            agent = scrub(str(getattr(e, "agent", "?") or "?"))
            content = scrub(str(getattr(e, "content", "") or ""))
            lines.append(
                f"<details><summary>{agent}</summary>\n\n```\n{content}\n```\n</details>"
            )
    elif not reason:
        lines.append("_(no error events recorded)_")
    lines += ["", "### What I expected", "", "<!-- describe the expected behaviour -->"]
    body = "\n".join(lines)
    if len(body) > _MAX_BODY_CHARS:
        suffix = "\n\n[Earlier report content exceeds this draft's size; review task history for more.]"
        body = body[:_MAX_BODY_CHARS - len(suffix)] + suffix
    return {"title": title, "body": body}


def build_report(
    goal, error_events, *, repo: str = DEFAULT_REPO, version: str | None = None,
) -> str:
    """Compatibility entry point for the explicitly requested CLI URL."""
    draft = build_report_fields(goal, error_events, repo=repo, version=version)
    return build_issue_url(repo, draft["title"], draft["body"])
