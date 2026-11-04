"""Run-as-tutorial export: deterministic markdown from a run's events."""
from __future__ import annotations

import types

from maverick.tutorial_export import tutorial_markdown


def _goal(**kw):
    base = {"title": "Deploy the docs site", "description": "Ship mkdocs to the VPS",
            "status": "done", "result": "Live at docs.example.com"}
    base.update(kw)
    return types.SimpleNamespace(**base)


def _ev(kind, content, agent="coder"):
    return types.SimpleNamespace(kind=kind, content=content, agent=agent)


def test_full_tutorial_structure():
    events = [
        _ev("plan", "1. build the site 2. rsync to the VPS 3. verify TLS"),
        _ev("finding", "mkdocs build needs the material theme pinned"),
        _ev("observation", "Run this to verify:\n```curl -I https://docs.example.com```"),
        _ev("error", "first rsync failed: permission denied on /var/www"),
    ]
    md = tutorial_markdown(_goal(), events, now=0)
    assert md.startswith("# Tutorial: Deploy the docs site")
    assert "## What this accomplishes" in md and "Ship mkdocs" in md
    assert "## The approach" in md
    assert "1. build the site" in md and "3. verify TLS" in md  # enumerated
    assert "### Step 1 — finding (coder)" in md
    assert "```" in md and "curl -I" in md            # fenced code preserved
    assert "## Dead ends" in md and "permission denied" in md
    assert "## Outcome" in md and "Live at docs.example.com" in md
    assert "1970-01-01" in md                           # injected clock


def test_secrets_scrubbed():
    leaky = _goal(result="token is sk-ant-api03-abcdefghijklmnopqrstuvwxyz012345")
    md = tutorial_markdown(leaky, [])
    assert "sk-ant" not in md and "REDACTED" in md


def test_export_scrubs_shareable_secret_shapes():
    private_key = (
        "-----BEGIN PRIVATE KEY-----\n"  # pragma: allowlist secret
        "KEY-BODY-SHOULD-NOT-LEAK\n"
        "-----END PRIVATE KEY-----"
    )
    goal = _goal(
        title="Docs export https://example.test/file?sig=GOAL-SIG-SHOULD-NOT-LEAK",
        description='DB_PASSWORD="super secret password"',  # pragma: allowlist secret
        result="see https://example.test/callback?token=RESULT-TOKEN-SHOULD-NOT-LEAK",
    )
    events = [
        _ev("finding", f"download with ?token=EVENT-TOKEN-SHOULD-NOT-LEAK\n{private_key}"),
        _ev("error", "retry failed with ?sig=ERR-SIG-SHOULD-NOT-LEAK"),
    ]

    md = tutorial_markdown(goal, events, now=0)

    assert "GOAL-SIG-SHOULD-NOT-LEAK" not in md
    assert "super secret password" not in md
    assert "RESULT-TOKEN-SHOULD-NOT-LEAK" not in md
    assert "EVENT-TOKEN-SHOULD-NOT-LEAK" not in md
    assert "KEY-BODY-SHOULD-NOT-LEAK" not in md
    assert "-----END PRIVATE KEY-----" not in md
    assert "ERR-SIG-SHOULD-NOT-LEAK" not in md
    assert md.count("[REDACTED:") >= 5


def test_no_events_no_result():
    md = tutorial_markdown(_goal(result="", status="failed"), [])
    assert "_The run ended with status: failed._" in md
    assert "## Steps" not in md


def test_trace_meta_excluded_and_clamping():
    events = [_ev("trace_meta", '{"commit": "abc"}', agent="system"),
              _ev("finding", "x" * 2000)]
    md = tutorial_markdown(_goal(), events)
    assert '"commit"' not in md
    assert "…" in md  # clamped long step


def test_error_overflow_summarised():
    events = [_ev("error", f"error {i}") for i in range(8)]
    md = tutorial_markdown(_goal(), events)
    assert "…and 3 more recorded errors" in md


def test_deterministic():
    events = [_ev("finding", "stable")]
    assert tutorial_markdown(_goal(), events, now=0) == tutorial_markdown(_goal(), events, now=0)
