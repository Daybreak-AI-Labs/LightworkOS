"""Destructive-op confirm gates must fail CLOSED on stringy values.

23 tools gated destructive ops with
`if not args.get("confirm"):`. Because `not "false"` is False in Python, a
`confirm: "false"` / `"0"` from a loose LLM or non-conforming MCP client
slipped the gate and fired the live delete/refund/send. All 23 now route
through `as_bool`, which only treats a real bool ``True`` as authorization.
"""
from __future__ import annotations

import pathlib

import pytest
from maverick.tools import as_bool

_TOOLS_DIR = pathlib.Path(__file__).resolve().parents[1] / "maverick" / "tools"

# The 23 tools (every file that gated on the unsafe form).
_FIXED_TOOLS = [
    "airtable_tool", "asana_tool", "calendly_tool", "clickup_tool",
    "cloudflare_tool", "confluence_tool", "dropbox_tool", "dynamodb_tool",
    "elasticsearch_tool", "gdrive_tool", "github_actions", "gmail_tool",
    "home_assistant_tool", "hubspot_tool", "mongodb_tool", "msgraph_tool",
    "replicate_tool", "ses_tool", "sns_tool", "spotify_tool", "trello_tool",
    "vercel_tool", "zoom_tool",
]


# ---- the shared gate's contract ----
@pytest.mark.parametrize("val,expected", [
    (True, True),
    (False, False),
    ("true", False),      # stringy true is NOT authorization (must be real bool)
    ("false", False),     # the bug: `not "false"` was False -> fired the op
    ("0", False),
    ("", False),
    (0, False), (1, False), (None, False),
])
def test_as_bool_only_true_authorizes(val, expected):
    assert as_bool(val) is expected


# ---- no tool retains the unsafe pattern; all gate via as_bool ----
@pytest.mark.parametrize("mod", _FIXED_TOOLS)
def test_tool_has_no_unsafe_confirm_gate(mod):
    src = (_TOOLS_DIR / f"{mod}.py").read_text(encoding="utf-8")
    assert 'if not args.get("confirm"):' not in src, (
        f"{mod} still has the fail-open confirm gate"
    )
    assert "as_bool(args.get(\"confirm\"))" in src, (
        f"{mod} does not gate confirm through as_bool"
    )


def test_no_tool_anywhere_uses_unsafe_confirm_gate():
    """Repo-wide guard: the fail-open pattern must not reappear in any tool."""
    offenders = [
        f.name for f in _TOOLS_DIR.glob("*.py")
        if 'if not args.get("confirm"):' in f.read_text(encoding="utf-8")
    ]
    assert offenders == [], f"fail-open confirm gate reintroduced in: {offenders}"


# ---- end-to-end on a dependency-free tool: stringy confirm -> dry run ----
def test_cloudflare_stringy_confirm_dry_runs(monkeypatch):
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "t")
    from maverick.tools.cloudflare_tool import cloudflare_tool
    out = cloudflare_tool().fn({
        "op": "dns_create", "zone_id": "z", "type": "A",
        "name": "x.example.com", "content": "1.2.3.4", "confirm": "false",
    })
    # Must NOT have fired the live create; must be the dry-run path.
    assert "DRY RUN" in out, out
