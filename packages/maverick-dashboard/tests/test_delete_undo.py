"""Every delete in the dashboard has a way back.

A delete either waits for the shared Undo toast (``window.mvUndo``: the item
leaves the page at once and the request is sent when the Undo time is up), or
it is listed below with why it cannot wait, and then it is confirmed by name
and consequence first. A privacy erasure is never held back for an undo
window. A new DELETE call that is neither fails this test.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "maverick_dashboard"
DELETE = re.compile(r"""method:\s*['"]DELETE['"]|[(,?]\s*["']DELETE["']\s*[,):]""")
UNDO_WINDOW = 25  # lines before the DELETE in which its mvUndo call starts
CONFIRMED = re.compile(r"mvConfirm\(|R\.confirm\(|\bask\(|ec-clear-confirm|ec-clear-yes|lightworkConnectionImpact\.review\(|Confirm removal")

PRIVACY = "privacy erasure: sent at once after a confirmation that names it"
NAMED = "confirmed by name and consequence: must take effect at once"
NOT_A_REMOVAL = "not a removal: lifts the emergency stop"
RESTORE = "restorable on the server: the page offers Restore afterwards"

# (file, distinctive text on the DELETE line) -> why it does not wait for Undo.
EXCEPTIONS = {
    ("templates/ekko.html", "/api/v1/ekko/data"): PRIVACY,
    ("templates/ekko.html", "/api/v1/ekko/device"): PRIVACY,
    ("templates/voice_unlock.html", "/profile"): PRIVACY,
    ("static/lightwork-employee-companion.js", '"/history"'): PRIVACY,
    # A schedule due within a minute could run during the undo window.
    ("templates/workflow_builder.html", "var resp = await fetch(url, { method: 'DELETE' })"): NAMED,
    # Disconnecting an account or clearing a role is often done to cut access now.
    ("templates/automations.html", "/api/v1/oauth/"): NAMED,
    ("static/lightwork-workspace-members.js", 'method:"DELETE"'): NAMED,
    # Resetting a role's permissions, and removing a connection after its
    # impact review, change access for running work at once.
    ("templates/roles.html", "/override"): NAMED,
    ("static/lightwork-connections.js", "action === 'remove' ? 'DELETE'"): NAMED,
    # A saved task view is removed after an inline review that names it.
    ("static/lightwork-task-views.js", "item.deleting ? 'DELETE'"): NAMED,
    # A reviewed deletion with a preview of every effect, and a permanent delete
    # offered beside a reversible Archive.
    ("static/lightwork-flow-retirement.js", "url + '?' + params"): NAMED,
    ("static/lightwork-third-party-contracts.js", "encodeURIComponent(r.record_id)"): NAMED,
    ("static/lightwork-tenants.js", "'Remove workspace', 'remove the workspace', 'DELETE'"): RESTORE,
    ("static/lightwork-ui.js", "requestOptions = {method: 'DELETE'}"): NOT_A_REMOVAL,
    ("templates/oversight.html", "haltCall('DELETE'"): NOT_A_REMOVAL,
    ("static/lightwork-agent-control-plane.js", ': { method: "DELETE" }'): NOT_A_REMOVAL,
}


def _sites():
    files = sorted(ROOT.glob("templates/*.html")) + sorted(ROOT.glob("templates/*.js")) + sorted(ROOT.glob("static/*.js"))
    for path in files:
        if "swagger" in path.name:
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        for number, line in enumerate(lines):
            if DELETE.search(line):
                yield path.relative_to(ROOT).as_posix(), number, line, lines


def test_every_delete_waits_for_undo_or_says_why_not():
    unexplained, used = [], set()
    for name, number, line, lines in _sites():
        before = "\n".join(lines[max(0, number - UNDO_WINDOW):number + 1])
        if "mvUndo(" in before:
            continue
        key = next((key for key in EXCEPTIONS if key[0] == name and key[1] in line), None)
        if key is None:
            unexplained.append(f"{name}:{number + 1}: {line.strip()[:120]}")
            continue
        used.add(key)
        if EXCEPTIONS[key] == RESTORE:
            assert "/restore" in "\n".join(lines), f"{name} must offer the restore it is listed for"
        if EXCEPTIONS[key] in (PRIVACY, NAMED):
            context = "\n".join(lines[max(0, number - 40):number + 1])
            assert CONFIRMED.search(context), f"{name}:{number + 1} must be confirmed by name first"
    assert unexplained == [], "Wrap the delete in window.mvUndo, or list why it cannot wait:\n" + "\n".join(unexplained)
    assert set(EXCEPTIONS) - used == set(), "A listed delete is gone; drop it from EXCEPTIONS"


def test_the_converted_deletes_use_undo():
    """The deletes the 6 October re-score found without a way back, and one more."""
    converted = {
        "templates/trust.html": "/api/v1/trust/agents/",
        "templates/fleets.html": "/api/v1/fleets/",
        "templates/partner.html": "/api/v1/partner/tenants/",
        "templates/_external_agent_actions.html": "/api/v1/external-agents/",
        "templates/assessments.html": "/api/v1/assessments/",
        "templates/workflow_builder.html": "/api/v1/triggers/",
        "templates/flow_designer.js": "/api/v1/triggers/",
        "static/lightwork-facts.js": "method:'DELETE'",
        "static/lightwork-privacy-rights-form.js": "/properties/",
        "templates/_workspace_memory_catalog.html": "method: 'DELETE', keepalive",
        "templates/shoring.html": "/function/",
        "static/lightwork-immune-console.js": "/api/v1/immune/twin/",
        "templates/privacy_notice_governance.html": 'call("DELETE"',
    }
    for name, marker in converted.items():
        source = (ROOT / name).read_text(encoding="utf-8")
        index = source.find(marker, source.find("mvUndo("))
        assert "mvUndo(" in source and index != -1, name
