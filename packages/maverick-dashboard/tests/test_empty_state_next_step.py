"""Empty screens say why they are empty and what to do next.

The shared empty state (the ``empty_state`` macro, ``window.mvEmpty``) carries
a reason and a next step. This ratchet counts the empty-list messages still
written by hand ("No ... yet", "Nothing ...") that offer no next step, in the
templates and page scripts. The count may only go down: move a message to the
shared empty state with a plain next step, or add the next step to its words.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "maverick_dashboard"
# A hand-written empty-list message: a short sentence that says a list, panel
# or history has nothing in it yet.
EMPTY = re.compile(r"""(?:^|[>'"`(]\s*)((?:No|Nothing|None|There are no|You have no)\b[^<>'"`{}\n]{0,160}?\byet\b[^<>'"`{}\n]{0,160})""")
# Words that give the next step (or say exactly what makes the list fill).
NEXT = re.compile(r"\b(?:add|start|create|choose|use|open|run|connect|turn on|set up|set one|ask|scan|search|try|press|"
                  r"select|install|upload|invite|approve|review|save|record|import|link|enter|pick|describe|draft|"
                  r"build|write|come back|appear|appears|shows? up|will show|once|after|when|recalculate|check|"
                  r"enroll|prepare|decide|assign|schedule|send|test|update|refresh|collect|request|publish|"
                  r"generate|fill|load|go to|visit|finish|until|below|above|view|analyze)\b", re.IGNORECASE)
# Short values in a table cell, badge, select placeholder, summary field or
# flow-step chip: they describe one field of a row, not an empty screen, so a
# next step would not fit. (file, text) -> where it sits.
VALUES = {
    ("_governance_operations.html", "None yet"): "policy version cell",
    ("compliance.html", "Nothing to show yet"): "header status value next to its badge",
    ("compliance.html", "No owner yet"): "owner cell of an obligation row",
    ("consent_experiments.html", "No experiments yet"): "select placeholder",
    ("consumer_trust_center_authority.html", "Nothing yet"): "summary field",
    ("external_agent_detail.html", "No access key yet"): "badge",
    ("external_agents.html", "None yet"): "access key cell",
    ("learning.html", "No saved points yet"): "select placeholder",
    ("learning.html", "None yet"): "recent activity cell",
    ("model_risk_assurance.html", "None yet"): "frameworks summary field",
    ("security_report.html", "No evidence cited yet."): "evidence cell of a report row",
    ("shoring.html", "No data yet"): "service-level status word",
    ("tenants_overview.html", "No tasks yet"): "tasks cell of a workspace row",
    ("usability_survey.html", "None yet"): "median-time cell of a first-session row",
    ("users.html", "No description yet."): "role description field",
    ("lightwork-agent-control-plane.js", "No agents or people yet"): "select placeholder",
    ("lightwork-ai-entity-tasks.js", "No AI systems in inventory yet"): "select placeholder",
    ("lightwork-compliance-scope-actions.js", "None yet"): "task plan cell",
    ("lightwork-feature-actions.js", "None yet"): "departments summary field",
    ("lightwork-learning-loop.js", "No models yet"): "select placeholder",
    ("lightwork-maintenance-ops.js", "No baseline recorded yet"): "select placeholder",
    ("lightwork-ops-panels.js", "No days recorded yet"): "select placeholder",
    ("lightwork-privacy-rights-consumer-delivery.js", "None yet"): "delivery code cell",
    ("lightwork-third-party-intelligence.js", "None yet"): "latest data or decision cell",
    ("lightwork-trust-receipts.js", "No activity recorded yet"): "select placeholder",
    ("flow_designer_presentation.js", "No instructions yet"): "flow-step chip",
    ("flow_designer_presentation.js", "No action chosen yet"): "flow-step chip",
    ("flow_designer_presentation.js", "No question yet"): "flow-step chip",
}
# The most this may be. Lower it when you fix one; never raise it.
MAX_WITHOUT_NEXT_STEP = 0


def _messages():
    files = sorted(ROOT.glob("templates/*.html")) + sorted(ROOT.glob("static/*.js")) + sorted(ROOT.glob("templates/*.js"))
    for path in files:
        if "swagger" in path.name:
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        for number, line in enumerate(lines, 1):
            # Inside a shared empty state (its title, with the body and action
            # on the next lines), or a status badge's value: not hand-written.
            near = "\n".join(lines[max(0, number - 3):number])
            if "empty_state(" in near or "mvEmpty(" in near or "mv-empty" in near or "badge=" in line:
                continue
            # A select's placeholder option ("No ... yet" when it has no choices).
            if "<option" in line or "Option(" in line or re.search(r"""\?\s*["']Choose\b""", line):
                continue
            # An operation's status line ("Nothing has been done yet."), not a list.
            if 'role="status"' in line:
                continue
            for match in EMPTY.finditer(line):
                # The message, and the words after it on its line and the next:
                # a page's own empty helper passes the title, then a body.
                following = lines[number] if number < len(lines) else ""
                yield path.name, number, match.group(1).strip(), line[match.start():] + "\n" + following


def without_next_step() -> list[tuple[str, int, str]]:
    return [(name, number, text) for name, number, text, rest in _messages()
            if not NEXT.search(rest) and (name, text) not in VALUES]


def test_every_listed_value_is_still_there():
    found = {(name, text) for name, _number, text, _rest in _messages()}
    assert set(VALUES) - found == set(), "A listed value is gone; drop it from VALUES"


def test_hand_written_empty_messages_without_a_next_step_do_not_grow():
    found = without_next_step()
    listing = "\n".join(f"{name}:{number}: {text}" for name, number, text in found)
    assert len(found) <= MAX_WITHOUT_NEXT_STEP, (
        f"{len(found)} empty messages have no next step (at most {MAX_WITHOUT_NEXT_STEP}). "
        f"Use the empty_state macro or window.mvEmpty with a next step:\n{listing}")


def test_the_shared_empty_state_offers_a_next_step():
    macro = (ROOT / "templates" / "_empty_state.html").read_text(encoding="utf-8")
    assert "action_label" in macro and "action_href" in macro
