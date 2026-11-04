"""Plain-language choices and result wording for the /simulate page.

The page offers selectors filled from the real action lists the safety gate
classifies (browser, desktop) and the built-in tool risk table, so a person
never has to type an action name. The decision logic stays in
``control_plane.simulate_action``; this module only words its answer.
"""
from __future__ import annotations

from .identity_format import humanize

SURFACES = (
    ("browser", "In a web browser"),
    ("computer", "On a desktop computer"),
    ("tool", "Using a tool"),
)

_BROWSER_ACTIONS = (
    ("navigate", "Open a web address"), ("click", "Click something"),
    ("type", "Type text"), ("fill_form", "Fill in a form"), ("press", "Press a key"),
    ("scroll", "Scroll the page"), ("go_back", "Go back"), ("go_forward", "Go forward"),
    ("save_session", "Save the signed-in session"), ("close", "Close the browser"),
    ("extract_text", "Read the page text"), ("screenshot", "Take a screenshot"),
    ("list_links", "List the links on the page"),
)
_COMPUTER_ACTIONS = (
    ("left_click", "Click"), ("double_click", "Double-click"), ("right_click", "Right-click"),
    ("middle_click", "Middle-click"), ("left_click_drag", "Drag"), ("type", "Type text"),
    ("key", "Press a key or shortcut"), ("mouse_move", "Move the mouse"), ("scroll", "Scroll"),
    ("screenshot", "Take a screenshot"), ("cursor_position", "Check where the mouse is"),
)

_TOOL_NAMES = {
    "shell": "Run commands on the server", "repl_exec": "Run code", "code_exec": "Run code",
    "computer": "Control a desktop", "browser": "Control a web browser",
    "write_file": "Write a file", "apply_patch": "Change files", "read_file": "Read a file",
    "research": "Research the web", "web_search": "Search the web", "memory": "Change saved memory",
    "clipboard": "Use the clipboard", "http": "Call another website",
}

DECISIONS = {
    "DENY": ("Blocked", "danger"),
    "REQUIRES APPROVAL": ("Needs a person's approval", "warn"),
    "allow (logged)": ("Allowed and recorded", "ok"),
    "not gated": ("Allowed", "ok"),
    "exposed": ("Available to agents", "ok"),
    "unknown tool": ("Unknown tool", "idle"),
}

SAFETY_SETTINGS = {
    "auto-deny": "Block risky actions automatically",
    "ask": "Ask a person before risky actions",
    "dashboard": "Ask a person in the dashboard before risky actions",
    "auto-approve": "Allow risky actions and record them",
}

RISKS = {"high": "High", "medium": "Medium", "low": "Low", "n/a": "Not risky"}


def tool_choices() -> list[tuple[str, str]]:
    try:
        from maverick.safety.tool_risk import _DEFAULT_RISK
    except Exception:  # safety table unavailable: offer nothing rather than guess
        return []
    names = sorted(set(_DEFAULT_RISK))
    return [(name, _TOOL_NAMES.get(name) or humanize(name)) for name in names]


def action_groups() -> list[dict]:
    return [
        {"surface": "browser", "label": "In a web browser", "actions": list(_BROWSER_ACTIONS)},
        {"surface": "computer", "label": "On a desktop computer", "actions": list(_COMPUTER_ACTIONS)},
        {"surface": "tool", "label": "Using a tool", "actions": tool_choices()},
    ]


def action_label(surface: str, action: str) -> str:
    for group in action_groups():
        if group["surface"] == surface:
            for value, label in group["actions"]:
                if value == action:
                    return label
    return humanize(action)


def explain(result: dict | None) -> dict | None:
    """Plain wording for a simulate_action() answer; None when there is none."""
    if not result:
        return None
    if result.get("error"):
        return {"error": "Choose where the action happens from the list and try again."}
    decision = str(result.get("decision") or "")
    label, badge = DECISIONS.get(decision, (humanize(decision), "idle"))
    mode = str(result.get("consent_mode") or "")
    risk = str(result.get("risk") or "n/a")
    if decision == "not gated":
        why = "This action only looks at things, so it is always allowed."
    elif decision == "DENY":
        why = "Your safety setting blocks risky actions automatically."
    elif decision == "REQUIRES APPROVAL":
        why = "Your safety setting sends risky actions to a person for approval first."
    elif decision == "allow (logged)":
        why = "Your safety setting allows risky actions but records each one."
    elif decision == "unknown tool":
        why = "Lightwork has no risk rating for this tool."
    else:
        why = ("Agents can use this tool. A workspace that only allows lower-risk tools "
               "hides it from agents.")
    return {
        "decision": label, "badge": badge, "why": why,
        "risk": RISKS.get(risk, humanize(risk)),
        "setting": SAFETY_SETTINGS.get(mode, humanize(mode)),
        "surface": dict(SURFACES).get(str(result.get("surface") or ""), ""),
        "action": action_label(str(result.get("surface") or ""), str(result.get("action") or "")),
        "target": result.get("target") or "",
    }
