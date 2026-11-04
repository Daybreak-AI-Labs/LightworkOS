"""Shared UI helpers instead of page copies.

Pages each carried their own DOM builder, fetch wrapper and status-line
setter. Eight copies of the DOM builder took ``el(tag, text, cls)`` while
the shared ``mvEl`` and every other copy take ``(tag, cls, text)``, so a call
copied from one page to another silently put the text in the class. These
ratchets keep one argument order, and keep the shared fetch and status
helpers in lightwork-ui.js.
"""
from __future__ import annotations

import re
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1] / "maverick_dashboard"
_BUILDER = re.compile(r"function\s+el\s*\(\s*(\w+)\s*,\s*(\w+)\s*(?:,\s*(\w+)\s*)?\)")


def _scripts() -> list[Path]:
    return sorted([*PACKAGE.glob("static/*.js"), *PACKAGE.glob("templates/*.html"), *PACKAGE.glob("templates/*.js")])


def test_dom_builders_take_the_class_before_the_text() -> None:
    reversed_order = []
    for path in _scripts():
        text = path.read_text(encoding="utf-8")
        for match in _BUILDER.finditer(text):
            second, third = match.group(2), match.group(3) or ""
            if re.fullmatch(r"te?xt|label|content", second) and re.fullmatch(r"cls|className|klass|cl", third):
                line = text.count("\n", 0, match.start()) + 1
                reversed_order.append(f"{path.relative_to(PACKAGE)}:{line}")
    assert reversed_order == [], "Write el(tag, cls, text), the order mvEl uses: " + ", ".join(reversed_order)


def test_the_shared_fetch_and_status_helpers_exist() -> None:
    ui = (PACKAGE / "static" / "lightwork-ui.js").read_text(encoding="utf-8")
    assert "window.mvFetchJSON = async function (url, opts, action)" in ui
    assert "window.mvStatus = function (element, text, opts)" in ui


_DEFINITION = re.compile(
    r"(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{"
    r"|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\s*)?\([^)]*\)\s*(?:=>)?\s*\{"
)

# The local fetch-and-read wrappers still allowed, each because moving it onto
# mvFetchJSON would change what the page does:
_KEPT_WRAPPERS = {
    # Also runs on the recovery page, whose shell has no lightwork-ui.js.
    ("lightwork-provider-spending.js", "request"),
    # Checks the page's access token on both sides of the request and of the
    # body read, and hands the Response to observe(); a stale answer from a
    # previous sign-in is dropped between the two.
    ("lightwork-source-analysis.js", "json"),
    ("lightwork-workspace-members.js", "api"),
    # Settings recovery, taught-workflow releases, instruction records, the
    # privacy handoff and workflow action forms: each shows the server's own detail sentence as written, and its own
    # status-specific wording, where mvFetchJSON would put mvErrorText's
    # words. Kept as written until they are moved deliberately.
    ("lightwork-webhook-recovery.js", "request"),
    ("lightwork-local-flow-release.js", "request"),
    ("lightwork-instruction-capture.js", "request"),
    ("lightwork-dsar-handoff.js", "call"),
    ("flow_designer_action_fields.js", "task"),
    # Local AI runtime and retention maintenance: each shows the
    # server's own detail and checks the workspace context of the reply
    # before it counts, in the page's own words.
    ("lightwork-local-runtime.js", "call"),
    ("lightwork-retention-maintenance.js", "call"),
    # Answer feedback, questionnaires and notices: the answer panel checks that the answer it reviewed is still
    # the live one between the reply and its body, before any access
    # decision, and counts a 404 as lost access only while it is live. The
    # questionnaire builder and notice proposals pass the server's sentence
    # through mvPlainDetail and fall back to their own, and the builder
    # names a cancel by the page as a timeout. The other wrappers for these
    # pages go through mvFetchJSON's serverDetail, messages and
    # onContextChange options.
    ("lightwork-answer-panel.js", "request"),
    ("lightwork-compliance-questionnaire-builder.js", "call"),
    ("lightwork-privacy-notice-proposals.js", "call"),
    # Reviewed-decision pages (human conversations, Knowledge sources, the
    # learning cycle, specialist drafts, vendor profiles): each checks that the view it asked for is still current
    # between the reply and its body, clears private state on lost access
    # before reading any detail, and otherwise shows the server's own sentence
    # with its own wording for an unconfirmed reply, so a lost answer is read
    # from its original instead of being retried.
    ("lightwork-human-conversation-handoffs.js", "request"),
    ("lightwork-knowledge-sources.js", "request"),
    ("lightwork-learning-flywheel.js", "request"),
    ("lightwork-specialist-drafts.js", "fetchCurrent"),
    ("lightwork-specialist-drafts.js", "historyGet"),
    ("lightwork-specialist-drafts.js", "request"),
    ("lightwork-vendor-profile.js", "request"),
    # Loaded by both shells and tested on its own without lightwork-ui.js; it
    # tells a refusal from a blocked request in its own words.
    ("lightwork-pins.js", "change"),
    # The public website chat widget runs on customers' sites from one script
    # tag, where lightwork-ui.js and window.mvFetchJSON do not exist. Its
    # request is cross-origin with no cookies, and it reads the status and the
    # body to show its own words.
    ("lightwork-public-chat-widget.js", "post"),
}

# Status-line setters that still write the text themselves, each named with
# why it does not go through mvStatus:
_KEPT_SETTERS = {
    # Not a status line: rendered results, output blocks, badges or translated labels.
    ("lightwork-answer-panel.js", "say"),
    # Sets the translated words and their language on a button or status alike.
    ("lightwork-chat-code-actions.js", "say"),
    ("lightwork-guided-actions.js", "show"),
    ("lightwork-maintenance-ops.js", "show"),
    ("lightwork-notification-badge.js", "show"),
    ("lightwork-privacy-rights-consumer-delivery.js", "status"),
    ("audit.html", "show"),
    ("compliance_scope_actions.html", "show"),
    ("compliance_scoping.html", "show"),
    ("learning.html", "show"),
    ("privacy_notice_governance.html", "show"),
    ("privacy_rights_consumer_delivery.html", "show"),
    ("privacy_rights_orchestration.html", "show"),
    # The line is its own live region and turns into an alert for a failure;
    # mvStatus leaves a page's own live region alone, so failures would stop
    # being assertive.
    ("lightwork-consent-workbench.js", "say"),
    ("lightwork-consent-publish-settings.js", "say"),
    ("lightwork-plugins.js", "setStatus"),
    ("lightwork-vendor-onboarding.js", "show"),
    ("privacy_notice_governance.html", "say"),
    ("lightwork-company-signin-migration.js", "say"),
    # A note inside one settings row; the page announces through its own region.
    ("lightwork-settings-all.js", "say"),
    # Pages served without the dashboard shell (no lightwork-ui.js).
    ("lightwork-third-party-portal.js", "setStatus"),
    ("lightwork-workspace-recovery.js", "say"),
}


def _definitions():
    for path in _scripts():
        if path.name == "lightwork-ui.js":
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for match in _DEFINITION.finditer(text):
            start, depth = match.end() - 1, 0
            for end in range(start, len(text)):
                if text[end] == "{":
                    depth += 1
                elif text[end] == "}":
                    depth -= 1
                    if depth == 0:
                        break
            yield path.name, match.group(1) or match.group(2), text[start:end + 1]


def test_pages_read_json_through_mv_fetch_json() -> None:
    wrappers = {
        (name, function)
        for name, function, body in _definitions()
        if "fetch(" in body and ".json()" in body and len(body) < 1500
    }
    assert wrappers - _KEPT_WRAPPERS == set(), "Send the request through window.mvFetchJSON"
    assert _KEPT_WRAPPERS - wrappers == set(), "A kept wrapper is gone; drop it from _KEPT_WRAPPERS"


def test_status_lines_are_written_through_mv_status() -> None:
    setters = {
        (name, function)
        for name, function, body in _definitions()
        if function in {"say", "setStatus", "status", "show"}
        and "textContent" in body and "mvStatus" not in body and len(body) < 600
    }
    assert setters - _KEPT_SETTERS == set(), "Write the status line with window.mvStatus"
    assert _KEPT_SETTERS - setters == set(), "A kept setter is gone; drop it from _KEPT_SETTERS"
