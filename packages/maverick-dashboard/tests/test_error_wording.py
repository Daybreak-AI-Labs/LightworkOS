"""Error messages say what happened and how to move on.

GOV.UK's error message rules: describe what happened, tell people how to fix
it, and leave out "please", "sorry", "oops" and "invalid". Four checks over
the dashboard's own copy (templates, browser scripts and the dashboard's
Python messages):

* every ``mvFail``/``mvErrorText`` call that names what the person was doing
  names it as a verb phrase ("save the policy"), because the shared helper
  turns it into "Could not save the policy." followed by the next step;
* no message says "Please try again", "sorry" or "oops";
* no sentence calls something "invalid";
* the supplier portal's reply checks, which show in logs and support views,
  read as plain sentences.
"""
from __future__ import annotations

import re
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1] / "maverick_dashboard"
_ACTION_CALL = re.compile(
    r"mv(?:Fail|ErrorText)\(\s*[^,()]*(?:\([^()]*\))?[^,()]*,\s*(['\"])((?:(?!\1).)*)\1\s*\)")
_LITERAL = re.compile(r"'((?:[^'\\\n]|\\.)*)'|\"((?:[^\"\\\n]|\\.)*)\"|`((?:[^`\\]|\\.)*)`")
_BANNED = re.compile(r"\bplease try again\b|\bsorry\b|\boops\b", re.IGNORECASE)

#: Sentences that call something "invalid". All were rewritten; keep it at 0.
MAX_INVALID_SENTENCES = 0


def _browser_copy() -> list[Path]:
    return sorted([*PACKAGE.glob("static/lightwork-*.js"), *PACKAGE.glob("templates/*.html"),
                   *PACKAGE.glob("templates/*.js")])


def _literals(path: Path):
    for match in _LITERAL.finditer(path.read_text(encoding="utf-8")):
        yield match.group(1) or match.group(2) or match.group(3) or ""


def test_failed_actions_are_named_as_what_the_person_was_doing():
    vague = []
    for path in _browser_copy():
        for match in _ACTION_CALL.finditer(path.read_text(encoding="utf-8")):
            action = match.group(2)
            if not re.fullmatch(r"[a-z][a-z' ,-]*[a-z]", action) or len(action.split()) < 2:
                vague.append(f"{path.name}: {action!r}")
    assert not vague, "Name the action as a verb phrase, like 'save the policy':\n" + "\n".join(vague)


def test_no_message_says_please_sorry_or_oops():
    found = []
    for path in [*_browser_copy(), *PACKAGE.glob("*.py")]:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if _BANNED.search(line):
                found.append(f"{path.name}:{number}: {line.strip()[:120]}")
    assert not found, "Say what happened and the next step instead:\n" + "\n".join(found)


def test_sentences_calling_things_invalid_only_go_down():
    found = [f"{path.name}: {text}" for path in _browser_copy() for text in _literals(path)
             if re.match(r"[A-Z]", text) and text.rstrip().endswith(".") and re.search(r"\binvalid\b", text, re.IGNORECASE)]
    assert len(found) <= MAX_INVALID_SENTENCES, "\n".join(found)


def test_supplier_portal_reply_checks_read_as_plain_sentences():
    source = (PACKAGE / "static/lightwork-third-party-portal.js").read_text(encoding="utf-8")
    messages = re.findall(r"(?:fail|PortalContractError)\((\"[^\"]*\"|`[^`]*`)\)", source)
    assert len(messages) > 30
    rough = [m for m in messages if not re.fullmatch(r"[\"`](?:The \$\{label\}|[A-Z]).*[.][\"`]", m)
             or re.search(r"\b(contract|bound|schema|manifest|invalid)\b", m)]
    assert rough == [], rough
