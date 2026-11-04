"""Ratchet: every confirmation names its action on its button.

No OK, Yes, Confirm, Continue or Submit on a confirming button, no "Yes, …"
prefix, and no ``mvConfirm`` call that falls back to the shared helper's
generic "Confirm". A dialog asks only what it will do, and its button says it.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "maverick_dashboard"
GENERIC = ("OK", "Ok", "Yes", "Confirm", "Continue", "Submit")
# The approval decision buttons are renamed with the approval-button work;
# nothing else may join this list.
YES_PREFIX_ALLOWED = {"templates/_approvals_queue.html"}


def _sources():
    for path in sorted([*ROOT.glob("static/*.js"), *ROOT.glob("templates/*.html"), *ROOT.glob("templates/*.js")]):
        if path.name == "lightwork-ui.js" or ".min." in path.name or path.name.startswith("swagger-ui"):
            continue
        yield path.relative_to(ROOT).as_posix(), path.read_text(encoding="utf-8", errors="ignore")


def _calls(text: str, name: str):
    for match in re.finditer(re.escape(name) + r"\s*\(", text):
        depth, end = 1, match.end()
        while end < len(text) and depth:
            depth += {"(": 1, ")": -1}.get(text[end], 0)
            end += 1
        yield text.count("\n", 0, match.start()) + 1, text[match.start():end]


def test_no_confirming_button_uses_a_generic_word():
    words = "|".join(GENERIC)
    pattern = re.compile(r"""okText\s*:\s*(?:[^,}]*\|\|\s*)?['"](""" + words + r""")['"]""")
    found = [(name, text.count("\n", 0, m.start()) + 1, m.group(0)) for name, text in _sources()
             for m in pattern.finditer(text)]
    assert found == []


def test_every_confirmation_dialog_names_its_action():
    missing = [(name, line) for name, text in _sources() for line, call in _calls(text, "mvConfirm")
               if "okText" not in call and not call.startswith("mvConfirm = ")]
    assert missing == []


def test_no_button_starts_with_yes():
    pattern = re.compile(r"<button[^>]*>\s*Yes,|okText\s*:\s*['\"]Yes,")
    found = sorted({name for name, text in _sources() if pattern.search(text)})
    assert set(found) <= YES_PREFIX_ALLOWED, found


def test_the_ratchet_sees_the_dialogs_it_checks():
    calls = sum(1 for _name, text in _sources() for _ in _calls(text, "mvConfirm"))
    assert calls > 200
