"""Main and destructive buttons say exactly what will happen.

Every ``btn--primary`` and ``btn--danger`` button or link in the dashboard
templates is labelled with a verb and what it acts on ("Save agent", "Delete
this workflow"), never a bare "Save" or "Delete". Labels written in Jinja are
checked branch by branch, and the quoted labels inside ``{{ ... }}`` are
checked too. A label that is only a variable is set by the page's own code
and is not read here.

The allowlist holds the labels another piece of work owns, each with why.
It may only shrink.
"""
from __future__ import annotations

import re
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1] / "maverick_dashboard"
_TAG = re.compile(
    r"<(button|a)\b([^>]*?\bclass=\"[^\"]*\bbtn--(?:primary|danger)\b[^\"]*\"[^>]*)>(.*?)</\1>", re.DOTALL)
_QUOTED = re.compile(r"'([^'{}]+)'|\"([^\"{}]+)\"")

#: Verbs a button label may start with.
VERBS = frozenset("""
accept add adopt allow analyze answer apply approve ask block build cancel capture change check choose
clean clear close collect compare confirm connect contact continue copy create deactivate delete deploy design
disconnect download draft edit enroll erase export find finish get go import install invite keep learn let
link look make manage mark move open pause pin place plant prepare preview print publish queue re-protect
record refresh reject reload remove rename request reset restart restore resume retire retry review revoke
run save schedule score search send set share show sign start stop submit suggest switch test try turn
undo unlink update upload use view withdraw work write
""".split())

#: (template, label): owned elsewhere, with the reason. May only shrink.
ALLOWED = {
    # Approval button names belong to the approvals work (stream X1).
    ("_chat_answer_panel.html", "Approve"),
    # The shared confirm and notice dialogs: page code sets the real label
    # ("Delete 3 agents", "Close report") each time the dialog opens.
    ("base.html", "Confirm"),
    ("base.html", "OK"),
    ("chat_base.html", "Confirm"),
    ("chat_base.html", "OK"),
    # "New task" is the product-wide name of the command (navigation,
    # Ctrl-K and the composer use the same words).
    ("_hero.html", "New task"),
    ("base.html", "New task"),
    ("goals.html", "New task"),
}


def _labels(inner: str) -> list[str]:
    """The visible labels one button can show (one per Jinja branch)."""
    inner = re.sub(r"\{#.*?#\}", "", inner, flags=re.DOTALL)
    labels = []
    for expression in re.findall(r"\{\{(.*?)\}\}", inner, flags=re.DOTALL):
        quoted = [a or b for a, b in _QUOTED.findall(expression)]
        labels += [q for q in quoted if q[:1].isupper()]
    text = re.sub(r"\{\{.*?\}\}", " X ", inner, flags=re.DOTALL)
    text = re.sub(r"<[^>]+>", " ", text)
    for branch in re.split(r"\{%.*?%\}", text, flags=re.DOTALL):
        branch = " ".join(branch.split())
        if branch and branch != "X" and re.search(r"[A-Za-z]{2}", branch):
            labels.append(branch)
    return labels


def _says_what_happens(label: str) -> bool:
    words = re.sub(r"^[^A-Za-z]+", "", label).removeprefix("Yes, ").replace(":", " ").split()
    return len(words) >= 2 and words[0].lower() in VERBS


def button_labels() -> list[tuple[str, int, str]]:
    found = []
    for path in sorted((PACKAGE / "templates").glob("*.html")):
        raw = path.read_text(encoding="utf-8")
        for match in _TAG.finditer(raw):
            line = raw.count("\n", 0, match.start()) + 1
            found += [(path.name, line, label) for label in _labels(match.group(3))]
    return found


def test_the_reader_splits_branches_and_reads_quoted_labels():
    assert _labels("{% if a %}Disconnect{% else %}Finish removal{% endif %}") == ["Disconnect", "Finish removal"]
    assert _labels("{{ 'Save agent' if x else 'Save specialist' }}") == ["Save agent", "Save specialist"]
    assert _labels("{{ action_label }}") == []
    assert _says_what_happens("Yes, cancel X invitations") and not _says_what_happens("Save")
    assert not _says_what_happens("New experiment")


def test_main_and_destructive_buttons_start_with_a_verb_and_name_what_they_act_on():
    labels = button_labels()
    assert len(labels) > 400  # the reader still finds the buttons
    bad = [(name, line, label) for name, line, label in labels
           if not _says_what_happens(label) and (name, label) not in ALLOWED]
    assert not bad, "Name the action and its object (for example 'Save agent'):\n" + "\n".join(
        f"{name}:{line} {label!r}" for name, line, label in bad)


def test_the_allowlist_only_names_labels_that_still_exist():
    present = {(name, label) for name, _line, label in button_labels()}
    assert present >= ALLOWED, sorted(ALLOWED - present)
