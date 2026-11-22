from __future__ import annotations

import re
from pathlib import Path

import pytest

TEMPLATES = (
    Path(__file__).resolve().parents[1] / "maverick_dashboard" / "templates"
)


@pytest.mark.parametrize(
    "template_name",
    (
        "assessment_evidence_autopopulation.html",
        "consent_application_scanner.html",
        "consent_custom_indexes.html",
        "consent_global_opt_out.html",
        "consent_publish_settings.html",
        "ekko.html",
        "governed_document_vault.html",
    ),
)
def test_extending_pages_leave_the_main_landmark_to_base(template_name: str) -> None:
    base = (TEMPLATES / "base.html").read_text(encoding="utf-8")
    source = (TEMPLATES / template_name).read_text(encoding="utf-8")

    assert base.count("<main") == 1
    assert base.count("</main>") == 1
    assert "{% extends \"base.html\" %}" in source
    assert "<main" not in source
    assert "</main>" not in source

    heading_levels = [int(level) for level in re.findall(r"<h([1-6])(?:\s|>)", source)]
    if "{% call hero(" in source or "{{ hero(" in source:
        # _hero.html renders the page title as the single H1.
        heading_levels.insert(0, 1)
    assert heading_levels.count(1) == 1
    assert set(heading_levels) == set(range(1, max(heading_levels) + 1))


@pytest.mark.parametrize(
    ("template_name", "labels"),
    (
        (
            "permissions.html",
            (
                'aria-label="Block the {{ t.name | humanize }} tool"',
                'aria-label="Allow the {{ t.name | humanize }} tool"',
                "btn.setAttribute('aria-label'",
            ),
        ),
        (
            "plugins.html",
            (
                'aria-label="Turn off {{ pname }}"',
                'aria-label="Turn on {{ pname }}"',
                'aria-label="Use default for {{ pname }}, your organization\'s setting"',
                'aria-label="Install plugin {{ plabel }}"',
            ),
        ),
        ("mcp.html", ('aria-label="Test server {{ label }}"', 'aria-label="Remove server {{ label }}"')),
        (
            "trust.html",
            (
                'aria-label="Unblock {{ label }}"',
                'aria-label="Block agent {{ label }}"',
                'aria-label="Remove {{ label }}"',
                'aria-label="Check access for {{ label }}"',
                'aria-label="Edit {{ label }}"',
            ),
        ),
        (
            "users.html",
            (
                'aria-label="Delete role {{ name | role_label }}"',
                'aria-label="Save role for {{ name_of(principal) }}"',
                'aria-label="Use standard role for {{ name_of(principal) }}"',
                'aria-label="Save departments for {{ name_of(principal) }}"',
                'aria-label="Use standard departments for {{ name_of(principal) }}"',
                'aria-label="Cancel invitation for {{ inv.email }}"',
            ),
        ),
        (
            "model_risk_assurance.html",
            (
                'aria-label="Review the {{ row.vendor }} assessment"',
                'aria-label="Attach to an AI system: {{ row.vendor }} review"',
            ),
        ),
        (
            "_workspace_worklist.html",
            (
                'aria-label="Assign the {{ s.subject }} assessment"',
                'aria-label="Review the {{ s.subject }} assessment"',
            ),
        ),
        (
            "workforce.html",
            (
                'aria-label="View team: {{ d.title }}"',
                'aria-label="Performance review: {{ d.title }}"',
                'aria-label="Set up team: {{ d.title }}"',
            ),
        ),
        (
            "agents.html",
            (
                'aria-label="Deploy team: \' + esc(d.title) + \'"',
                'aria-label="View \' + esc(d.title) + \' details"',
            ),
        ),
    ),
)
def test_repeated_actions_include_their_target(
    template_name: str,
    labels: tuple[str, ...],
) -> None:
    source = (TEMPLATES / template_name).read_text(encoding="utf-8")

    for label in labels:
        assert label in source


def test_spoken_names_contain_the_visible_words():
    """WCAG 2.5.3 (label in name): a voice-control user says what they see.

    When a button or link has both visible words and an ``aria-label``, the
    label contains those words in order: "Use template: Weekly update" for a
    "Use template" button, not "Use the Weekly update template".
    """
    tag = re.compile(r"""<(button|a)\b[^>]*?\baria-label="([^"]*)"[^>]*>([^<]*)</\1>""", re.DOTALL)

    def words(text: str) -> str:
        text = re.sub(r"\{\{.*?\}\}|\{%.*?%\}|'\s*\+.*?\+\s*'", " ", text)
        return " ".join(re.sub(r"[^\w\s]", " ", text.lower()).split())

    static = TEMPLATES.parent / "static"
    broken = []
    for source in sorted(TEMPLATES.rglob("*.html")) + sorted(static.glob("lightwork*.js")):
        text = source.read_text(encoding="utf-8", errors="ignore")
        for match in tag.finditer(text):
            label, visible = match.group(2), match.group(3)
            if not visible.strip() or any(mark in visible for mark in ("{{", "{%", "'")):
                continue
            if words(label) and words(visible) not in words(label):
                line = text[:match.start()].count("\n") + 1
                broken.append(f"{source.name}:{line}: shows {visible.strip()!r}, named {label!r}")
    assert not broken, "\n".join(broken)
