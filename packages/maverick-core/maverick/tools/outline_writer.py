"""Long-form writing pipeline tool.

A deterministic *structuring* helper for the outline -> draft -> polish pipeline.
It organizes text; it does not generate prose with a model. The caller supplies
the topic / outline, and this lays out the scaffolding so a downstream writer
(human or model) fills the prose in.

ops:
  - outline(topic[, sections])  — a numbered outline of section headings.
  - expand(outline[, words_per_section]) — a draft skeleton: each heading with a
    placeholder paragraph spec and a per-section target word count.
  - checklist() — a fixed polish checklist for the final pass.
"""
from __future__ import annotations

from typing import Any

from . import Tool

# Deterministic section roles cycled through to derive headings from a topic.
# Front-loaded with the canonical long-form arc; wraps for large section counts.
_SECTION_ROLES = [
    "Introduction",
    "Background",
    "Key Concepts",
    "Analysis",
    "Examples",
    "Challenges",
    "Best Practices",
    "Case Study",
    "Future Directions",
    "Conclusion",
]

# Upper bound on the model-supplied section count (mirrors synthetic_data's
# _MAX_ROWS): _outline is O(sections) in CPU and memory in-process, so an
# unbounded integer would stall the goal / exhaust kernel memory.
_MAX_SECTIONS = 100


def _clean_topic(topic: Any) -> str:
    if topic is None:
        return ""
    return " ".join(str(topic).split()).strip()


def _heading_for(role: str, topic: str) -> str:
    """Compose a deterministic heading from a section role and the topic."""
    if role == "Introduction":
        return f"Introduction to {topic}"
    if role == "Conclusion":
        return f"Conclusion: {topic}"
    return f"{role} of {topic}"


def _outline(topic: str, sections: int) -> str:
    lines = [f"Outline: {topic} ({sections} sections)"]
    for i in range(sections):
        role = _SECTION_ROLES[i % len(_SECTION_ROLES)]
        # Disambiguate wrapped roles so headings stay unique.
        if i >= len(_SECTION_ROLES):
            role = f"{role} (cont. {i // len(_SECTION_ROLES) + 1})"
        lines.append(f"{i + 1}. {_heading_for(role, topic)}")
    return "\n".join(lines)


def _expand(outline: list[Any], words_per_section: int) -> str:
    headings = [" ".join(str(h).split()).strip() for h in outline]
    headings = [h for h in headings if h]
    if not headings:
        return "ERROR: outline must contain at least one non-empty heading"
    total = words_per_section * len(headings)
    lines = [
        f"Draft skeleton: {len(headings)} section(s), "
        f"~{words_per_section} words/section, ~{total} words total"
    ]
    for i, h in enumerate(headings, 1):
        lines.append(f"## {i}. {h}")
        lines.append(
            f"[paragraph: state the main point of '{h}', support with 2-3 "
            f"details, then transition to the next section]"
        )
        lines.append(f"target_words: {words_per_section}")
    return "\n".join(lines)


def _checklist() -> str:
    items = [
        "Thesis is stated clearly in the introduction",
        "Each section has one main point and supports it",
        "Transitions connect adjacent sections",
        "Claims are backed by specific evidence or examples",
        "Terminology is consistent throughout",
        "No unsupported superlatives or filler",
        "Conclusion restates the thesis and synthesizes (no new claims)",
        "Spelling, grammar, and punctuation pass a final read",
    ]
    lines = ["Polish checklist:"]
    lines.extend(f"[ ] {it}" for it in items)
    return "\n".join(lines)


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if op == "outline":
        topic = _clean_topic(args.get("topic"))
        if not topic:
            return "ERROR: topic is required for op=outline"
        try:
            sections = int(args.get("sections", 5))
        except (TypeError, ValueError):
            return "ERROR: sections must be an integer"
        if sections < 1 or sections > _MAX_SECTIONS:
            return f"ERROR: sections must be 1..{_MAX_SECTIONS}"
        return _outline(topic, sections)
    if op == "expand":
        outline = args.get("outline")
        if not isinstance(outline, list):
            return "ERROR: outline (array of headings) is required for op=expand"
        try:
            wps = int(args.get("words_per_section", 150))
        except (TypeError, ValueError):
            return "ERROR: words_per_section must be an integer"
        if wps < 1:
            return "ERROR: words_per_section must be >= 1"
        return _expand(outline, wps)
    if op == "checklist":
        return _checklist()
    return f"ERROR: unknown op {op!r} (expected outline|expand|checklist)"


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["outline", "expand", "checklist"]},
        "topic": {"type": "string", "description": "subject for op=outline"},
        "sections": {
            "type": "integer",
            "description": f"section count (default 5, max {_MAX_SECTIONS})",
        },
        "outline": {
            "type": "array",
            "items": {"type": "string"},
            "description": "headings for op=expand",
        },
        "words_per_section": {
            "type": "integer",
            "description": "target words per section for op=expand (default 150)",
        },
    },
    "required": ["op"],
}


def outline_writer() -> Tool:
    return Tool(
        name="outline_writer",
        description=(
            "Long-form writing pipeline (outline->draft->polish), a deterministic "
            "text-structuring helper (no model). op=outline with 'topic' "
            "[+'sections', default 5] -> a numbered outline. op=expand with "
            "'outline' (list of headings) [+'words_per_section', default 150] -> a "
            "draft skeleton with a paragraph spec and target word count per "
            "section. op=checklist -> a final polish checklist."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
