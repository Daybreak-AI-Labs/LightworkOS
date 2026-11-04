"""Focused regressions for the Flow authoring accessibility contracts."""

from __future__ import annotations

import re
from pathlib import Path

TEMPLATES = Path(__file__).parents[1] / "maverick_dashboard" / "templates"


def _source(name: str) -> str:
    return (TEMPLATES / name).read_text(encoding="utf-8")


def test_qa_064_flow_designer_keyboard_selection_movement_and_pan() -> None:
    source = _source("flow_designer.js")
    node_handler = source[
        source.index("gNodes.addEventListener('keydown'") :
        source.index("canvas.addEventListener('keydown'")
    ]
    canvas_handler = source[
        source.index("canvas.addEventListener('keydown'") :
        source.index("function deleteEdge")
    ]

    assert "evt.key === 'Enter' || evt.key === ' '" in node_handler
    assert "selectNode(id); return" in node_handler
    assert "var step = evt.shiftKey ? 48 : 16" in node_handler
    for key, movement in (
        ("ArrowLeft", "dx = -step"),
        ("ArrowRight", "dx = step"),
        ("ArrowUp", "dy = -step"),
        ("ArrowDown", "dy = step"),
    ):
        assert f"evt.key === '{key}'" in node_handler
        assert movement in node_handler
    assert "pushHistory(); selected = id; multiSel = {}" in node_handler
    assert "n.x += dx; n.y += dy" in node_handler

    for key, movement in (
        ("ArrowLeft", "view.x += 32"),
        ("ArrowRight", "view.x -= 32"),
        ("ArrowUp", "view.y += 32"),
        ("ArrowDown", "view.y -= 32"),
    ):
        assert f"evt.key === '{key}'" in canvas_handler
        assert movement in canvas_handler
    assert "if (handled) { evt.preventDefault(); render(); }" in canvas_handler


def test_qa_064_flow_designer_keyboard_delete_and_escape_are_context_safe() -> None:
    source = _source("flow_designer.js")
    keyboard = source[
        source.index("// keyboard: Delete removes") : source.index("buildExamples();")
    ]

    assert "var typing = tag === 'INPUT' || tag === 'TEXTAREA'" in keyboard
    assert "e.key === 'Escape' && !typing" in keyboard
    assert "selected = null; selectedEdge = null; multiSel = {}" in keyboard
    assert "e.key === 'Delete' || e.key === 'Backspace'" in keyboard
    assert "if (selectedEdge) { e.preventDefault(); deleteEdge(selectedEdge); }" in keyboard
    assert "Object.keys(multiSel).length" in keyboard
    assert "deleteSelection()" in keyboard
    assert "deleteNode(selected)" in keyboard


def test_qa_065_generated_property_condition_and_approval_controls_are_named() -> None:
    source = _source("flow_designer.js")
    generic_field = source[
        source.index("function field(label, inputEl)") :
        source.index("function input(val, oninput, ph)")
    ]
    condition = source[
        source.index("function conditionField(n, label)") :
        source.index("// ---- serialize / api ----")
    ]
    approval_start = source.index("if (n.kind === 'approval') {")
    approval = source[
        approval_start : source.index("if (n.kind === 'delay')", approval_start)
    ]

    assert "l.id = labelId" in generic_field
    assert "inputEl.setAttribute('aria-labelledby', labelId)" in generic_field
    assert "l.htmlFor = inputEl.id" in generic_field
    # Each question in each condition group names its own controls.
    assert "var name = label + ', group ' + (groupIndex + 1) + ', question ' + (questionIndex + 1);" in condition
    assert "match.setAttribute('aria-label', label + ': which questions must match')" in condition
    assert "keySel.setAttribute('aria-label', name + ': information to check')" in condition
    assert "opSel.setAttribute('aria-label', name + ': comparison')" in condition
    assert "kindSel.setAttribute('aria-label', name + ': value type')" in condition
    assert "valueInput.setAttribute('aria-label', name + ': value')" in condition
    assert "remove.setAttribute('aria-label', name + ': remove question')" in condition
    assert "lb.setAttribute('aria-label', 'Approver question ' + (fi + 1))" in approval
    assert "ci0.setAttribute('aria-label', 'Extra answer ' + (ci + 1))" in approval


def test_qa_066_workflow_picker_traps_escape_tab_and_restores_opener() -> None:
    source = _source("workflow_builder.html")
    picker = source[
        source.index("var pickerOpener = null") :
        source.index("// ---- shared draft action")
    ]
    close_picker = picker[
        picker.index("function closePicker()") :
        picker.index("function pickerFocusables()")
    ]

    assert "pickerOpener = document.activeElement" in picker
    assert "tpSearch.focus()" in picker
    assert "if (e.key === 'Escape') { e.preventDefault(); closePicker(); return; }" in picker
    assert "if (e.key !== 'Tab') return" in picker
    assert "document.activeElement === first" in picker
    assert "e.preventDefault(); last.focus()" in picker
    assert "document.activeElement === last" in picker
    assert "e.preventDefault(); first.focus()" in picker
    assert "pickerOpener && pickerOpener.isConnected" in close_picker
    assert "typeof pickerOpener.focus === 'function'" in close_picker
    assert "pickerOpener.focus()" in close_picker
    assert close_picker.index("pickerOpener.focus()") < close_picker.index(
        "pickerOpener = null"
    )


def _designer_css_rules() -> tuple[str, list[tuple[str, str]]]:
    """Leaf CSS rules of the designer's inline stylesheet as (selector, body)."""
    source = _source("flow_designer.html")
    style = source[source.index("<style>") : source.index("</style>")]
    style = re.sub(r"/\*.*?\*/", "", style, flags=re.DOTALL)
    rules = [(sel.strip(), body) for sel, body in re.findall(r"([^{}]+)\{([^{}]*)\}", style)]
    return style, rules


def test_qa_067_flow_designer_copilot_drawer_stays_inside_the_window() -> None:
    """The copilot drawer used to sit absolutely positioned inside the canvas
    wrap (overflow:hidden), where a fixed 320px width overflowed the wrap's
    start edge whenever the middle grid track was narrower than the drawer:
    the header read "...pilot" and messages were left-truncated. It is now one
    shared drawer fixed to the window, outside the view containers, so it must
    size to the window and still hug the end edge; the canvas track keeps its
    floor for the canvas itself."""
    style, rules = _designer_css_rules()
    source = _source("flow_designer.html")
    canvas_wrap = source[source.index('<div class="fd__canvas-wrap">'):source.index('id="fd-canvas"')]
    assert 'id="fd-chat"' not in canvas_wrap

    chat_rules = [body for sel, body in rules if sel == ".fd__chat"]
    assert chat_rules, "the .fd__chat drawer rule is missing"
    assert any("position: fixed" in body for body in chat_rules)
    assert any("width: min(25rem, calc(100vw - 2rem))" in body for body in chat_rules)
    for body in chat_rules:
        widths = re.findall(r"(?<![\w-])width:\s*([^;]+);", body)
        assert all("min(" in width for width in widths), widths
        # Logical insets: the drawer hugs the END edge, so RTL mirrors it.
        assert "right:" not in body and "left:" not in body
    assert any("inset-inline-end: 1rem" in body for body in chat_rules)
    for overlay in (".fd__crumbs", ".fd__minimap"):
        bodies = [body for sel, body in rules if sel == overlay]
        assert any("inset-inline-start: 8px" in body for body in bodies), overlay
        assert not any("left:" in body for body in bodies), overlay

    canvas_grid = [
        body
        for sel, body in rules
        if sel == '.fd[data-view="canvas"] .fdx-work' and "grid-template-columns" in body
    ]
    assert any("minmax(360px, 1fr)" in body for body in canvas_grid), canvas_grid

    # The stacked fallback must cover the whole band where three columns
    # cannot hold a 320px drawer (floor + palette + props + gaps + shell).
    breakpoints = [
        int(px) for px in re.findall(r"@media \(max-width: (\d+)px\)", style)
    ]
    assert max(breakpoints) >= 1200, breakpoints
    stacked = style[style.index(f"@media (max-width: {max(breakpoints)}px)") :]
    assert '.fd[data-view="canvas"] .fdx-work { grid-template-columns: 1fr;' in stacked
    # A bare auto grid row collapses the SVG to its 150px default height.
    assert '.fd[data-view="canvas"] .fd__canvas-wrap { height:' in stacked

