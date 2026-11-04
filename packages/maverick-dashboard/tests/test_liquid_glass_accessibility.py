"""Shared liquid-glass ownership and accessibility fallbacks.

Glass is opt-in (Display preferences > Glass effects, or the installation's
``[dashboard] glass``). Without it, panes, rows, controls and dialogs are solid
and only the top bar and sidebar blur what lies behind them: the blur on every
pane and control made the slowest interaction per page 58-89% slower.
"""
from __future__ import annotations

import re
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1] / "maverick_dashboard"
CSS = PACKAGE / "static" / "lightwork.css"
TEMPLATES = PACKAGE / "templates"

NAMED_SURFACES = {
    "finance_board.html": (".fb-kpi", ".fb-card"),
    "privacy_board.html": (".pb-kpi", ".pb-card"),
    "get_started.html": (".gs__step", ".gs__step--done"),
    "chat_goal.html": (
        ".msg--user .bubble",
        ".worklog",
        ".deliverable",
        ".signoff",
        ".artifact",
        ".ask",
        ".activity",
    ),
    "learning.html": (".lrn__row", ".lrn__moat"),
    "partner.html": (".pf-tile",),
    "run_tree.html": (".rt-node",),
}


def _rule(source: str, selector: str) -> str:
    match = re.search(
        rf"{re.escape(selector)}\s*\{{([^{{}}]*)\}}", source, re.DOTALL
    )
    assert match is not None, selector
    return match.group(1)


def test_named_page_surfaces_delegate_material_to_shared_css() -> None:
    """Page CSS owns layout/state; the shared stylesheet owns its material."""
    shared = CSS.read_text(encoding="utf-8")

    for filename, selectors in NAMED_SURFACES.items():
        template = (TEMPLATES / filename).read_text(encoding="utf-8")
        for selector in selectors:
            assert "background:" not in _rule(template, selector), (filename, selector)
            shared_selector = ".gs__step" if selector == ".gs__step--done" else selector
            assert shared_selector in shared, (filename, selector)

    # Base solid fallback, the solid default, opt-in glass, and the
    # reduced-transparency fallback for people who turn glass on.
    assert shared.count(".fb-kpi, .fb-card") == 4
    assert "var(--glass-sheen), var(--glass)" in shared
    assert "linear-gradient(var(--glass-tint, transparent)" in shared


def test_copilot_foregrounds_and_transparency_fallbacks_are_theme_safe() -> None:
    shared = CSS.read_text(encoding="utf-8")

    assert "color: var(--brand-fg)" in _rule(shared, ".mv-copilot__fab")
    assert "color: var(--brand-fg)" in _rule(shared, ".mv-copilot__msg--user")
    assert "body.theme-hicontrast .mv-copilot" in shared
    assert "@media (prefers-reduced-transparency: reduce)" in shared

    # Both accessibility paths explicitly disable both the standard and WebKit
    # filters on the panel and every Copilot sub-surface that can be translucent.
    copilot_fallback = shared[shared.index("body.theme-hicontrast .mv-copilot") :]
    assert copilot_fallback.count("-webkit-backdrop-filter: none") >= 2
    assert copilot_fallback.count("backdrop-filter: none") >= 2
    for selector in (
        ".mv-copilot__prompt",
        ".mv-copilot__msg--bot",
        ".mv-copilot__egress",
        ".mv-copilot__row .input",
    ):
        assert copilot_fallback.count(selector) >= 2, selector


def test_danger_actions_remain_semantic_not_glass_controls() -> None:
    shared = CSS.read_text(encoding="utf-8")

    assert ".btn:not(.btn--primary):not(.btn--danger)" in shared
    danger = _rule(shared, ".btn--danger")
    assert "background: var(--danger)" in danger
    assert "border-color: var(--danger)" in danger
    assert "color: var(--danger-fg)" in danger


def test_quiet_buttons_stay_quiet_after_the_glass_controls() -> None:
    """The material control rules (0,1,1 solid; 0,2,1 with Glass effects)
    beat ``.btn--ghost`` (0,1,0), so quiet buttons rendered exactly like
    default ones. A ghost rule of equal weight after all three control rules
    (solid, glass and reduced transparency) drops the fill, the blur and the
    edge highlight and keeps the border."""
    shared = CSS.read_text(encoding="utf-8")
    selector = "body:not(.theme-hicontrast) :where(.btn--ghost:not(.btn--primary):not(.btn--danger))"
    quiet = _rule(shared, selector)
    assert "background-color: transparent" in quiet
    assert "-webkit-backdrop-filter: none" in quiet and "backdrop-filter: none" in quiet
    assert "box-shadow: none" in quiet
    assert "border" not in quiet
    glass = [m.start() for m in re.finditer(r":where\(\s*\.btn:not\(\.btn--primary\):not\(\.btn--danger\)", shared)]
    assert len(glass) == 3
    assert shared.index(selector) > glass[-1]
    # With Glass effects on, the same quiet rule carries the glass weight too.
    ghost_rule = next(selectors for _, selectors, _ in _style_rules(shared) if selector in selectors)
    assert "body.glass-on:not(.theme-hicontrast) :where(.btn--ghost:not(.btn--primary):not(.btn--danger))" in ghost_rule

    hover = _rule(shared, ".btn--ghost:where(:not(.btn--primary, .btn--danger, :disabled)):hover")
    assert "background-color: color-mix(in srgb, var(--text) 8%, transparent)" in hover


# ---- Glass effects are opt-in ------------------------------------------------

def _split_selectors(prelude: str) -> list[str]:
    """Split a selector list on top-level commas (not inside :where()/:not())."""
    parts, depth, current = [], 0, ""
    for ch in prelude:
        depth += (ch == "(") - (ch == ")")
        if ch == "," and depth == 0:
            parts.append(" ".join(current.split()))
            current = ""
        else:
            current += ch
    parts.append(" ".join(current.split()))
    return [part for part in parts if part]


def _style_rules(css: str) -> list[tuple[tuple[str, ...], list[str], list[tuple[str, str]]]]:
    """Every style rule as (enclosing at-rule preludes, selectors, declarations)."""
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)
    rules, stack, start, i = [], [], 0, 0
    while i < len(css):
        ch = css[i]
        if ch == "{":
            prelude = " ".join(css[start:i].split())
            if prelude.startswith("@") and not prelude.startswith("@font-face"):
                stack.append(prelude)
                start = i + 1
            else:
                end = css.index("}", i)
                declarations = []
                for item in css[i + 1:end].split(";"):
                    if ":" in item:
                        prop, value = item.split(":", 1)
                        declarations.append((prop.strip(), " ".join(value.split())))
                rules.append((tuple(stack), _split_selectors(prelude), declarations))
                i, start = end, end + 1
        elif ch == "}":
            if stack:
                stack.pop()
            start = i + 1
        i += 1
    return rules


def _subject(selector: str) -> str:
    return selector.split()[-1]


REDUCED = "@media (prefers-reduced-transparency: reduce)"
SOLID = "body:not(.theme-hicontrast) "
GLASS = "body.glass-on:not(.theme-hicontrast) "


def test_blur_stays_on_the_top_bar_and_sidebar_unless_glass_effects_are_on() -> None:
    """No pane, row, control, dialog or full-screen backdrop blurs by default;
    a blurring rule either belongs to Glass effects or styles the top bar or
    the sidebar themselves."""
    blurring = 0
    for _context, selectors, declarations in _style_rules(CSS.read_text(encoding="utf-8")):
        for prop, value in declarations:
            if prop in ("backdrop-filter", "-webkit-backdrop-filter") and not value.startswith("none"):
                blurring += 1
                for selector in selectors:
                    assert ".glass-on" in selector or _subject(selector) in (".topbar", ".sidebar"), selector
            if prop.startswith("background") and re.search(r"\bfixed\b", value):
                assert all(".glass-on" in selector for selector in selectors), selectors
    assert blurring >= 10  # the glass rules are still there, behind the opt-in


def test_glass_effects_restore_the_full_glass_look() -> None:
    """Turning Glass effects on brings back every layer of the original look."""
    rules = _style_rules(CSS.read_text(encoding="utf-8"))

    def declared(selector: str, prop: str, *, reduced: bool = False) -> str:
        for context, selectors, declarations in rules:
            if selector in selectors and (REDUCED in context) == reduced:
                for name, value in declarations:
                    if name == prop:
                        return value
        raise AssertionError((selector, prop))

    assert declared(GLASS + ".panel", "backdrop-filter") == "blur(20px) saturate(160%)"
    assert declared(GLASS + ".panel", "background") == "var(--glass-sheen), var(--glass)"
    assert declared(GLASS.strip(), "background-attachment") == "fixed"
    assert declared(GLASS.strip(), "--surface-1") == "color-mix(in srgb, var(--panel) 76%, transparent)"
    assert declared(GLASS + ".navfinder", "backdrop-filter") == "blur(28px) saturate(170%)"
    assert declared(GLASS + ".navfinder::backdrop", "backdrop-filter") == "blur(3px)"
    assert declared(GLASS + ".mv-copilot", "backdrop-filter") == "blur(24px) saturate(175%)"
    controls = next(s for _, sels, _ in rules for s in sels
                    if s.startswith(GLASS + ":where( .btn:not(.btn--primary)"))
    assert declared(controls, "backdrop-filter") == "blur(12px) saturate(150%)"
    # Reduced transparency still wins over the opt-in, backdrop included.
    assert declared(GLASS + ".panel", "backdrop-filter", reduced=True) == "none"
    assert declared(GLASS + ".navfinder::backdrop", "backdrop-filter", reduced=True) == "none"
    # The top bar and sidebar keep their glass for everyone.
    assert declared(SOLID + ".topbar", "backdrop-filter") == "blur(20px) saturate(180%)"
    assert declared(SOLID + ".sidebar", "backdrop-filter") == "blur(20px) saturate(170%)"


def test_the_solid_default_reuses_the_reduced_transparency_material() -> None:
    """The solid look is the product's designed reduced-transparency surface,
    not an ad hoc one: each solid rule declares exactly what the reduced
    fallback declares for the same components (apart from removing blur)."""
    rules = _style_rules(CSS.read_text(encoding="utf-8"))
    supports = [(c, s, d) for c, s, d in rules if c and c[0].startswith("@supports")]

    def material(declarations):
        return sorted((p, v) for p, v in declarations if "backdrop-filter" not in p)

    solid = {tuple(sel[len(SOLID):] for sel in sels): material(d) for c, sels, d in supports
             if len(c) == 1 and all(sel.startswith(SOLID) for sel in sels)}
    # A fixed panel outside <main> (the Copilot) is solid in its own base rule.
    base = {tuple(sels): dict(d) for c, sels, d in rules if not c}
    compared = 0
    for context, selectors, declarations in supports:
        if REDUCED not in context or not all(sel.startswith(GLASS) for sel in selectors):
            continue
        key = tuple(sel[len(GLASS):] for sel in selectors)
        if any(part.endswith("::backdrop") for part in key) or key in (("",), ()):
            continue
        if key in solid:
            assert solid[key] == material(declarations), key
        else:
            assert key in base, key
            assert all(base[key].get(p) == v for p, v in material(declarations)), key
        compared += 1
    assert compared >= 6  # panes, dialogs, Copilot, governance cards, board surfaces, controls


def test_page_panes_lose_their_own_blur_without_glass_effects() -> None:
    """Pages that style their own glass panes (task rows, the Settings index,
    Agent Factory cards...) declare blur locally; one shared rule turns it off
    outside Glass effects, in high contrast and for reduced transparency."""
    rules = _style_rules(CSS.read_text(encoding="utf-8"))
    guards = [(c, s, dict(d)) for c, s, d in rules
              if any(sel.endswith(":not(.topbar, .sidebar)") for sel in s)]
    selectors = {sel for _, sels, _ in guards for sel in sels}
    assert "body:not(.glass-on) :not(.topbar, .sidebar)" in selectors
    assert "body.theme-hicontrast :not(.topbar, .sidebar)" in selectors
    assert any(REDUCED in c for c, _, _ in guards)
    for _context, _sels, declarations in guards:
        assert declarations["backdrop-filter"] == "none !important"
        assert declarations["-webkit-backdrop-filter"] == "none !important"
    goals = (TEMPLATES / "goals.html").read_text(encoding="utf-8")
    assert "backdrop-filter: blur(12px)" in goals  # the page-local pane the guard covers
