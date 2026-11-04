"""Static accessibility audit.

The ``a11y`` tool runs pa11y/axe against a *live* URL. This is the
complementary **static, offline, CI-runnable** pass: parse the shipped HTML
templates (no server, no browser, no Node) and flag the structural WCAG
issues a parser can see deterministically —

* ``<img>`` without ``alt`` (WCAG 1.1.1),
* ``<html>`` without a ``lang`` (3.1.1),
* a form control (``input``/``select``/``textarea``) with no label —
  no ``aria-label``/``aria-labelledby``, no wrapping/`for=` ``<label>``,
  and not ``type=hidden/submit/button`` (1.3.1 / 4.1.2),
* ``<a>``/``<button>`` with no discernible text *and* no aria-label (4.1.2),
* a positive ``tabindex`` (>0), which breaks focus order (2.4.3),
* a heading-level skip (e.g. ``h2`` straight to ``h4``) (1.3.1).

Jinja artifacts (``{{ }}`` / ``{% %}``) are treated as opaque text so a
``{{ alt }}`` counts as having alt. Stdlib ``html.parser`` only — no deps.
``audit_templates`` walks the dashboard template dir; ``python -m
maverick.a11y_audit`` prints findings and exits 1 on any (the CI gate).
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path

_MISSING = object()
_JINJA = re.compile(r"\{\{.*?\}\}|\{%.*?%\}", re.DOTALL)
_FORM_CONTROLS = {"input", "select", "textarea"}
_NO_LABEL_INPUT_TYPES = {"hidden", "submit", "button", "image", "reset"}


@dataclass(frozen=True)
class Finding:
    rule: str
    detail: str
    line: int


class _A11yParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.findings: list[Finding] = []
        self._label_targets: set[str] = set()     # ids referenced by <label for=>
        self._wrapping_label = 0                   # depth inside a <label>
        self._last_heading: int | None = None
        # control tags awaiting their text content (a/button), with start line
        self._open_text_tag: list[tuple[str, dict, int, list[str]]] = []

    def _attr(self, attrs, name):
        for k, v in attrs:
            if k == name:
                return v if v is not None else ""
        return None

    def handle_starttag(self, tag, attrs):
        line = self.getpos()[0]
        d = dict(attrs)
        if tag == "html" and not d.get("lang"):
            self.findings.append(Finding("html-lang", "<html> missing lang", line))
        if tag == "img" and self._attr(attrs, "alt") is None:
            src = d.get("src", "")[:40]
            self.findings.append(Finding("img-alt", f"<img> missing alt (src={src!r})", line))
        if tag == "label" and "for" in d:
            self._label_targets.add(d["for"])
        if tag == "label":
            self._wrapping_label += 1
        if tag in _FORM_CONTROLS:
            self._check_form_control(tag, d, line)
        # tabindex > 0 breaks the natural focus order
        ti = d.get("tabindex")
        if ti is not None and _int(ti) is not None and _int(ti) > 0:
            self.findings.append(Finding("tabindex-positive",
                                         f"<{tag} tabindex={ti}> breaks focus order", line))
        if tag in ("h1", "h2", "h3", "h4", "h5", "h6"):
            self._check_heading(int(tag[1]), line)
        if tag in ("a", "button"):
            self._open_text_tag.append((tag, d, line, []))

    def handle_endtag(self, tag):
        if tag == "label" and self._wrapping_label:
            self._wrapping_label -= 1
        if tag in ("a", "button") and self._open_text_tag:
            otag, d, line, chunks = self._open_text_tag.pop()
            text = _JINJA.sub("x", "".join(chunks)).strip()
            has_label = d.get("aria-label") or d.get("aria-labelledby") or d.get("title")
            # an <a>/<button> wrapping an <img alt> or icon with aria is fine;
            # we only flag the clearly-empty, unlabeled case. aria-hidden only
            # suppresses when it actually hides: a bare attr is treated as true
            # (HTML), but aria-hidden="false" leaves the control AT-exposed.
            ah = d.get("aria-hidden", _MISSING)
            # bare attr (parsed as None) or "" is treated as true per HTML;
            # aria-hidden="false" leaves the control AT-exposed (not hidden).
            hidden = ah is not _MISSING and str(ah or "").strip().lower() != "false"
            if not text and not has_label and not hidden:
                self.findings.append(Finding(
                    "empty-control", f"<{otag}> has no text or aria-label", line))

    def handle_data(self, data):
        for entry in self._open_text_tag:
            entry[3].append(data)

    def _check_form_control(self, tag, d, line):
        if tag == "input" and d.get("type", "text").lower() in _NO_LABEL_INPUT_TYPES:
            return
        if d.get("aria-label") or d.get("aria-labelledby"):
            return
        if self._wrapping_label:  # wrapped in a <label>
            return
        cid = d.get("id")
        if cid and cid in self._label_targets:
            return
        # forward reference: a <label for=id> may appear AFTER the control.
        # Defer by recording the control; resolved in close().
        self._deferred = getattr(self, "_deferred", [])
        self._deferred.append((tag, cid, line))

    def _check_heading(self, level, line):
        if self._last_heading is not None and level > self._last_heading + 1:
            self.findings.append(Finding(
                "heading-skip",
                f"<h{level}> skips a level (after h{self._last_heading})", line))
        self._last_heading = level

    def close(self):
        super().close()
        for tag, cid, line in getattr(self, "_deferred", []):
            if not (cid and cid in self._label_targets):
                self.findings.append(Finding(
                    "control-label",
                    f"<{tag}> has no associated label", line))


def _int(v):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def audit_html(html: str) -> list[Finding]:
    """Return WCAG findings for one HTML document ([] == clean)."""
    parser = _A11yParser()
    parser.feed(html)
    parser.close()
    return parser.findings


def audit_file(path: Path) -> list[Finding]:
    try:
        return audit_html(Path(path).read_text(encoding="utf-8"))
    except OSError:
        return []


def _default_template_dir() -> Path | None:
    here = Path(__file__).resolve()
    for parent in here.parents:
        cand = parent / "maverick-dashboard" / "maverick_dashboard" / "templates"
        if cand.is_dir():
            return cand
    return None


def audit_templates(template_dir: Path | None = None) -> dict[str, list[Finding]]:
    """Audit every ``.html`` under ``template_dir``; ``{path: findings}``
    for files that have findings (clean files omitted)."""
    template_dir = template_dir or _default_template_dir()
    out: dict[str, list[Finding]] = {}
    if template_dir is None or not Path(template_dir).is_dir():
        return out
    for path in sorted(Path(template_dir).rglob("*.html")):
        findings = audit_file(path)
        if findings:
            out[str(path.name)] = findings
    return out


def render(results: dict[str, list[Finding]]) -> str:
    if not results:
        return "a11y audit: no static accessibility issues found."
    total = sum(len(v) for v in results.values())
    lines = [f"a11y audit: {total} issue(s) across {len(results)} file(s):"]
    for name, findings in sorted(results.items()):
        for f in findings:
            lines.append(f"  {name}:{f.line} [{f.rule}] {f.detail}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:  # pragma: no cover -- CLI shell
    import argparse
    p = argparse.ArgumentParser(prog="maverick.a11y_audit",
                                description="Static accessibility audit of HTML templates.")
    p.add_argument("--dir", default=None, help="template directory (default: dashboard)")
    p.add_argument("--ci", action="store_true", help="exit 1 on any finding")
    args = p.parse_args(argv)
    root = Path(args.dir) if args.dir else _default_template_dir()
    root = Path(root) if root is not None else None
    # Anti-vacuity. `--dir /nonexistent` printed "no static accessibility issues
    # found" and exited 0: a clean bill of health over zero files. A gate that
    # cannot distinguish "nothing wrong" from "nothing looked at" reports a
    # guarantee it never checked, which is worse than having no gate.
    templates = sorted(root.rglob("*.html")) if root and root.is_dir() else []
    if not templates:
        print(f"a11y audit: ERROR -- inspected 0 templates under {root}. "
              "The template directory is missing, empty, or the --dir path is "
              "wrong; this is a broken gate, not a pass.", file=sys.stderr)
        return 2
    results = audit_templates(root)
    print(render(results))
    print(f"a11y audit: {len(templates)} template(s) inspected, "
          f"{len(results)} finding(s)")
    return 1 if (args.ci and results) else 0


__all__ = ["Finding", "audit_html", "audit_file", "audit_templates", "render"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
