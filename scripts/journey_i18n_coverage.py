"""Report literal template copy still outside explicit translation bindings.

This is a conservative engineering inventory, not a linguistic qualification.
Dynamic labels, shared includes and JavaScript/API messages need separate review.
Run from the repository root; no dashboard startup or provider access is needed.
"""
from __future__ import annotations

import argparse
import ast
import json
import re
from html.parser import HTMLParser
from pathlib import Path

from jinja2 import Environment, nodes

ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "packages/maverick-dashboard/maverick_dashboard"
JOURNEYS = ("employee_activation.html", "preferences.html", "_display_preferences.html",
            "chat.html", "chat_goal.html", "_conversation_inbox_panel.html", "_chat_answer_panel.html", "project_reviews.html",
            "task_file_recovery.html", "workflow_builder.html")


class CopyParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.skipped = []
        self.rows = []

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "pre", "code", "textarea"}:
            self.skipped.append(tag)
        if self.skipped:
            return
        for name, value in attrs:
            if name in {"aria-label", "title", "placeholder"}:
                self.record(value or "", name)

    def handle_endtag(self, tag):
        if self.skipped and self.skipped[-1] == tag:
            self.skipped.pop()

    def handle_data(self, value):
        if not self.skipped:
            self.record(value, "text")

    def record(self, value, kind):
        value = " ".join(value.split())
        if re.search(r"[A-Za-z]{2}", value) and "__DYNAMIC__" not in value:
            self.rows.append({"line": self.getpos()[0], "kind": kind, "source": value})


def report():
    catalog = {}
    # Follow the catalog modules actually wired into ROWS. New journey copy may
    # have a feature-specific filename (for example flow credential migration).
    wiring = ast.parse((DASHBOARD / "i18n_journeys.py").read_text(encoding="utf-8"))
    modules = [node.module for node in wiring.body
               if isinstance(node, ast.ImportFrom) and node.level == 1 and node.module
               and any(alias.name == "ROWS" for alias in node.names)]
    for module in modules:
        path = DASHBOARD / (module + ".py")
        for node in ast.parse(path.read_text(encoding="utf-8")).body:
            if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "ROWS" for target in node.targets):
                catalog.update({row[0]: row[1:] for row in ast.literal_eval(node.value)})
    pages = {}
    for name in JOURNEYS:
        source = (DASHBOARD / "templates" / name).read_text(encoding="utf-8")
        # Newlines remain stable so each untranslated fragment has a source location.
        stripped = re.sub(r"\{(?:\{.*?\}|%.*?%|#.*?#)\}", lambda match: "__DYNAMIC__" + "\n" * match[0].count("\n"), source, flags=re.DOTALL)
        parser = CopyParser()
        parser.feed(stripped)
        tree = Environment().parse(source)
        bindings = [call.args[0].value for call in tree.find_all(nodes.Call)
                    if isinstance(call.node, nodes.Name) and call.node.name in {"ui", "ut"}
                    and call.args and isinstance(call.args[0], nodes.Const)
                    and isinstance(call.args[0].value, str)]
        missing = sorted({value for value in bindings if value not in catalog})
        pages[name] = {"literal_bindings": len(bindings), "remaining_literal_fragments": len(parser.rows),
                       "bound_sources_missing_catalog": missing,
                       "remaining": [{**row, "catalog_available": row["source"] in catalog} for row in parser.rows]}
    return {"catalog_sources": len(catalog), "draft_languages": ["fr", "de", "ja", "zh"],
            "qualified_complete_body_languages": ["en"], "arabic_seed_unchanged": True,
            "method": "Literal HTML text and label attributes outside script/style/pre/code/textarea and Jinja expressions, plus catalog availability for literal ui/ut arguments parsed from Jinja. Counts are occurrences, not unique strings. Dynamic labels, includes, browser/API copy, linguistic review and visual/assistive-technology review are not measured.",
            "pages": pages}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    value = report()
    rendered = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    if arguments.output:
        arguments.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered)
