"""Export the dashboard's navigation as a tree for tree testing.

Tree testing (Treejack-style tools such as Optimal Workshop) asks people
where they would look for something in a bare text tree. This writes today's
tree ("classic") and the job-named tree ("areas") from the page registry, so
both studies test exactly what the product would show:

    python -m maverick_dashboard.nav_tree --export classic
    python -m maverick_dashboard.nav_tree --export areas --format csv --role operator
    python -m maverick_dashboard.nav_tree --export areas --answers docs/tree-test/tasks.csv

``--role`` keeps only the pages that role sees out of the box (the floors and
defaults, without this installation's Settings overrides); without it the
tree holds every customer-ready page. ``--answers`` prints, for each task in
a tasks CSV (columns role, id, task, answers), the tree node(s) that count as
a correct answer; ``answers`` holds registry paths separated by "|".

The classic tree lists every page under its sidebar group, including pages
folded out of the rail (as the page finder shows them). That is generous to
the classic design: in the product those pages are only reachable from
other pages' own links or by search.
"""
from __future__ import annotations

import argparse
import csv
import io
import sys

from . import ui_visibility as registry


def _visible(page: dict, role: str | None) -> bool:
    if not registry.customer_ready(page):
        return False
    if role is None or (page["path"], role) in registry.LOCKED:
        return True
    return registry.eligible(page, role) and registry.default_visible(page, role)


def tree(mode: str, role: str | None = None) -> list[tuple[tuple[str, ...], str]]:
    """Every leaf as (labels from the top level down, registry path)."""
    pages = [page for page in registry.PAGES if _visible(page, role)]
    if mode == "classic":
        order = []
        for page in pages:
            if page["group"] not in order:
                order.append(page["group"])
        order.sort(key=lambda group: group == "Advanced tools")
        return [((registry.group_title(group), page["label"]), page["path"])
                for group in order for page in pages if page["group"] == group]
    if mode != "areas":
        raise ValueError("Choose classic or areas.")
    leaves = []
    for title, hub, sections in registry.AREAS:
        in_area = [page for page in pages if registry.PAGE_AREAS.get(page["path"], ("",))[0] == title]
        names = [*sections, *(registry.PAGE_AREAS[page["path"]][1] for page in in_area)]
        for section in dict.fromkeys(names):
            members = [page for page in in_area if registry.PAGE_AREAS[page["path"]][1] == section]
            lead = registry.section_lead(hub, section)
            members.sort(key=lambda page, lead=lead: lead({"href": page["path"], "label": page["label"]}))
            if len(members) == 1 and members[0]["label"].casefold() == section.casefold():
                leaves.append(((title, section), members[0]["path"]))
                continue
            leaves.extend(((title, section, page["label"]), page["path"]) for page in members)
    return leaves


def as_text(leaves) -> str:
    """Tab-indented, one node per line: paste into a tree-testing tool."""
    lines, previous = [], ()
    for labels, _path in leaves:
        for depth, label in enumerate(labels):
            if previous[: depth + 1] != labels[: depth + 1]:
                lines.append("\t" * depth + label)
        previous = labels
    return "\n".join(lines) + "\n"


def as_csv(leaves) -> str:
    """One row per leaf: Level 1..3 and the page's address."""
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(["Level 1", "Level 2", "Level 3", "Address"])
    for labels, path in leaves:
        writer.writerow([*labels, *([""] * (3 - len(labels))), path])
    return out.getvalue()


def read_tasks(path: str) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def answers(leaves, tasks: list[dict]) -> list[dict]:
    """Each task with its correct node(s) in this tree; ``missing`` lists
    answer addresses the tree does not hold (none should)."""
    by_path: dict[str, list[str]] = {}
    for labels, path in leaves:
        by_path.setdefault(path, []).append(" > ".join(labels))
    result = []
    for task in tasks:
        paths = [item for item in task["answers"].split("|") if item]
        result.append({"role": task["role"], "id": task["id"], "task": task["task"],
                       "nodes": [node for item in paths for node in by_path.get(item, [])],
                       "missing": [item for item in paths if item not in by_path]})
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--export", choices=("classic", "areas"), required=True)
    parser.add_argument("--format", choices=("text", "csv"), default="text")
    parser.add_argument("--role", default=None, help="a built-in role, e.g. admin, operator, auditor, viewer")
    parser.add_argument("--answers", default=None, help="a tasks CSV; prints each task's correct node(s)")
    args = parser.parse_args(argv)
    leaves = tree(args.export, args.role)
    if args.answers:
        writer = csv.writer(sys.stdout, lineterminator="\n")
        writer.writerow(["Role", "Task", "Correct answer(s)"])
        for row in answers(leaves, read_tasks(args.answers)):
            writer.writerow([row["role"], f'{row["id"]}. {row["task"]}', " | ".join(row["nodes"])])
        return 0
    sys.stdout.write(as_csv(leaves) if args.format == "csv" else as_text(leaves))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
