"""Every literal in-product link points at a route the dashboard serves.

A link to a page that was never registered (``/flows``, ``/login``) is a dead
end for the person who clicks it, and nothing else notices: the page that
shows the link renders fine. This reads the literal links in templates, page
scripts and the Python that builds link payloads, and matches each against
the app's GET routes. Built links (``"/goals/" + id``) end in a slash and are
skipped; a route that answers 404 while its feature is off still counts as
served.
"""
from __future__ import annotations

import pathlib
import re

from maverick_dashboard.app import app
from starlette.routing import Match

ROOT = pathlib.Path(__file__).resolve().parents[1] / "maverick_dashboard"
LINK = re.compile(
    r"""(?:href=|"href":\s*|direct_ui=|"direct_ui":\s*|\.href\s*=\s*)"""
    r"""["'](/[A-Za-z0-9_\-/.]*[A-Za-z0-9_\-.])(?:[?#][^"']*)?["']""")


def _served(path: str) -> bool:
    scope = {"type": "http", "path": path, "method": "GET", "root_path": "",
             "query_string": b"", "headers": []}
    return any(route.matches(scope)[0] == Match.FULL for route in app.router.routes)


def _links():
    for pattern in ("*.py", "*.html", "*.js"):
        for source in sorted(ROOT.rglob(pattern)):
            for number, line in enumerate(source.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                for match in LINK.finditer(line):
                    path = match.group(1)
                    if not path.startswith(("/static/", "/api/")):
                        yield f"{source.relative_to(ROOT)}:{number}", path


def test_the_scan_sees_ordinary_links():
    found = {path for _, path in _links()}
    assert {"/settings", "/goals", "/workflows"} <= found
    assert _served("/workflows") and _served("/flows/designer/abc")
    assert not _served("/flows")


def test_literal_in_product_links_resolve():
    broken = [f"{where}: {path}" for where, path in _links() if not _served(path)]
    assert not broken, "Links to pages the dashboard does not serve:\n" + "\n".join(broken)


def test_copilot_actions_open_and_appear_on_served_pages():
    from maverick_dashboard import product_operations

    broken = []
    for key, adapter in product_operations.adapters().items():
        direct = adapter.direct_ui.split("#")[0].split("?")[0]
        if direct and not _served(direct):
            broken.append(f"{key}: opens {direct}")
        for page in adapter.pages:  # fnmatch patterns; "*" means every page
            path = page.split("?")[0]
            if path != "*" and not (_served(path.replace("*", "x"))
                                    or ("*" in path and _served(path.split("/*")[0] or "/"))):
                broken.append(f"{key}: offered on {page}")
    assert not broken, "Copilot actions name pages the dashboard does not serve:\n" + "\n".join(broken)


def test_saved_work_links_open_the_flow_and_the_run():
    from maverick_dashboard.connection_dependencies import _flow_href, _run_href

    assert _flow_href("flow-1") == "/flows/designer/flow-1" and _served(_flow_href("flow-1"))
    assert _run_href("flow 1", "run_2") == "/flows/flow%201/runs/run_2" and _served("/flows/flow-1/runs/run_2")
