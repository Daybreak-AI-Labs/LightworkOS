"""The connector count in the docs must be derived from the registry, not typed.

Ten documentation locations claimed "214 write-capable" connectors while the
registry held 2,877 -- a 13x internal contradiction that survived because nothing
asserted the number. Two other files (docs/connectors.md, docs/FEATURES.md) had
the right figure the whole time, so the repo simultaneously published both. The
stale number was an *under*-claim, which is why nobody noticed: an inflated
number gets challenged, a deflated one just sits there.

This test is the gate. It fails when the registry grows and the docs don't, which
is the only reliable way to keep prose in step with a list that changes on most
connector PRs.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from maverick.tools._connector_specs import _GRAPHQL_SPECS, _SPECS

REPO_ROOT = Path(__file__).resolve().parents[3]

# Every file that states the write-capable connector count in prose.
DOCS_STATING_THE_COUNT = (
    "docs/technical-overview.md",
    "docs/architecture.md",
    "docs/connectors.md",
    "docs/FEATURES.md",
    "docs/handbook.md",
    "docs/index.md",
    "docs/enterprise/security-evidence-map.md",
)

# Matches "2,877 write-capable" and "**2,877 write-capable" alike, with or
# without the thousands separator, so a future edit dropping the comma still
# gets checked rather than silently skipped. The leading \d matters: a bare
# [\d,]+ also matches the comma in prose like "(CSV/XLSX, write-capable)".
_COUNT_RE = re.compile(r"(\d[\d,]*)\s+write-capable")


def _registry_total() -> int:
    return len(_SPECS) + len(_GRAPHQL_SPECS)


@pytest.mark.parametrize("relpath", DOCS_STATING_THE_COUNT)
def test_doc_connector_count_matches_the_registry(relpath: str) -> None:
    path = REPO_ROOT / relpath
    if not path.exists():  # pragma: no cover -- doc moved or removed
        pytest.skip(f"{relpath} not present")
    text = path.read_text(encoding="utf-8")
    found = _COUNT_RE.findall(text)
    assert found, (
        f"{relpath} is listed as stating the write-capable connector count but no "
        "'<n> write-capable' phrase was found. Either restore the count or drop "
        "this file from DOCS_STATING_THE_COUNT."
    )
    total = _registry_total()
    for raw in found:
        stated = int(raw.replace(",", ""))
        assert stated == total, (
            f"{relpath} says {raw} write-capable connectors; the registry holds "
            f"{total} ({len(_SPECS)} REST + {len(_GRAPHQL_SPECS)} GraphQL). "
            f"Update the doc to {total:,}."
        )


def test_no_doc_still_carries_the_stale_214_figure() -> None:
    """Belt and braces: catch the old number in any Markdown file.

    Only the files in DOCS_STATING_THE_COUNT are checked against the registry
    total, but 214 specifically was never correct, so it should not reappear
    anywhere in the tree.
    """
    stale = []
    for path in REPO_ROOT.glob("**/*.md"):
        if any(part in {".git", "node_modules", "site", "_site"} for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):  # pragma: no cover
            continue
        if "214 write-capable" in text:
            stale.append(str(path.relative_to(REPO_ROOT)))
    assert not stale, (
        "the stale 214 write-capable connector figure is back in: "
        + ", ".join(sorted(stale))
    )
