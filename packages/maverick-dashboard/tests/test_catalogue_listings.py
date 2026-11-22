"""Listings over the whole specialist catalogue stay linear.

There are about two thousand packs. Asking ``domain_suites_allowed`` about
each one re-reads the caller's grants and re-resolves the catalogue per pack;
a listing uses one ``domain_suites_checker`` and passes the profile it holds.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "maverick_dashboard"


def test_catalogue_listings_do_not_check_each_pack_from_scratch():
    offenders = []
    for source in sorted(ROOT.rglob("*.py")):
        text = source.read_text(encoding="utf-8")
        for match in re.finditer(r"available_domains\(\)\.items\(\)", text):
            window = text[match.start(): match.start() + 400]
            if "domain_suites_allowed(" in window:
                offenders.append(f"{source.name}:{text[:match.start()].count(chr(10)) + 1}")
    assert not offenders, "Use auth.domain_suites_checker(request) once and pass each profile: " + ", ".join(offenders)
