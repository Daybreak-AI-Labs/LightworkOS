"""Privacy/security control catalog + the find_controls tool."""
from __future__ import annotations

import asyncio

from click.testing import CliRunner
from maverick.cli import main
from maverick.controls import CONTROLS, find_controls, render_control


def test_find_controls_matches_by_keyword():
    dpa = find_controls("vendor has no DPA")
    assert dpa and dpa[0].id == "VN-1"
    assert "Art. 28" in dpa[0].frameworks["GDPR"]
    assert any(c.id == "CR-1" for c in find_controls("encrypt data at rest"))


def test_find_controls_empty_or_no_match_returns_empty():
    assert find_controls("") == []
    assert find_controls("a") == []                 # no token > 2 chars
    assert find_controls("zzzqqq flibbertigibbet") == []


def test_find_controls_respects_limit():
    hits = find_controls("data encryption access control breach retention", limit=2)
    assert len(hits) == 2


def test_render_control_cites_multiple_frameworks():
    c = next(c for c in CONTROLS if c.id == "LM-1")
    out = render_control(c)
    assert "LM-1" in out and "SOC 2" in out and "Art." in out


def test_find_controls_tool_runs():
    from maverick.tools.control_tools import find_controls_tool

    tool = find_controls_tool()
    assert tool.name == "find_controls"
    out = asyncio.run(tool.fn({"query": "no data processing agreement"}))
    assert "VN-1" in out
    assert asyncio.run(tool.fn({"query": ""})).startswith("ERROR")


def test_find_controls_is_low_risk():
    # Low risk so it survives the privacy analyst pack's max_risk = "low" clamp.
    from maverick.safety.tool_risk import tool_risk
    assert tool_risk("find_controls") == "low"


def test_privacy_analyst_pack_grants_find_controls():
    from pathlib import Path

    from maverick import domain as dom

    pack = dom.load_domain(
        Path(dom.__file__).parent / "domains" / "privacy_compliance.toml"
    )
    assert "find_controls" in pack.allow_tools


def test_cli_controls():
    r = CliRunner().invoke(main, ["controls", "vendor", "has", "no", "DPA"])
    assert r.exit_code == 0 and "VN-1" in r.output


def test_find_controls_tool_tolerates_a_non_integer_limit():
    import asyncio

    from maverick.tools.control_tools import find_controls_tool
    out = asyncio.run(find_controls_tool().fn({"query": "dpa", "limit": "abc"}))
    assert "VN-1" in out          # bad limit -> default, not a crash
