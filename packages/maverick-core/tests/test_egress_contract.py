"""The gate that keeps the egress guard's coverage claim true.

``egress_guard`` wraps ``httpx``, ``httpx2``, ``requests`` and ``urllib``,
which covers direct application calls plus provider SDK traffic. That claim has
exactly one way to quietly stop being true: someone adds a connector using a
client library the guard does not wrap.

That is not hypothetical. It is precisely how the previous design failed -- a
convention that authors had to remember, with nothing failing when they did
not, decaying to 87 ungated modules.
"""

from __future__ import annotations

import textwrap

import pytest
from maverick import egress_contract as gate


def test_the_census_is_substantial() -> None:
    """Anti-vacuity: every assertion here is empty over an empty scan."""
    census = gate.scan()
    assert len(census) > 50, len(census)


def test_the_repo_is_currently_clean() -> None:
    census = gate.scan()
    _, uncovered = gate.classify(census)
    assert gate.problems(uncovered) == []


def test_the_recorded_holes_are_real() -> None:
    """A debt register with stale entries is an exemption list."""
    census = gate.scan()
    _, uncovered = gate.classify(census)
    for module in gate.KNOWN_UNCOVERED:
        assert module in uncovered, (
            f"{module} is recorded as uncovered but the scan disagrees")


def test_the_guarded_libraries_are_actually_guarded() -> None:
    """The gate's notion of 'covered' must match what the guard wraps.

    If these drifted apart, the gate would bless modules the guard never
    touches -- a green check certifying nothing.
    """
    from maverick.egress_guard import COVERED_LIBRARIES
    assert set(COVERED_LIBRARIES) == {
        "httpx",
        "httpx2",
        "requests",
        "urllib",
    }


# -- negative controls: the gate must be able to fail ----------------------

def _scan_dir(tmp_path, source: str) -> dict:
    (tmp_path / "pkg").mkdir(exist_ok=True)
    (tmp_path / "pkg" / "mod.py").write_text(textwrap.dedent(source),
                                             encoding="utf-8")
    original = gate.REPO_ROOT
    gate.REPO_ROOT = tmp_path
    try:
        return gate.scan(roots=("pkg",))
    finally:
        gate.REPO_ROOT = original


def test_an_unguarded_library_is_detected(tmp_path) -> None:
    """The committed mutant. Without this the gate could accept anything."""
    census = _scan_dir(tmp_path, """
        import aiohttp
        async def go():
            async with aiohttp.ClientSession() as s:
                await s.get("https://evil.example.com")
    """)
    _, uncovered = gate.classify(census)
    assert uncovered, "an aiohttp module must be reported as uncovered"
    assert gate.problems(uncovered), "and must be a build failure"


def test_an_aliased_import_does_not_evade_the_gate(tmp_path) -> None:
    """`import aiohttp as ah` was invisible to the detector.

    Not an attack -- ordinary style. Found the embarrassing way: a stray probe
    file using exactly this form sat inside the package while the gate reported
    the repo clean. A detector that matches on the written name rather than the
    imported one checks spelling, not behaviour.
    """
    census = _scan_dir(tmp_path, """
        import aiohttp as ah
        async def go():
            async with ah.ClientSession() as s:
                await s.get("https://evil.example.com")
    """)
    _, uncovered = gate.classify(census)
    assert uncovered, "an aliased aiohttp import must still be seen"


def test_an_aliased_guarded_import_is_resolved_too(tmp_path) -> None:
    """Positive control: resolution must not turn every alias into a hit."""
    census = _scan_dir(tmp_path, """
        import httpx as hx
        def go():
            return hx.get("https://api.example.com")
    """)
    _, uncovered = gate.classify(census)
    assert census and not uncovered, (census, uncovered)


def test_an_aliased_httpx2_import_is_guarded(tmp_path) -> None:
    """Provider-SDK transport calls belong to the guarded family too."""
    census = _scan_dir(tmp_path, """
        import httpx2 as hx
        async def go():
            async with hx.AsyncClient() as client:
                return await client.post("https://api.example.com")
    """)
    _, uncovered = gate.classify(census)
    assert census and not uncovered, (census, uncovered)


def test_a_plain_dotted_import_still_resolves(tmp_path) -> None:
    """Regression: mapping `import x.y` to "x.y" produced "x.y.y.z".

    The first alias implementation did exactly that and made eight real
    modules invisible -- the census dropped from 94 to 86. Only an explicit
    `as` rebinds; a plain dotted import binds the top-level name.
    """
    census = _scan_dir(tmp_path, """
        import urllib.request
        def go():
            return urllib.request.urlopen("https://api.example.com")
    """)
    assert census, "urllib.request.urlopen must still be seen"


def test_a_guarded_library_is_not_flagged(tmp_path) -> None:
    """Positive control: rejecting everything would also pass the test above."""
    census = _scan_dir(tmp_path, """
        import httpx
        def go():
            return httpx.get("https://api.example.com")
    """)
    _, uncovered = gate.classify(census)
    assert not uncovered, uncovered


def test_building_a_request_object_is_not_a_network_call(tmp_path) -> None:
    """Precision matters more than reach here.

    An earlier detector matched any ``urllib.request.*`` call and flagged
    ``urllib.request.Request(...)``, which constructs a request and sends
    nothing. It reported two modules that were fine. A gate that cries wolf
    gets muted, and a muted gate is worse than no gate at all.
    """
    census = _scan_dir(tmp_path, """
        import urllib.request
        def build():
            return urllib.request.Request("https://api.example.com")
    """)
    assert census == {}, census


def test_urlopen_is_a_network_call(tmp_path) -> None:
    """Paired with the above: precision must not become blindness."""
    census = _scan_dir(tmp_path, """
        import urllib.request
        def go():
            return urllib.request.urlopen("https://api.example.com")
    """)
    assert census, "urlopen is an outbound request and must be seen"


def test_a_stale_recorded_hole_is_reported(tmp_path) -> None:
    """A module that got migrated must be removed from the register."""
    problems = gate.problems({})
    assert any("no longer reaches the network" in p for p in problems), problems


def test_tests_are_not_scanned(tmp_path) -> None:
    """This very file calls httpx; scanning tests would make the gate noise."""
    census = gate.scan()
    assert not any("/tests/" in m for m in census), \
        [m for m in census if "/tests/" in m]


def test_generated_build_copies_are_not_scanned(tmp_path) -> None:
    root = tmp_path / "packages"
    generated = root / "example" / "build" / "lib" / "example"
    generated.mkdir(parents=True)
    (generated / "client.py").write_text(
        "import aiohttp\naiohttp.ClientSession()\n",
        encoding="utf-8",
    )
    original = gate.REPO_ROOT
    gate.REPO_ROOT = tmp_path
    try:
        assert gate.scan(roots=("packages",)) == {}
    finally:
        gate.REPO_ROOT = original


# -- CLI -------------------------------------------------------------------

def test_the_cli_refuses_an_empty_scan(monkeypatch, capsys) -> None:
    """A gate that inspects nothing must not report success."""
    monkeypatch.setattr(gate, "scan", lambda *a, **k: {})
    assert gate.main(["--ci"]) == 2
    assert "0 modules" in capsys.readouterr().err


def test_the_cli_passes_on_the_real_repo() -> None:
    assert gate.main(["--ci"]) == 0


# -- the transports that had no gate --------------------------------------

def test_webrtc_is_not_registered_by_default() -> None:
    """No default tool opens a bidirectional P2P data channel to an arbitrary
    peer. The ``webrtc`` name stays risk-tiered and containment-denied for a
    plugin that registers it."""
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        pass

    names = set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}))
    assert names, "anti-vacuity: the registry must have built"
    assert "websocket" in names, "control: sibling transports stay registered"
    assert "webrtc" not in names, "no default tool may register as webrtc"


@pytest.mark.parametrize("tool", ["webrtc", "websocket"])
def test_the_exfil_transports_carry_a_high_risk_tier(tool) -> None:
    from maverick.safety.tool_risk import _DEFAULT_RISK
    assert _DEFAULT_RISK.get(tool) == "high", tool


@pytest.mark.parametrize("tool", ["webrtc", "websocket"])
def test_the_exfil_transports_are_containment_denied(tool) -> None:
    from maverick.containment import DEFAULT_DENY_TOOLS
    assert tool in DEFAULT_DENY_TOOLS, tool
