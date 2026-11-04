"""Digests that bind a reviewed operation to exactly what was shown."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

import pytest
from maverick.governed_operations import dataclass_digest, digest


@dataclass
class _Step:
    name: str
    tools: tuple[str, ...] = ()


@dataclass
class _Pack:
    name: str
    steps: list[_Step] = field(default_factory=list)
    extra: dict[str, object] = field(default_factory=dict)
    note: str | None = None


def test_dataclass_digest_matches_the_digest_of_asdict():
    pack = _Pack("ops", [_Step("a", ("email", "notify")), _Step("b")],
                 {"z": [1, 2.5, None, True], "a": {"nested": "é"}}, None)
    assert dataclass_digest(pack) == digest(asdict(pack))
    pack.steps[0].tools = ("email",)
    assert dataclass_digest(pack) == digest(asdict(pack))


def test_every_published_specialist_keeps_its_revision():
    # /chat lists every specialist with this revision; starting work compares it
    # with digest(asdict(profile)) of the chosen one.
    from maverick.domain import available_domains

    profiles = list(available_domains().values())
    assert len(profiles) > 1000
    assert [dataclass_digest(profile) for profile in profiles] == [digest(asdict(profile)) for profile in profiles]


def test_dataclass_digest_refuses_what_json_cannot_hold():
    with pytest.raises(TypeError):
        dataclass_digest(_Pack("ops", extra={"bad": object()}))
    with pytest.raises(ValueError):
        dataclass_digest(_Pack("ops", extra={"bad": float("nan")}))
