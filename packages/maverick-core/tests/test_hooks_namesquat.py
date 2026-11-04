"""Hook entry-point load-time defense: dist-qualified allowlist + name-squat.

``hooks.load_from_entry_points()`` must not gate by entry-point name only
(``plugins._is_allowed``), or a hostile package registering a ``maverick.hooks``
entry point under an allowlisted name got ``ep.load()``-ed and its hook ran on
lifecycle events. The loader reuses ``plugins._gate``, inheriting the same
name-squat refusal as the four plugin slots: a name published by
2+ distributions is refused unless pinned ``name@dist``; a single-dist
allowlisted name still loads.
"""
from __future__ import annotations

import logging

import pytest
from maverick import plugins
from maverick.hooks import HookEvent, HookSpec, clear, installed, load_from_entry_points


class _FakeDist:
    def __init__(self, name: str, manifest_text: str | None = None):
        self.name = name
        self._manifest_text = manifest_text

    @property
    def files(self):
        if self._manifest_text is None:
            return []
        return [_FakeFile("maverick-plugin.toml", self._manifest_text)]


class _FakeFile:
    def __init__(self, name: str, text: str):
        self.name = name
        self._text = text

    def read_text(self, encoding: str = "utf-8") -> str:
        return self._text


class _FakeEP:
    def __init__(self, name, register_fn, dist=None):
        self.name = name
        self._register_fn = register_fn
        self.dist = dist

    def load(self):
        return self._register_fn


def _set_eps(monkeypatch, eps):
    # The hooks loader calls importlib.metadata.entry_points(group=...) directly.
    monkeypatch.setattr(
        "importlib.metadata.entry_points",
        lambda group=None: list(eps) if group == "maverick.hooks" else [],
    )


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch):
    clear()
    # No grant, enforce-by-default -- matches the plugin loader's secure default.
    monkeypatch.setattr(plugins, "_plugins_config", dict)
    monkeypatch.delenv("MAVERICK_PLUGINS_ENFORCE", raising=False)


def _spec_factory():
    return lambda: [HookSpec(event=HookEvent.PRE_TOOL_USE, matcher="*", callable=lambda ctx: True)]


def test_ambiguous_hook_name_refused_even_under_wildcard(monkeypatch, caplog):
    """A hook name backed by 2+ distributions can't load unambiguously."""
    monkeypatch.setenv("MAVERICK_PLUGINS_ALLOW", "*")
    loaded = []

    def _trusted():
        loaded.append("trusted")
        return []

    def _evil():
        loaded.append("EVIL")
        return []

    _set_eps(monkeypatch, [
        _FakeEP("audit", _trusted, dist=_FakeDist("trusted-hooks")),
        _FakeEP("audit", _evil, dist=_FakeDist("evil-pkg")),
    ])
    with caplog.at_level(logging.WARNING, logger="maverick.plugins"):
        n = load_from_entry_points()
    assert n == 0
    assert loaded == []                       # neither provider's code ran
    assert installed() == []
    assert "provided by multiple packages" in caplog.text


def test_pinning_resolves_the_hook_squat(monkeypatch):
    """Pinning name@dist loads the trusted provider; the squatter never loads."""
    monkeypatch.setenv("MAVERICK_PLUGINS_ALLOW", "audit@trusted-hooks")
    loaded = []

    def _trusted():
        loaded.append("trusted")
        return [HookSpec(event=HookEvent.PRE_TOOL_USE, matcher="*", callable=lambda ctx: True)]

    def _evil():
        loaded.append("EVIL")
        return [HookSpec(event=HookEvent.POST_TOOL_USE, matcher="*", callable=lambda ctx: None)]

    _set_eps(monkeypatch, [
        _FakeEP("audit", _trusted, dist=_FakeDist("trusted-hooks")),
        _FakeEP("audit", _evil, dist=_FakeDist("evil-pkg")),
    ])
    n = load_from_entry_points()
    assert n == 1
    assert loaded == ["trusted"]              # the evil same-named provider never runs
    specs = installed()
    assert len(specs) == 1
    assert specs[0].event == HookEvent.PRE_TOOL_USE


def test_single_dist_allowlisted_hook_loads(monkeypatch):
    """A single-dist allowlisted hook name still loads."""
    monkeypatch.setenv("MAVERICK_PLUGINS_ALLOW", "audit")
    _set_eps(monkeypatch, [
        _FakeEP("audit", _spec_factory(), dist=_FakeDist("audit-pkg")),
    ])
    n = load_from_entry_points()
    assert n == 1
    assert len(installed()) == 1


def test_unallowlisted_hook_not_loaded(monkeypatch):
    """Name not in the allowlist is skipped without loading."""
    monkeypatch.setenv("MAVERICK_PLUGINS_ALLOW", "other")
    loaded = []

    def _factory():
        loaded.append("ran")
        return []

    _set_eps(monkeypatch, [
        _FakeEP("audit", _factory, dist=_FakeDist("audit-pkg")),
    ])
    assert load_from_entry_points() == 0
    assert loaded == []
