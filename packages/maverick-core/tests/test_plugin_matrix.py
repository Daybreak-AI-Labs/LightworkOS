"""Plugin compatibility matrix: rows, rendering, and the CI gate."""
from __future__ import annotations

import maverick.plugins as plugins_mod
from maverick import plugin_matrix as pmx
from maverick.plugin_manifest import parse_dict


class _EP:
    def __init__(self, name, dist="acme-dist"):
        self.name = name
        self.value = f"{dist}:factory"
        self._dist = dist


def _wire(monkeypatch, eps_by_group, manifests, cfg=None, granted=None):
    monkeypatch.setattr(plugins_mod, "_entry_points",
                        lambda group: list(eps_by_group.get(group, [])))
    monkeypatch.setattr(plugins_mod, "_ep_dist_name", lambda ep: ep._dist)
    monkeypatch.setattr(plugins_mod, "_plugins_config", lambda: cfg or {})
    monkeypatch.setattr(plugins_mod, "_allowed_plugin_names",
                        lambda: _allow_from_cfg(cfg or {}))
    monkeypatch.setattr(plugins_mod, "_permission_policy",
                        lambda: (set(granted or []), True))
    monkeypatch.setattr(plugins_mod, "_find_manifest",
                        lambda ep: manifests.get(ep.name))


def _allow_from_cfg(cfg):
    enabled = cfg.get("enabled")
    if enabled is None:
        return set()
    if isinstance(enabled, str):
        items = {p.strip() for p in enabled.split(",") if p.strip()}
    else:
        items = {str(x).strip() for x in enabled if str(x).strip()}
    return None if "*" in items else items


def _manifest(api="2", *, network=False):
    return parse_dict({
        "plugin": {"name": "p", "version": "0.1.0", "api_version": api,
                   "license": "MIT", "author": "a",
                   "permissions": {"network": network}}
    })


def test_matrix_rows_cover_groups_and_compat(monkeypatch):
    _wire(monkeypatch,
          {"maverick.tools": [_EP("alpha")], "maverick.skills": [_EP("beta")]},
          {"alpha": _manifest("2"), "beta": _manifest("1")},
          cfg={"enabled": ["alpha", "beta"]})
    rows = {r.name: r for r in pmx.build_matrix()}
    assert rows["alpha"].compatible and not rows["alpha"].deprecated
    assert rows["beta"].compatible and rows["beta"].deprecated
    assert rows["alpha"].enabled and rows["beta"].enabled


def test_matrix_no_manifest_is_v1_era(monkeypatch):
    _wire(monkeypatch, {"maverick.tools": [_EP("bare")]}, {}, cfg={})
    (row,) = pmx.build_matrix()
    assert row.api_version == "?" and row.compatible
    assert "no manifest" in row.notes
    assert row.enabled is False  # not allowlisted


def test_matrix_flags_ungranted_permissions(monkeypatch):
    _wire(monkeypatch, {"maverick.tools": [_EP("net")]},
          {"net": _manifest("2", network=True)},
          cfg={"enabled": ["net"]}, granted=[])
    (row,) = pmx.build_matrix()
    assert row.permissions_ok is False


def test_problems_gate_only_enabled(monkeypatch):
    _wire(monkeypatch, {"maverick.tools": [_EP("old"), _EP("future")]},
          {"old": _manifest("1"), "future": _manifest("3")},
          cfg={"enabled": ["future"]})
    rows = pmx.build_matrix()
    probs = pmx.problems(rows)
    # 'future' (enabled, v3) trips the gate; 'old' (disabled) does not.
    assert len(probs) == 1 and "future" in probs[0]


def test_problems_empty_when_all_loadable(monkeypatch):
    _wire(monkeypatch, {"maverick.tools": [_EP("alpha")]},
          {"alpha": _manifest("2")}, cfg={"enabled": ["*"]})
    assert pmx.problems(pmx.build_matrix()) == []


def test_render_empty_and_populated(monkeypatch):
    _wire(monkeypatch, {}, {})
    out = pmx.render(pmx.build_matrix())
    assert "no maverick plugins installed" in out

    _wire(monkeypatch, {"maverick.tools": [_EP("alpha")]},
          {"alpha": _manifest("1")}, cfg={"enabled": ["alpha"]})
    out = pmx.render(pmx.build_matrix())
    assert "alpha" in out and "DEPRECATED" in out and "kernel API v2" in out


def test_matrix_uses_runtime_allowlist_semantics(monkeypatch):
    _wire(monkeypatch, {"maverick.tools": [_EP("future")]},
          {"future": _manifest("3")}, cfg={})
    monkeypatch.setattr(plugins_mod, "_allowed_plugin_names", lambda: {"future"})

    (row,) = pmx.build_matrix()

    assert row.enabled is True
    assert "future" in pmx.problems([row])[0]


def test_matrix_enables_all_when_runtime_allowlist_is_wildcard(monkeypatch):
    _wire(monkeypatch, {"maverick.tools": [_EP("future")]},
          {"future": _manifest("3")}, cfg={})
    monkeypatch.setattr(plugins_mod, "_allowed_plugin_names", lambda: None)

    (row,) = pmx.build_matrix()

    assert row.enabled is True


def test_matrix_supports_string_enabled_config(monkeypatch):
    _wire(monkeypatch, {"maverick.tools": [_EP("future")]},
          {"future": _manifest("3")}, cfg={"enabled": "future"})

    (row,) = pmx.build_matrix()

    assert row.enabled is True
    assert "future" in pmx.problems([row])[0]
