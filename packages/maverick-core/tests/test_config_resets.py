"""Reviewed overlay reset contracts. Authored for the deferred test run."""
from types import SimpleNamespace

import pytest
from maverick.config import _deep_merge_config
from maverick.config_resets import METADATA, merge_dashboard, reset_spec


def setting(path, *, entries=False, fixed=(), scalar_entries=False, control="table"):
    return SimpleNamespace(id=".".join(path) + (".other" if entries else ""), path=path,
                           fixed_keys=fixed, key_kind="entries" if entries else "key",
                           row_kind="rate" if scalar_entries else "named", control=control)


def test_reset_masks_installer_rows_and_inherit_restores_without_mutating_installer():
    row = setting(("dashboard", "group_roles"))
    base = {"dashboard": {"group_roles": {"Finance": "operator"}, "default_role": "viewer"}}
    overlay = {METADATA: {row.id: reset_spec(row)}}
    assert merge_dashboard(base, overlay, _deep_merge_config) == {"dashboard": {"group_roles": {}, "default_role": "viewer"}}
    assert merge_dashboard(base, {}, _deep_merge_config) == base
    assert base['dashboard']['group_roles'] == {'Finance': 'operator'}
    runtime = _deep_merge_config(merge_dashboard(base, overlay, _deep_merge_config),
                                 {"dashboard": {"group_roles": {"Security": "admin"}}})
    assert runtime['dashboard']['group_roles'] == {'Security': 'admin'}
    assert METADATA not in runtime


def test_entries_reset_keeps_fixed_keys_and_unowned_nested_tables():
    row = setting(("rate_limits",), entries=True, fixed=("shell",), scalar_entries=True)
    base = {'rate_limits': {'shell': '2/minute', 'custom': '3/minute', 'nested': {'enabled': True}}}
    overlay = {METADATA: {row.id: reset_spec(row)}}
    assert merge_dashboard(base, overlay, _deep_merge_config)['rate_limits'] == {
        'shell': '2/minute', 'nested': {'enabled': True}}


def test_scalar_reset_to_none_removes_inherited_value():
    row = setting(("budget", "max_wall_seconds"), control="number")
    overlay = {METADATA: {row.id: reset_spec(row)}}
    assert 'max_wall_seconds' not in merge_dashboard({'budget': {'max_wall_seconds': 300}}, overlay, _deep_merge_config)['budget']


def test_unreadable_reset_metadata_refuses_ambiguous_merge():
    with pytest.raises(ValueError):
        merge_dashboard({'budget': {}}, {METADATA: {'bad': {'path': ['budget']}}}, _deep_merge_config)
