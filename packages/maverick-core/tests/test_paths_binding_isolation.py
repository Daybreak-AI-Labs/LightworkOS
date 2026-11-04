"""A module first imported while a test replaced a ``maverick.paths`` helper
must get the real helper back before the next test (repo-root conftest).

The two tests run in order: the first leaves the binding a replaced helper
creates, the second checks the suite undid it.
"""
from __future__ import annotations

import importlib
import sys

import pytest

_PROBE = "maverick_paths_binding_probe"


def test_a_module_imported_under_a_replaced_data_dir_binds_the_stand_in(tmp_path, monkeypatch):
    sys.modules.pop(_PROBE, None)
    (tmp_path / f"{_PROBE}.py").write_text("from maverick.paths import data_dir\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))

    def stand_in(*parts, **_kwargs):
        return tmp_path.joinpath(*parts)

    monkeypatch.setattr("maverick.paths.data_dir", stand_in)
    probe = importlib.import_module(_PROBE)
    # monkeypatch restores maverick.paths, not the name this import copied.
    assert probe.data_dir is stand_in


def test_the_next_test_sees_the_real_data_dir_in_that_module():
    from maverick import paths

    probe = sys.modules.get(_PROBE)
    if probe is None:
        pytest.skip("checks the binding the test above leaves; run the module")
    try:
        assert probe.data_dir is paths.data_dir
    finally:
        sys.modules.pop(_PROBE, None)
