"""Hot plugin reload: editing a plugin module's code on disk takes effect after
reload_plugin() without restarting the process."""
from __future__ import annotations

import sys
import textwrap
import types

from click.testing import CliRunner
from maverick import plugins as plugins_mod
from maverick.plugins import reload_plugin


class _EP:
    """Minimal entry-point stand-in with a dist name."""

    def __init__(self, name, value, dist_name):
        self.name = name
        self.value = value
        self.dist = types.SimpleNamespace(name=dist_name)


def _install_plugin_module(tmp_path, body: str):
    pkg = tmp_path / "hotdemo_plugin.py"
    pkg.write_text(textwrap.dedent(body))
    if str(tmp_path) not in sys.path:
        sys.path.insert(0, str(tmp_path))
    return pkg


def test_reload_drops_modules_and_picks_up_new_code(tmp_path, monkeypatch):
    mod_file = _install_plugin_module(tmp_path, "VERSION = 'v1'\n")
    eps = [_EP("hotdemo", "hotdemo_plugin:tool", "hotdemo-dist")]
    monkeypatch.setattr(plugins_mod, "_entry_points",
                        lambda group: eps if group == "maverick.tools" else [])

    import hotdemo_plugin  # first import
    assert hotdemo_plugin.VERSION == "v1"

    # Author edits the file on disk... (bump mtime past the cached stat —
    # a same-second, same-size rewrite would otherwise satisfy the .pyc check)
    mod_file.write_text("VERSION = 'v2'\n")
    import os
    st = mod_file.stat()
    os.utime(mod_file, (st.st_atime + 5, st.st_mtime + 5))
    # ...without reload the stale module sticks:
    import hotdemo_plugin as again
    assert again.VERSION == "v1"

    dropped = reload_plugin("hotdemo-dist")
    assert dropped == ["hotdemo_plugin"]
    import hotdemo_plugin as fresh
    assert fresh.VERSION == "v2"

    # cleanup
    sys.modules.pop("hotdemo_plugin", None)
    sys.path.remove(str(tmp_path))


def test_reload_unknown_dist_returns_empty(monkeypatch):
    monkeypatch.setattr(plugins_mod, "_entry_points", lambda group: [])
    assert reload_plugin("not-installed") == []


def test_reload_drops_submodules_too(tmp_path, monkeypatch):
    pkg_dir = tmp_path / "hotpkg"
    pkg_dir.mkdir()
    (pkg_dir / "__init__.py").write_text("from . import sub\n")
    (pkg_dir / "sub.py").write_text("X = 1\n")
    sys.path.insert(0, str(tmp_path))
    try:
        eps = [_EP("p", "hotpkg:factory", "hotpkg-dist")]
        monkeypatch.setattr(plugins_mod, "_entry_points",
                            lambda group: eps if group == "maverick.channels" else [])
        import hotpkg  # noqa: F401
        assert "hotpkg.sub" in sys.modules
        dropped = reload_plugin("hotpkg-dist")
        assert set(dropped) == {"hotpkg", "hotpkg.sub"}
        assert "hotpkg" not in sys.modules and "hotpkg.sub" not in sys.modules
    finally:
        sys.modules.pop("hotpkg", None)
        sys.modules.pop("hotpkg.sub", None)
        sys.path.remove(str(tmp_path))


def test_cli_plugin_reload_command(monkeypatch):
    from maverick import cli as cli_mod
    monkeypatch.setattr(plugins_mod, "reload_plugin", lambda d: ["m1", "m2"])
    res = CliRunner().invoke(cli_mod.main, ["plugin", "reload", "some-dist"])
    assert res.exit_code == 0, res.output
    assert "dropped 2 module(s)" in res.output

    monkeypatch.setattr(plugins_mod, "reload_plugin", lambda d: [])
    res = CliRunner().invoke(cli_mod.main, ["plugin", "reload", "ghost"])
    assert res.exit_code == 1
    assert "no maverick entry points" in res.output
