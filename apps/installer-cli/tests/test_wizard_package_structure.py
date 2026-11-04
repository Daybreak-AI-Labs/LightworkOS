"""The installer wizard is a package: a facade plus step modules behind seams.

``maverick_installer.wizard`` keeps every name and every monkeypatch seam the
tests rely on.  The biggest steps live in their own
modules and reach the prompt primitives, the console and the ``CONFIG_*``
paths through ``_seams`` at call time, so a patch on the facade applies to
them exactly as it did when they were defined in the facade.
"""
from __future__ import annotations

import ast
import inspect
import io
import pathlib

from maverick_installer import wizard
from maverick_installer.wizard import _seams, advanced, assessments, security_suite
from rich.console import Console

PACKAGE = pathlib.Path(wizard.__file__).parent
STEP_MODULES = (advanced, assessments, security_suite)
PROMPT_SEAMS = {"_q_confirm", "_q_text", "_q_select", "_q_checkbox", "_q_secret", "console"}
FACADE_ONLY = {"CONFIG_DIR", "CONFIG_FILE", "ENV_FILE", "questionary", "PARTIAL_STATE_PATH"}


def _module_tree(module) -> ast.Module:
    return ast.parse(pathlib.Path(module.__file__).read_text(encoding="utf-8"))


def test_the_import_path_and_every_moved_name_survive():
    for module in STEP_MODULES:
        for name, obj in vars(module).items():
            if inspect.isfunction(obj) and obj.__module__ == module.__name__:
                assert getattr(wizard, name) is obj, name
    # Each step module owns a pick_* step and the _cfg_* writer for its answers.
    assert inspect.getmodule(wizard.pick_advanced) is inspect.getmodule(wizard._cfg_advanced) is advanced
    assert inspect.getmodule(wizard.pick_assessments) is inspect.getmodule(wizard._cfg_assessments) is assessments
    assert (
        inspect.getmodule(wizard.pick_security_suite)
        is inspect.getmodule(wizard._cfg_security_suite)
        is security_suite
    )


def test_the_facade_keeps_the_prompt_primitives_and_the_flows():
    for name in (
        "_q_confirm", "_q_text", "_q_select", "_q_checkbox", "_q_secret", "_ask",
        "run", "run_fast", "run_express", "run_consumer", "write_config", "preflight",
        "collect_api_keys", "pick_providers", "pick_channels", "smoke_test",
    ):
        assert getattr(wizard, name).__module__ == "maverick_installer.wizard", name
    assert isinstance(wizard.console, Console)
    assert isinstance(wizard.CONFIG_FILE, pathlib.Path)


def test_step_modules_reach_the_patchable_names_only_through_the_seams():
    for module in STEP_MODULES:
        tree = _module_tree(module)
        from_seams: set[str] = set()
        from_elsewhere: set[str] = set()
        for node in tree.body:
            if isinstance(node, ast.ImportFrom):
                names = {alias.asname or alias.name for alias in node.names}
                (from_seams if node.module == "_seams" else from_elsewhere).update(names)
            elif isinstance(node, ast.Import):
                from_elsewhere.update(alias.asname or alias.name.split(".")[0] for alias in node.names)
        defined = {n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
        for node in tree.body:
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                defined.update(t.id for t in targets if isinstance(t, ast.Name))
        assert not (from_elsewhere | defined) & PROMPT_SEAMS, module.__name__
        loaded = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
        assert loaded & PROMPT_SEAMS <= from_seams, (module.__name__, loaded & PROMPT_SEAMS - from_seams)
        assert not loaded & FACADE_ONLY, (module.__name__, loaded & FACADE_ONLY)
        # Local imports inside functions must not bypass the seams either.
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.endswith("wizard"):
                raise AssertionError(f"{module.__name__} imports the facade directly")


def test_the_seams_module_exposes_exactly_the_patchable_surface():
    public = {name for name in vars(_seams) if not name.startswith("__")}
    assert public >= PROMPT_SEAMS | {"config_file"}
    assert _seams._facade() is wizard
    assert _seams.console.print == wizard.console.print


def test_a_patch_on_the_facade_reaches_the_step_modules(monkeypatch, tmp_path):
    asked: list[str] = []

    def confirm(message, default=True):
        asked.append(message)
        return default

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_text", lambda message, default="": default)
    monkeypatch.setattr(wizard, "_q_select", lambda message, choices, default=None: default or choices[0])
    monkeypatch.setattr(wizard, "_q_checkbox", lambda message, choices, default=None: list(default or []))
    output = io.StringIO()
    monkeypatch.setattr(wizard, "console", Console(file=output, width=120))
    monkeypatch.setattr(wizard, "CONFIG_FILE", tmp_path / "config.toml")
    (tmp_path / "config.toml").write_text('[consent_registry]\nsubject_salt = "salt-from-the-patched-path"\n')

    # Call the step modules' own functions, not the facade attributes.
    assert assessments.pick_assessments() == {}
    assert asked[0] == "Enable assessment doc discovery?"
    assert "Assessment assists" in output.getvalue()
    assert advanced._prior_consent_salt() == "salt-from-the-patched-path"
    security_suite.pick_security_suite()
    assert "Security/GRC" in output.getvalue() or len(asked) > 10


def test_patching_a_console_method_on_the_shared_object_still_works(monkeypatch):
    seen: list[str] = []
    monkeypatch.setattr(wizard.console, "print", lambda *args, **kwargs: seen.append(str(args[0]) if args else ""))
    _seams.console.print("through the proxy")
    assert seen == ["through the proxy"]


def test_no_complexity_waiver_and_the_facade_stays_under_its_ratchet():
    sizes = {path.name: len(path.read_text(encoding="utf-8").splitlines()) for path in PACKAGE.glob("*.py")}
    for path in PACKAGE.glob("*.py"):
        assert "noqa: C901" not in path.read_text(encoding="utf-8"), path.name
    # wizard.py was 12,771 lines as one file. The facade must keep shrinking:
    # move the next step out instead of raising this bound.
    assert sizes["__init__.py"] <= 7_000, sizes
    for name in ("advanced.py", "assessments.py", "security_suite.py"):
        assert sizes[name] <= 4_000, sizes
