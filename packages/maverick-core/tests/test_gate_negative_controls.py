"""Every CI gate must be able to fail, and must not pass over an empty scope.

Five shipped gates were found passing while inspecting zero items. A gate that
cannot fail is worse than no gate: it occupies a green column and reports a
guarantee it never checked. ``evaluator_anchors.lock.json`` was
``{"checksums": {}, "sizes": {}}`` while printing "OK"; ``a11y_audit --dir
/nonexistent`` printed "no static accessibility issues found" and exited 0.

Two properties per gate:

* **anti-vacuity** -- an empty scope is reported as empty, not as a pass. Where
  empty is a legitimate state (no plugins installed, no anchors released) the
  gate still exits 0, but says so in words that cannot be mistaken for a clean
  bill of health.
* **negative control** -- a committed mutant the gate must reject. This is the
  half that proves the gate works, and it is generalised here from the idiom
  already used by ``test_redteam_ci.py::test_main_fails_on_missed_attack`` and
  ``test_migration_governance.py``.
"""

from __future__ import annotations

import json

import pytest
from maverick import a11y_audit, evaluator_evolution, plugin_matrix

# --------------------------------------------------------------------------
# a11y_audit
# --------------------------------------------------------------------------

def test_a11y_refuses_to_pass_over_an_empty_directory(tmp_path, capsys) -> None:
    """The reported bug: a clean bill of health over zero templates."""
    rc = a11y_audit.main(["--ci", "--dir", str(tmp_path / "nope")])
    assert rc == 2
    assert "inspected 0 templates" in capsys.readouterr().err


def test_a11y_refuses_an_existing_but_empty_directory(tmp_path, capsys) -> None:
    """Present-but-empty is the same failure as absent, and was also a pass."""
    (tmp_path / "templates").mkdir()
    rc = a11y_audit.main(["--ci", "--dir", str(tmp_path / "templates")])
    assert rc == 2
    assert "inspected 0 templates" in capsys.readouterr().err


def test_a11y_negative_control_rejects_a_planted_violation(tmp_path) -> None:
    """The committed mutant: a template the gate MUST reject."""
    d = tmp_path / "templates"
    d.mkdir()
    (d / "bad.html").write_text(
        '<html lang="en"><body><img src="x.png"></body></html>', encoding="utf-8")
    assert a11y_audit.main(["--ci", "--dir", str(d)]) == 1


def test_a11y_passes_a_clean_template(tmp_path) -> None:
    """The control for the control: a clean file must not fail, or rejection
    proves nothing about discrimination."""
    d = tmp_path / "templates"
    d.mkdir()
    (d / "ok.html").write_text(
        '<html lang="en"><body><img src="x.png" alt="x"></body></html>',
        encoding="utf-8")
    assert a11y_audit.main(["--ci", "--dir", str(d)]) == 0


def test_a11y_on_the_real_tree_inspects_a_substantial_number(capsys) -> None:
    assert a11y_audit.main(["--ci"]) == 0
    out = capsys.readouterr().out
    assert "template(s) inspected" in out
    count = int(out.split("a11y audit: ")[-1].split(" template")[0])
    assert count > 50, count


# --------------------------------------------------------------------------
# evaluator_evolution
# --------------------------------------------------------------------------

def test_evaluator_gate_does_not_call_an_empty_lock_a_pass(capsys) -> None:
    """0 anchors + 0 locked must not print the same word as a real pass."""
    rc = evaluator_evolution.main(["--ci"])
    out = capsys.readouterr().out
    anchors = evaluator_evolution.discover_anchors()
    locked = len(evaluator_evolution.load_lock().get("checksums") or {})
    if not anchors and not locked:
        assert rc == 0
        assert "NO ANCHORS COMMITTED" in out
        assert "governing nothing" in out
        # The old wording. It must not reappear for an empty scope.
        assert "governance: OK" not in out
    else:  # pragma: no cover -- once anchors are released
        assert "governance: OK" in out


def test_evaluator_gate_rejects_locked_anchors_deleted_from_disk(
        monkeypatch, capsys) -> None:
    """Negative control: the laundering the ratchet exists to catch.

    A lock with entries and nothing on disk means released anchors were removed.
    validate() walks what is present, so it cannot see an absence; this is the
    case that must not slip through as "OK / 0 anchor(s)".
    """
    monkeypatch.setattr(evaluator_evolution, "discover_anchors", dict)
    monkeypatch.setattr(evaluator_evolution, "load_lock",
                        lambda: {"checksums": {"reviewer": "deadbeef"},
                                 "sizes": {"reviewer": 12}})
    monkeypatch.setattr(evaluator_evolution, "validate", list)
    assert evaluator_evolution.main(["--ci"]) == 1
    assert "released anchors were removed" in capsys.readouterr().err


def test_evaluator_gate_reports_a_real_pass_when_anchors_exist(
        monkeypatch, capsys) -> None:
    monkeypatch.setattr(evaluator_evolution, "discover_anchors",
                        lambda: {"reviewer": [object(), object()]})
    monkeypatch.setattr(evaluator_evolution, "load_lock",
                        lambda: {"checksums": {"reviewer": "abc"},
                                 "sizes": {"reviewer": 2}})
    monkeypatch.setattr(evaluator_evolution, "validate", list)
    assert evaluator_evolution.main(["--ci"]) == 0
    out = capsys.readouterr().out
    assert "governance: OK" in out
    assert "1 anchor(s) on disk, 1 locked" in out


def test_evaluator_gate_still_fails_on_a_real_problem(monkeypatch) -> None:
    monkeypatch.setattr(evaluator_evolution, "validate",
                        lambda: ["reviewer: checksum changed since release"])
    assert evaluator_evolution.main(["--ci"]) == 1


# --------------------------------------------------------------------------
# plugin_matrix
# --------------------------------------------------------------------------

def test_plugin_matrix_names_the_empty_case_distinctly(monkeypatch, capsys) -> None:
    monkeypatch.setattr(plugin_matrix, "build_matrix", list)
    assert plugin_matrix.main(["--ci"]) == 0
    out = capsys.readouterr().out
    assert "0 plugins installed" in out
    assert "NOT evidence" in out


def test_plugin_matrix_negative_control_rejects_an_incompatible_plugin(
        monkeypatch, capsys) -> None:
    """The committed mutant: the gate must reject what it exists to reject."""
    monkeypatch.setattr(plugin_matrix, "build_matrix", lambda: ["row"])
    monkeypatch.setattr(plugin_matrix, "render", lambda rows: "")
    monkeypatch.setattr(
        plugin_matrix, "problems",
        lambda rows: ["evil-plugin declares api_version 9, unsupported"])
    assert plugin_matrix.main(["--ci"]) == 1
    assert "PROBLEM: evil-plugin" in capsys.readouterr().out


def test_plugin_matrix_passes_a_compatible_plugin(monkeypatch, capsys) -> None:
    monkeypatch.setattr(plugin_matrix, "build_matrix", lambda: ["row"])
    monkeypatch.setattr(plugin_matrix, "render", lambda rows: "")
    monkeypatch.setattr(plugin_matrix, "problems", lambda rows: [])
    assert plugin_matrix.main(["--ci"]) == 0
    assert "1 plugin(s) checked, 0 problem(s)" in capsys.readouterr().out


# --------------------------------------------------------------------------
# the lock file this whole class of bug hid behind
# --------------------------------------------------------------------------

def test_the_empty_evaluator_lock_is_recorded_as_empty_not_pretended_full() -> None:
    """Documents the actual committed state rather than asserting a wish.

    If anchors are released later this flips, and the assertion below becomes
    the real check. Either way the file's contents and the gate's words agree.
    """
    path = evaluator_evolution.anchor_lock_path()
    if not path.exists():
        pytest.skip("no lock committed")
    data = json.loads(path.read_text(encoding="utf-8"))
    checksums = data.get("checksums") or {}
    on_disk = evaluator_evolution.discover_anchors()
    assert set(checksums) == set(on_disk), (
        "the lock and the anchor directory disagree; one of them was edited "
        "without the other")
