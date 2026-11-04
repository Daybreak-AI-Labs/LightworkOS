"""The audit refusal contract, and the gate that keeps it.

Two things are pinned here. First, that both refusals share a base a caller can
catch in one handler, so a call site hardened against one refusal is not blind
to the other. Second, that the gate itself can actually fail: a gate that
cannot fail proves nothing, so every assertion below has a negative control.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest
from maverick import audit_contract
from maverick.audit import AuditRefused, AuditWriteRefused, audit_event
from maverick.audit.signing import OffHostSigningRequiredError

# -- the type hierarchy ----------------------------------------------------

def test_both_refusals_share_one_catchable_base() -> None:
    assert issubclass(AuditWriteRefused, AuditRefused)
    assert issubclass(OffHostSigningRequiredError, AuditRefused)


def test_refusals_remain_runtime_errors() -> None:
    """Handlers predating these names must keep working."""
    assert issubclass(AuditRefused, RuntimeError)
    assert issubclass(OffHostSigningRequiredError, RuntimeError)


def test_the_off_host_refusal_is_not_a_write_refused() -> None:
    """They are siblings, not parent/child -- which is why the base exists.

    If someone later makes one inherit the other, `except AuditWriteRefused`
    would start silently covering both and the base would look redundant. It
    is not: they are raised by different modules for different reasons.
    """
    assert not issubclass(OffHostSigningRequiredError, AuditWriteRefused)
    assert not issubclass(AuditWriteRefused, OffHostSigningRequiredError)


# -- audit_event applies the contract --------------------------------------

@pytest.mark.parametrize("exc", [
    AuditWriteRefused("floor requires signed logs"),
    OffHostSigningRequiredError("custody policy requires an off-host key"),
])
def test_audit_event_propagates_every_refusal(monkeypatch, exc) -> None:
    import maverick.audit

    def _refuse(*a, **kw):
        raise exc

    monkeypatch.setattr(maverick.audit, "record", _refuse)
    with pytest.raises(AuditRefused):
        audit_event("tool_start", tool="wire_transfer")


def test_audit_event_swallows_ordinary_failures_but_logs_them(monkeypatch, caplog) -> None:
    import logging

    import maverick.audit

    def _boom(*a, **kw):
        raise OSError("disk full")

    monkeypatch.setattr(maverick.audit, "record", _boom)
    with caplog.at_level(logging.WARNING, logger="maverick.audit.writer"):
        assert audit_event("tool_start", tool="wire_transfer") is False
    assert any("write failed" in r.getMessage() for r in caplog.records)
    assert any(r.exc_info for r in caplog.records)


def test_audit_event_returns_true_on_success(monkeypatch) -> None:
    import maverick.audit

    seen = {}

    def _ok(kind, **payload):
        seen.update({"kind": kind, **payload})
        return True

    monkeypatch.setattr(maverick.audit, "record", _ok)
    assert audit_event("tool_start", agent="a", goal_id=3, tool="t") is True
    assert seen["kind"] == "tool_start" and seen["goal_id"] == 3


# -- the gate detects what it claims to ------------------------------------

def _scan_source(tmp_path: Path, body: str) -> list[dict]:
    f = tmp_path / "mod.py"
    f.write_text(textwrap.dedent(body), encoding="utf-8")
    return audit_contract.scan_file(f)


def test_gate_flags_a_bare_except_around_an_audit_write(tmp_path) -> None:
    hits = _scan_source(tmp_path, """
        from maverick.audit import record

        def go():
            try:
                record("tool_start", tool="t")
            except Exception:
                pass
    """)
    assert len(hits) == 1
    assert hits[0]["catches"] == ["Exception"]


def test_gate_flags_catching_only_half_the_pair(tmp_path) -> None:
    """The exact mistake that shipped: hardened against the wrong refusal."""
    hits = _scan_source(tmp_path, """
        from maverick.audit import AuditWriteRefused, record

        def go():
            try:
                record("tool_start", tool="t")
            except AuditWriteRefused:
                raise
            except Exception:
                pass
    """)
    assert len(hits) == 1
    assert hits[0]["partial"] == ["AuditWriteRefused"]


def test_gate_accepts_the_base_class_reraise(tmp_path) -> None:
    assert _scan_source(tmp_path, """
        from maverick.audit import AuditRefused, record

        def go():
            try:
                record("tool_start", tool="t")
            except AuditRefused:
                raise
            except Exception:
                pass
    """) == []


def test_gate_requires_the_handler_to_actually_reraise(tmp_path) -> None:
    """Catching the base and swallowing it is worse than not catching it."""
    hits = _scan_source(tmp_path, """
        from maverick.audit import AuditRefused, record

        def go():
            try:
                record("tool_start", tool="t")
            except AuditRefused:
                pass
            except Exception:
                pass
    """)
    assert len(hits) == 1


@pytest.mark.parametrize("broad", ["Exception", "BaseException", "RuntimeError", "(ValueError, Exception)"])
def test_gate_rejects_refusal_handler_shadowed_by_broad_catch(tmp_path, broad) -> None:
    hits = _scan_source(tmp_path, f"""
        from maverick.audit import AuditRefused, record

        def go():
            try:
                record("event")
            except {broad}:
                return "swallowed"
            except AuditRefused:
                raise
    """)
    assert len(hits) == 1


@pytest.mark.parametrize("handler_body", [
    "return None\nraise",
    "if suppress:\n    return None\nraise",
    "raise RuntimeError('replacement error')",
])
def test_gate_does_not_credit_unreachable_or_replaced_reraise(tmp_path, handler_body) -> None:
    source = (
        "from maverick.audit import AuditRefused, record\n"
        "def go(suppress=True):\n"
        "    try:\n"
        "        record('event')\n"
        "    except AuditRefused:\n"
        + textwrap.indent(handler_body, "        ") + "\n"
        "    except Exception:\n"
        "        pass\n"
    )
    assert len(_scan_source(tmp_path, source)) == 1


@pytest.mark.parametrize("handler", ["AuditRefused", "(AuditRefused, Exception)"])
def test_gate_flags_typed_swallow_without_another_broad_handler(tmp_path, handler) -> None:
    assert len(_scan_source(tmp_path, f"""
        from maverick.audit import AuditRefused, record

        def go():
            try:
                record("event")
            except {handler}:
                return None
    """)) == 1


def test_gate_rejects_earlier_refusal_subclass_swallow(tmp_path) -> None:
    assert len(_scan_source(tmp_path, """
        from maverick.audit import AuditRefused, AuditWriteRefused, record

        def go():
            try:
                record("event")
            except AuditWriteRefused:
                return None
            except AuditRefused:
                raise
            except Exception:
                pass
    """)) == 1


@pytest.mark.parametrize("handler_body", ["raise", "log_warning()\nraise", "raise error"])
def test_gate_accepts_reachable_refusal_propagation(tmp_path, handler_body) -> None:
    source = (
        "from maverick.audit import AuditRefused, record\n"
        "def go():\n"
        "    try:\n"
        "        record('event')\n"
        "    except AuditRefused as error:\n"
        + textwrap.indent(handler_body, "        ") + "\n"
        "    except Exception:\n"
        "        pass\n"
    )
    assert _scan_source(tmp_path, source) == []


def test_gate_rejects_rebinding_the_caught_exception_before_raise(tmp_path) -> None:
    assert len(_scan_source(tmp_path, """
        from maverick.audit import AuditRefused, record

        def go():
            try:
                record("event")
            except AuditRefused as error:
                error = RuntimeError("different exception")
                raise error
            except Exception:
                pass
    """)) == 1


def test_gate_ignores_unrelated_dot_record_calls(tmp_path) -> None:
    """A naive name match inflates the census with metrics recorders."""
    assert _scan_source(tmp_path, """
        import logging

        def go(metrics):
            try:
                metrics.record("latency", 5)
                logging.getLogger(__name__).info("x")
            except Exception:
                pass
    """) == []


def test_gate_ignores_an_audit_write_with_no_handler(tmp_path) -> None:
    assert _scan_source(tmp_path, """
        from maverick.audit import record

        def go():
            record("tool_start", tool="t")
    """) == []


def test_baseline_paths_are_host_independent(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(audit_contract, "REPO_ROOT", tmp_path)
    nested = tmp_path / "packages" / "maverick-core" / "maverick" / "module.py"
    assert audit_contract._rel(nested) == (
        "packages/maverick-core/maverick/module.py"
    )


def test_gate_does_not_scan_generated_build_copies(tmp_path, monkeypatch) -> None:
    """A local package build must not duplicate every source finding."""
    monkeypatch.setattr(audit_contract, "REPO_ROOT", tmp_path)
    source = tmp_path / "packages" / "example.py"
    generated = tmp_path / "packages" / "example" / "build" / "lib" / "example.py"
    source.parent.mkdir(parents=True)
    generated.parent.mkdir(parents=True)
    body = textwrap.dedent("""
        from maverick.audit import record

        def go():
            try:
                record("event")
            except Exception:
                pass
    """)
    source.write_text(body, encoding="utf-8")
    generated.write_text(body, encoding="utf-8")

    violations, inspected = audit_contract.scan(("packages",))

    assert inspected == 1
    assert [hit["file"] for hit in violations] == ["packages/example.py"]


# -- the gate cannot pass vacuously ----------------------------------------

def test_gate_exits_non_zero_when_it_inspects_nothing(monkeypatch, capsys) -> None:
    """Five shipped gates pass having inspected zero items. Not this one."""
    monkeypatch.setattr(audit_contract, "SEARCH_ROOTS", ("no_such_root",))
    assert audit_contract.main(["--ci"]) == 2
    assert "inspected 0 files" in capsys.readouterr().err


def test_gate_inspects_a_real_and_substantial_tree() -> None:
    violations, inspected = audit_contract.scan()
    assert inspected > 500, inspected
    # The baseline is debt, not an exemption: every entry must still be a real
    # site, or the ratchet is hiding a fix nobody recorded.
    known = audit_contract.load_baseline()
    # Same key the gate uses -- file::enclosing-function, not file:line, so an
    # unrelated edit above a violation does not renumber it into a false
    # "fixed + new" pair.
    live = {audit_contract._key(v) for v in violations}
    stale = known - live
    assert not stale, (
        "baselined violations no longer present -- run "
        f"`python -m maverick.audit_contract --regen` to shrink: {sorted(stale)}"
    )


def test_the_agent_and_orchestrator_paths_are_off_the_baseline() -> None:
    """The kernel's own goal/tool records must honour the contract outright.

    These are the sites 'every action is recorded' actually depends on; they are
    fixed, not baselined, and must not regress into the debt register.
    """
    known = audit_contract.load_baseline()
    kernel = [k for k in known
              if k.startswith("packages/maverick-core/maverick/agent.py::")
              or k.startswith("packages/maverick-core/maverick/orchestrator.py::")]
    assert not kernel, kernel


def test_baseline_is_valid_json_with_the_expected_shape() -> None:
    data = json.loads(audit_contract.BASELINE.read_text(encoding="utf-8"))
    assert isinstance(data["known"], list)
    assert all("::" in k for k in data["known"])


def test_self_harness_forget_and_relapse_audits_never_swallow_a_refusal(monkeypatch) -> None:
    """Both non-strict self-harness audit writes re-raise a declined write."""
    import maverick.audit
    from maverick import self_harness

    def _refuse(*a, **kw):
        raise AuditWriteRefused("floor requires signed logs")

    monkeypatch.setattr(maverick.audit, "record", _refuse)
    with pytest.raises(AuditRefused):
        self_harness._relapse_audit("model-x", "always cite", {"recent_outcomes": [False, True]})
    with pytest.raises(AuditRefused):
        self_harness._forget_finalize("model-x", "always cite", {}, {}, [], path=None,
                                      strict=False, effect_guard=None)
