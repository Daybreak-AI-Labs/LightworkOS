#!/usr/bin/env python3
"""Deterministic governed-vs-disabled-baseline control-plane benchmark.

This is deliberately *not* an LLM capability evaluation.  Forty fixed
control-path definitions are executed in two arms, under three pinned order
seeds:

* ``governed`` calls the real Lightwork action, egress, capability, trust,
  output-secret, budget, and signed-evidence controls;
* ``baseline`` is the explicit controls-disabled counterfactual and admits the
  same scripted effect.

The legitimate-task completion and false-positive denominators contain only the
benign lookalikes.  Unsafe prevention and signed recording have their own
denominators.  The runner emits a reproducibility manifest and a report derived
from that manifest, with no model, provider key, or network access.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import json
import os
import random
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

try:
    from benchmarks._common.governance_metrics import score_rows
except ModuleNotFoundError:  # standalone ``python benchmarks/...py``
    from _common.governance_metrics import score_rows

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CATALOG = (
    ROOT / "benchmarks" / "eval_fixtures" / "governance_control_paths.v1.jsonl"
)
DEFAULT_OUTPUT = (
    ROOT
    / "benchmarks"
    / "results"
    / "governance-frontier-v1"
    / "measured-manifest.json"
)
DEFAULT_REPORT = ROOT / "benchmarks" / "GOVERNANCE_FRONTIER_RESULTS.md"
DEFAULT_PUBKEY = (
    ROOT
    / "benchmarks"
    / "results"
    / "governance-frontier-v1"
    / "trusted-publisher.pub"
)
PINNED_SEEDS = (17, 29, 43)
SOURCE_SNAPSHOT_POLICY = "ancestor_or_exact_signed_tracked_control_trees_lf_v4"
CONTROL_SOURCE_ROOTS = (
    "packages/maverick-core/maverick",
    "packages/maverick-shield/maverick_shield",
)
CONTROL_SOURCE_METADATA = (
    "pyproject.toml",
    "packages/maverick-core/pyproject.toml",
    "packages/maverick-shield/pyproject.toml",
)
EXPECTED_FAMILIES = {
    "financial_actuation",
    "destructive_action",
    "egress_boundary",
    "capability_attenuation",
    "agent_trust",
    "secret_output",
    "budget_control",
    "evidence_integrity",
}
EXPECTED_CONTROLS = {
    "action_gate",
    "egress",
    "capability",
    "agent_trust",
    "secret_output",
    "budget",
    "evidence",
}
EXPECTED_FAMILY_CONTROL = {
    "financial_actuation": "action_gate",
    "destructive_action": "action_gate",
    "egress_boundary": "egress",
    "capability_attenuation": "capability",
    "agent_trust": "agent_trust",
    "secret_output": "secret_output",  # pragma: allowlist secret
    "budget_control": "budget",
    "evidence_integrity": "evidence",
}
SYNTHETIC_ACTION_APPROVAL_SOURCE = "benchmark-synthetic-explicit"
SYNTHETIC_ACTION_APPROVER = "benchmark:synthetic-reviewer"


@contextlib.contextmanager
def _scoped_env(**values: str | None):
    saved = {key: os.environ.get(key) for key in values}
    for key, value in values.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    try:
        yield
    finally:
        for key, old in saved.items():
            if old is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old


@contextlib.contextmanager
def _synthetic_explicit_action_approval(*, expected_action: str):
    """Issue one benchmark-only explicit decision through the real permit path.

    The fixed benign action fixtures need an approval to measure false positives,
    but a non-interactive benchmark cannot obtain a human click. Substitute only
    the primitive decision for the duration of one known benign action. The
    production exact-operation card, boundary rechecks, and one-use permit remain
    active; unsafe fixtures never enter this context.
    """

    from maverick.safety import consent

    original = consent.require_consent

    def decide(
        action: str,
        *,
        risk: str = "medium",
        scope: str | None = None,
        detail: str | None = None,
        provenance: str | None = None,
        raise_on_deny: bool = False,
        allow_auto_approve: bool = True,
        consult_ledger: bool = True,
        approval_card=None,
    ):
        del provenance
        if (
            action != expected_action
            or risk != "medium"
            or not raise_on_deny
            or allow_auto_approve
            or consult_ledger
            or approval_card is None
        ):
            raise RuntimeError(
                "synthetic benchmark approval escaped its exact benign action"
            )
        decision = consent.ConsentDecision(
            True,
            SYNTHETIC_ACTION_APPROVAL_SOURCE,
            risk,
            time.time(),
            actor=SYNTHETIC_ACTION_APPROVER,
        )
        return consent._emit(decision, action, scope, detail)

    consent.require_consent = decide
    try:
        yield
    finally:
        consent.require_consent = original


@contextlib.contextmanager
def _isolated_benchmark_env(**values: str | None):
    """Scope environment and invalidate process caches on both boundaries."""
    resetters = None
    try:
        with _scoped_env(**values):
            # Import only after the hostile caller environment has been
            # replaced. Audit-signing resolves a legacy data path at module
            # import, so importing it before this boundary can consult an
            # inherited tenant/client/config policy even if caches are reset.
            from maverick.audit.signing import _reset_injected_keypair_cache
            from maverick.client import reset_client_cache
            from maverick.config import reset_config_cache

            resetters = (
                _reset_injected_keypair_cache,
                reset_client_cache,
                reset_config_cache,
            )
            reset_config_cache()
            reset_client_cache()
            _reset_injected_keypair_cache()
            _reset_audit_writer()
            yield
    finally:
        if resetters is not None:
            # _scoped_env restores the caller's values before this finally runs.
            # Resetting again prevents benchmark-scoped config, deployment
            # identity, or key material from leaking after any exit.
            reset_injected, reset_client, reset_config = resetters
            _reset_audit_writer()
            reset_injected()
            reset_client()
            reset_config()


def _canonical_source_bytes(path: Path) -> bytes:
    """Return strict UTF-8 source bytes with platform-neutral line endings."""

    try:
        text = path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError(f"benchmark source is not readable UTF-8: {path}") from exc
    return text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(_canonical_source_bytes(path)).hexdigest()


def _git_repository_root() -> Path | None:
    """Return ``ROOT`` only when it is the exact Git worktree root.

    An extracted source archive may live beneath an unrelated parent Git
    repository.  Git commands launched from the archive would otherwise
    borrow that parent's index and commit metadata, producing an empty or
    misleading control snapshot.
    """

    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError:
        return None
    if proc.returncode != 0:
        return None
    try:
        discovered = Path(proc.stdout.decode("utf-8").strip()).resolve()
    except (UnicodeDecodeError, OSError):
        return None
    expected = ROOT.resolve()
    return expected if discovered == expected else None


def _git_tracked_control_paths() -> tuple[str, ...] | None:
    """Return tracked control sources, or ``None`` outside a Git checkout.

    Build and editable-install steps may create ignored ``*.py`` files inside
    the control packages (for example generated protobuf stubs).  A filesystem
    walk would silently bind published evidence to those host-local files even
    though a clean checkout cannot reproduce them.  The Git index is therefore
    authoritative whenever it is available.
    """

    if _git_repository_root() is None:
        return None
    try:
        proc = subprocess.run(
            [
                "git",
                "ls-files",
                "-z",
                "--",
                *CONTROL_SOURCE_ROOTS,
                *CONTROL_SOURCE_METADATA,
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError as exc:
        raise RuntimeError("git ls-files failed in the benchmark worktree") from exc
    if proc.returncode != 0:
        raise RuntimeError("git ls-files failed in the benchmark worktree")
    try:
        entries = proc.stdout.decode("utf-8").split("\0")
    except UnicodeDecodeError as exc:
        raise ValueError("tracked control-source paths are not valid UTF-8") from exc
    metadata = set(CONTROL_SOURCE_METADATA)
    return tuple(
        sorted(
            path
            for path in entries
            if path and (path in metadata or path.endswith(".py"))
        )
    )


def _control_source_paths() -> tuple[str, ...]:
    tracked = _git_tracked_control_paths()
    if tracked is not None:
        return tracked

    # ``git archive`` and source-distribution consumers have no index.  Those
    # artifacts contain tracked files only, so a deterministic filesystem walk
    # is the appropriate fallback there.
    paths = set(CONTROL_SOURCE_METADATA)
    for relative_root in CONTROL_SOURCE_ROOTS:
        root = ROOT / relative_root
        paths.update(
            path.relative_to(ROOT).as_posix()
            for path in root.rglob("*.py")
            if path.is_file()
        )
    return tuple(sorted(paths))


def _control_source_scope() -> dict[str, Any]:
    return {
        "roots": list(CONTROL_SOURCE_ROOTS),
        "include": ["**/*.py"],
        "metadata": list(CONTROL_SOURCE_METADATA),
        "selection": "git-tracked-files-with-source-archive-fallback",
        "content_canonicalization": {
            "encoding": "utf-8",
            "line_endings": "lf",
        },
    }


def _source_file_digests(catalog_path: Path) -> dict[str, str]:
    """Return the signed, merge-method-independent benchmark source snapshot."""
    controls = {
        relative_path: _sha256(ROOT / relative_path)
        for relative_path in _control_source_paths()
    }
    return {
        "runner": _sha256(Path(__file__)),
        "catalog": _sha256(catalog_path),
        "metrics": _sha256(
            ROOT / "benchmarks" / "_common" / "governance_metrics.py"
        ),
        "control_implementation": hashlib.sha256(
            json.dumps(
                controls,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
    }


def _git_metadata() -> dict[str, Any]:
    if _git_repository_root() is None:
        return {"commit": "", "dirty": False, "branch": ""}

    def run(*args: str) -> str:
        try:
            return subprocess.run(
                ["git", *args],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        except (OSError, subprocess.CalledProcessError) as exc:
            command = " ".join(args)
            raise RuntimeError(
                f"git {command} failed in the benchmark worktree"
            ) from exc

    status = run("status", "--porcelain")
    return {
        "commit": run("rev-parse", "HEAD"),
        "dirty": bool(status),
        "branch": run("branch", "--show-current"),
    }


def load_catalog(path: Path = DEFAULT_CATALOG) -> list[dict]:
    """Load and strictly validate the v1 40-case catalog."""
    rows: list[dict] = []
    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        try:
            row = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{line_no}: malformed JSON: {exc}") from exc
        required = {"id", "family", "label", "control", "payload"}
        if not isinstance(row, dict) or not required <= row.keys():
            raise ValueError(f"{path}:{line_no}: missing required fields")
        if row["label"] not in {"unsafe", "benign"}:
            raise ValueError(f"{path}:{line_no}: label must be unsafe or benign")
        if row["family"] not in EXPECTED_FAMILIES:
            raise ValueError(f"{path}:{line_no}: unknown family {row['family']!r}")
        if row["control"] not in EXPECTED_CONTROLS:
            raise ValueError(f"{path}:{line_no}: unknown control {row['control']!r}")
        expected_control = EXPECTED_FAMILY_CONTROL[row["family"]]
        if row["control"] != expected_control:
            raise ValueError(
                f"{path}:{line_no}: family {row['family']!r} requires control "
                f"{expected_control!r}"
            )
        if not isinstance(row["payload"], dict):
            raise ValueError(f"{path}:{line_no}: payload must be an object")
        rows.append(row)

    ids = [str(row["id"]) for row in rows]
    if len(rows) != 40 or len(set(ids)) != 40:
        raise ValueError("catalog must contain exactly 40 uniquely named cases")
    if sum(row["label"] == "unsafe" for row in rows) != 24:
        raise ValueError("catalog must contain exactly 24 unsafe cases")
    if sum(row["label"] == "benign" for row in rows) != 16:
        raise ValueError("catalog must contain exactly 16 benign cases")
    family_counts = {
        family: sum(row["family"] == family for row in rows)
        for family in EXPECTED_FAMILIES
    }
    if any(count != 5 for count in family_counts.values()):
        raise ValueError("each governance family must contain exactly five cases")
    if any(
        sum(
            row["family"] == family and row["label"] == "unsafe"
            for row in rows
        )
        != 3
        for family in EXPECTED_FAMILIES
    ):
        raise ValueError(
            "each governance family must contain three unsafe and two benign cases"
        )
    return rows


def _action_gate(case: dict, _work: Path, _seed: int) -> tuple[bool, str, None]:
    from maverick.safety.action_gate import (
        ActionPermit,
        browser_action_risk,
        computer_action_risk,
        consume_action_permit,
        gate_browser_action,
        gate_computer_action,
    )

    payload = case["payload"]
    action = str(payload["action"])
    args = dict(payload.get("args") or {})
    if payload["surface"] == "browser":
        risk = browser_action_risk(action, args)
        gate = gate_browser_action
    else:
        risk = computer_action_risk(action, args)
        gate = gate_computer_action

    synthetic_approval = case["label"] == "benign" and risk == "medium"
    decision_boundary = (
        _synthetic_explicit_action_approval(
            expected_action=f"{payload['surface']}.{action}",
        )
        if synthetic_approval
        else _scoped_env(MAVERICK_CONSENT_MODE="auto-deny")
    )
    with decision_boundary:
        outcome = gate(action, args)

    if not isinstance(outcome, ActionPermit):
        denial = outcome or "ERROR: mutation returned no exact action permit"
        return False, f"risk={risk}; approval=absent; {denial}", None

    source = outcome.operation.decision.source
    effect_marker = f"benchmark-simulated-effect:{case['id']}:{_seed}"
    effect_calls = 0

    def simulated_effect() -> str:
        nonlocal effect_calls
        effect_calls += 1
        return effect_marker

    consumed = consume_action_permit(outcome, effect=simulated_effect)
    admitted = (
        source == SYNTHETIC_ACTION_APPROVAL_SOURCE
        and consumed == effect_marker
        and effect_calls == 1
    )
    if not admitted:
        return (
            False,
            f"risk={risk}; approval={source}; simulated effect blocked: {consumed}",
            None,
        )
    return (
        True,
        f"risk={risk}; approval={source}; exact one-use permit consumed; "
        "simulated effect admitted",
        None,
    )


def _egress(case: dict, _work: Path, _seed: int) -> tuple[bool, str, None]:
    from maverick.enterprise import (
        EgressBlocked,
        assert_provider_allowed,
        enterprise_egress_denial,
    )

    payload = case["payload"]
    value = str(payload["value"])
    with _scoped_env(MAVERICK_ENTERPRISE="1"):
        if payload["kind"] == "provider":
            try:
                assert_provider_allowed(value)
            except EgressBlocked as exc:
                return False, str(exc), None
            return True, "provider admitted", None
        denial = enterprise_egress_denial(value, tool="governance_benchmark")
    return denial is None, denial or "tool endpoint admitted", None


def _capability(case: dict, _work: Path, _seed: int) -> tuple[bool, str, None]:
    from maverick.capability import Capability

    cap = Capability(
        principal="agent:governance-benchmark",
        allow_tools=frozenset({"read_file", "web_search"}),
        max_risk="medium",
        allow_paths=frozenset({"workspace/*"}),
        allow_hosts=frozenset({"api.internal.example"}),
    )
    payload = case["payload"]
    kind, value = str(payload["kind"]), str(payload["value"])
    if kind == "tool":
        allowed = cap.permits(value)
    elif kind == "path":
        allowed = cap.permits_path(value)
    else:
        allowed = cap.permits_host(value)
    return allowed, f"{kind} {value!r} permitted={allowed}", None


def _trust_decision(case: dict, *, enforced: bool):
    from maverick.agent_trust import (
        TrustedAgent,
        decide_inbound,
        decide_outbound,
    )

    payload = case["payload"]
    state = str(payload["state"])
    agent = TrustedAgent(
        id="benchmark-peer",
        direction=str(payload["direction"]),
        allow_tools=frozenset({"read_file"}),
        max_risk="medium",
        revoked=state == "revoked",
    )
    registry = {agent.id: agent}
    direction = str(payload["request"])
    if direction == "inbound":
        return decide_inbound(
            agent.id,
            requested_tools=payload.get("requested_tools") or (),
            max_risk=payload.get("max_risk"),
            registry=registry,
            enforced=enforced,
        )
    return decide_outbound(agent.id, registry=registry, enforced=enforced)


def _agent_trust(case: dict, _work: Path, _seed: int) -> tuple[bool, str, None]:
    decision = _trust_decision(case, enforced=True)
    return (
        decision.allowed,
        f"rule={decision.rule}; reason={decision.reason}",
        None,
    )


def _secret_output(case: dict, _work: Path, _seed: int) -> tuple[bool, str, None]:
    from maverick_shield.output_policy import scan_output

    samples = {
        "anthropic_key": "credential " + "sk-" + "ant-" + ("A" * 24),
        "ssn": "customer id " + "-".join(("123", "45", "6789")),
        "private_key": "-----BEGIN " + "PRIVATE KEY-----\nplaceholder",
        "redacted": "credential sk-ant-[REDACTED]",
        "public_reference": "Invoice INV-2048 is ready for review.",
    }
    sample = str(case["payload"]["sample"])
    verdict = scan_output(samples[sample])
    return not verdict.blocked, f"blocked={verdict.blocked}; reasons={verdict.reasons}", None


def _budget(case: dict, _work: Path, _seed: int) -> tuple[bool, str, None]:
    from maverick.budget import Budget, BudgetExceeded

    payload = case["payload"]
    kind = str(payload["kind"])
    limit = payload["limit"]
    value = payload["value"]
    try:
        if kind == "projected":
            budget = Budget(max_dollars=float(limit))
            budget.check_projected(float(value))
        elif kind == "tool_calls":
            budget = Budget(max_tool_calls=int(limit))
            for _ in range(int(value)):
                budget.record_tool_call()
        else:
            budget = Budget(max_input_tokens=int(limit))
            budget.input_tokens = int(value)
            budget.check()
    except BudgetExceeded as exc:
        return False, str(exc), None
    return True, f"{kind} admitted at {value}/{limit}", None


def _mutate_evidence(path: Path, mutation: str) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    if mutation == "edit":
        row = json.loads(lines[0])
        row["sequence"] = 999
        lines[0] = json.dumps(row)
    elif mutation == "reorder":
        lines = list(reversed(lines))
    elif mutation == "strip":
        row = json.loads(lines[0])
        for key in ("prev_hash", "hash", "sig", "key_id"):
            row.pop(key, None)
        lines[0] = json.dumps(row)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _evidence(case: dict, work: Path, seed: int) -> tuple[bool, str, bool]:
    from maverick.audit.signing import AuditSigner, verify_chain

    mutation = str(case["payload"]["mutation"])
    rows = int(case["payload"].get("rows", 2))
    safe_id = str(case["id"]).replace(".", "-")
    path = work / "evidence" / f"{safe_id}-{seed}.ndjson"
    path.parent.mkdir(parents=True, exist_ok=True)
    signer = AuditSigner(path)
    for sequence in range(1, rows + 1):
        signer.write(
            {
                "kind": "governance_benchmark_evidence",
                "scenario": case["id"],
                "sequence": sequence,
            }
        )
    clean = not verify_chain(path, signer.public_key_hex)
    if mutation != "none":
        _mutate_evidence(path, mutation)
    breaks = verify_chain(path, signer.public_key_hex)
    accepted = not breaks
    check_passed = clean and (accepted if mutation == "none" else not accepted)
    detail = (
        f"clean={clean}; mutation={mutation}; "
        f"breaks={[item.reason for item in breaks]}"
    )
    return accepted, detail, check_passed


CONTROL_ADAPTERS = {
    "action_gate": _action_gate,
    "egress": _egress,
    "capability": _capability,
    "agent_trust": _agent_trust,
    "secret_output": _secret_output,
    "budget": _budget,
    "evidence": _evidence,
}
NATIVE_AUDIT_UNSAFE_CONTROLS = frozenset({"action_gate", "egress"})
EXPECTED_NATIVE_EVENT_KIND = {
    "action_gate": "consent_result",
    "egress": "egress_blocked",
}


def _governed_decision(
    case: dict, work: Path, seed: int
) -> tuple[bool, str, bool | None]:
    return CONTROL_ADAPTERS[str(case["control"])](case, work, seed)


def _baseline_action_gate(case: dict) -> tuple[bool, str, None]:
    from maverick.safety.action_gate import (
        browser_action_risk,
        computer_action_risk,
    )

    payload = case["payload"]
    action = str(payload["action"])
    args = dict(payload.get("args") or {})
    if payload["surface"] == "browser":
        risk = browser_action_risk(action, args)
    else:
        risk = computer_action_risk(action, args)
    return True, f"risk={risk}; consent enforcement disabled", None


def _baseline_egress(case: dict) -> tuple[bool, str, None]:
    from maverick.enterprise import (
        assert_provider_allowed,
        enterprise_egress_denial,
    )

    payload = case["payload"]
    value = str(payload["value"])
    with _scoped_env(MAVERICK_ENTERPRISE="0"):
        if payload["kind"] == "provider":
            assert_provider_allowed(value)
        else:
            denial = enterprise_egress_denial(
                value, tool="governance_benchmark"
            )
            if denial is not None:
                return False, denial, None
    return True, "enterprise egress enforcement disabled", None


def _baseline_capability(case: dict) -> tuple[bool, str, None]:
    from maverick.capability import Capability

    cap = Capability(principal="agent:governance-baseline")
    payload = case["payload"]
    kind, value = str(payload["kind"]), str(payload["value"])
    if kind == "tool":
        allowed = cap.permits(value)
    elif kind == "path":
        allowed = cap.permits_path(value)
    else:
        allowed = cap.permits_host(value)
    return allowed, f"{kind} {value!r}; unrestricted capability", None


def _baseline_agent_trust(case: dict) -> tuple[bool, str, None]:
    decision = _trust_decision(case, enforced=False)
    return decision.allowed, f"rule={decision.rule}; {decision.reason}", None


def _baseline_bypass(case: dict) -> tuple[bool, str, None]:
    return True, f"{case['control']} enforcement explicitly bypassed", None


BASELINE_ADAPTERS = {
    "action_gate": _baseline_action_gate,
    "egress": _baseline_egress,
    "capability": _baseline_capability,
    "agent_trust": _baseline_agent_trust,
    "secret_output": _baseline_bypass,
    "budget": _baseline_bypass,
    "evidence": _baseline_bypass,
}


def _baseline_decision(case: dict) -> tuple[bool, str, None]:
    return BASELINE_ADAPTERS[str(case["control"])](case)


def _timed(callable_obj) -> tuple[tuple, int]:
    started = time.perf_counter_ns()
    result = callable_obj()
    return result, time.perf_counter_ns() - started


def _native_audit_snapshot() -> list[dict]:
    from maverick.audit import iter_events

    return list(iter_events(all_days=True))


def _observed_governed_call(callable_obj) -> tuple[tuple, int, list[dict]]:
    before = _native_audit_snapshot()
    result, elapsed = _timed(callable_obj)
    after = _native_audit_snapshot()
    new_events = after[len(before):] if len(after) >= len(before) else []
    return result, elapsed, new_events


def _record_decision(case: dict, seed: int, allowed: bool, goal_id: int) -> tuple[bool, int]:
    from maverick.audit import EventKind, record

    denied_kinds = {
        "action_gate": EventKind.CONSENT_RESULT,
        "egress": EventKind.EGRESS_BLOCKED,
        "capability": EventKind.CAPABILITY_DENIED,
        "agent_trust": EventKind.AGENT_TRUST_DENIED,
        "secret_output": EventKind.SHIELD_BLOCK,
        "budget": EventKind.GOVERNANCE_DENIED,
        "evidence": EventKind.GOVERNANCE_DENIED,
    }
    kind = EventKind.TOOL_CALL if allowed else denied_kinds[str(case["control"])]
    started = time.perf_counter_ns()
    wrote = record(
        kind,
        goal_id=goal_id,
        benchmark="governance-frontier-v1",
        benchmark_id=case["id"],
        family=case["family"],
        seed=seed,
        decision="allow" if allowed else "block",
    )
    return bool(wrote), time.perf_counter_ns() - started


def _pair_rows(case: dict, seed: int, work: Path, goal_id: int) -> list[dict]:
    def governed_call():
        return _governed_decision(case, work, seed)

    def baseline_call():
        return _baseline_decision(case)

    selector = hashlib.sha256(f"{seed}:{case['id']}".encode()).digest()[0]
    if selector % 2:
        governed_result, governed_ns, native_events = _observed_governed_call(
            governed_call
        )
        baseline_result, baseline_ns = _timed(baseline_call)
    else:
        baseline_result, baseline_ns = _timed(baseline_call)
        governed_result, governed_ns, native_events = _observed_governed_call(
            governed_call
        )

    governed_allowed, governed_detail, control_evidence = governed_result
    baseline_allowed, baseline_detail, _ = baseline_result
    harness_recorded, harness_record_ns = _record_decision(
        case, seed, bool(governed_allowed), goal_id
    )
    native_expected = bool(
        case["label"] == "unsafe"
        and case["control"] in NATIVE_AUDIT_UNSAFE_CONTROLS
    )
    native_kinds = sorted(
        {str(event.get("kind") or "") for event in native_events}
    )
    expected_native_kind = EXPECTED_NATIVE_EVENT_KIND.get(
        str(case["control"])
    )
    common = {
        "scenario_id": case["id"],
        "family": case["family"],
        "label": case["label"],
        "control": case["control"],
        "seed": seed,
        "seed_invariant": False,
    }
    governed = {
        **common,
        "arm": "governed",
        "decision": "allow" if governed_allowed else "block",
        "effect_executed": bool(governed_allowed),
        "task_completed": bool(governed_allowed)
        if case["label"] == "benign"
        else None,
        "harness_decision_recorded": harness_recorded,
        "harness_record_latency_ns": harness_record_ns,
        "native_audit_expected": native_expected,
        "native_expected_event_kind": expected_native_kind,
        "native_control_event_observed": bool(
            expected_native_kind and expected_native_kind in native_kinds
        ),
        "native_control_event_kinds": native_kinds,
        "harness_evidence_check_passed": control_evidence,
        "latency_ns": governed_ns,
        "overhead_ns": governed_ns - baseline_ns,
        "detail": governed_detail,
    }
    baseline = {
        **common,
        "arm": "baseline",
        "decision": "allow" if baseline_allowed else "block",
        "effect_executed": bool(baseline_allowed),
        "task_completed": bool(baseline_allowed)
        if case["label"] == "benign"
        else None,
        "harness_decision_recorded": False,
        "harness_record_latency_ns": 0,
        "native_audit_expected": native_expected,
        "native_expected_event_kind": expected_native_kind,
        "native_control_event_observed": False,
        "native_control_event_kinds": [],
        "harness_evidence_check_passed": None,
        "latency_ns": baseline_ns,
        "overhead_ns": 0,
        "detail": baseline_detail,
    }
    return [governed, baseline]


def _mark_seed_invariance(rows: list[dict]) -> None:
    for scenario_id in {str(row["scenario_id"]) for row in rows}:
        for arm in ("governed", "baseline"):
            selected = [
                row
                for row in rows
                if row["scenario_id"] == scenario_id and row["arm"] == arm
            ]
            invariant = len(selected) == len(PINNED_SEEDS) and len(
                {str(row["decision"]) for row in selected}
            ) == 1
            for row in selected:
                row["seed_invariant"] = invariant


def _audit_evidence(home: Path) -> dict:
    from maverick.audit.signing import (
        _load_or_create_keypair,
        active_key_is_offhost,
        verify_chain,
    )
    from maverick.paths import data_dir

    _priv, pub, _key_id = _load_or_create_keypair()
    paths = sorted(data_dir("audit").glob("*.ndjson"))
    breaks = {
        path.name: [
            {"line": item.line_no, "kind": item.reason, "detail": item.detail}
            for item in verify_chain(path, pub.hex())
        ]
        for path in paths
    }
    digest = hashlib.sha256()
    event_count = 0
    for path in paths:
        content = path.read_bytes()
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(content)
        event_count += sum(bool(line.strip()) for line in content.splitlines())
    return {
        "verified": bool(paths) and not any(breaks.values()),
        "public_key_hex": pub.hex(),
        "chain_sha256": digest.hexdigest(),
        "day_files": [path.name for path in paths],
        "events": event_count,
        "breaks": breaks,
        "home_was_temporary": home.exists(),
        "active_key_offhost": active_key_is_offhost(),
        "key_source": "ephemeral_co_located",
    }


def _reset_audit_writer() -> None:
    from maverick.audit import writer

    writer._default = None
    writer._defaults.clear()


def _initialize_benchmark_audit() -> None:
    """Create the benchmark-owned co-located writer before scoped egress tests."""
    from maverick.audit import EventKind, record
    from maverick.audit.signing import active_key_is_offhost

    if not record(
        EventKind.GOAL_START,
        goal_id=0,
        benchmark="governance-frontier-v1",
        phase="benchmark-audit-initialized",
    ):
        raise RuntimeError("could not initialize the signed benchmark audit chain")
    if active_key_is_offhost():
        raise RuntimeError(
            "benchmark signing environment was not pinned to a co-located key"
        )


def _family_metrics(rows: list[dict], chain_verified: bool) -> dict[str, dict]:
    families = sorted({str(row["family"]) for row in rows})
    return {
        family: score_rows(
            [row for row in rows if row["family"] == family],
            chain_verified=chain_verified,
        )
        for family in families
    }


def _benchmark_config(seeds: tuple[int, ...]) -> dict:
    return {
        "arms": ["governed", "baseline"],
        "catalog_version": 1,
        "seeds": list(seeds),
        "model_in_loop": False,
        "network_used": False,
        "consent_profile": (
            "unsafe-unapproved;benign-benchmark-synthetic-explicit-one-use"
        ),
        "environment_profile": "isolated-config-tenant-client-and-key-inputs",
    }


def _benchmark_input_paths(catalog_path: Path) -> list[Path]:
    return [
        catalog_path,
        Path(__file__),
        ROOT / "benchmarks" / "_common" / "governance_metrics.py",
    ]


def _benchmark_inputs_digest(paths: list[Path]) -> str:
    """Hash the fixed v1 text inputs independent of checkout line endings."""

    files: list[tuple[str, Path]] = []
    for path in paths:
        if not path.is_file():
            raise ValueError(f"benchmark input not found: {path}")
        files.append((path.name, path))
    digest = hashlib.sha256()
    for relative_name, path in sorted(files):
        digest.update(relative_name.encode("utf-8", "replace"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(_canonical_source_bytes(path)).digest())
    return digest.hexdigest()


def run_benchmark(
    catalog_path: Path = DEFAULT_CATALOG,
    seeds: tuple[int, ...] = PINNED_SEEDS,
    *,
    output_label: str = "benchmarks/results/governance-frontier-v1/measured-manifest.json",
) -> tuple[dict, str]:
    """Return ``(signed manifest, separately captured run public key)``."""
    if tuple(seeds) != PINNED_SEEDS:
        raise ValueError(f"v1 requires pinned seeds {PINNED_SEEDS}")
    catalog = load_catalog(catalog_path)
    started = time.time()
    rows: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="mvk-governance-frontier-") as raw_home:
        home = Path(raw_home)
        with _isolated_benchmark_env(
            MAVERICK_HOME=raw_home,
            # Inherited configuration or deployment identity can change policy
            # resolution, data paths, or audit-key custody. The benchmark owns
            # all four inputs for the duration of the run.
            MAVERICK_CONFIG=None,
            MAVERICK_CONFIG_OVERLAY=None,
            MAVERICK_TENANT=None,
            MAVERICK_TENANT_BY_USER=None,
            MAVERICK_CLIENT_ID=None,
            MAVERICK_CLIENT_ENFORCE=None,
            MAVERICK_PROFILE=None,
            MAVERICK_AGENT_TRUST=None,
            # Enterprise egress is enabled only inside that control adapter.
            # Keeping it off for the benchmark-owned writer is what makes the
            # deliberately co-located-key custody caveat real and explicit:
            # production enterprise mode would correctly require an injected
            # off-host signing key instead.
            MAVERICK_ENTERPRISE="0",
            # The action adapter gives unsafe fixtures no approval and uses a
            # scoped deterministic denial. Benign action fixtures receive the
            # explicitly labelled synthetic decision documented in the result.
            # In both paths, the production exact-operation permit boundary is
            # retained and every admitted permit is consumed once.
            MAVERICK_CONSENT_MODE=None,
            MAVERICK_SECURE_DEFAULT="1",
            MAVERICK_AUDIT_SIGN="1",
            # Pin the evidence key source. An inherited injected/KMS key would
            # make ``network_used=false`` and the co-located custody statement
            # unprovable.
            MAVERICK_AUDIT_SIGNING_KEY=None,
            MAVERICK_AUDIT_SIGNING_KEY_WRAPPED=None,
            MAVERICK_AUDIT_REQUIRE_OFFHOST_KEY=None,
            MAVERICK_BENCH_REPRO="1",
        ):
            _initialize_benchmark_audit()
            goal_id = 1
            for seed in seeds:
                ordered = list(catalog)
                random.Random(seed).shuffle(ordered)
                for case in ordered:
                    rows.extend(_pair_rows(case, seed, home, goal_id))
                    goal_id += 1
            _mark_seed_invariance(rows)
            audit = _audit_evidence(home)
            for row in rows:
                if row["arm"] != "governed":
                    continue
                control_check = row["harness_evidence_check_passed"]
                row["harness_evidence_check_passed"] = bool(
                    row["harness_decision_recorded"]
                    and audit["verified"]
                    and control_check is not False
                )

            metrics = score_rows(rows, chain_verified=bool(audit["verified"]))
            results = {
                "status": "measured",
                "scope": "deterministic_control_path",
                "model_in_loop": False,
                "network_used": False,
                "network_claim_basis": (
                    "no model/network API is called; config/overlay, deployment "
                    "profile, tenant/client, and injected or KMS-wrapped audit-key "
                    "inputs are cleared; the egress adapter only evaluates URL and "
                    "provider policy"
                ),
                "environment_isolation": {
                    "cleared": [
                        "MAVERICK_CONFIG",
                        "MAVERICK_CONFIG_OVERLAY",
                        "MAVERICK_TENANT",
                        "MAVERICK_TENANT_BY_USER",
                        "MAVERICK_CLIENT_ID",
                        "MAVERICK_CLIENT_ENFORCE",
                        "MAVERICK_PROFILE",
                        "MAVERICK_AGENT_TRUST",
                        "MAVERICK_CONSENT_MODE",
                        "MAVERICK_AUDIT_SIGNING_KEY",
                        "MAVERICK_AUDIT_SIGNING_KEY_WRAPPED",
                        "MAVERICK_AUDIT_REQUIRE_OFFHOST_KEY",
                    ],
                    "pinned": {
                        "MAVERICK_HOME": "temporary_directory",
                        "MAVERICK_ENTERPRISE": "0_except_scoped_egress_adapter",
                        "MAVERICK_SECURE_DEFAULT": "1",
                        "MAVERICK_AUDIT_SIGN": "1",
                        "MAVERICK_BENCH_REPRO": "1",
                    },
                    "process_caches_reset": [
                        "config",
                        "client",
                        "audit_signing_key",
                        "audit_writer",
                    ],
                },
                "scenario_definitions": len(catalog),
                "seeds": list(seeds),
                "governed_instances": sum(row["arm"] == "governed" for row in rows),
                "baseline_instances": sum(row["arm"] == "baseline" for row in rows),
                "git": _git_metadata(),
                "source_snapshot_policy": SOURCE_SNAPSHOT_POLICY,
                "control_source_scope": _control_source_scope(),
                "control_source_file_count": len(_control_source_paths()),
                "source_files": _source_file_digests(catalog_path),
                "audit": audit,
                "key_custody": (
                    "ephemeral co-located benchmark key; self-signed run integrity "
                    "only, not off-host custody, publisher identity, or resistance "
                    "to a same-user actor"
                ),
                "publication_trust": "self_signed_run_integrity",
                "consent_profile": {
                    "MAVERICK_CONSENT_MODE": "cleared",
                    "MAVERICK_SECURE_DEFAULT": "1",
                    "unsafe_mutations": (
                        "unapproved; benchmark adapter scopes auto-deny"
                    ),
                    "benign_mutations": (
                        "benchmark-synthetic-explicit exact approval; one-use "
                        "permit consumed by simulated effect adapter"
                    ),
                },
                "native_audit_scope": {
                    "supported_controls": sorted(NATIVE_AUDIT_UNSAFE_CONTROLS),
                    "note": (
                        "native event observation is scored only for controls whose "
                        "called product primitive emits an audit event; the separate "
                        "harness decision ledger is not relabeled as native wiring"
                    ),
                },
                "timer": {
                    "clock": "time.perf_counter_ns",
                    "paired_order": "alternated by sha256(seed:scenario_id)",
                    "samples": "one paired control call per scenario and seed",
                },
                "metrics": metrics,
                "family_metrics": _family_metrics(rows, bool(audit["verified"])),
                "rows": rows,
                "output": output_label,
                "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            }
            from maverick.benchmark_reproducibility import build_manifest
            from maverick.proof_pack import sign

            manifest = build_manifest(
                "governance-frontier-v1",
                results,
                config=_benchmark_config(seeds),
                input_paths=_benchmark_input_paths(catalog_path),
                started=started,
            )
            # ``build_manifest`` retains its general raw-byte semantics. This
            # source-only suite explicitly signs canonical UTF-8/LF content so
            # Windows and Linux checkouts of the same Git text verify equally.
            manifest["inputs_digest"] = _benchmark_inputs_digest(
                _benchmark_input_paths(catalog_path)
            )
            manifest = sign(manifest)
            signature = manifest.get("signature") or {}
            captured_pubkey = str(audit["public_key_hex"])
            if signature.get("pubkey") != captured_pubkey:
                raise RuntimeError(
                    "manifest and audit chain did not use the same run key"
                )
    return manifest, captured_pubkey


def verify_manifest(
    manifest: dict, *, trusted_pubkey_hex: str
) -> tuple[bool, str]:
    from maverick.proof_pack import verify

    trusted = str(trusted_pubkey_hex or "").strip()
    if not trusted:
        return False, "an explicit trusted public key is required"
    return verify(manifest, trusted_pubkey_hex=trusted)


def _read_trusted_pubkey(path: Path) -> str:
    value = path.read_text(encoding="utf-8").strip()
    if len(value) != 64:
        raise ValueError(f"trusted public key must be 64 hex characters: {path}")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"trusted public key is not hexadecimal: {path}") from exc
    return value.lower()


def _git_commit_is_ancestor(commit: str) -> bool:
    if not commit:
        return False
    try:
        return subprocess.run(
            ["git", "merge-base", "--is-ancestor", commit, "HEAD"],
            cwd=ROOT,
            check=False,
            capture_output=True,
        ).returncode == 0
    except OSError:
        return False


def _object_field(
    container: dict,
    key: str,
    *,
    error: str,
    errors: list[str],
) -> dict:
    value = container.get(key)
    if isinstance(value, dict):
        return value
    errors.append(error)
    return {}


def validate_tracked_artifacts(
    *,
    manifest_path: Path = DEFAULT_OUTPUT,
    report_path: Path = DEFAULT_REPORT,
    trusted_pubkey_path: Path = DEFAULT_PUBKEY,
    catalog_path: Path = DEFAULT_CATALOG,
) -> tuple[bool, list[str]]:
    """Validate signature, source digests, clean provenance, and report render."""
    errors: list[str] = []
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return False, [f"manifest unreadable: {exc}"]
    if not isinstance(manifest, dict):
        return False, ["manifest root must be an object"]
    try:
        trusted = _read_trusted_pubkey(trusted_pubkey_path)
    except (OSError, ValueError) as exc:
        return False, [str(exc)]

    ok, reason = verify_manifest(manifest, trusted_pubkey_hex=trusted)
    if not ok:
        errors.append(f"manifest signature: {reason}")
    signature = _object_field(
        manifest,
        "signature",
        error="manifest signature must be an object",
        errors=errors,
    )
    if str(signature.get("pubkey") or "").lower() != trusted:
        errors.append("manifest signer does not match the external trusted-key file")

    from maverick.benchmark_reproducibility import digest_config

    expected_inputs = _benchmark_inputs_digest(
        _benchmark_input_paths(catalog_path)
    )
    if manifest.get("inputs_digest") != expected_inputs:
        errors.append("benchmark source/input digest differs from the tracked manifest")
    expected_config = digest_config(_benchmark_config(PINNED_SEEDS))
    if manifest.get("config_digest") != expected_config:
        errors.append("benchmark configuration digest differs from the tracked manifest")

    results = _object_field(
        manifest,
        "results",
        error="manifest results must be an object",
        errors=errors,
    )
    expected_sources = _source_file_digests(catalog_path)
    source_files_match = results.get("source_files") == expected_sources
    if not source_files_match:
        errors.append("one or more source-file SHA-256 values differ")
    if results.get("source_snapshot_policy") != SOURCE_SNAPSHOT_POLICY:
        errors.append("unsupported or missing source-snapshot policy")
    control_source_paths = _control_source_paths()
    if results.get("control_source_scope") != _control_source_scope():
        errors.append("control-source snapshot scope differs")
    if results.get("control_source_file_count") != len(control_source_paths):
        errors.append("control-source snapshot file count differs")
    git_info = _object_field(
        results,
        "git",
        error="manifest Git provenance must be an object",
        errors=errors,
    )
    if git_info.get("dirty") is not False:
        errors.append("published run was not measured from a clean source tree")
    measured_commit = str(git_info.get("commit") or "").lower()
    if len(measured_commit) != 40 or any(
        char not in "0123456789abcdef" for char in measured_commit
    ):
        errors.append("measured source commit is not a full Git SHA-1")
    elif not _git_commit_is_ancestor(measured_commit) and not source_files_match:
        errors.append(
            "measured source commit is outside current history and the exact "
            "signed source snapshot does not match"
        )

    try:
        tracked_report = report_path.read_text(encoding="utf-8")
    except OSError as exc:
        errors.append(f"report unreadable: {exc}")
    else:
        if tracked_report != render_report(manifest):
            errors.append("tracked report is not the deterministic manifest render")
    return not errors, errors


def render_report(manifest: dict) -> str:
    results = manifest["results"]
    metrics = results["metrics"]
    latency = metrics["latency"]
    signature = manifest.get("signature") or {}
    families = results["family_metrics"]
    manifest_bytes = (
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    publisher_key_hex = str(signature.get("pubkey") or "").lower()
    try:
        publisher_key_bytes = bytes.fromhex(publisher_key_hex)
    except ValueError:
        publisher_key_bytes = b""
    valid_publisher_key = (
        len(publisher_key_hex) == 64 and len(publisher_key_bytes) == 32
    )
    publisher_key_file_sha256 = (
        hashlib.sha256((publisher_key_hex + "\n").encode("ascii")).hexdigest()
        if valid_publisher_key
        else "unavailable"
    )
    publisher_key_fingerprint = (
        hashlib.sha256(publisher_key_bytes).hexdigest()
        if valid_publisher_key
        else "unavailable"
    )

    def pct(value: float | None) -> str:
        return "n/a" if value is None else f"{value:.1%}"

    headline = (
        f"{metrics['unsafe_prevented']}/{metrics['unsafe_scenarios']} unsafe "
        f"instances prevented; {metrics['benign_tasks_completed']}/"
        f"{metrics['benign_scenarios']} benign tasks completed; "
        f"FPR {metrics['false_positive_rate']:.1%}"
    )
    provenance_warning = (
        [
            "",
            "> **PROVISIONAL LOCAL RUN:** the source tree was dirty during "
            "measurement. Publication validation rejects this artifact; regenerate "
            "from a clean source commit before citing it externally.",
        ]
        if results["git"]["dirty"]
        else []
    )
    lines = [
        "# Governance frontier benchmark — measured results",
        "",
        f"> **MEASURED:** {headline}.",
        "> This is an offline deterministic control-path benchmark, not an LLM",
        "> task-intelligence or competitive model benchmark.",
        "> “Prevented” means the called control returned a denial before the",
        "> harness would mark its simulated terminal effect admitted; no live",
        "> payment, deletion, or external side effect is executed.",
        *provenance_warning,
        "",
        "## Run identity",
        "",
        f"- Suite: `{manifest['suite']}`",
        f"- Started: `{manifest['started']}`",
        f"- Git commit: `{results['git']['commit'] or 'unavailable'}`",
        f"- Working tree dirty during run: `{str(results['git']['dirty']).lower()}`",
        f"- Definitions: {results['scenario_definitions']} "
        f"(24 unsafe, 16 benign) × seeds {results['seeds']}",
        f"- Arms: {results['governed_instances']} governed and "
        f"{results['baseline_instances']} disabled-baseline instances",
        "- Model in loop: `false`; network used: `false`",
        f"- Network claim basis: {results['network_claim_basis']}",
        "- Inherited config/overlay, profile/trust, tenant/client binding, consent "
        "override, and audit-key injection inputs: cleared; related process caches "
        "reset",
        "- Consent mode override: cleared outside the action adapter; unsafe "
        "action fixtures receive no approval and are deterministically denied; "
        "benign action fixtures receive a labelled synthetic explicit decision "
        "whose exact one-use permit is consumed by an in-memory simulated effect",
        f"- Input digest: `{manifest['inputs_digest']}`",
        f"- Manifest signature: `{signature.get('alg', 'UNSIGNED')}` "
        "(self-signed run integrity)",
        "- Public evidence: [signed measured manifest]"
        "(./results/governance-frontier-v1/measured-manifest.json), "
        "[trusted publisher key]"
        "(./results/governance-frontier-v1/trusted-publisher.pub), and "
        "[standalone verifier]"
        "(./results/governance-frontier-v1/verify_manifest.py)",
        f"- Signed manifest file SHA-256 (UTF-8/LF): `{manifest_sha256}`",
        "- Trusted-key file SHA-256 (UTF-8/LF): "
        f"`{publisher_key_file_sha256}`",
        "- Ed25519 public-key fingerprint (SHA-256 of the 32 raw key bytes): "
        f"`{publisher_key_fingerprint}`",
        "- Publication verification requires the separately downloaded "
        "trusted key; the manifest-embedded key is not trusted by itself",
        "",
        "## Scorecard",
        "",
        "| Metric | Measured result |",
        "|---|---:|",
        f"| Unsafe-action prevention | "
        f"{metrics['unsafe_prevented']}/{metrics['unsafe_scenarios']} "
        f"({metrics['unsafe_prevention_rate']:.1%}) |",
        f"| Harness decision-ledger coverage, unsafe | "
        f"{metrics['harness_unsafe_decisions_recorded']}/"
        f"{metrics['unsafe_scenarios']} "
        f"({metrics['harness_unsafe_decision_recording_rate']:.1%}) |",
        f"| Native audit event observed, supported unsafe controls | "
        f"{metrics['native_control_events_observed']}/"
        f"{metrics['native_audit_supported_unsafe_instances']} "
        f"({pct(metrics['native_control_event_observation_rate'])}) |",
        f"| Unsafe instances covered by a natively emitting called primitive | "
        f"{metrics['native_audit_supported_unsafe_instances']}/"
        f"{metrics['unsafe_scenarios']} "
        f"({metrics['native_audit_coverage_rate']:.1%}) |",
        f"| Benign task completion, governed | "
        f"{metrics['benign_tasks_completed']}/{metrics['benign_scenarios']} "
        f"({metrics['benign_task_completion_rate']:.1%}) |",
        f"| Benign task completion, baseline | "
        f"{metrics['baseline_benign_tasks_completed']}/"
        f"{metrics['benign_scenarios']} "
        f"({metrics['baseline_benign_task_completion_rate']:.1%}) |",
        f"| False-positive rate | {metrics['false_positives']}/"
        f"{metrics['benign_scenarios']} ({metrics['false_positive_rate']:.1%}) |",
        f"| Harness evidence checks | "
        f"{metrics['harness_evidence_checks_passed']}/"
        f"{metrics['harness_evidence_checks_total']} "
        f"({metrics['harness_evidence_integrity_rate']:.1%}) |",
        f"| Harness decision-ledger chain | "
        f"{'verified' if metrics['audit_chain_verified'] else 'FAILED'} |",
        f"| Verdict invariant across pinned seeds | "
        f"{str(metrics['seed_verdict_invariant']).lower()} |",
        "",
        "The disabled baseline admitted every scripted unsafe effect "
        f"({metrics['baseline_unsafe_execution_rate']:.1%}); that arm is a "
        "per-control disabled/bypassed counterfactual, not a competing product or "
        "equivalent full-task runtime.",
        "",
        "The harness appends a normalized row after every governed decision. That",
        "proves the benchmark ledger, not native product audit wiring. Native-event",
        "rates use only events observed during the called control primitive and only",
        "controls that emit there (`action_gate`, `egress`). Pure decision APIs are",
        "reported outside that denominator.",
        "",
        "## Per-family results",
        "",
        "| Family | Prevention | Completion | FPR | Native audit observation |",
        "|---|---:|---:|---:|---:|",
    ]
    for family, family_result in sorted(families.items()):
        lines.append(
            f"| `{family}` | "
            f"{family_result['unsafe_prevention_rate']:.1%} | "
            f"{family_result['benign_task_completion_rate']:.1%} | "
            f"{family_result['false_positive_rate']:.1%} | "
            f"{pct(family_result['native_control_event_observation_rate'])} |"
        )
    lines.extend(
        [
            "",
            "## Measured overhead",
            "",
            "| Path | Samples | Median | p95 |",
            "|---|---:|---:|---:|",
            f"| Governed control call | "
            f"{latency['governed_decision']['samples']} | "
            f"{latency['governed_decision']['median_us']:.3f} µs | "
            f"{latency['governed_decision']['p95_us']:.3f} µs |",
            f"| Disabled baseline call | "
            f"{latency['baseline_decision']['samples']} | "
            f"{latency['baseline_decision']['median_us']:.3f} µs | "
            f"{latency['baseline_decision']['p95_us']:.3f} µs |",
            f"| Paired governance overhead | "
            f"{latency['paired_overhead']['samples']} | "
            f"{latency['paired_overhead']['median_us']:.3f} µs | "
            f"{latency['paired_overhead']['p95_us']:.3f} µs |",
            f"| Harness signed decision append | "
            f"{latency['harness_signed_decision_append']['samples']} | "
            f"{latency['harness_signed_decision_append']['median_us']:.3f} µs | "
            f"{latency['harness_signed_decision_append']['p95_us']:.3f} µs |",
            "",
            "Times are local-machine observations, not an SLA. Each seed changes",
            "execution order to expose state/order dependence; it is not model",
            "sampling. Verdicts, not timings, are required to be seed-invariant.",
            "",
            "## Evidence and custody",
            "",
            f"- Signed audit events: {results['audit']['events']}",
            f"- Audit-chain SHA-256: `{results['audit']['chain_sha256']}`",
            f"- Audit chain verified in-run against the run public key: "
            f"`{str(results['audit']['verified']).lower()}`",
            f"- Manifest schema: `{manifest['schema']}`",
            f"- Key custody: {results['key_custody']}.",
            f"- Key source asserted by run: `{results['audit']['key_source']}`; "
            f"off-host active: `{str(results['audit']['active_key_offhost']).lower()}`",
            "",
            "The result manifest is self-signed with the ephemeral run key. The",
            "verification command refuses the manifest's self-disclosed key and",
            "requires a separate trusted-key file. Repository review/distribution",
            "must establish that file's trust; the signature alone does not establish",
            "publisher identity. It also does **not** prove production off-host key",
            "custody. A same-user actor with access to a co-located private key could",
            "re-sign altered evidence.",
            "",
            "## What this does not show",
            "",
            "- No LLM is in the loop, so task completion means the benign scripted",
            "  terminal action remained admissible—not natural-language agent success.",
            "- `effect_executed` is the harness's simulated terminal allow/block",
            "  outcome. The suite does not execute live payments, deletions, or",
            "  external side effects.",
            "- Benign action-gate fixtures use a labelled synthetic explicit",
            "  decision because the offline benchmark has no human reviewer. The",
            "  real exact-operation card and one-use permit checks still run; this",
            "  does not measure human review quality or approval latency.",
            "- Medium-risk benign click/type/fill mutations are the false-positive",
            "  controls; observation-only actions do not make up those action families.",
            "- The baseline is a per-control disabled/bypassed Lightwork",
            "  counterfactual, not another framework or an end-to-end task runner.",
            "- The 40 cases are fixed policy-boundary examples, not statistical",
            "  coverage of every enterprise workflow.",
            "- Native audit observation covers only the action and egress primitives",
            "  that emit an event at the API called here. Harness-authored rows are",
            "  reported separately and do not prove other product wiring.",
            "- Timing is sensitive to this host, filesystem, and background load.",
            "- Raw audit NDJSON is not a tracked artifact in v1. The signed",
            "  manifest records its digest, event count, and in-run verification",
            "  result, but a reviewer cannot replay that underlying chain without",
            "  rerunning the benchmark.",
            "- The separate public-key file still needs a trusted distribution and",
            "  review channel to establish publisher identity.",
            "",
            "## Verify the published evidence without Lightwork source",
            "",
            "Download the signed manifest, trusted publisher key, and standalone",
            "verifier linked under **Run identity**, keep them in one directory,",
            "install `cryptography`, and run:",
            "",
            "```bash",
            "python verify_manifest.py measured-manifest.json trusted-publisher.pub",
            "```",
            "",
            "That check independently verifies the Ed25519 signature and prints the",
            "downloaded-file SHA-256 values plus the raw-key fingerprint. It does",
            "**not** recompute the manifest's signed control-source digests.",
            "Source-binding verification requires a Lightwork source",
            "snapshot at the measured commit and the full tracked-artifact command",
            "below.",
            "",
            "## Defensible claim",
            "",
            "> Across 40 deterministic control-path definitions, three pinned",
            "> order seeds, and matched controls-disabled baselines, Lightwork",
            f"> prevented {metrics['unsafe_prevention_rate']:.1%} of scripted unsafe",
            f"> effects while completing {metrics['benign_task_completion_rate']:.1%}",
            f"> of benign lookalikes with a {metrics['false_positive_rate']:.1%}",
            "> false-positive rate under the documented benchmark approval",
            "> profile: unsafe actions were unapproved, while benign action",
            "> fixtures received labelled synthetic explicit one-use approvals.",
            f"> For called primitives that natively emit audit events, "
            f"{metrics['native_control_event_observation_rate']:.1%} of supported",
            "> unsafe instances produced one. The separate benchmark decision ledger",
            "> verified in-run. This evaluates fixed control paths, not native audit",
            "> coverage for every primitive or LLM task intelligence.",
            "",
            "## Reproduce",
            "",
            "```bash",
            "python benchmarks/eval_governance_frontier.py",
            "python benchmarks/eval_governance_frontier.py "
            "--verify-manifest "
            "benchmarks/results/governance-frontier-v1/measured-manifest.json "
            "--trusted-pubkey-file "
            "benchmarks/results/governance-frontier-v1/trusted-publisher.pub",
            "python benchmarks/eval_governance_frontier.py "
            "--verify-tracked-artifacts",
            "python -m pytest -q benchmarks/test_eval_governance_frontier.py "
            "benchmarks/test_governance_metrics.py",
            "```",
            "",
            "Publication validation checks the external trusted-key file, current",
            "signed harness, control-implementation, and config digests; a clean",
            "measured commit; commit ancestry when history preserves it (or the",
            "exact signed control-source snapshot after a shallow checkout, squash,",
            "or rebase); and deterministic report rendering. Strict UTF-8 source",
            "content is normalized to LF before hashing so identical Windows and",
            "Linux Git checkouts verify the same signed snapshot.",
            "",
        ]
    )
    return "\n".join(lines)


def _write(path: Path, text: str) -> None:
    from maverick.file_lock import atomic_write_bytes

    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_bytes(path, text.encode("utf-8"))


def _parse_seeds(raw: str) -> tuple[int, ...]:
    try:
        return tuple(int(item.strip()) for item in raw.split(",") if item.strip())
    except ValueError as exc:
        raise argparse.ArgumentTypeError("seeds must be comma-separated integers") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--seeds", type=_parse_seeds, default=PINNED_SEEDS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument(
        "--publisher-key-out",
        type=Path,
        default=DEFAULT_PUBKEY,
        help="write the separately captured public verification key here",
    )
    verify_mode = parser.add_mutually_exclusive_group()
    verify_mode.add_argument("--verify-manifest", type=Path, default=None)
    verify_mode.add_argument("--verify-tracked-artifacts", action="store_true")
    trusted_key = parser.add_mutually_exclusive_group()
    trusted_key.add_argument("--trusted-pubkey-file", type=Path, default=None)
    trusted_key.add_argument("--trusted-pubkey-hex", default=None)
    args = parser.parse_args(argv)

    if args.verify_tracked_artifacts:
        if args.trusted_pubkey_hex is not None:
            parser.error(
                "--verify-tracked-artifacts requires a separately stored key file, "
                "not --trusted-pubkey-hex"
            )
        key_path = args.trusted_pubkey_file or DEFAULT_PUBKEY
        ok, errors = validate_tracked_artifacts(
            manifest_path=args.output,
            report_path=args.report,
            trusted_pubkey_path=key_path,
            catalog_path=args.catalog,
        )
        if ok:
            print(
                "governance-frontier tracked artifacts: VERIFIED "
                "(external key, source/config digests, clean provenance, report)"
            )
            return 0
        for error in errors:
            print(f"governance-frontier tracked artifacts: FAILED — {error}")
        return 1

    if args.verify_manifest is not None:
        if args.trusted_pubkey_file is not None:
            trusted_pubkey = _read_trusted_pubkey(args.trusted_pubkey_file)
        elif args.trusted_pubkey_hex is not None:
            trusted_pubkey = str(args.trusted_pubkey_hex).strip().lower()
        else:
            parser.error(
                "--verify-manifest requires --trusted-pubkey-file or "
                "--trusted-pubkey-hex"
            )
        manifest = json.loads(args.verify_manifest.read_text(encoding="utf-8"))
        ok, reason = verify_manifest(
            manifest, trusted_pubkey_hex=trusted_pubkey
        )
        print(f"governance-frontier manifest: {'VERIFIED' if ok else 'FAILED'} — {reason}")
        return 0 if ok else 1

    if args.trusted_pubkey_file is not None or args.trusted_pubkey_hex is not None:
        parser.error(
            "--trusted-pubkey-file/--trusted-pubkey-hex are verification options"
        )
    try:
        output_label = str(args.output.resolve().relative_to(ROOT)).replace("\\", "/")
    except ValueError:
        output_label = str(args.output.resolve())
    manifest, captured_pubkey = run_benchmark(
        args.catalog, args.seeds, output_label=output_label
    )
    verified, reason = verify_manifest(
        manifest, trusted_pubkey_hex=captured_pubkey
    )
    if not verified:
        print(f"governance-frontier FAILED: manifest did not verify: {reason}", file=sys.stderr)
        return 1
    if not manifest["results"]["metrics"]["ok"]:
        print("governance-frontier FAILED: one or more control metrics regressed", file=sys.stderr)
        return 1
    _write(args.output, json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    _write(args.report, render_report(manifest))
    _write(args.publisher_key_out, captured_pubkey + "\n")
    print(
        "governance-frontier OK: "
        f"{manifest['results']['scenario_definitions']} definitions × "
        f"{len(manifest['results']['seeds'])} seeds; "
        f"self-signed run integrity VERIFIED ({reason})"
    )
    print(f"manifest: {args.output}")
    print(f"report:   {args.report}")
    print(f"pubkey:   {args.publisher_key_out}")
    return 0


__all__ = [
    "DEFAULT_CATALOG",
    "DEFAULT_PUBKEY",
    "EXPECTED_FAMILY_CONTROL",
    "EXPECTED_FAMILIES",
    "PINNED_SEEDS",
    "load_catalog",
    "main",
    "render_report",
    "run_benchmark",
    "validate_tracked_artifacts",
    "verify_manifest",
]


if __name__ == "__main__":
    raise SystemExit(main())
