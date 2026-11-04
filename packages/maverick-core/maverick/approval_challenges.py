"""Closed, modeled approval-race challenges and a disposable native receiver.

No customer incident is inferred. The exported program has a fixed finite
language; a receiver never executes uploaded Python, expressions or commands.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import types
from collections import deque
from dataclasses import dataclass, replace
from pathlib import Path

from .budget import Budget, BudgetExceeded

SCHEMA = "lightwork.approval-challenge.v1"
BOUNDS = {"requests": 1, "reviewers": 2, "steps": 12, "states": 50000}
FAMILIES = {"claim_changed": "Another reviewer takes the request after review",
            "card_changed": "The request changes after review",
            "round_changed": "An earlier review is reused after undo",
            "expired": "The review expires before the vote commits"}
GUARD = ["same_reviewed_request", "claim_available_or_held_by_reviewer", "same_decision_round", "review_not_expired"]


def enabled():
    from .config import config_source_errors, load_global_config
    return not config_source_errors(include_tenant=True) and load_global_config().get("approval_challenges", {}).get("enable") is True


def _bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def _sha(value):
    return hashlib.sha256(_bytes(value)).hexdigest()


@dataclass(frozen=True)
class State:
    card: int = 0
    claim: int = 0
    round: int = 0
    expired: bool = False
    review: tuple | None = None
    votes: int = 0
    delivered: int = 0
    effective: bool = False
    violation: bool = False


def _identity(state):
    return state.card, state.claim, state.round, state.expired


def _valid(state):
    return state.review == _identity(state) and state.claim in (0, 1) and not state.expired


def _step(state, action, quorum, *, atomic):
    if action == "read_review" and not state.effective and not state.expired:
        return replace(state, review=_identity(state))
    if action == "change_claim" and not state.effective and state.claim == 0:
        return replace(state, claim=2)
    if action == "change_card" and not state.effective and state.card == 0:
        return replace(state, card=1)
    if action == "expire" and not state.expired:
        return replace(state, expired=True)
    if action == "undo" and state.effective and state.round == 0:
        return replace(state, round=1, votes=0, delivered=0, effective=False)
    if action == "vote_other" and not state.effective and state.votes.bit_count() < quorum and state.claim in (0, 2):
        return replace(state, votes=state.votes | 2)
    if action == "vote_reviewed" and state.review is not None and not state.effective and state.votes.bit_count() < quorum and not state.votes & 1:
        if atomic and not _valid(state):
            return None
        return replace(state, votes=state.votes | 1, violation=not _valid(state))
    if action == "deliver_audit" and state.votes:
        return replace(state, delivered=state.votes, effective=state.votes.bit_count() >= quorum)
    return None


def compile_challenge(family, quorum):
    if type(family) is not str or family not in FAMILIES or type(quorum) is not int or quorum not in (1, 2):
        raise ValueError("Choose a supported approval change and one or two required sign-offs.")
    budget = Budget(max_wall_seconds=3, max_dollars=0, max_tool_calls=0)
    change = {"claim_changed": "change_claim", "card_changed": "change_card", "round_changed": "undo", "expired": "expire"}[family]
    actions = ("read_review", change, "vote_reviewed", "vote_other", "deliver_audit")
    queue, seen = deque([(State(), ())]), {State()}
    witness = None
    while queue:
        budget.check()
        state, schedule = queue.popleft()
        if len(schedule) >= BOUNDS["steps"]:
            continue
        for action in actions:
            after = _step(state, action, quorum, atomic=False)
            if after is None or after == state:
                continue
            trace = (*schedule, action)
            if after.violation:
                witness = list(trace)
                queue.clear()
                break
            if after not in seen:
                if len(seen) >= BOUNDS["states"]:
                    raise ValueError("The practice reached its situation limit. Its result is unknown; no challenge was qualified.")
                seen.add(after)
                queue.append((after, trace))
    if witness is None:
        raise ValueError("This practice did not expose an outdated sign-off within its limits. No failure example was invented.")
    # Exhaustively inspect the corrected finite model within the same bound.
    queue, checked = deque([(State(), 0)]), {State(): 0}
    while queue:
        budget.check()
        state, depth = queue.popleft()
        if depth >= BOUNDS["steps"]:
            continue
        for action in actions:
            after = _step(state, action, quorum, atomic=True)
            if after is None or after == state:
                continue
            if after.violation:
                raise ValueError("The practice correction still permits the violation. This challenge cannot be qualified.")
            if after not in checked:
                if len(checked) >= BOUNDS["states"]:
                    raise ValueError("The corrected practice reached its situation limit. Its result is unknown.")
                checked[after] = depth + 1
                queue.append((after, depth + 1))
    return {"schema": SCHEMA, "evidence_class": "bounded_protocol_model", "family": family, "quorum": quorum,
            "bounds": BOUNDS, "fault_variant": "review_checked_before_commit_only", "schedule": witness,
            "guard": GUARD, "corrected_model_states": len(checked), "permitted_release": "selected_structural_pattern_and_quorum_only"}


def artifact(value):
    if type(value) is not dict or type(value.get("family")) is not str or value.get("family") not in FAMILIES:
        raise ValueError("Choose an unmodified Lightwork approval challenge file.")
    current = compile_challenge(value["family"], value.get("quorum"))
    if _bytes(value) != _bytes(current):
        raise ValueError("This file does not match the supported practice file. No uploaded code or custom instructions were run.")
    return current


def parse(data):
    if type(data) is not bytes or not 1 <= len(data) <= 8192:
        raise ValueError("Choose a Lightwork approval challenge file within the 8 KB limit.")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("The challenge file repeats a field.")
            result[key] = value
        return result
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("This is not a supported Lightwork approval challenge file.") from exc
    return artifact(value)


def adapter_version():
    from .approval_vote_review import (
        approval_review_identity,
        channel_vote_review,
        require_locked_vote_review,
    )
    from .channel_approvals import decide_from_channel, record_vote
    from .world_model import WorldModel
    functions = (approval_review_identity, channel_vote_review, require_locked_vote_review, decide_from_channel, record_vote,
                 WorldModel.decide_approval_audited, WorldModel.claim_approval, WorldModel.undo_approval_decision,
                 WorldModel.mark_approval_audit_delivered)
    def constant(item):
        if isinstance(item, types.CodeType):
            return code_version(item)
        if isinstance(item, (tuple, list)):
            return [type(item).__name__, [constant(part) for part in item]]
        if isinstance(item, (set, frozenset)):
            return [type(item).__name__, sorted(json.dumps(constant(part)) for part in item)]
        return [type(item).__name__, repr(item)]

    def code_version(code):
        # The executable behavior of a code object, field by field. Never
        # marshal: its output also records how many references each constant
        # has in this process, so merely importing an unrelated module changed
        # the version. Installation paths (co_filename) are not behavior.
        return [code.co_code.hex(), code.co_argcount, code.co_posonlyargcount, code.co_kwonlyargcount,
                code.co_flags, code.co_name, getattr(code, "co_qualname", code.co_name), list(code.co_names),
                list(code.co_varnames), list(code.co_freevars), list(code.co_cellvars),
                getattr(code, "co_exceptiontable", b"").hex(), [constant(item) for item in code.co_consts]]
    # Bind whole files as well as loaded entry-point bodies: a helper, constant
    # or closed receiver change must invalidate a saved result. This declared
    # local adapter scope does not include customer settings or other products.
    root = Path(__file__).resolve().parent
    names = ("approval_challenges.py", "approval_vote_review.py", "approval_cards.py", "channel_approvals.py", "world_model.py",
             "file_lock.py", "paths.py", "config.py", "client.py", "crypto_at_rest.py", "safety/consent.py", "safety/dual_control.py",
             "safety/secret_detector.py", "audit/__init__.py", "audit/signing.py")
    files, total = [], 0
    for name in names:
        try:
            with (root / name).open("rb") as handle:
                data = handle.read(2 * 1024 * 1024 + 1)
        except OSError as exc:
            raise ValueError("The local software version could not be checked. No current safeguard result is confirmed.") from exc
        total += len(data)
        if len(data) > 2 * 1024 * 1024 or total > 8 * 1024 * 1024:
            raise ValueError("The local software version could not be checked within its limit. No current safeguard result is confirmed.")
        files.append([name, hashlib.sha256(data).hexdigest()])
    return _sha([sys.version, sqlite3.sqlite_version, files, [_sha(code_version(function.__code__)) for function in functions]])


def check_native(value):
    """Run only this module's fixed adapter; no customer settings cross over."""
    value = artifact(value)
    before = adapter_version()
    env = {key: os.environ[key] for key in ("SystemRoot", "WINDIR", "PATH", "TEMP", "TMP", "LANG") if key in os.environ}
    env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent)
    env["PYTHONIOENCODING"] = "utf-8"
    budget = Budget(max_wall_seconds=12, max_dollars=0, max_tool_calls=0)
    with tempfile.TemporaryDirectory(prefix="lightwork-approval-challenge-") as temporary:
        home = Path(temporary)
        (home / "config.toml").write_text("[approval]\nrequire_acknowledgement = false\n", encoding="utf-8")
        env.update(MAVERICK_HOME=str(home), MAVERICK_CONFIG=str(home / "config.toml"), MAVERICK_ENCRYPT_AT_REST="0",
                   MAVERICK_AUDIT_SIGN="1", MAVERICK_AUDIT_SIGNING_KEY=secrets.token_hex(32), MAVERICK_PROFILE="standard",
                   HOME=str(home), USERPROFILE=str(home), MAVERICK_CLIENT_ID="modeled-local-client", MAVERICK_TENANT="modeled-local-workspace")
        try:
            completed = subprocess.run([sys.executable, "-m", "maverick.approval_challenges", "--native-worker"],
                input=_bytes(value), capture_output=True, env=env, cwd=temporary,
                timeout=10, check=False)
            budget.check()
        except (subprocess.TimeoutExpired, BudgetExceeded) as exc:
            raise ValueError("The isolated local check exceeded its allowance. Its result is unknown; it was stopped without changing your approval queue.") from exc
    if completed.returncode or len(completed.stdout) > 8192:
        raise ValueError("The local approval check could not complete its isolated check. Its result is unknown; no customer request was changed.")
    try:
        result = json.loads(completed.stdout)
    except (ValueError, UnicodeError) as exc:
        raise ValueError("The local check result could not be verified. No current protection is claimed.") from exc
    expected = {"adapter_version", "fault_variant_reproduced", "native_guard_blocked", "native_vote_recorded", "evidence_class", "customer_queue_changed"}
    if type(result) is not dict or set(result) != expected or any(type(result[key]) is not bool for key in expected - {"adapter_version", "evidence_class"}):
        raise ValueError("The local check result could not be verified. No current protection is claimed.")
    if result["evidence_class"] != "isolated_native_execution_of_bounded_model" or result["customer_queue_changed"]:
        raise ValueError("The local check did not match its declared isolated scope.")
    if result.get("adapter_version") != before or adapter_version() != before:
        raise ValueError("The installed approval safeguards changed during the check. Review a fresh local result.")
    return result


def _native_replay(value, *, guarded, path):
    from .approval_cards import build_approval_card, encode_approval_detail
    from .approval_vote_review import channel_vote_review
    from .channel_approvals import ChannelApprovalRefused, audit_approval_decision, record_vote
    from .world_model import WorldModel

    world = WorldModel(path)
    def card(*, changed=False, expired=False):
        return build_approval_card(action="modeled.local.review", summary="Changed fictional request" if changed else "Fictional local approval challenge", target_label="Disposable local model",
            target={}, parameters={}, parameter_summary=["Record only a fictional vote"], actor="user:model-requester", workspace="model",
            role="operator", authority_versions={}, input_versions={}, credential_versions={}, budget={"currency": "USD", "maximum": 0},
            expires_at=1 if expired else 4102444800, known_effects=["Record a fictional vote in a disposable local database"], unresolved_assumptions=[], before="Fictional pending request", after="Fictional vote", irreversible=False)
    request_card = card()
    # A request the consent wait holds, so the declared undo transition applies.
    identity = world.create_approval("modeled.local.review", detail=encode_approval_detail(request_card),
        approvals_required=value["quorum"], requested_by="user:model-requester", undoable=True)
    review, last_event, violation = None, None, False
    for action in value["schedule"]:
        if action == "read_review":
            review = channel_vote_review(world, world.get_approval(identity), status="approved", actor="user:model-reviewer",
                                         binding=request_card["binding_sha256"])
        elif action == "change_claim":
            if not world.claim_approval(identity, "user:model-other"):
                raise ValueError("The declared native claim transition was unavailable.")
        elif action in ("change_card", "expire"):
            # Explicitly modeled mutation in the disposable DB, never an
            # invented customer incident or a production card-edit operation.
            replacement = card(changed=action == "change_card", expired=action == "expire")
            with world._writing() as conn:
                conn.execute("UPDATE approvals SET detail = ? WHERE id = ?", (encode_approval_detail(replacement), identity))
        elif action == "vote_other":
            other = channel_vote_review(world, world.get_approval(identity), status="approved", actor="user:model-other", binding=request_card["binding_sha256"])
            last_event = record_vote(world, identity, "approved", "user:model-other", reviewed_card=other)
        elif action == "deliver_audit":
            if last_event is not None:
                audit_approval_decision(world, last_event)
        elif action == "undo":
            if world.undo_approval_decision(identity, undone_by="user:model-reviewer", within_seconds=60) != "undone":
                raise ValueError("The declared native undo transition was unavailable.")
        elif action == "vote_reviewed":
            try:
                last_event = record_vote(world, identity, "approved", "user:model-reviewer", reviewed_card=review if guarded else None)
            except ChannelApprovalRefused as exc:
                if guarded and exc.reason in ("stale_card", "expired"):
                    return {"blocked": True, "vote_recorded": False}
                raise
            current = world.get_approval(identity)
            changed = (review["identity"] != channel_vote_review(world, current, status="approved", actor="user:model-reviewer",
                        binding=request_card["binding_sha256"])["identity"] or review["event_id"] != world.approval_audit_event_id(identity, "approved", "user:model-reviewer"))
            violation = violation or changed
    return {"blocked": False, "vote_recorded": bool(last_event), "violation": violation}


def _worker():
    import socket
    def no_network(*_args, **_kwargs):
        raise RuntimeError("Network access is unavailable in this isolated approval check.")
    socket.create_connection = no_network
    socket.socket.connect = no_network
    socket.socket.connect_ex = no_network
    value = parse(sys.stdin.buffer.read(8193))
    home = Path(os.environ["MAVERICK_HOME"])
    from .paths import tenant_scope
    # Distinct fictional tenants keep each receiver's native audit identities
    # separate, including delivered first-round votes before an undo.
    with tenant_scope(tenant="modeled-local-fault"):
        fault = _native_replay(value, guarded=False, path=home / "modeled-fault.db")
    with tenant_scope(tenant="modeled-local-receiver"):
        actual = _native_replay(value, guarded=True, path=home / "native-receiver.db")
    print(json.dumps({"adapter_version": adapter_version(), "fault_variant_reproduced": bool(fault.get("violation")),
                      "native_guard_blocked": actual["blocked"], "native_vote_recorded": actual["vote_recorded"],
                      "evidence_class": "isolated_native_execution_of_bounded_model", "customer_queue_changed": False}))


if __name__ == "__main__":
    if sys.argv[1:] != ["--native-worker"]:
        raise SystemExit("This module accepts only its fixed isolated native receiver.")
    _worker()
