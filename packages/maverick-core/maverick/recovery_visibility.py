"""Complete bounded paired-history diagnostics on isolated native approvals.

The generated histories are fictional local practices. They say nothing about
unobserved remote effects, customer incidents, or research superiority.
"""
from __future__ import annotations

import itertools
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
from collections import deque
from pathlib import Path

from .approval_challenges import adapter_version as approval_version
from .budget import Budget, BudgetExceeded
from .governed_operations import digest

SCHEMA = "lightwork.recovery-visibility.v1"
MAX_STEPS, MAX_OPERATIONS, MAX_SECONDS = 3, 1200, 20
ACTIONS = {"first_vote": "First reviewer records a sign-off", "other_vote": "Second reviewer records a sign-off",
           "activity": "Deliver all currently pending local activity", "undo": "Separately undo the effective decision"}
OBSERVATIONS = {"status": "Current decision status", "count": "Number of current sign-offs",
                "receipt": "Original first-reviewer decision receipt", "activity": "Original local activity acknowledgement",
                "round": "Number of separate Undo decisions"}
OBLIGATIONS = {
    "not_recorded": "No accepted original first-reviewer vote is recorded. Another person's decision is not this reviewer's receipt.",
    "activity_unknown": "The original first-reviewer vote is recorded, but local activity delivery is unconfirmed. Do not repeat the vote or claim an effective decision.",
    "undone": "The original first-reviewer vote has local activity acknowledgement and was separately undone. Its historical receipt does not authorize a new vote.",
    "waiting": "The original first-reviewer vote has local activity acknowledgement; a further distinct sign-off is still needed.",
    "effective": "The original first-reviewer vote has local activity acknowledgement and the fictional decision is effective. Do not repeat it.",
}


def choices(value):
    if (type(value) is not dict or set(value) != {"quorum", "steps", "observations"}
            or type(value["quorum"]) is not int or value["quorum"] not in (1, 2)
            or type(value["steps"]) is not int or not 1 <= value["steps"] <= MAX_STEPS
            or type(value["observations"]) is not list or not 1 <= len(value["observations"]) <= len(OBSERVATIONS)
            or any(type(item) is not str or item not in OBSERVATIONS for item in value["observations"])
            or len(set(value["observations"])) != len(value["observations"])):
        raise ValueError("Choose one or two sign-offs, up to three interactions and distinct named observations.")
    return {**value, "observations": sorted(value["observations"])}


def version():
    return digest([SCHEMA, approval_version(), Path(__file__).read_bytes().hex()])


def check(value):
    """Execute only the installed fixed receiver in a fresh local environment."""
    value, before = choices(value), version()
    env = {name: os.environ[name] for name in ("SystemRoot", "WINDIR", "PATH", "TEMP", "TMP", "LANG") if name in os.environ}
    env.update(PYTHONPATH=str(Path(__file__).resolve().parent.parent), PYTHONIOENCODING="utf-8")
    budget = Budget(max_dollars=0, max_tool_calls=0, max_wall_seconds=MAX_SECONDS + 5)
    with tempfile.TemporaryDirectory(prefix="lightwork-recovery-visibility-") as temporary:
        home = Path(temporary)
        (home / "config.toml").write_text("[approval]\nrequire_acknowledgement = false\n", encoding="utf-8")
        env.update(MAVERICK_HOME=str(home), MAVERICK_CONFIG=str(home / "config.toml"), MAVERICK_ENCRYPT_AT_REST="0",
                   MAVERICK_AUDIT_SIGN="1", MAVERICK_AUDIT_SIGNING_KEY=secrets.token_hex(32), MAVERICK_PROFILE="standard",
                   HOME=str(home), USERPROFILE=str(home), MAVERICK_CLIENT_ID="fictional-visibility", MAVERICK_TENANT="fictional-visibility")
        try:
            completed = subprocess.run([sys.executable, "-m", "maverick.recovery_visibility", "--native-worker"],
                input=json.dumps(value).encode(), capture_output=True, env=env, cwd=temporary,
                timeout=MAX_SECONDS + 2, check=False)
            budget.check()
        except (subprocess.TimeoutExpired, BudgetExceeded) as exc:
            raise ValueError("The complete practice exceeded its allowance. Its result is unknown; no live decision was changed.") from exc
    if completed.returncode or len(completed.stdout) > 131072:
        raise ValueError("The complete isolated practice could not be confirmed. Its result is unknown and must not be repeated as the original request.")
    result = json.loads(completed.stdout)
    if (type(result) is not dict or result.get("schema") != SCHEMA or result.get("source") != before
            or result.get("complete") is not True or result.get("live_changed") is not False or version() != before):
        raise ValueError("The installed practice or its complete result changed. No current diagnostic is confirmed.")
    return result


def _replay(schedule, quorum, home, ordinal, budget):
    from .approval_cards import build_approval_card, encode_approval_detail
    from .approval_vote_review import channel_vote_review
    from .channel_approvals import ChannelApprovalRefused, audit_approval_decision, record_vote
    from .paths import tenant_scope
    from .world_model import WorldModel

    def charge():
        budget.record_tool_call()

    with tenant_scope(tenant="fictional-visibility-" + str(ordinal)):
        charge()
        with WorldModel(home / ("practice-" + str(ordinal) + ".db")) as world:
            card = build_approval_card(action="fictional.local.visibility", summary="Fictional missing-reply practice",
                target_label="Disposable local practice", target={}, parameters={}, parameter_summary=["Record a fictional sign-off"],
                actor="user:fictional-requester", workspace="fictional", role="operator", authority_versions={}, input_versions={},
                credential_versions={}, budget={"currency": "USD", "maximum": 0}, expires_at=4102444800,
                known_effects=["Fictional votes and local activity only"], unresolved_assumptions=[],
                before="Pending fictional request", after="Fictional local decision", irreversible=False)
            # A request the consent wait holds, so the practice's undo steps apply.
            identity = world.create_approval(card["action"], detail=encode_approval_detail(card), approvals_required=quorum,
                                             requested_by="user:fictional-requester", undoable=True)
            original = world.approval_audit_event_id(identity, "approved", "user:fictional-first")
            for action in schedule:
                charge()
                if action in ("first_vote", "other_vote"):
                    actor = "user:fictional-first" if action == "first_vote" else "user:fictional-other"
                    try:
                        review = channel_vote_review(world, world.get_approval(identity), status="approved", actor=actor, binding=card["binding_sha256"])
                        record_vote(world, identity, "approved", actor, reviewed_card=review)
                    except ChannelApprovalRefused as exc:
                        if exc.reason in {"not_pending", "pending_finalization", "vote_not_accepted", "stale_card"}:
                            return None
                        raise
                elif action == "activity":
                    pending = world.pending_approval_audit_events(approval_id=identity)
                    if not pending:
                        return None
                    for event in pending:
                        charge()
                        if not audit_approval_decision(world, event):
                            raise ValueError("Local activity delivery remains unknown. No complete practice result is established.")
                elif world.undo_approval_decision(identity, undone_by="user:fictional-first", within_seconds=60) != "undone":
                    return None
            charge()
            state, receipt = world.approval_state(identity), world.get_approval_audit_event(original)
            round_number = world._approval_undo_round(identity)
            observed = {"status": state["status"], "count": state["approved_count"], "receipt": receipt is not None,
                        "activity": "not_recorded" if receipt is None else "pending" if receipt.delivered_at is None else "acknowledged",
                        "round": round_number}
            obligation = ("not_recorded" if receipt is None else "activity_unknown" if receipt.delivered_at is None
                          else "undone" if round_number else "waiting" if state["status"] == "pending" else "effective")
            pending = world.pending_approval_audit_events(approval_id=identity)
            key = digest([observed, sorted(state["approvers"]), sorted((row.status, row.decided_by, row.final_status or "") for row in pending)])
            return {"steps": list(schedule), "observed": observed, "obligation": obligation, "key": key}


def _projection(row, fields):
    return json.dumps({field: row["observed"][field] for field in fields}, sort_keys=True)


def _pair_key(pair):
    return sum(len(row["steps"]) for row in pair), tuple(tuple(row["steps"]) for row in pair)


def _indexed_pair(rows, fields, budget):
    groups, pairs = {}, []
    for row in rows:
        budget.check()
        group = groups.setdefault(_projection(row, fields), {})
        for other in group.values():
            if other["obligation"] != row["obligation"]:
                pairs.append(sorted([other, row], key=lambda item: (len(item["steps"]), item["steps"])))
        previous = group.get(row["obligation"])
        if previous is None or (len(row["steps"]), row["steps"]) < (len(previous["steps"]), previous["steps"]):
            group[row["obligation"]] = row
    return min(pairs, key=_pair_key) if pairs else None


def _plain_pair(rows, fields, budget):
    pairs = []
    for left, right in itertools.combinations(rows, 2):
        budget.check()
        if left["obligation"] != right["obligation"] and _projection(left, fields) == _projection(right, fields):
            pairs.append(sorted([left, right], key=lambda item: (len(item["steps"]), item["steps"])))
    return min(pairs, key=_pair_key) if pairs else None


def diagnose(value, home):
    value = choices(value)
    started, source = time.perf_counter(), version()
    budget = Budget(max_dollars=0, max_tool_calls=MAX_OPERATIONS, max_wall_seconds=MAX_SECONDS)
    initial = _replay((), value["quorum"], home, 0, budget)
    rows, seen, queue, attempts = [initial], {initial["key"]}, deque([initial]), 1
    while queue:
        budget.check()
        previous = queue.popleft()
        if len(previous["steps"]) >= value["steps"]:
            continue
        for action in ACTIONS:
            budget.check()
            row = _replay([*previous["steps"], action], value["quorum"], home, attempts, budget)
            attempts += 1
            if row is not None and row["key"] not in seen:
                seen.add(row["key"])
                rows.append(row)
                queue.append(row)
    fields = value["observations"]
    pair = _indexed_pair(rows, fields, budget)
    baseline = _plain_pair(rows, fields, budget)
    matched = (pair is None and baseline is None) or (pair is not None and baseline is not None and _pair_key(pair) == _pair_key(baseline))
    if not matched:
        raise ValueError("The same-information comparison disagreed. No complete diagnostic is established.")
    extras, sufficient = [name for name in OBSERVATIONS if name not in fields], []
    for count in range(len(extras) + 1):
        for subset in itertools.combinations(extras, count):
            budget.check()
            if _indexed_pair(rows, [*fields, *subset], budget) is None:
                sufficient.append(list(subset))
        if sufficient:
            break
    if pair:
        verified = []
        for row in pair:
            fresh = _replay(row["steps"], value["quorum"], home, attempts, budget)
            attempts += 1
            if fresh is None or fresh["observed"] != row["observed"] or fresh["obligation"] != row["obligation"]:
                raise ValueError("The paired native histories could not be reproduced. Their result is unknown.")
            verified.append({key: fresh[key] for key in ("steps", "observed", "obligation")})
        pair = verified
    budget.check()
    if version() != source:
        raise ValueError("The installed native source changed during the practice.")
    return {"schema": SCHEMA, "source": source, "complete": True, "live_changed": False, "choices": value,
            "labels": {"actions": ACTIONS, "observations": OBSERVATIONS, "obligations": OBLIGATIONS},
            "states": len(rows), "native_replays": attempts, "local_operations": budget.tool_calls,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 3), "pair": pair,
            "minimum_total_interactions": _pair_key(pair)[0] if pair else None,
            "sufficient_additions": sufficient, "same_information_comparison_matched": matched,
            "comparison_pairs": len(rows) * (len(rows) - 1) // 2}


def _worker():
    def deny(event, _args):
        if event.startswith(("socket.", "subprocess.", "os.exec", "os.spawn")) or event in {"os.system", "os.fork", "os.startfile"}:
            raise PermissionError("External operations are unavailable in this isolated practice.")
    sys.addaudithook(deny)
    raw = sys.stdin.buffer.read(4097)
    if len(raw) > 4096:
        raise ValueError("Unsupported practice input.")
    print(json.dumps(diagnose(json.loads(raw), Path(os.environ["MAVERICK_HOME"])), allow_nan=False))


if __name__ == "__main__":
    if sys.argv[1:] != ["--native-worker"]:
        raise SystemExit("Only the fixed isolated native practice is supported.")
    _worker()
