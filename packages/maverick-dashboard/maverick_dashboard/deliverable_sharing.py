"""Fresh result previews and version-bound public release metadata.

New ``r1_`` links never resolve without their governed metadata. Publishing a
native token before saving metadata is therefore fail-closed even if storage
fails or the process exits between those writes. Legacy links retain their
existing current-release checks. No token is stored in the metadata record.
"""
from __future__ import annotations

import hashlib
import json

from maverick.governed_records import GovernedRecordStore

MAX_LIFETIME = 7 * 24 * 3600
LIFETIMES = (3600, 24 * 3600, MAX_LIFETIME)
MAX_CONVERSATION_TURNS = 1000
MAX_CONVERSATION_BYTES = 2 * 1024 * 1024


class ShareAuditPending(RuntimeError):
    """A public release is not active until its governed audit receipt exists."""


def _store():
    return GovernedRecordStore("deliverable-share-releases", "shr", "deliverable_share_release")


def _id(goal_id, link_id):
    return f"shr-{int(goal_id)}-{int(link_id)}"


def _fingerprint(content, *, bounded=False):
    encoded = json.dumps(content, sort_keys=True, separators=(",", ":"), default=str).encode()
    if bounded and len(encoded) > MAX_CONVERSATION_BYTES:
        raise ValueError("This conversation is too large to share in one link.")
    return hashlib.sha256(encoded).hexdigest()


def snapshot(world, goal):
    """The public view's exact saved content, including selected latest artifacts."""
    artifacts = world.latest_artifacts(goal.id)
    content = {"goal_id": goal.id, "owner": goal.owner or "", "title": goal.title,
               "result": goal.result or "", "updated_at": goal.updated_at,
               "domain": goal.domain, "status": goal.status,
               "artifacts": [{key: a.get(key) for key in ("id", "kind", "title", "content", "version", "created_at")}
                             for a in artifacts]}
    return {**content, "sha256": _fingerprint(content)}


def conversation_snapshot(world, goal, *, require_latest=False):
    """Exact owner-reviewed web transcript through this completed message.

    Later messages never expand an existing public link. Earlier turns and
    answered clarifications are re-read on every public request, so edits,
    deletions and changed release decisions invalidate the reviewed digest.
    """
    from maverick.chat_threads import ChatThreads
    from maverick.domain import available_domains, deliverable_release_allowed, enforced_gate
    from maverick.stop_reasons import stop_payload

    if goal.status != "done" or not (goal.result or "").strip():
        raise ValueError("Finish this conversation before sharing it.")
    chat = ChatThreads(world)
    binding = chat.binding(goal.id)
    if binding is None or binding.owner != (goal.owner or ""):
        raise ValueError("This task is not part of a saved web conversation.")
    if require_latest and chat.latest(goal.id) != goal.id:
        raise ValueError("Open the latest message to share the full conversation.")

    selected = chat.selected_turns(goal.id)
    selected_users = [turn for turn in selected if turn.role == "user"]
    selected_answers = [turn for turn in selected if turn.role == "assistant"]
    if (len(selected_users) != 1 or not selected_answers
            or selected_users[0].id >= selected_answers[-1].id
            or selected_answers[-1].content != goal.result):
        raise ValueError("This message's saved conversation changed. Open it before sharing.")

    pages, before, count = [], None, 0
    while True:
        page, more = chat.history(goal.id, before_id=before, limit=100)
        count += len(page)
        # The selected message contributes its reviewed user/assistant pair.
        if count + 2 > MAX_CONVERSATION_TURNS:
            raise ValueError("This conversation is too long to share in one link.")
        if not page:
            break
        pages.append(page)
        if not more:
            break
        before = page[0].id
    earlier = [turn for page in reversed(pages) for turn in page]
    goals, profiles, review_revisions = {}, {}, []
    domain_profiles = available_domains()
    for goal_id in {goal.id, *(turn.goal_id for turn in earlier)}:
        member = world.get_goal(goal_id)
        if (member is None or (member.owner or "") != binding.owner
                or (member.id != binding.root_id and member.parent_id != binding.root_id)
                or member.status not in {"done", "failed", "cancelled", "blocked"}):
            raise ValueError("A message in this conversation is no longer available to share.")
        review = world.signoff_for(member.id)
        review_revisions.append((member.id, review["decision"], review["decided_by"],
                                 review["created_at"]) if review else (member.id, None))
        if member.domain:
            profile = domain_profiles.get(member.domain)
            if profile is None or not deliverable_release_allowed(profile, review):
                raise ValueError("A message in this conversation needs current release approval.")
            profiles[member.id] = profile
        goals[goal_id] = member

    transcript = []
    revisions = []
    earlier_answers = {turn.goal_id for turn in earlier if turn.role == "assistant"}
    last_user_turn = {turn.goal_id: turn.id for turn in earlier if turn.role == "user"}
    for member in goals.values():
        revisions.append((member.id, member.updated_at, member.status, member.title,
                          member.description, member.result, member.domain))

    def questions(goal_id):
        return [{"role": "clarification", "question": q.question, "answer": q.answer,
                 "question_id": q.id, "goal_id": goal_id}
                for q in world.all_questions(goal_id) if q.answer is not None]

    for turn in earlier:
        member = goals[turn.goal_id]
        if turn.role == "user":
            transcript.append({"role": "user", "text": turn.content, "turn_id": turn.id,
                               "goal_id": turn.goal_id})
            transcript.extend(questions(turn.goal_id))
            # A stopped web message can have a saved request but no assistant
            # turn: the orchestrator writes answer turns only on completion.
            # Keep the public transcript faithful without releasing its raw
            # technical stop reason.
            if (member.status in {"failed", "cancelled", "blocked"}
                    and turn.goal_id not in earlier_answers
                    and last_user_turn[turn.goal_id] == turn.id):
                stopped = stop_payload(member.status, member.result)
                text = (stopped.get("message", "") + "\n\n" + stopped.get("action", "")).strip() if stopped else "This request was cancelled."
                transcript.append({"role": "assistant", "text": text, "stopped": True,
                                   "goal_id": turn.goal_id})
        else:
            text = turn.content
            if member.status in {"failed", "cancelled", "blocked"}:
                stopped = stop_payload(member.status, member.result)
                text = (stopped.get("message", "") + "\n\n" + stopped.get("action", "")).strip() if stopped else "Work stopped."
            elif member.id in profiles and enforced_gate(profiles[member.id]) is not None and text != member.result:
                raise ValueError("A previously reviewed answer changed. Open it before sharing the full conversation.")
            transcript.append({"role": "assistant", "text": text, "turn_id": turn.id,
                               "goal_id": turn.goal_id,
                               **({"stopped": True} if member.status in {"failed", "cancelled", "blocked"} else {})})
    transcript.append({"role": "user", "text": selected_users[0].content,
                       "turn_id": selected_users[0].id, "goal_id": goal.id})
    transcript.extend(questions(goal.id))
    transcript.append({"role": "assistant", "text": selected_answers[-1].content,
                       "turn_id": selected_answers[-1].id, "goal_id": goal.id})
    content = {"scope": "conversation", "goal_id": goal.id, "owner": goal.owner or "",
               "title": goal.title, "result": goal.result, "updated_at": goal.updated_at,
               "domain": goal.domain, "status": goal.status, "artifacts": [],
               "transcript": transcript, "member_goal_ids": sorted(goals),
               "member_revisions": sorted(revisions), "review_revisions": sorted(review_revisions)}
    return {**content, "sha256": _fingerprint(content, bounded=True)}


def remember(world, goal, *, link_id, source, label, lifetime, actor):
    conversation = source.get("scope") == "conversation"
    record = {"id": _id(goal.id, link_id), "schema": 2 if conversation else 1, "goal_id": goal.id,
              "link_id": link_id, "source_sha256": source["sha256"],
              "label": label, "lifetime_seconds": lifetime, "owner": actor,
              "release_version": goal.updated_at}
    if conversation:
        record["scope"] = "conversation"
        record["turn_ids"] = [turn["turn_id"] for turn in source["transcript"] if "turn_id" in turn]
    saved = _store().create(record, actor=actor or "local-operator", action="confirmed_public_release")
    if saved.get("_audit_pending"):
        raise ShareAuditPending("public release audit receipt is pending")


def source_generation(world):
    """A conservative SQLite write witness for one public read.

    The dashboard's file-backed SQLite world reads from a persistent,
    per-thread connection, distinct from its writer connection. Pin that exact
    reader in query-only mode and record its own ``total_changes`` as well:
    ``data_version`` alone changes only for commits on other connections.
    An unrelated write may refuse a share read; it cannot make a changed
    source look current. Other backends and unpinned readers retain the full
    second source comparison.
    """
    import sqlite3

    from maverick.world_model import WorldModel

    if not isinstance(world, WorldModel) or world._is_memory:
        return None
    reader = world._reader()
    if reader is None or reader is world.conn:
        return None
    try:
        reader.execute("PRAGMA query_only = ON")
        if int(reader.execute("PRAGMA query_only").fetchone()[0]) != 1:
            return None
        return reader, int(reader.execute("PRAGMA data_version").fetchone()[0]), reader.total_changes
    except (sqlite3.Error, TypeError, ValueError):
        return None


def _release_record(world, goal, token):
    digest = hashlib.sha256(token.encode()).hexdigest()
    rows = world.query("SELECT id FROM share_links WHERE goal_id=? AND token_sha256=?", (goal.id, digest))
    if len(rows) != 1:
        return None
    record = _store().get(_id(goal.id, int(rows[0][0])))
    return record if record and not record.get("_audit_pending") and record.get("goal_id") == goal.id else None


def _conversation_policy_current(source):
    """Recheck mutable domain-pack release rules without rereading turns."""
    from maverick.domain import available_domains, deliverable_release_allowed, enforced_gate

    profiles = available_domains()
    reviews = {row[0]: {"decision": row[1]} if row[1] else None for row in source["review_revisions"]}
    answers = {}
    for turn in source["transcript"]:
        if turn["role"] == "assistant" and not turn.get("stopped"):
            answers.setdefault(turn["goal_id"], []).append(turn["text"])
    for member in source["member_revisions"]:
        goal_id, result, domain = member[0], member[5], member[6]
        if not domain:
            continue
        profile = profiles.get(domain)
        if (profile is None or not deliverable_release_allowed(profile, reviews.get(goal_id))
                or enforced_gate(profile) is not None
                and any(answer != result for answer in answers.get(goal_id, ()))):
            return False
    return True


def release_snapshot(world, goal, token):
    """Return only the exact current content a version-bound token released."""
    if not token.startswith("r1_"):
        return None
    record = _release_record(world, goal, token)
    if record is None:
        return None
    try:
        if record.get("schema") == 1:
            source = snapshot(world, goal)
        elif record.get("schema") == 2 and record.get("scope") == "conversation":
            source = conversation_snapshot(world, goal)
            if record.get("turn_ids") != [turn["turn_id"] for turn in source["transcript"] if "turn_id" in turn]:
                return None
        else:
            return None
    except (OSError, ValueError, KeyError, TypeError, RuntimeError):
        return None
    return source if record.get("source_sha256") == source["sha256"] else None


def release_matches(world, goal, token, *, source=None, generation=None):
    """Token authority cannot silently expand to a later unreviewed version."""
    if not token.startswith("r1_"):
        return True
    if source is None or generation is None:
        return release_snapshot(world, goal, token) is not None
    record = _release_record(world, goal, token)
    if record is None or record.get("source_sha256") != source.get("sha256"):
        return False
    if source.get("scope") == "conversation":
        if record.get("schema") != 2 or record.get("scope") != "conversation":
            return False
        if record.get("turn_ids") != [turn["turn_id"] for turn in source["transcript"] if "turn_id" in turn]:
            return False
        if not _conversation_policy_current(source):
            return False
    elif record.get("schema") != 1:
        return False
    current = source_generation(world)
    return (current is not None and current[0] is generation[0]
            and current[1:] == generation[1:])


def listing(world, goal):
    result = []
    current_by_scope = {}
    for row in world.share_links_for_goal(goal.id):
        record = _store().get(_id(goal.id, row["id"]))
        unavailable = record is None or record.get("goal_id") != goal.id
        record = None if unavailable else record
        audit_pending = bool(record and record.get("_audit_pending"))
        scope = "conversation" if record and record.get("scope") == "conversation" else "result"
        if not unavailable and scope not in current_by_scope:
            try:
                current_by_scope[scope] = (conversation_snapshot(world, goal) if scope == "conversation"
                                           else snapshot(world, goal))["sha256"]
            except (OSError, ValueError, KeyError, TypeError, RuntimeError):
                current_by_scope[scope] = ""
        stale = bool(record and record.get("source_sha256") != current_by_scope[scope])
        result.append({**row, "label": record.get("label") if record else f"Read-only link #{row['id']}",
                       "scope": scope,
                       "stale": stale, "active": row["active"] and not unavailable and not stale and not audit_pending,
                       "state": "revoked" if row["revoked"] else "expired" if row["expired"] else
                                "unavailable" if unavailable else "audit pending" if audit_pending else
                                "source changed" if stale else "active"})
    return result
