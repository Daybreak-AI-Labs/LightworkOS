"""Selected immutable deliverable copies with exact recipient and review authority."""
from __future__ import annotations

import base64
import copy
import hashlib
import re
from pathlib import Path

from .governed_operations import digest
from .governed_records import GovernedRecordCapacityError, GovernedRecordStore
from .paths import current_tenant_id_strict
from .privacy_ops import RecordConflict

STORE = GovernedRecordStore("deliverable_bundles", "DLB", "deliverable_bundle")
# The inbox reads the whole namespace, so creation keeps it within this bound;
# a full store archives its oldest settled (revoked) bundles to make room.
_MAX_BUNDLES = 1000
MAX_BYTES = 6 * 1024 * 1024
MAX_ITEMS = 30
LIFETIMES = (3600, 86400, 604800)


class BundleDenied(PermissionError):
    """Current source or recipient authority does not permit this bundle."""


def _text(value, label, limit, *, empty=False):
    if not isinstance(value, str) or len(value) > limit or any(ord(c) < 32 and c not in "\n\t\r" for c in value):
        raise ValueError(f"{label} exceeds its supported text limit or contains control characters.")
    value = value.strip()
    if not value and not empty:
        raise ValueError(f"{label} is required.")
    return value


def _ids(values):
    if not isinstance(values, list) or len(values) > MAX_ITEMS or any(type(v) is not int or v < 1 for v in values):
        raise ValueError("Choose at most 30 available items.")
    if len(set(values)) != len(values):
        raise ValueError("Choose each item only once.")
    return sorted(values)


def _identity(actor):
    if not isinstance(actor, str) or not actor.startswith("user:") or len(actor) <= 5:
        raise BundleDenied("Sign in with a named workspace account.")
    return actor


def _operation(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{12,100}", value):
        raise ValueError("The save reference is invalid.")
    return value


def _item(key, title, data, *, kind, source):
    if len(data) > MAX_BYTES:
        raise ValueError("Selected content exceeds the six-megabyte bundle limit.")
    return {"key": key, "title": title, "kind": kind, "source": source,
            "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "content_base64": base64.b64encode(data).decode("ascii")}


class DeliverableBundles:
    def __init__(self, world, *, actor, eligible, store=None):
        self.world, self.actor, self.eligible = world, _identity(actor), eligible
        self.store = store or STORE
        self.tenant = current_tenant_id_strict()
        if not self.tenant:
            raise BundleDenied("Select a workspace before preparing shared deliverables.")

    def _context(self):
        if current_tenant_id_strict() != self.tenant:
            raise BundleDenied("Your workspace changed. Reload before continuing.")

    def _allowed(self, actor, domain, permission):
        self._context()
        from .domain import suites_for_domain

        suites = suites_for_domain(domain) if domain else ()
        if any(self.eligible(actor, suite, permission, True) is not True for suite in suites):
            raise BundleDenied("Current workspace membership or permissions do not allow this bundle.")
        if not suites and self.eligible(actor, None, permission, True) is not True:
            raise BundleDenied("Current workspace membership or permissions do not allow this bundle.")

    def _source(self, goal_id):
        self._context()
        goal = self.world.get_goal(goal_id)
        if goal is None or goal.owner != self.actor:
            raise BundleDenied("Only the current task owner can select its private evidence.")
        self._allowed(self.actor, goal.domain, "operate")
        return goal

    def _bounded_inventory(self, goal_id):
        row = self.world.query("SELECT COUNT(*),COALESCE(SUM(LENGTH(content)),0) FROM artifacts WHERE goal_id=?", (goal_id,))[0]
        count = self.world.query("SELECT COUNT(*) FROM attachments WHERE goal_id=?", (goal_id,))[0][0]
        if row[0] + count > 1000 or row[1] > 2 * MAX_BYTES:
            raise ValueError("This task exceeds the supported evidence inventory. Select a smaller task.")

    def candidates(self, goal_id):
        goal = self._source(goal_id)
        self._bounded_inventory(goal_id)
        artifacts = self.world.artifacts_for_goal(goal_id)
        attachments = self.world.list_attachments(goal_id)
        if len(artifacts) + len(attachments) > 1000:
            raise ValueError("This task exceeds the supported evidence inventory. Select a smaller task.")
        return {"goal_id": goal.id, "title": goal.title, "status": goal.status,
                "updated_at": goal.updated_at, "result": goal.result or "",
                "artifacts": [{k: a[k] for k in ("id", "title", "kind", "version")} for a in artifacts],
                "attachments": [{"id": a.id, "title": a.filename, "bytes": a.size_bytes, "mime": a.mime} for a in attachments]}

    def _artifact_items(self, goal_id, selected):
        artifacts = self.world.artifacts_for_goal(goal_id)
        matches = {a["id"]: a for a in artifacts}
        if any(identifier not in matches for identifier in selected):
            raise BundleDenied("A selected artifact is unavailable on this task.")
        latest = {a["title"]: a["version"] for a in artifacts}
        items = [_item(f"artifact-{identifier}", matches[identifier]["title"],
                       matches[identifier]["content"].encode("utf-8"), kind="artifact",
                       source={"id": identifier, "version": matches[identifier]["version"],
                               "kind": matches[identifier]["kind"], "latest_version": latest[matches[identifier]["title"]]})
                 for identifier in selected]
        return items

    def _attachment_items(self, goal_id, selected):
        from . import attachments

        matches = {a.id: a for a in self.world.list_attachments(goal_id)}
        if any(identifier not in matches for identifier in selected):
            raise BundleDenied("A selected evidence file is unavailable on this task.")
        result = []
        for identifier in selected:
            row = matches[identifier]
            path = Path(row.path)
            expected_root = attachments._root_for_goal(goal_id).resolve()
            if path.is_symlink() or path.resolve().parent != expected_root:
                raise BundleDenied("The selected evidence file is outside this task's private storage.")
            if not path.is_file() or path.stat().st_size > 2 * MAX_BYTES or row.size_bytes > MAX_BYTES:
                raise ValueError("A selected evidence file is unavailable or exceeds the bundle limit. Restore it before preparing this bundle.")
            data = attachments.read_bytes(path)
            if len(data) != row.size_bytes or hashlib.sha256(data).hexdigest() != row.sha256:
                raise ValueError("A selected evidence file failed its stored size or checksum check.")
            result.append(_item(f"evidence-{identifier}", row.filename, data, kind="evidence",
                                source={"id": identifier, "mime": row.mime, "sha256": row.sha256}))
        return result

    def capture(self, goal_id, *, artifact_ids, attachment_ids, include_result):
        goal = self._source(goal_id)
        self._bounded_inventory(goal_id)
        artifact_ids, attachment_ids = _ids(artifact_ids), _ids(attachment_ids)
        if type(include_result) is not bool or len(artifact_ids) + len(attachment_ids) + int(include_result) > MAX_ITEMS:
            raise ValueError("Choose at most 30 result, artifact and evidence items.")
        items = self._artifact_items(goal.id, artifact_ids) + self._attachment_items(goal.id, attachment_ids)
        if include_result:
            items.insert(0, _item("saved-result", "Saved result", (goal.result or "").encode("utf-8"),
                                  kind="result", source={"updated_at": goal.updated_at}))
        if not items or sum(item["bytes"] for item in items) > MAX_BYTES:
            raise ValueError("Choose at least one item within the six-megabyte bundle limit.")
        fresh = self._source(goal_id)
        if fresh.updated_at != goal.updated_at:
            raise RecordConflict("The task changed while its evidence was being captured. Preview again.")
        source = {"goal_id": goal.id, "title": goal.title, "domain": goal.domain, "owner": goal.owner,
                  "updated_at": goal.updated_at, "status": goal.status,
                  "selection": {"artifact_ids": artifact_ids, "attachment_ids": attachment_ids, "include_result": include_result},
                  "items": [{k: v for k, v in item.items() if k != "content_base64"} for item in items]}
        return {"source": source, "source_version": digest(source), "items": items}

    def prepare(self, goal_id, *, artifact_ids, attachment_ids, include_result, name, recipient, note,
                unresolved, lifetime):
        capture = self.capture(goal_id, artifact_ids=artifact_ids, attachment_ids=attachment_ids, include_result=include_result)
        recipient = _identity(recipient)
        if recipient == self.actor:
            raise ValueError("Choose another named recipient for independent acceptance.")
        self._allowed(recipient, capture["source"]["domain"], "view")
        if lifetime not in LIFETIMES:
            raise ValueError("Choose one hour, one day or seven days of access.")
        material = {"name": _text(name, "Bundle name", 160), "recipient": recipient,
                    "note": _text(note, "Recipient's job", 4000),
                    "unresolved": _text(unresolved, "Unresolved items", 4000, empty=True),
                    "lifetime": lifetime, **capture}
        material["source_warnings"] = []
        if capture["source"]["status"] != "done":
            material["source_warnings"].append("The source task is not complete; this is a captured working draft.")
        if any(item["kind"] == "artifact" and item["source"]["version"] != item["source"]["latest_version"] for item in capture["items"]):
            material["source_warnings"].append("An older artifact version is selected. Its acceptance is stale relative to the current source.")
        material["review_version"] = digest({k: v for k, v in material.items() if k != "items"})
        return material

    def create(self, goal_id, *, expected_review, operation_id, **choices):
        operation_id = _operation(operation_id)
        identifier = "DLB-" + digest([self.actor, operation_id])[:32]
        request_hash = digest({"goal_id": goal_id, "review": expected_review, "choices": choices})
        previous = self.store.get(identifier)
        if previous:
            self._authorize(previous)
            if previous["request_hash"] != request_hash:
                raise RecordConflict("This save reference belongs to a different bundle.")
            return self.get(identifier)
        prepared = self.prepare(goal_id, **choices)
        if prepared["review_version"] != expected_review:
            raise RecordConflict("The selected evidence or recipient changed. Review a fresh preview before sharing.")
        now = self.store.authoritative_time()
        record = {"id": identifier, "schema": "lightwork.deliverable-bundle.v1",
                  "owner": self.actor, "request_hash": request_hash, "status": "shared",
                  "expires_at": now + prepared["lifetime"], "acceptance": None,
                  "operations": {}, "payload": prepared}
        try:
            try:
                self.store.create(dict(record), actor=self.actor, action="share_selected_bundle",
                                  max_records=_MAX_BUNDLES)
            except GovernedRecordCapacityError:
                # Expired bundles still read "shared", which the store does not
                # archive; mark them expired so the retry can make room.
                if not self._settle_expired(now):
                    raise
                self.store.create(dict(record), actor=self.actor, action="share_selected_bundle",
                                  max_records=_MAX_BUNDLES)
        except RecordConflict:
            committed = self.store.get(identifier)
            if not committed or committed.get("request_hash") != request_hash:
                raise
            self._authorize(committed)
        return self.get(identifier)

    def _settle_expired(self, now) -> int:
        """Mark shared bundles whose access has ended as ``expired``, a settled
        status the store archives when full. Returns how many were marked."""
        settled = 0
        for row in self.store.list(limit=_MAX_BUNDLES):
            if row.get("status") != "shared" or float(row.get("expires_at") or 0) > now:
                continue

            def expire(value):
                value["status"] = "expired"

            try:
                if self.store.update(row["id"], expire, expected_revision=row["revision"],
                                     action="expire_bundle", actor="deliverable-bundle retention"):
                    settled += 1
            except RecordConflict:
                continue
        return settled

    def _authorize(self, record):
        self._context()
        if not record or record.get("schema") != "lightwork.deliverable-bundle.v1":
            raise BundleDenied("This bundle is unavailable.")
        payload = record["payload"]
        if self.actor not in {record["owner"], payload["recipient"]}:
            raise BundleDenied("This bundle is unavailable to your account.")
        self._allowed(self.actor, payload["source"]["domain"], "view")
        self._allowed(record["owner"], payload["source"]["domain"], "view")
        if self.actor != record["owner"] and (record["status"] != "shared" or record["expires_at"] <= self.store.authoritative_time()):
            raise BundleDenied("Access to this bundle ended. Previously downloaded copies cannot be recalled.")

    def stale(self, record):
        source = record["payload"]["source"]
        goal = self.world.get_goal(source["goal_id"])
        if goal is None or goal.owner != source["owner"] or goal.updated_at != source["updated_at"]:
            return True
        self._bounded_inventory(goal.id)
        artifacts = {a["id"]: a for a in self.world.artifacts_for_goal(goal.id)}
        latest = {a["title"]: a["version"] for a in artifacts.values()}
        attachments = {a.id: a for a in self.world.list_attachments(goal.id)}
        for item in source["items"]:
            original = item["source"]
            if item["kind"] == "artifact":
                current = artifacts.get(original["id"])
                if current is None or current["version"] != original["version"] or latest.get(item["title"]) != original["version"]:
                    return True
                if hashlib.sha256(current["content"].encode("utf-8")).hexdigest() != item["sha256"]:
                    return True
            if item["kind"] == "evidence":
                current = attachments.get(original["id"])
                if current is None or current.sha256 != item["sha256"]:
                    return True
        return False

    def get(self, identifier):
        record = self.store.get(identifier)
        self._authorize(record)
        result = copy.deepcopy({k: v for k, v in record.items() if k not in {"_audit_pending", "operations", "request_hash"}})
        result["stale"] = self.stale(record)
        result["acceptance_current"] = bool(record["acceptance"] and not result["stale"])
        from .domain import suites_for_domain
        suites = suites_for_domain(record["payload"]["source"]["domain"])
        operates = all(self.eligible(self.actor, suite, "operate", True) is True for suite in suites)
        if not suites:
            operates = self.eligible(self.actor, None, "operate", True) is True
        result["can_accept"] = operates and self.actor == record["payload"]["recipient"] and not result["stale"]
        result["can_revoke"] = operates and self.actor == record["owner"] and record["status"] == "shared"
        return result

    def inbox(self):
        rows = self.store.list(limit=_MAX_BUNDLES + 1)
        if len(rows) > _MAX_BUNDLES:
            raise ValueError("The bundle inventory exceeds its current supported bound.")
        result = []
        for row in rows:
            try:
                self._authorize(row)
            except BundleDenied:
                continue
            result.append({"id": row["id"], "name": row["payload"]["name"], "owner": row["owner"],
                           "recipient": row["payload"]["recipient"], "status": row["status"],
                           "expires_at": row["expires_at"], "revision": row["revision"]})
        return result

    def respond(self, identifier, *, action, note, expected_revision, operation_id):
        operation_id = _operation(operation_id)
        note = _text(note, "Review comment", 4000, empty=action == "revoke")
        request_hash = digest([self.actor, action, note, expected_revision])
        current = self.store.get(identifier)
        self._authorize(current)
        if current.get("operations", {}).get(operation_id) == request_hash:
            return self.get(identifier)
        if operation_id in current.get("operations", {}):
            raise RecordConflict("This save reference belongs to another response.")

        def mutate(record):
            self._authorize(record)
            if len(record["operations"]) >= 500:
                raise ValueError("This bundle reached its response limit. Preserve its history and create a fresh bundle if needed.")
            if action == "accept":
                if self.actor != record["payload"]["recipient"] or self.stale(record):
                    raise RecordConflict("Only the named recipient can accept an unchanged source version.")
                self._allowed(self.actor, record["payload"]["source"]["domain"], "operate")
                record["acceptance"] = {"actor": self.actor, "note": note,
                                        "source_version": record["payload"]["source_version"],
                                        "at": self.store.authoritative_time()}
            elif action == "revoke" and self.actor == record["owner"]:
                self._allowed(self.actor, record["payload"]["source"]["domain"], "operate")
                record["status"] = "revoked"
            else:
                raise BundleDenied("This response is unavailable to your account.")
            record["operations"][operation_id] = request_hash

        self.store.update(identifier, mutate, expected_revision=expected_revision, actor=self.actor, action="bundle_" + action)
        return self.get(identifier)


def decoded_items(record):
    """Verify captured bytes before rendering or exporting any recipient copy."""
    items = []
    for item in record["payload"]["items"]:
        content = base64.b64decode(item["content_base64"], validate=True)
        if len(content) != item["bytes"] or hashlib.sha256(content).hexdigest() != item["sha256"]:
            raise ValueError("Captured bundle content failed its size or checksum check.")
        items.append((item, content))
    if len(items) > MAX_ITEMS or sum(len(content) for _, content in items) > MAX_BYTES:
        raise ValueError("Captured bundle exceeds its supported size.")
    return items
