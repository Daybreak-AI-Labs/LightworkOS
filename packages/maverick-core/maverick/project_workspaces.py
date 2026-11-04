"""Project outcome planning without extending live task or review authority.

Workspace membership shares only deliberately entered planning metadata. Source
results remain separately authorized, versioned references, checked on every use.
Milestone ordering and prerequisites are planning data, never execution edges.
"""
from __future__ import annotations

import copy
import datetime as dt
import re
import threading
from contextlib import contextmanager

from .domain import suite_for, suites_for_domain
from .governed_operations import digest
from .governed_records import GovernedMutationFence, GovernedRecordStore
from .paths import current_tenant_id_strict
from .privacy_ops import RecordConflict
from .project_reviews import ProjectReviewDenied, _principal, _request, _seal, _text, _validate

_WORKSPACES = GovernedRecordStore("project_workspaces", "PW", "project_workspace")
_DEFAULTS = GovernedRecordStore("project_workspace_defaults", "PWD", "project_workspace_defaults")
SCHEMA = "lightwork.project-workspace.v1"
DEFAULT_SCHEMA = "lightwork.project-workspace-defaults.v1"
VIEWS = ("list", "board", "timeline")
ACTIONS = {"details", "member", "milestone", "remove_milestone", "reorder", "dependency",
           "context", "remove_context", "save_defaults", "apply_defaults"}
_LOCK = threading.RLock()


def owned_defaults_inventory(principal):
    """Bounded My Data inventory; caller supplies its verified named owner."""
    principal = _principal(principal)
    if not current_tenant_id_strict():
        raise ProjectReviewDenied("Select the owner's workspace before reviewing project defaults")
    record = _DEFAULTS.get("PWD-" + digest(principal)[:32])
    if not record:
        return []
    record = _validate(record, DEFAULT_SCHEMA)
    if record["owner"] != principal:
        raise ProjectReviewDenied("Personal project defaults ownership could not be verified")
    if record["structure"] is None:
        return []
    return [{"id": record["id"], "revision": record["revision"], "owner": principal}]


def erase_owned_defaults(principal, *, record_id, expected_revision, operation_id, actor):
    """Reviewed My Data erasure; leave a revision barrier against stale saves.

    The privacy adapter owns consent/holds/approvals and caller authorization.
    This helper enforces exact target ownership, tenant binding and reviewed CAS;
    no shared project records or linked source records are touched.
    """
    principal, actor, operation_id = _principal(principal), _principal(actor), _request(operation_id)
    if not current_tenant_id_strict() or record_id != "PWD-" + digest(principal)[:32]:
        raise ProjectReviewDenied("Personal project defaults target is outside the reviewed owner scope")
    if type(expected_revision) is not int or expected_revision < 1:
        raise ValueError("Review the current project defaults version before erasure")
    request_sha = digest({"owner": principal, "actor": actor, "revision": expected_revision, "erase": True})
    key = "erase:" + operation_id
    current = _DEFAULTS.get(record_id)
    if not current:
        raise RecordConflict("The reviewed project defaults record is unavailable")
    current = _validate(current, DEFAULT_SCHEMA)
    if current["owner"] != principal:
        raise ProjectReviewDenied("Personal project defaults ownership changed")
    previous = current["operations"].get(key)
    if previous is not None:
        if previous != request_sha:
            raise RecordConflict("This erasure request identity belongs to another review")
        return {"status": "unconfirmed" if current.get("_audit_pending") else "replayed", "revision": current["revision"]}
    if current["structure"] is None:
        if current["revision"] != expected_revision:
            raise RecordConflict("Project defaults changed after the erasure review")
        return {"status": "unconfirmed" if current.get("_audit_pending") else "confirmed", "revision": current["revision"]}
    def clear(record):
        _validate(record, DEFAULT_SCHEMA)
        if record["owner"] != principal:
            raise ProjectReviewDenied("Personal project defaults ownership changed")
        record["structure"] = None
        record["operations"][key] = request_sha
        _seal(record)
    saved = _DEFAULTS.update(record_id, clear, expected_revision=expected_revision,
                             action="erase_personal_project_defaults", actor=actor)
    if saved is None:
        raise RecordConflict("The reviewed project defaults record is unavailable")
    return {"status": "unconfirmed" if saved.get("_audit_pending") else "confirmed", "revision": saved["revision"]}


class ProjectWorkspaces:
    def __init__(self, world, *, principal, eligible, reviews=None, store=None, defaults=None):
        self.world = world
        self.principal = _principal(principal)
        self.eligible = eligible
        self.reviews = reviews
        self.store = store or _WORKSPACES
        self.defaults = defaults or _DEFAULTS
        self.tenant = current_tenant_id_strict()
        if not self.tenant:
            raise ProjectReviewDenied("Select a workspace to use project workspaces")

    def _require(self, principal, suite, permission="view", *, member=False):
        if (current_tenant_id_strict() != self.tenant or
                self.eligible(principal, suite, permission, member) is not True):
            raise ProjectReviewDenied("Current workspace membership or permissions do not allow this project")

    def _require_domain(self, principal, domain, permission="view", *, member=False):
        suites = suites_for_domain(domain)
        for suite in suites or (None,):
            self._require(principal, suite, permission, member=member)

    def _project(self, project_id):
        if type(project_id) is not int or project_id < 1:
            raise ValueError("Choose a project")
        project = self.world.get_project(project_id)
        if not project or not project.get("owner") or project.get("status") != "active":
            raise ProjectReviewDenied("This project is unavailable")
        self._require_domain(self.principal, project.get("domain", ""))
        identity = {key: project[key] for key in ("id", "owner", "created_at")}
        return project, "PW-" + digest(identity)[:32]

    def _raw(self, project_id, *, write=False):
        project, record_id = self._project(project_id)
        record = self.store.get(record_id)
        if record:
            record = _validate(record, SCHEMA)
            if record["owner"] != project["owner"] or record["project_id"] != project_id:
                raise ProjectReviewDenied("The project identity changed")
        else:
            record = {"id": record_id, "schema": SCHEMA, "project_id": project_id,
                      "owner": project["owner"], "revision": 0, "outcome": "", "criteria": [],
                      "labels": [], "members": [], "milestones": [], "context": [],
                      "default_view": "list", "operations": {}, "history": []}
        owner = self.principal == project["owner"]
        if not owner and self.principal not in record["members"]:
            raise ProjectReviewDenied("The project owner has not shared this workspace with you")
        self._require_domain(self.principal, project.get("domain", ""),
                      "operate" if write else "view", member=not owner)
        if write and not owner:
            raise ProjectReviewDenied("Only the project owner can change workspace planning or sharing")
        return project, copy.deepcopy(record)

    def _task(self, project_id, goal_id):
        if type(goal_id) is not int or goal_id < 1:
            raise ValueError("Choose a linked task")
        goal = self.world.get_goal(goal_id)
        # A metadata grant is deliberately insufficient, including for admins.
        if not goal or goal.owner != self.principal or goal.project_id != project_id:
            raise ProjectReviewDenied("The linked task is private or no longer belongs to this project")
        self._require_domain(self.principal, goal.domain)
        return goal

    def _packet(self, project_id, packet_id):
        if self.reviews is None:
            raise ProjectReviewDenied("Project reviews are disabled; ask an administrator to enable them")
        if not isinstance(packet_id, str) or not re.fullmatch(r"PRP-[0-9a-f]{32}", packet_id):
            raise ValueError("Choose a review packet")
        packet = self.reviews.get(packet_id)
        if packet["project_id"] != project_id:
            raise ProjectReviewDenied("The review packet belongs to another project")
        return packet

    def _source(self, project_id, kind, source_id):
        if kind == "result":
            if not isinstance(source_id, str) or not source_id.isdecimal():
                raise ValueError("Choose a task result")
            goal = self._task(project_id, int(source_id))
            if not goal.result or goal.status in {"active", "pending"}:
                raise ValueError("The selected task does not have a stable saved result")
            source = {"title": goal.title, "content": goal.result, "status": goal.status,
                      "updated_at": goal.updated_at, "owner": goal.owner, "project_id": project_id}
            return {**source, "version": digest(source), "kind": kind, "source_id": source_id,
                    "href": f"/chat/goal/{goal.id}", "accepted": False}
        if kind == "review":
            packet = self._packet(project_id, source_id)
            return {"title": packet["snapshot"]["title"], "content": packet["snapshot"]["result"],
                    "status": packet["status"], "updated_at": packet["updated_at"],
                    "version": digest({"source": packet["source_version"], "revision": packet["revision"]}),
                    "kind": kind, "source_id": source_id, "href": "/project-reviews",
                    "accepted": packet["status"] == "approved" and not packet["stale"],
                    "stale": packet["stale"]}
        raise ValueError("Choose a saved result or review packet")

    def preview_source(self, project_id, kind, source_id):
        self._raw(project_id)
        return self._source(project_id, kind, source_id)

    def open_source(self, project_id, reference):
        _, record = self._raw(project_id)
        ref = next((ref for ref in record["context"] if ref["reference"] == reference), None)
        if not ref:
            raise ProjectReviewDenied("This context reference is no longer in the workspace")
        source = self._source(project_id, ref["kind"], ref["source_id"])
        if source["version"] != ref["version"] or source.get("stale"):
            raise RecordConflict("This context source changed. The owner must review its current version before reuse")
        self._raw(project_id)  # revalidate the sharing grant before publication
        current = self._source(project_id, ref["kind"], ref["source_id"])
        if current["version"] != source["version"] or current.get("stale"):
            raise RecordConflict("This context source changed while it was opening. Review it again")
        return current

    def _milestone_state(self, project_id, row):
        sources, accepted, complete, restricted = [], True, True, False
        for goal_id in row["goals"]:
            try:
                goal = self._task(project_id, goal_id)
                sources.append({"kind": "task", "id": goal.id, "title": goal.title,
                                "status": goal.status, "href": f"/chat/goal/{goal.id}"})
                complete = complete and goal.status == "done"
            except ProjectReviewDenied:
                restricted, complete = True, False
        for packet_id in row["reviews"]:
            try:
                packet = self._packet(project_id, packet_id)
                current = packet["status"] == "approved" and not packet["stale"]
                accepted = accepted and current
                sources.append({"kind": "review", "id": packet_id, "title": packet["snapshot"]["title"],
                                "status": "source changed" if packet["stale"] else packet["status"],
                                "href": "/project-reviews"})
            except ProjectReviewDenied:
                restricted, accepted = True, False
        state = ("restricted" if restricted else "accepted" if row["reviews"] and accepted and complete
                 else "work complete" if row["goals"] and complete and not row["reviews"]
                 else "waiting for review" if row["reviews"] and complete else "in progress"
                 if sources else "not linked")
        return {**{key: value for key, value in row.items() if key not in {"goals", "reviews"}},
                "state": state, "sources": sources, "restricted_sources": restricted}

    def get(self, project_id):
        project, record = self._raw(project_id)
        owner = self.principal == project["owner"]
        milestones = [self._milestone_state(project_id, row) for row in record["milestones"]]
        sources, accepted = [], []
        for ref in record["context"]:
            try:
                current = self._source(project_id, ref["kind"], ref["source_id"])
                fresh = current["version"] == ref["version"] and not current.get("stale")
                sources.append({"reference": ref["reference"], "title": current["title"],
                                "kind": current["kind"], "fresh": fresh,
                                "state": "ready" if fresh else "changed; owner review needed"})
            except (ProjectReviewDenied, ValueError):
                sources.append({"reference": ref["reference"] if owner else "", "title": "Restricted source",
                                "kind": "restricted", "fresh": False, "state": "current source access required"})
        if self.reviews:
            for item in self.reviews.inbox():
                if item["project_id"] == project_id and item["status"] == "approved" and not item["stale"]:
                    packet = self._packet(project_id, item["id"])
                    accepted.append({"id": packet["id"], "title": packet["snapshot"]["title"],
                                     "accepted_at": max(row["at"] for row in packet["history"] if row["action"] == "approve"),
                                     "href": "/project-reviews"})
        self._raw(project_id)
        return {"project_id": project_id, "name": project["name"], "revision": record["revision"],
                "owner": record["owner"], "can_edit": owner, "outcome": record["outcome"],
                "criteria": record["criteria"], "labels": record["labels"], "default_view": record["default_view"],
                "members": record["members"] if owner else [], "milestones": milestones, "context": sources,
                "latest_accepted": max(accepted, key=lambda item: item["accepted_at"]) if accepted else None,
                "execution_dependencies_changed": False, "task_access_granted": False,
                "editor": {"milestones": record["milestones"], "context": record["context"]} if owner else None}

    def list(self):
        ids = {project["id"] for project in self.world.list_projects(owner=self.principal)
               if project.get("status") == "active"}
        records = self.store.list(limit=10001)
        if len(records) > 10000:
            raise ValueError("Project workspace listing reached its supported limit")
        for row in records:
            row = _validate(row, SCHEMA)
            if self.principal in row["members"]:
                ids.add(row["project_id"])
        result = []
        for project_id in sorted(ids):
            try:
                project, record = self._raw(project_id)
                result.append({"project_id": project_id, "name": project["name"], "outcome": record["outcome"],
                               "labels": record["labels"], "owned": self.principal == project["owner"]})
            except ProjectReviewDenied:
                continue
        return result

    def choices(self, project_id):
        project, _ = self._raw(project_id, write=True)
        goals = []
        for goal in self.world.list_goals(project_id=project_id, owner=self.principal, limit=500, order="desc"):
            try:
                self._task(project_id, goal.id)
                goals.append({"id": goal.id, "title": goal.title, "result_available": bool(goal.result)
                              and goal.status not in {"active", "pending"}})
            except ProjectReviewDenied:
                continue
        packets = [row for row in self.reviews.inbox() if row["project_id"] == project_id] if self.reviews else []
        return {"goals": goals, "reviews": [{"id": row["id"], "title": row["title"], "status": row["status"]}
                                             for row in packets], "suite": suite_for(project.get("domain", ""))}

    def personal_defaults(self):
        self._require(self.principal, None)
        record = self.defaults.get("PWD-" + digest(self.principal)[:32])
        if not record:
            return {"revision": 0, "structure": None}
        record = _validate(record, DEFAULT_SCHEMA)
        if record["owner"] != self.principal:
            raise ProjectReviewDenied("Personal project defaults are unavailable")
        return {"revision": record["revision"], "structure": copy.deepcopy(record["structure"])}

    @staticmethod
    def _lines(value, label, count=30, limit=1000):
        if not isinstance(value, list) or len(value) > count:
            raise ValueError(f"{label} supports up to {count} entries")
        result = [_text(item, label, limit) for item in value]
        if len(set(result)) != len(result):
            raise ValueError(f"{label} contains duplicate entries")
        return result

    def plan(self, project_id, action, payload):
        project, record = self._raw(project_id, write=True)
        if action not in ACTIONS or not isinstance(payload, dict):
            raise ValueError("Choose a supported project operation")
        after = copy.deepcopy(record)
        handler = {"details": self._plan_metadata, "member": self._plan_member,
                   "milestone": self._plan_milestone, "remove_milestone": self._plan_ordering,
                   "reorder": self._plan_ordering, "dependency": self._plan_ordering,
                   "context": self._plan_context, "remove_context": self._plan_context,
                   "save_defaults": self._plan_defaults, "apply_defaults": self._plan_defaults}[action]
        handler(project_id, project, record, after, payload, action)
        changed = [{"field": key.replace("_", " "), "before": record[key], "after": after[key]}
                   for key in ("outcome", "criteria", "labels", "default_view", "members", "milestones", "context")
                   if record[key] != after[key]]
        return {"revision": record["revision"], "action": action, "changes": changed,
                "after": after, "defaults_revision": self.personal_defaults()["revision"]}

    def _plan_metadata(self, project_id, project, record, after, payload, action):
        if set(payload) != {"outcome", "criteria", "labels", "default_view"}:
            raise ValueError("Review all project outcome fields before saving")
        after["outcome"] = _text(payload["outcome"], "Outcome", 6000, empty=True)
        after["criteria"] = self._lines(payload["criteria"], "Acceptance criteria")
        after["labels"] = self._lines(payload["labels"], "Labels", 20, 80)
        if payload["default_view"] not in VIEWS:
            raise ValueError("Choose a list, board or timeline view")
        after["default_view"] = payload["default_view"]

    def _plan_member(self, project_id, project, record, after, payload, action):
        if set(payload) != {"member", "allowed"} or type(payload["allowed"]) is not bool:
            raise ValueError("Choose a named member and a sharing decision")
        member = _principal(payload["member"])
        if member == self.principal:
            raise ValueError("The owner already has workspace access")
        members = set(after["members"])
        if payload["allowed"]:
            self._require_domain(member, project.get("domain", ""), member=True)
            members.add(member)
        else:
            members.discard(member)
        if len(members) > 100:
            raise ValueError("A workspace supports at most 100 named members")
        after["members"] = sorted(members)

    def _plan_milestone(self, project_id, project, record, after, payload, action):
        if set(payload) != {"id", "title", "due", "goals", "reviews"}:
            raise ValueError("Review the milestone and its linked work before saving")
        milestone_id = payload["id"]
        if not isinstance(milestone_id, str) or not re.fullmatch(r"[a-f0-9]{32}", milestone_id):
            raise ValueError("Milestone reference is invalid")
        due = payload["due"]
        if not isinstance(due, str):
            raise ValueError("Choose a valid milestone date")
        if due:
            if dt.date.fromisoformat(due).isoformat() != due:
                raise ValueError("Choose a valid milestone date")
        goals, reviews = payload["goals"], payload["reviews"]
        if (not isinstance(goals, list) or not isinstance(reviews, list) or len(goals) + len(reviews) > 50
                or any(type(value) is not int for value in goals) or any(not isinstance(value, str) for value in reviews)
                or len(set(goals)) != len(goals) or len(set(reviews)) != len(reviews)):
            raise ValueError("Choose up to 50 distinct linked tasks or reviews")
        for goal_id in goals:
            self._task(project_id, goal_id)
        for packet_id in reviews:
            self._packet(project_id, packet_id)
        previous = next((row for row in after["milestones"] if row["id"] == milestone_id), None)
        row = {"id": milestone_id, "title": _text(payload["title"], "Milestone", 200), "due": due,
               "goals": goals, "reviews": reviews, "depends_on": previous["depends_on"] if previous else []}
        if previous:
            after["milestones"][after["milestones"].index(previous)] = row
        else:
            if len(after["milestones"]) >= 100:
                raise ValueError("A workspace supports at most 100 milestones")
            after["milestones"].append(row)

    def _plan_ordering(self, project_id, project, record, after, payload, action):
        keys = {"id"} if action == "remove_milestone" else {"id", "direction"} if action == "reorder" else {"id", "prerequisite", "required"}
        if set(payload) != keys:
            raise ValueError("Review the selected milestone change")
        rows = after["milestones"]
        row = next((row for row in rows if row["id"] == payload["id"]), None)
        if row is None:
            raise RecordConflict("This milestone was removed; reload the workspace")
        if action == "remove_milestone":
            rows.remove(row)
            for other in rows:
                other["depends_on"] = [item for item in other["depends_on"] if item != row["id"]]
        elif action == "reorder":
            if payload["direction"] not in {"up", "down"}:
                raise ValueError("Choose Move up or Move down")
            index = rows.index(row)
            new_index = max(0, min(len(rows) - 1, index + (-1 if payload["direction"] == "up" else 1)))
            rows.insert(new_index, rows.pop(index))
        else:
            prerequisite = payload["prerequisite"]
            if type(payload["required"]) is not bool or prerequisite == row["id"] or prerequisite not in {item["id"] for item in rows}:
                raise ValueError("Choose another milestone as a planning prerequisite")
            depends = set(row["depends_on"])
            depends.add(prerequisite) if payload["required"] else depends.discard(prerequisite)
            row["depends_on"] = sorted(depends)
            graph = {item["id"]: item["depends_on"] for item in rows}
            visited = set()
            def visit(node, path):
                if node in path:
                    raise ValueError("Planning prerequisites cannot form a cycle")
                if node in visited:
                    return
                for parent in graph[node]:
                    visit(parent, path | {node})
                visited.add(node)
            for node in graph:
                visit(node, set())

    def _plan_context(self, project_id, project, record, after, payload, action):
        if action == "remove_context":
            if set(payload) != {"reference"}:
                raise ValueError("Choose a context reference to remove")
            after["context"] = [row for row in after["context"] if row["reference"] != payload["reference"]]
        else:
            if set(payload) != {"kind", "source_id", "version"}:
                raise ValueError("Review the current source before adding context")
            source = self._source(project_id, payload["kind"], payload["source_id"])
            if payload["version"] != source["version"] or source.get("stale"):
                raise RecordConflict("The source changed; review its current saved version")
            reference = digest({"kind": payload["kind"], "source_id": payload["source_id"]})[:32]
            after["context"] = [row for row in after["context"] if row["reference"] != reference]
            if len(after["context"]) >= 100:
                raise ValueError("A project supports at most 100 context references")
            after["context"].append({**payload, "reference": reference})

    def _plan_defaults(self, project_id, project, record, after, payload, action):
        defaults = self.personal_defaults()
        if (set(payload) != {"defaults_revision"} or type(payload["defaults_revision"]) is not int
                or payload["defaults_revision"] != defaults["revision"]):
            raise RecordConflict("Your project defaults changed; review them again")
        if action == "apply_defaults":
            if not defaults["structure"]:
                raise ValueError("Save your own project structure before applying defaults")
            if after["milestones"]:
                raise ValueError("Apply a reusable structure to a project without milestones; existing linked work is kept")
            structure = copy.deepcopy(defaults["structure"])
            for index, row in enumerate(structure["milestones"]):
                row["id"] = digest({"project": record["id"], "index": index, "defaults": defaults["revision"]})[:32]
                row.update(goals=[], reviews=[], depends_on=[], due="")
            after.update(structure)

    @staticmethod
    def _request_digest(action, payload, expected_revision):
        return digest({"action": action, "payload": payload, "revision": expected_revision})

    def receipt(self, project_id, operation_id, action, payload, expected_revision):
        _, record = self._raw(project_id, write=True)
        operation_id = _request(operation_id)
        if action == "save_defaults":
            defaults = self.defaults.get("PWD-" + digest(self.principal)[:32])
            receipt = (_validate(defaults, DEFAULT_SCHEMA) if defaults else {}).get("operations", {}).get(operation_id)
        else:
            receipt = record["operations"].get(operation_id)
        if receipt is None:
            return False
        request_sha = self._request_digest(action, payload, expected_revision)
        if action == "save_defaults":
            request_sha = digest({"project": record["id"], "change": request_sha})
        if receipt != request_sha:
            raise RecordConflict("This request reference belongs to another project change")
        return True

    @contextmanager
    def _guard(self, project_id):
        _, record_id = self._project(project_id)
        if self.store.authority_scope != "tenant" or self.defaults.authority_scope != "tenant":
            raise ValueError("Project workspace stores must be tenant scoped")
        if self.store.backend_kind != self.defaults.backend_kind:
            raise ValueError("Project workspaces and defaults must share their authority backend")
        if self.store.backend_kind == "postgres":
            yield
            return
        from .file_lock import cross_process_lock, ensure_private_directory
        from .paths import data_dir
        path = ensure_private_directory(data_dir("project_workspace_authority")) / (record_id + ".lock")
        with _LOCK, cross_process_lock(path, strict=True):
            yield

    def change(self, project_id, action, payload, *, expected_revision, operation_id):
        with self._guard(project_id):
            return self._change(project_id, action, payload, expected_revision=expected_revision, operation_id=operation_id)

    def _change(self, project_id, action, payload, *, expected_revision, operation_id):
        operation_id = _request(operation_id)
        if type(expected_revision) is not int or expected_revision < 0:
            raise ValueError("Workspace version is invalid")
        if self.receipt(project_id, operation_id, action, payload, expected_revision):
            return {"status": "replayed", "workspace": self.get(project_id)}
        planned = self.plan(project_id, action, payload)
        if planned["revision"] != expected_revision:
            raise RecordConflict("The project workspace changed. Your draft is kept; reload and review current values")
        record = planned["after"]
        if len(record["operations"]) >= 2000 and not (action == "member" and payload.get("allowed") is False):
            raise ValueError("Workspace change history reached its supported limit; existing access can still be revoked")
        if action == "member" and payload.get("allowed") is False and not planned["changes"]:
            return {"status": "confirmed", "workspace": self.get(project_id)}
        if action == "save_defaults":
            if not expected_revision:
                raise ValueError("Save this project's outcome before saving its reusable structure")
            self._save_defaults(record, payload["defaults_revision"], operation_id,
                                digest({"project": record["id"], "change": self._request_digest(action, payload, expected_revision)}))
            return {"status": "confirmed", "workspace": self.get(project_id)}
        record["operations"][operation_id] = self._request_digest(action, payload, expected_revision)
        record["history"].append({"operation_id": operation_id, "action": action, "actor": self.principal,
                                  "at": self.store.authoritative_time()})
        _seal(record)
        # Store CAS prevents lost updates and preserves all request receipts.
        if expected_revision:
            def update(current):
                _validate(current, SCHEMA)
                project, identity = self._project(project_id)
                self._require_domain(self.principal, project.get("domain", ""), "operate")
                if identity != current["id"] or project["owner"] != self.principal or current["owner"] != self.principal:
                    raise ProjectReviewDenied("Project ownership changed; the reviewed update cannot be applied")
                current.update({key: value for key, value in record.items() if key not in {"revision", "created_at", "updated_at", "_audit_pending"}})
            self.store.update(record["id"], update, expected_revision=expected_revision,
                              action="project_" + action, actor=self.principal)
        else:
            self._raw(project_id, write=True)
            record.pop("revision", None)
            self.store.create(record, action="project_" + action, actor=self.principal, max_records=10000)
        return {"status": "confirmed", "workspace": self.get(project_id)}

    def _save_defaults(self, workspace, expected_revision, operation_id, request_sha):
        record_id = "PWD-" + digest(self.principal)[:32]
        current = self.defaults.get(record_id)
        if current:
            _validate(current, DEFAULT_SCHEMA)
        if (current or {}).get("revision", 0) != expected_revision:
            raise RecordConflict("Your project defaults changed; review them again")
        structure = {key: copy.deepcopy(workspace[key]) for key in ("outcome", "criteria", "labels", "default_view")}
        structure["milestones"] = [{"title": row["title"]} for row in workspace["milestones"]]
        operations = (current or {}).get("operations", {}).copy()
        if len(operations) >= 2000:
            raise ValueError("Personal project defaults history reached its supported limit")
        operations[operation_id] = request_sha
        record = {"id": record_id, "schema": DEFAULT_SCHEMA, "owner": self.principal,
                  "structure": structure, "operations": operations}
        _seal(record)
        fence = None
        if self.store.backend_kind == "postgres":
            def validate(source, _now):
                _validate(source, SCHEMA)
                if source["revision"] != workspace["revision"]:
                    raise RecordConflict("The source project changed; review its structure again")
            fence = GovernedMutationFence(self.store.namespace, self.store.prefix, workspace["id"], "tenant", validate)
        if current:
            self.defaults.update(record_id, lambda value: value.update(record), expected_revision=expected_revision,
                                 action="save_project_defaults", actor=self.principal, fence=fence)
        else:
            self.defaults.create(record, action="save_project_defaults", actor=self.principal, max_records=10000, fence=fence)
