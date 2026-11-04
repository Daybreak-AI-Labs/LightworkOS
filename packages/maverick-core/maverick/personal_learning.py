"""Current owned learning inventory with opaque independently reviewed targets."""
from __future__ import annotations

import hashlib
import json

from . import learning_content, self_learning
from .file_lock import cross_process_lock


def _key(name, digest):
    return hashlib.sha256(json.dumps([name, digest], separators=(",", ":")).encode()).hexdigest()


def owned_tools(owner):
    if not isinstance(owner, str) or not owner.startswith("user:"):
        raise ValueError("A named owner is required.")
    names = self_learning.generated_tool_names(owner=owner)
    if len(names) > 5000:
        raise ValueError("Owned generated tools exceed the complete review window.")
    result = []
    for name in sorted(names):
        path = self_learning.generated_tools_dir() / (name + ".py")
        with cross_process_lock(path, strict=True):
            source = self_learning._read_generated_source(path)
            digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
            if not learning_content.source_allowed_now(path, digest, owner=owner):
                raise ValueError("Owned generated-tool authority changed; refresh the inventory.")
            meta = json.loads(learning_content.metadata_path(path).read_text(encoding="utf-8"))
        result.append({"id": _key(name, digest), "digest": digest, "name": name, "goal_id": meta.get("goal_id")})
    return result


def reviewed_targets(owner):
    # Names can contain private business context. Independent deletion reviewers
    # receive only opaque current-source keys and source task IDs, never names.
    return [{key: row[key] for key in ("id", "digest", "goal_id")} for row in owned_tools(owner)]


def erase_reviewed(owner, targets, *, actor):
    current = {row["id"]: row for row in owned_tools(owner)}
    if reviewed_targets(owner) != targets:
        raise ValueError("Generated sources changed. Their owner must review a new exact scope.")
    removed = 0
    for target in targets:
        row = current[target["id"]]
        self_learning.delete_generated_tool(row["name"], actor=actor, owner=owner, expected_digest=target["digest"])
        removed += 1
    return {"state": "purged", "removed": removed,
            "retained": "Content-free revocation/audit receipts remain. Unknown, excluded, unavailable or unconsented derived files are outside this current authorized selection and are not claimed purged."}


def inventory(owner):
    tools = owned_tools(owner)
    lessons = self_learning.history(owner=owner, limit=501)
    return {"tools": tools,
            "learning_records": [{"goal_id": row.goal_id, "kind": row.kind, "date": row.ts} for row in lessons[:500]],
            "learning_records_truncated": len(lessons) > 500,
            "state": "current-authorized-only",
            "limits": "Only current source-authorized, consented tools and currently readable ledger lineage are listed. An empty result does not certify no retained files. Unknown ownership, excluded sources and unavailable records remain withheld; ledger rows and prior models are retained and are not claimed purged or unlearned."}
