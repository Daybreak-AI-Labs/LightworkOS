"""Exact workflow content and publication evidence for recommendation outcomes."""
from __future__ import annotations

import time
from contextlib import contextmanager

from ..flow import store
from ..privacy_ops import RecordConflict


def bind(flow_id, *, version, revision):
    """Capture the reviewed definition and transitive children, never activate it."""
    definition_digest, current_version, children = store.snapshot_current_flow_bundle(flow_id)
    definition = store.load_flow_snapshot(definition_digest)
    if current_version != version or definition.revision != revision:
        raise RecordConflict("The selected workflow changed. Review its current definition.")
    release_digest = store.release_digest_for(definition_digest, children)
    published = store.load_published_bundle(flow_id)
    release = published[1] if published and published[1]["release_digest"] == release_digest else None
    return {"flow_id": flow_id, "revision": revision, "version": version,
            "definition_digest": definition_digest, "release_digest": release_digest,
            "release_id": release["release_id"] if release else "", "selected_at": time.time()}


def current(binding):
    """Recheck the complete reviewed bundle immediately before recording selection."""
    observed = bind(binding["flow_id"], version=binding["version"], revision=binding["revision"])
    if any(observed[key] != binding[key] for key in ("definition_digest", "release_digest", "release_id")):
        raise RecordConflict("The selected workflow changed. Review its current definition.")


@contextmanager
def selection_guard(binding):
    """Always acquire flow locks before recommendation locks, as native saves do."""
    if binding is None:
        yield
        return
    with store._activation_lock(binding["flow_id"]), store._definitions_lock():
        current(binding)
        yield


def release_for(binding, previous):
    """Retain an observed publication; never infer activation from a generation."""
    if binding.get("release_id"):
        return binding
    if previous and previous.get("release_id") and previous.get("selection") == binding:
        return previous
    published = store.load_published_bundle(binding["flow_id"])
    if published and published[1]["published_at"] >= binding["selected_at"]:
        definition, release = published
        exact = release["release_digest"] == binding["release_digest"]
        reviewed_draft = (binding.get("allow_draft_edits") and definition.revision == binding["revision"]
                          and definition.version >= binding["version"])
        if exact or reviewed_draft:
            # Building creates an editable draft. Its first observed explicit
            # publication adopts the customer's final definition, including
            # edits. Reusing an existing workflow remains exact-content bound.
            return {**binding, "definition_digest": release["definition_digest"],
                    "release_digest": release["release_digest"], "release_id": release["release_id"],
                    "version": definition.version, "selection": binding}
    return None


def matches(row, binding):
    """A grouped retry cannot borrow another release's receipt or attempt costs."""
    source = row["source"]
    runs = [item for item in source["sources"] if item["kind"] == "flow"]
    if not runs or any(
        item.get("flow_id") != binding["flow_id"]
        or item.get("definition_digest") != binding["definition_digest"]
        or item.get("release_digest") != binding["release_digest"]
        or item.get("release_id") != binding["release_id"]
        or item["at"] < binding["selected_at"]
        for item in runs
    ):
        return False
    if source["performed_at"] is None or source.get("partial_execution"):
        return True  # Failed attempts still contribute their exact bound costs.
    identifiers = {item["id"] for item in runs}
    return any(item.get("full_task") and item.get("run_id") in identifiers
               and item.get("release_id") == binding["release_id"]
               and item.get("revision") == binding["revision"]
               for item in source["evidence"])
