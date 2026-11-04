"""Chat follow-up admission helpers importable by spawned test children."""
from __future__ import annotations

from maverick.attachment_submissions import SubmissionConflict, SubmissionStore
from maverick.world_model import WorldModel


def _create(world, *, root=None, token="root", owner="user:alice"):
    return SubmissionStore(world).create(
        token=token, fingerprint=token, owner=owner, title="Report",
        description="Keep budget BUDGET-ALPHA-731", manifest=[], parent_id=root,
        chat_text="Keep budget BUDGET-ALPHA-731" if root is None else "Revise the report",
        chat_root_id=root,
    )


def _process_reply(path, root, index, barrier, output):
    with WorldModel(path) as world:
        barrier.wait(timeout=30)
        try:
            receipt = _create(world, root=root, token=f"process-{index}")
            output.put(("admitted", receipt["goal_id"]))
        except SubmissionConflict:
            output.put(("refused", None))
