"""One run identity shared by corpus, rejected/candidate rows and text sidecars."""
from __future__ import annotations

import hashlib
import json
import re


def record_trajectory_id(record: dict) -> str:
    identity = record.get("record_id")
    if identity is not None:
        if not isinstance(identity, str) or not re.fullmatch(r"trj_[0-9a-f]{32}", identity):
            raise ValueError("Invalid donation record identity")
        return identity
    # Legacy timestamps cannot distinguish same-second runs. Canonical content
    # gives existing records a deterministic migration identity, including their
    # precise timestamp, goal, outcomes and draft/candidate evidence. Re-export
    # corpus and sidecar together; never alias to the old lossy hash-second id.
    payload = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return "legacy_" + hashlib.sha256(payload.encode("utf-8")).hexdigest()
