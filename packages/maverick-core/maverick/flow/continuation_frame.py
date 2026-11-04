"""Mutable interpreter checkpoint frame with explicit transition operations."""
from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any


@dataclass
class ContinuationFrame:
    """Own a live frame without changing its persisted dictionary schema.

    Nested invocations share the underlying dictionary. An exception saves the
    current data without advancing the cursor; only a completed node replaces
    the frame and drops its completed child frames.
    """

    raw: dict[str, Any]
    flow_id: str

    def start(self, data: dict, cursor: str | None) -> tuple[str | None, int]:
        if self.raw:
            if self.raw.get("flow_id") != self.flow_id or not isinstance(self.raw.get("data"), dict):
                raise ValueError("flow continuation does not match its graph")
            data.clear()
            data.update(copy.deepcopy(self.raw["data"]))
        else:
            self.raw.update(flow_id=self.flow_id, cursor=cursor, data=copy.deepcopy(data), seen=0)
        return self.raw["cursor"], int(self.raw.get("seen", 0))

    def checkpoint_data(self, data: dict) -> None:
        """Record current data while retaining the active node and children."""
        self.raw["data"] = copy.deepcopy(data)

    def advance(self, cursor: str | None, data: dict, seen: int) -> None:
        """Commit a completed node and retire its nested execution frames."""
        self.raw.clear()
        self.raw.update(flow_id=self.flow_id, cursor=cursor, data=copy.deepcopy(data), seen=seen)
