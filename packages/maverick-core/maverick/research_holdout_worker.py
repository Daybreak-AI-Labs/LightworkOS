"""Evaluator-custody process for held-out generator families.

The parent receives only an opaque process handle and bounded equality oracle.
Private generator parameters and reference answers stay in this process after
initialization and are never returned by any command.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from typing import Any

_MAX_MESSAGE_BYTES = 1_048_576
_MAX_EVALUATIONS = 128


def _canonical(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _write(value: object) -> None:
    sys.stdout.write(_canonical(value) + "\n")
    sys.stdout.flush()


def _read() -> dict[str, Any]:
    raw = sys.stdin.buffer.readline(_MAX_MESSAGE_BYTES + 1)
    if not raw or len(raw) > _MAX_MESSAGE_BYTES or not raw.endswith(b"\n"):
        raise ValueError("invalid evaluator message")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("invalid evaluator message")
    return value


def main() -> int:
    try:
        initial = _read()
        if initial.get("command") != "initialize":
            raise ValueError("initialization required")
        families = initial.get("families")
        if not isinstance(families, dict) or not families:
            raise ValueError("held-out families are required")
        references: dict[str, object] = {}
        for family_id, row in families.items():
            if not isinstance(family_id, str) or not isinstance(row, dict):
                raise ValueError("held-out family is invalid")
            references[family_id] = row["reference_solution"]
        custody_sha256 = hashlib.sha256(os.urandom(32)).hexdigest()
        # An opaque session identifier proves that the same evaluator process
        # answered later requests without exposing any answer-derived digest.
        _write({
            "ok": True,
            "schema": "maverick.research-heldout-custody.v1",
            "family_count": len(references),
            "custody_sha256": custody_sha256,
        })
        evaluations = 0
        while True:
            request = _read()
            command = request.get("command")
            if command == "close":
                _write({"ok": True, "closed": True})
                return 0
            if command != "evaluate":
                _write({"ok": False, "error": "unsupported evaluator command"})
                continue
            evaluations += 1
            if evaluations > _MAX_EVALUATIONS:
                _write({"ok": False, "error": "held-out evaluation budget exhausted"})
                continue
            family_id = request.get("family_id")
            if family_id not in references:
                _write({"ok": False, "error": "held-out family is unavailable"})
                continue
            try:
                passed = _canonical(request.get("candidate")) == _canonical(references[family_id])
            except (TypeError, ValueError):
                _write({"ok": False, "error": "candidate is not canonical JSON"})
                continue
            _write({"ok": True, "passed": passed})
    except (BrokenPipeError, EOFError):
        return 0
    except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        _write({"ok": False, "error": "evaluator initialization was refused"})
        return 2


if __name__ == "__main__":  # pragma: no cover - exercised through the controller
    raise SystemExit(main())
