"""Crash-only logging: a sink that is safe to ``kill -9`` at any byte
.

Post-incident forensics are only as good as the last record that actually
reached disk. A buffered logger loses its tail on SIGKILL/OOM — exactly the
records describing the crash — and a torn final line can poison naive readers
of everything before it. This sink makes the failure mode boring:

* **Append-only JSONL, one fsync'd write per record.** :meth:`CrashOnlyLog.append`
  serializes the record, issues a single ``os.write`` to an ``O_APPEND`` fd,
  then ``os.fsync``. There is no in-memory buffer, no background flusher and
  no ``close()`` required for durability: once ``append`` returns, the record
  survives ``kill -9`` and (modulo storage lies) power loss.
* **Monotonic ``seq``** persisted in every record. On reopen the writer scans
  the file and resumes from the last *intact* record, so sequence numbers
  stay monotonic across process deaths; :func:`verify` detects holes (an
  append that raised after incrementing, or external truncation).
* **Torn-tail recovery.** A crash mid-write legally leaves one incomplete
  final line. :func:`replay` parses only newline-terminated lines as records;
  an unterminated tail is kept iff it parses as a complete record (a strict
  prefix of a JSON object can never parse, so a half-written record cannot be
  misread as data) and otherwise discarded and flagged ``torn_tail``.
  Unparseable lines *before* the tail are not a legal crash artifact of this
  writer; they are counted in ``corrupt`` instead. On reopen the writer seals
  an unterminated tail with a newline so new appends never splice into it.
* **fsync policy knob** for tests/throughput runs: ``[logging]
  crash_only_fsync = "always"|"never"`` (env ``MAVERICK_CRASH_ONLY_FSYNC``
  wins). Default ``"always"`` — that IS the feature; ``"never"`` keeps the
  same format and recovery but trades the per-record durability guarantee for
  speed, so it is documented strictly as a test/bulk mode. The policy is
  resolved once at construction (a config read per append would dwarf the
  write), and a ``fsync=`` constructor argument overrides both for direct
  injection.

The log file is created 0600. The clock is injectable (``clock=``) so tests
are deterministic. Stdlib-only, thread-safe (one lock around seq+write), and
nothing enables it by default. ``[logging] crash_log`` (see
:mod:`maverick.logging_config`) keeps a crash-safe copy of warnings and errors
through it.
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

FSYNC_ALWAYS = "always"
FSYNC_NEVER = "never"


def fsync_policy() -> str:
    """Resolve the fsync knob: env ``MAVERICK_CRASH_ONLY_FSYNC`` wins over
    ``[logging] crash_only_fsync``; anything unrecognized -> ``"always"``."""
    env = os.environ.get("MAVERICK_CRASH_ONLY_FSYNC", "").strip().lower()
    if env in (FSYNC_ALWAYS, FSYNC_NEVER):
        return env
    try:
        from .config import load_config
        v = str((load_config() or {}).get("logging", {}).get(
            "crash_only_fsync", FSYNC_ALWAYS)).strip().lower()
        return v if v in (FSYNC_ALWAYS, FSYNC_NEVER) else FSYNC_ALWAYS
    except Exception:  # pragma: no cover -- config never blocks logging
        return FSYNC_ALWAYS


def _parse_record(raw: bytes) -> dict | None:
    """One line -> record dict, or None if it isn't a JSON object."""
    try:
        rec = json.loads(raw)
    except ValueError:
        return None
    return rec if isinstance(rec, dict) else None


def _encode_line(rec: dict) -> bytes:
    """One JSON line for ``rec``. A value json cannot encode as given (a lone
    surrogate, a non-string dict key) falls back to ASCII escapes and its
    ``str`` form, so an exotic field cannot stop the record being written."""
    try:
        return json.dumps(rec, ensure_ascii=False, separators=(",", ":"),
                          default=str).encode("utf-8") + b"\n"
    except (TypeError, ValueError):
        plain = (str, int, float, bool, type(None))
        safe = {str(k): v if isinstance(v, plain) else str(v) for k, v in rec.items()}
        return json.dumps(safe, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n"


@dataclass
class ReplayResult:
    """Outcome of :func:`replay`.

    ``records`` are the intact records in file order. ``torn_tail`` is True
    iff a final *incomplete* line was discarded (the legal ``kill -9``
    artifact). ``corrupt`` counts unparseable non-tail lines — those indicate
    external damage (or a previously sealed torn tail), never a clean crash.
    Iterating / ``len()`` operate on ``records``.
    """

    records: list[dict]
    torn_tail: bool
    corrupt: int

    def __iter__(self):
        return iter(self.records)

    def __len__(self) -> int:
        return len(self.records)


def replay(path: str | Path) -> ReplayResult:
    """Read every intact record from ``path``; tolerate a torn final line.

    A missing file replays as empty (recovery code shouldn't have to care
    whether the process died before the first append). See
    :class:`ReplayResult` for the exact tail/corruption semantics.
    """
    try:
        data = Path(path).read_bytes()
    except FileNotFoundError:
        return ReplayResult(records=[], torn_tail=False, corrupt=0)
    records: list[dict] = []
    corrupt = 0
    torn_tail = False

    terminated = data.endswith(b"\n")
    lines = data.split(b"\n")
    if terminated:
        body, tail = lines[:-1], None  # drop the empty piece after the last \n
    else:
        body, tail = lines[:-1], lines[-1]

    for raw in body:
        if not raw.strip():
            continue
        rec = _parse_record(raw)
        if rec is None:
            corrupt += 1
        else:
            records.append(rec)

    if tail is not None and tail.strip():
        rec = _parse_record(tail)
        if rec is None:
            torn_tail = True  # incomplete final line: discard, don't poison
        else:
            # The whole record made it to disk; only its newline was lost.
            # (A strict prefix of a JSON object never parses, so this cannot
            # accept a half-written record.)
            records.append(rec)

    return ReplayResult(records=records, torn_tail=torn_tail, corrupt=corrupt)


def verify(path: str | Path) -> dict:
    """Integrity summary for a crash-only log file.

    Returns ``{"records", "torn_tail", "corrupt", "first_seq", "last_seq",
    "gaps"}`` where ``gaps`` is a list of ``(prev_seq, next_seq)`` pairs whose
    intermediate sequence numbers are absent (an append that raised after
    incrementing, a discarded torn record, or external tampering).
    """
    result = replay(path)
    seqs = [r["seq"] for r in result.records
            if isinstance(r.get("seq"), int) and not isinstance(r.get("seq"), bool)]
    gaps = [(a, b) for a, b in zip(seqs, seqs[1:], strict=False) if b > a + 1]
    return {
        "records": len(result.records),
        "torn_tail": result.torn_tail,
        "corrupt": result.corrupt,
        "first_seq": seqs[0] if seqs else None,
        "last_seq": seqs[-1] if seqs else None,
        "gaps": gaps,
    }


class CrashOnlyLog:
    """Append-only, fsync-per-record JSONL log (see the module docstring).

    ``append(kind, **fields)`` returns the persisted ``seq``. The reserved
    keys ``seq``/``ts`` always win over a same-named field. ``close()`` is
    optional hygiene (releases the fd); durability never depends on it.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        fsync: bool | None = None,
        clock: Callable[[], float] = time.time,
    ):
        self.path = Path(path)
        self._clock = clock
        self._fsync = fsync if fsync is not None else (fsync_policy() == FSYNC_ALWAYS)
        self._lock = threading.Lock()
        from .file_lock import open_private_append

        self._fd = open_private_append(
            self.path, require_private_parent=True,
        )
        try:
            self._seq = self._recover()
        except BaseException:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = -1
            raise

    def _recover(self) -> int:
        """Seal a torn tail and return the last intact seq (0 for a new file).

        Sealing (appending one ``\\n`` to an unterminated file) guarantees the
        next append starts on a fresh line instead of splicing into the torn
        one; later replays then count the sealed fragment under ``corrupt``.
        O(file) once per open — the price of not trusting any sidecar state.
        """
        try:
            data = self.path.read_bytes()
        except OSError:  # pragma: no cover -- fd open succeeded, read raced
            data = b""
        if data and not data.endswith(b"\n"):
            os.write(self._fd, b"\n")
            if self._fsync:
                os.fsync(self._fd)
        seqs = [r["seq"] for r in replay(self.path).records
                if isinstance(r.get("seq"), int) and not isinstance(r.get("seq"), bool)]
        return max(seqs) if seqs else 0

    def append(self, kind: str, **fields) -> int:
        """Durably append one record; returns its monotonic ``seq``.

        Serialize -> single ``os.write`` of the whole line to the ``O_APPEND``
        fd -> ``os.fsync`` (policy permitting). Values json can't represent
        are stringified (``default=str``) — an exotic field must not be able
        to kill the crash log. If the OS shorts the write (effectively never
        for line-sized writes on regular files) the remainder is written
        immediately; a crash inside that window is exactly the torn tail
        :func:`replay` already tolerates.
        """
        with self._lock:
            seq = self._seq + 1
            rec: dict = {"seq": seq, "ts": float(self._clock()), "kind": str(kind)}
            for k, v in fields.items():
                rec.setdefault(k, v)
            line = _encode_line(rec)
            # The sequence number is consumed only once its line is written,
            # so a record that cannot be written leaves no gap.
            view = memoryview(line)
            while view:
                try:
                    n = os.write(self._fd, view)
                except OSError:
                    if len(view) < len(line):
                        # Seal the torn fragment so the next record starts on
                        # its own line instead of joining onto it.
                        with contextlib.suppress(OSError):
                            os.write(self._fd, b"\n")
                    raise
                view = view[n:]
            self._seq = seq
            if self._fsync:
                os.fsync(self._fd)
        return seq

    @property
    def last_seq(self) -> int:
        """The most recently issued sequence number (0 before any append)."""
        with self._lock:
            return self._seq

    def close(self) -> None:
        """Release the fd. Optional: durability NEVER depends on calling it."""
        try:
            os.close(self._fd)
        except OSError:  # pragma: no cover -- already closed
            pass
        self._fd = -1


__all__ = [
    "CrashOnlyLog",
    "ReplayResult",
    "replay",
    "verify",
    "fsync_policy",
    "FSYNC_ALWAYS",
    "FSYNC_NEVER",
]
