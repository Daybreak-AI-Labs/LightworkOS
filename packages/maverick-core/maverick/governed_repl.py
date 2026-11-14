"""Governed session kernel -- persistent Python execution as an audited artifact.

A model that writes CODE against a live namespace converts more capability per
token than one composing fixed tool schemas: a loop, a filter and a join are
three lines instead of thirty tool calls. The price of that leverage is that
the work stops being legible -- and arbitrary code is precisely what an audited
deployment cannot admit. This module pays the price rather than skipping it:
every statement is hashed, screened, receipted on the tamper-evident lineage
chain (PREPARE before the effect, COMMIT after), audited, and appended to a
per-session ledger. The code IS the audited artifact.

Persistence without a resident process
--------------------------------------
Sandbox backends expose one-shot ``exec(cmd, timeout=)``; there is no long-lived
kernel to attach to, and inventing one would mean a host process living outside
the sandbox chokepoint (kernel rule 4). So the namespace is carried explicitly:
a small driver script loads the prior namespace from a JSON state file, execs
the new statement in it, and re-dumps only the JSON-serializable globals. The
obvious alternative -- replaying the session's prelude before each statement --
re-runs every side effect the session already performed (one ``send_invoice()``
becomes N), so it is not an alternative at all.

Values that cannot cross that boundary (modules, callables, sockets, arbitrary
objects) are DROPPED and named in the result's ``dropped`` list rather than
silently vanishing, so the caller can see exactly what the next statement will
not find.

The session's ``work`` subdirectory IS the sandbox workdir, so the driver, the
statement and the result file are visible from both sides. The session's
control state (``meta.json``: counter, owner, closed flag) and its ledger sit
beside it, outside what an isolating backend mounts, so a statement cannot
reset its own cap, change its owner or rewrite its history. (The ``local``
backend runs on the host and isolates nothing.) A backend with no shared
workdir (ssh, kubernetes) therefore cannot host a session in v1.

No tool access
--------------
The kernel gets plain Python and nothing else -- it has no bridge into the
``ToolRegistry``, deliberately. A kernel that could call tools would dispatch
them outside :func:`maverick.tool_authz.authorize`: unauthorized, unpriced, and
invisible to the dispatch-contract CI gate that fails the build on exactly that
pattern. Any tool bridge would have to route every call through
``tool_authz.authorize`` before it reaches a registry, not around it.

OFF by default (``[repl] enable``, or ``MAVERICK_REPL=1``) per kernel rule 1:
shipping this module changes nothing until an operator admits it.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import logging
import os
import re
import shlex
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path

log = logging.getLogger(__name__)

_DRIVER_NAME = "_driver.py"
_STATE_NAME = "state.json"
_META_NAME = "meta.json"
_LEDGER_NAME = "ledger.jsonl"
_WORK_NAME = "work"

#: Session ids are bare lowercase hex, so validating one is also what keeps a
#: caller-supplied id from walking out of the repl root as a path segment.
_SESSION_RE = re.compile(r"^[0-9a-f]{16}$")

#: How much of a statement is quoted (redacted) into the receipt and ledger.
#: The digest is the identity; the excerpt is only there to make a human
#: reading the ledger able to recognise the statement.
_EXCERPT_CHARS = 200

#: Slack granted to the driver's own output truncation. The driver runs inside
#: the sandbox and cannot import the redactor, so it cuts blind; redaction then
#: happens host-side on the larger buffer and the final cap is applied after.
#: Without the slack a secret straddling the driver's cut could survive as an
#: unmatchable fragment in the returned prefix.
_SCAN_SLACK_CHARS = 4096

# The statement driver. Runs in the sandbox with no maverick imports available:
# argv is (state, code, result, max_state_bytes, max_output_chars). It reports
# through a result FILE rather than stdout because backends cap stdout, and a
# head-truncated JSON envelope is unparseable exactly when output matters most.
_DRIVER = '''"""Carry the session namespace across one governed statement."""
import builtins
import contextlib
import io
import json
import sys
import traceback
import types

state_path, code_path, result_path = sys.argv[1], sys.argv[2], sys.argv[3]
max_state_bytes, max_output = int(sys.argv[4]), int(sys.argv[5])

try:
    with open(state_path, encoding="utf-8") as fh:
        namespace = dict(json.load(fh))
except (OSError, ValueError):
    namespace = {}
namespace["__builtins__"] = builtins

with open(code_path, encoding="utf-8") as fh:
    source = fh.read()

out, err = io.StringIO(), io.StringIO()
ok = True
with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
    try:
        exec(compile(source, "<statement>", "exec"), namespace)
    except BaseException:
        # A traceback is a RESULT, not a driver failure: report it and keep
        # the session alive. SystemExit is caught too -- user code must not
        # be able to end the driver before the state is re-dumped.
        ok = False
        traceback.print_exc(file=err)

dropped, carried = [], {}
for name, value in namespace.items():
    if name.startswith("__"):
        continue
    if callable(value) or isinstance(value, types.ModuleType):
        dropped.append(name)
        continue
    try:
        json.dumps(value)
    except (TypeError, ValueError):
        dropped.append(name)
        continue
    carried[name] = value

blob = json.dumps(carried)
state_bytes = len(blob.encode("utf-8"))
too_large = state_bytes > max_state_bytes
if not too_large:
    with open(state_path, "w", encoding="utf-8") as fh:
        fh.write(blob)

stdout_text, stderr_text = out.getvalue(), err.getvalue()
with open(result_path, "w", encoding="utf-8") as fh:
    json.dump({
        "ok": ok,
        "stdout": stdout_text[:max_output],
        "stderr": stderr_text[:max_output],
        "truncated": len(stdout_text) > max_output or len(stderr_text) > max_output,
        "dropped": sorted(dropped),
        "state_bytes": state_bytes,
        "state_too_large": too_large,
    }, fh)
sys.exit(0 if ok else 1)
'''


class ReplError(Exception):
    """A governed refusal: the kernel is disabled, the session is unknown or
    closed, a cap was reached, or a screen/receipt would not let a statement
    run. Ordinary user-code failure is NOT this -- a traceback comes back as a
    result with ``ok=False``."""


def _policy() -> dict:
    """The live ``[repl]`` policy. Resolved per call (not bound at import) so
    config edits and tests take effect without a reload."""
    from .config import get_repl
    return get_repl()


def enabled() -> bool:
    """Whether the operator has admitted governed code execution."""
    try:
        return bool(_policy()["enable"])
    except Exception:  # pragma: no cover -- config must never admit by accident
        log.warning("repl: policy unreadable; treating the kernel as disabled",
                    exc_info=True)
        return False


def _root() -> Path:
    from .paths import data_dir
    return data_dir("repl")


def _session_dir(session_id: str) -> Path:
    sid = str(session_id or "")
    if not _SESSION_RE.match(sid) or not (_root() / sid / _META_NAME).exists():
        raise ReplError(f"unknown repl session {session_id!r}")
    return _root() / sid


def _read_meta(session_dir: Path) -> dict:
    from .file_lock import atomic_read_text, ensure_private_file
    path = session_dir / _META_NAME
    ensure_private_file(path)
    return json.loads(atomic_read_text(path))


def _write_meta(session_dir: Path, meta: dict) -> None:
    from .file_lock import atomic_write_text
    atomic_write_text(session_dir / _META_NAME, json.dumps(meta, sort_keys=True),
                      mode=0o600)


def open_session(goal_id: int | None = None, *, principal: str = "") -> str:
    """Create a kernel session and return its id.

    The session directory holds the metadata and the ledger; its ``work``
    subdirectory is the sandbox workdir and holds the driver, the carried
    namespace and each statement's source and result.
    """
    if not enabled():
        raise ReplError(
            "governed repl is disabled; set [repl] enable = true or MAVERICK_REPL=1")
    from .file_lock import atomic_write_text, ensure_private_directory
    session_id = uuid.uuid4().hex[:16]
    session_dir = _root() / session_id
    ensure_private_directory(session_dir)
    work_dir = ensure_private_directory(session_dir / _WORK_NAME)
    atomic_write_text(work_dir / _DRIVER_NAME, _DRIVER, mode=0o600)
    atomic_write_text(work_dir / _STATE_NAME, "{}", mode=0o600)
    _write_meta(session_dir, {
        "session": session_id,
        "created": time.time(),
        "goal_id": goal_id,
        "principal": principal,
        "statements": 0,
        "closed": False,
    })
    return session_id


def session_info(session_id: str) -> dict:
    """Who a session belongs to and where it stands: ``{session, goal_id,
    principal, statements, closed, created}``. Raises :class:`ReplError` for
    an unknown session. Lets a caller check ownership before acting."""
    meta = _read_meta(_session_dir(session_id))
    return {key: meta.get(key) for key in
            ("session", "goal_id", "principal", "statements", "closed", "created")}


def sessions_for(goal_id: int | None, principal: str, *, limit: int = 20) -> list[dict]:
    """The sessions ``principal`` opened for ``goal_id``, newest first, as
    :func:`session_info` rows. Bounded: scans at most 5000 session
    directories and returns at most ``limit`` rows."""
    root = _root()
    if not root.exists():
        return []
    rows: list[dict] = []
    for scanned, entry in enumerate(root.iterdir()):
        if scanned >= 5000:
            break
        if not _SESSION_RE.match(entry.name) or not (entry / _META_NAME).exists():
            continue
        try:
            info = session_info(entry.name)
        except (ReplError, OSError, ValueError):
            continue
        if info.get("goal_id") == goal_id and info.get("principal") == principal:
            rows.append(info)
    rows.sort(key=lambda r: float(r.get("created") or 0), reverse=True)
    return rows[:max(1, int(limit))]


def runs_on_host() -> bool:
    """Whether statements would run directly on this computer rather than in
    an isolated sandbox (the configured backend shares the host filesystem, or
    no sandbox can be built -- the conservative answer)."""
    from .sandbox import fs_is_host_visible
    try:
        sandbox = _sandbox_for(_root())
    except ReplError:
        return True
    return fs_is_host_visible(sandbox)


def transcript(session_id: str) -> list[dict]:
    """The session's append-only statement ledger, oldest first."""
    from .file_lock import atomic_read_text
    ledger = _session_dir(session_id) / _LEDGER_NAME
    if not ledger.exists():
        return []
    return [json.loads(line) for line in atomic_read_text(ledger).splitlines()
            if line.strip()]


def _exec_takes_timeout(sandbox) -> bool:
    """Whether ``sandbox.exec`` accepts ``timeout=``, decided from its
    signature. Catching TypeError instead would re-run a statement that
    raised TypeError after it started, a second time and with no timeout."""
    try:
        params = inspect.signature(sandbox.exec).parameters.values()
    except (TypeError, ValueError):
        return True  # not introspectable: keep the timeout
    return any(p.name == "timeout" or p.kind is p.VAR_KEYWORD for p in params)


def close_session(session_id: str) -> bool:
    """Close a session; return whether this call closed it.

    The carried namespace and the statement bodies are removed -- they are
    working state. The ledger stays: it is the audit artifact, and an audit
    artifact that disappears when the session ends proves nothing.
    """
    try:
        session_dir = _session_dir(session_id)
    except ReplError:
        return False
    from .file_lock import cross_process_lock
    # The same lock execute() holds, so a close cannot land mid-statement.
    with cross_process_lock(session_dir / _META_NAME):
        meta = _read_meta(session_dir)
        if meta.get("closed"):
            return False
        meta["closed"] = True
        meta["closed_at"] = time.time()
        _write_meta(session_dir, meta)
        work_dir = session_dir / _WORK_NAME
        stale = [work_dir / _STATE_NAME, work_dir / _DRIVER_NAME]
        stale += list(work_dir.glob("stmt_*.py")) + list(work_dir.glob("res_*.json"))
        for path in stale:
            path.unlink(missing_ok=True)
    return True


def _redact(text: str) -> str:
    """Strip secrets from sandbox output before it is returned or stored.

    Fail CLOSED: if the detector cannot run we keep a digest for correlation
    instead of passing unscanned output through (governed_actions takes the
    same line for lineage text)."""
    from .safety.secret_detector import redact
    try:
        return redact(text or "")[0]
    except Exception:  # pragma: no cover -- the redactor is pure regex
        digest = hashlib.sha256((text or "").encode("utf-8")).hexdigest()[:16]
        log.warning("repl: redaction failed; withholding output %s", digest,
                    exc_info=True)
        return f"[unredactable output sha256:{digest}]"


def _cap(text: str, limit: int) -> tuple[str, bool]:
    return text[:limit], len(text) > limit


def _excerpt(source: str) -> str:
    return _redact(source)[:_EXCERPT_CHARS]


def _screen(source: str) -> None:
    """Refuse a statement carrying injection tripwires.

    Fail closed on BOTH a hit and a broken checker: this is the boundary
    between model-written text and code we are about to run, and a screen that
    cannot answer is not an answer of "clean".
    """
    from .memory_guard import injection_markers
    try:
        markers = injection_markers(source)
    except Exception as exc:
        raise ReplError(
            f"repl statement refused: the injection screen failed ({exc})") from exc
    if markers:
        raise ReplError("repl statement refused: injection markers "
                        + ", ".join(sorted(markers)))


def _receipt(goal_id: int | None, params: dict, principal: str, phase: str,
             transaction_id: str, *, result: str = "") -> bool:
    """Append a PREPARE/COMMIT link to the hash-chained lineage ledger.

    ``force`` traces the statement whatever its nominal risk; ``strict``
    verifies the existing chain first, so a tampered ledger refuses rather than
    extending. Returns whether the link was persisted."""
    from .governed_actions import record_tool_lineage
    try:
        return bool(record_tool_lineage(
            goal_id, "repl.execute", params, actor=principal, phase=phase,
            transaction_id=transaction_id, result=result, force=True, strict=True))
    except Exception:
        log.warning("repl: %s receipt failed for statement %s", phase,
                    str(params.get("statement_sha256", ""))[:12], exc_info=True)
        return False


def _interpreter(sandbox: object) -> str:
    """Which python runs the driver. The host interpreter is only meaningful
    when the sandbox shares this filesystem; container/remote backends get the
    image's own ``python3``."""
    from .sandbox import fs_is_host_visible
    if fs_is_host_visible(sandbox) and sys.executable:
        return sys.executable
    return "python3"


def _sandbox_for(session_dir: Path):
    from .sandbox import build_sandbox
    try:
        return build_sandbox(workdir=session_dir)
    except Exception as exc:
        raise ReplError(f"no sandbox available for the repl kernel: {exc}") from exc


def _driver_command(sandbox: object, argv: list[str]) -> str:
    """Serialize trusted driver argv for the target sandbox's command shell.

    A host-visible backend executes through the host shell.  On Windows that
    is ``cmd.exe``, where the single quotes emitted by :func:`shlex.join` are
    literal characters rather than quoting syntax.  Container and remote
    backends retain POSIX quoting even when their client runs on Windows.
    """
    from .sandbox import fs_is_host_visible

    if sys.platform == "win32" and fs_is_host_visible(sandbox):
        return subprocess.list2cmdline(argv)
    return shlex.join(argv)


def _read_result(path: Path, limit: int) -> str:
    """Read the statement's result file without following a link the
    statement planted there, blocking on a FIFO, or reading without bound."""
    flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(os.open(path, flags), "rb") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            raise OSError(f"statement result is not a regular file: {path.name}")
        data = fh.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"statement result exceeds {limit} bytes")
    return data.decode("utf-8")


def _run_statement(sandbox, work_dir: Path, index: int, source: str,
                   policy: dict) -> tuple[dict, int, float]:
    """Run one statement through ``sandbox.exec`` and read its result file."""
    from .file_lock import atomic_write_text
    code_name, result_name = f"stmt_{index}.py", f"res_{index}.json"
    atomic_write_text(work_dir / code_name, source, mode=0o600)
    cmd = _driver_command(
        sandbox,
        [
            _interpreter(sandbox),
            _DRIVER_NAME,
            _STATE_NAME,
            code_name,
            result_name,
            str(int(policy["max_state_bytes"])),
            str(int(policy["max_output_chars"]) + _SCAN_SLACK_CHARS),
        ],
    )
    started = time.monotonic()
    if _exec_takes_timeout(sandbox):
        res = sandbox.exec(cmd, timeout=float(policy["max_seconds"]))
    else:  # backend without a per-call timeout kwarg
        res = sandbox.exec(cmd)
    wall = time.monotonic() - started
    exit_code = int(getattr(res, "exit_code", 1))
    # Two capped streams, each character at most 12 bytes once JSON-escaped,
    # plus the dropped names (bounded by the namespace) and the envelope.
    output_chars = int(policy["max_output_chars"]) + _SCAN_SLACK_CHARS
    limit = 24 * output_chars + int(policy["max_state_bytes"]) + 65536
    try:
        payload = json.loads(_read_result(work_dir / result_name, limit))
        if not isinstance(payload, dict):
            raise ValueError("statement result is not an object")
    except (OSError, ValueError):
        # No result file: the driver never got to write one (timeout, killed
        # process, missing interpreter). The backend's own streams are all we
        # have, and they describe an infrastructure failure, not user code.
        payload = {
            "ok": False,
            "stdout": str(getattr(res, "stdout", "") or ""),
            "stderr": str(getattr(res, "stderr", "") or "")
                      or "the statement driver produced no result",
            "truncated": False, "dropped": [], "state_too_large": False,
        }
    return payload, exit_code, wall


def _append_ledger(session_dir: Path, row: dict) -> None:
    """Append one row to the session ledger. Callers hold the session lock, so
    the read-modify-write is already serialized."""
    from .file_lock import atomic_read_text, atomic_write_text, ensure_private_file
    ledger = session_dir / _LEDGER_NAME
    prior = ""
    if ledger.exists():
        ensure_private_file(ledger)
        prior = atomic_read_text(ledger)
    atomic_write_text(ledger, prior + json.dumps(row, sort_keys=True) + "\n",
                      mode=0o600)


def execute(session_id: str, code: str, *, goal_id: int | None = None,
            principal: str = "") -> dict:
    """Run one statement in ``session_id`` and return its governed result.

    Returns ``{"ok", "stdout", "stderr", "exit_code", "statement_sha256",
    "wall_seconds", "truncated", "dropped"}``. Ordinary user-code failure never
    raises -- a traceback comes back on ``stderr`` with ``ok=False``.
    :class:`ReplError` is reserved for governance refusals: the kernel is
    disabled, the session is unknown or closed, the statement is screened out
    or unreceiptable, the statement cap is reached, or the namespace would grow
    past ``max_state_bytes``.
    """
    if not enabled():
        raise ReplError(
            "governed repl is disabled; set [repl] enable = true or MAVERICK_REPL=1")
    session_dir = _session_dir(session_id)
    source = str(code or "")
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
    _screen(source)
    from .file_lock import cross_process_lock
    # A kernel is sequential: hold the session lock across the whole statement
    # so the counter, the carried namespace and the ledger cannot interleave.
    with cross_process_lock(session_dir / _META_NAME):
        return _execute_locked(session_dir, source, digest, _policy(),
                               goal_id, principal)


def _execute_locked(session_dir: Path, source: str, digest: str, policy: dict,
                    goal_id: int | None, principal: str) -> dict:
    meta = _read_meta(session_dir)
    session_id = str(meta.get("session", ""))
    if meta.get("closed"):
        raise ReplError(f"repl session {session_id} is closed")
    index = int(meta.get("statements", 0)) + 1
    if index > int(policy["max_statements"]):
        raise ReplError(f"repl session {session_id} reached its "
                        f"{policy['max_statements']}-statement cap")
    work_dir = session_dir / _WORK_NAME
    if not work_dir.is_dir():
        raise ReplError(f"repl session {session_id} predates the separate "
                        "work directory; open a new session")
    sandbox = _sandbox_for(work_dir)
    # Consume the slot before running: a statement that crashes the process
    # must still count against the cap.
    meta["statements"] = index
    _write_meta(session_dir, meta)

    params = {"session": session_id, "statement": index,
              "statement_sha256": digest, "excerpt": _excerpt(source),
              "code_bytes": len(source.encode("utf-8"))}
    transaction_id = digest[:16]
    if not _receipt(goal_id, params, principal, "prepare", transaction_id):
        raise ReplError("repl statement refused: the PREPARE receipt could not "
                        "be persisted (no receipt, no effect)")

    payload, exit_code, wall = _run_statement(
        sandbox, work_dir, index, source, policy)
    limit = int(policy["max_output_chars"])
    stdout, stdout_cut = _cap(_redact(str(payload.get("stdout", ""))), limit)
    stderr, stderr_cut = _cap(_redact(str(payload.get("stderr", ""))), limit)
    ok = bool(payload.get("ok")) and exit_code == 0
    oversized = bool(payload.get("state_too_large"))
    result = {
        "ok": ok,
        "stdout": stdout,
        "stderr": stderr,
        "exit_code": exit_code,
        "statement_sha256": digest,
        "wall_seconds": round(wall, 4),
        "truncated": bool(payload.get("truncated")) or stdout_cut or stderr_cut,
        "dropped": list(payload.get("dropped") or []),
    }
    # Receipt, audit and ledger describe what happened -- including the refusal
    # below, which lands after the statement has already run.
    _receipt(goal_id, params, principal, "commit", transaction_id,
             result=f"exit={exit_code} ok={ok} state_refused={oversized}")
    from .audit import EventKind, audit_event
    audit_event(EventKind.REPL_EXECUTED, agent="governed_repl", goal_id=goal_id,
                session=session_id, statement_sha256=digest, ok=ok,
                exit_code=exit_code, wall_seconds=result["wall_seconds"])
    _append_ledger(session_dir, {
        "ts": time.time(), "session": session_id, "statement": index,
        "statement_sha256": digest, "excerpt": params["excerpt"], "ok": ok,
        "exit_code": exit_code, "wall_seconds": result["wall_seconds"],
        "truncated": result["truncated"], "dropped": result["dropped"],
        "state_bytes": int(payload.get("state_bytes") or 0),
        "state_refused": oversized,
    })
    if oversized:
        raise ReplError(
            f"repl statement refused: the carried namespace would reach "
            f"{payload.get('state_bytes')} bytes, past the "
            f"{policy['max_state_bytes']}-byte cap (state left unchanged)")
    return result
