"""Bounded pipes and explicit lifetime ownership for configured executables.

The three I/O threads belong to one child, not an executor or one thread per
request. Killing the owned process tree releases blocked pipe I/O; cleanup joins
them before returning. The asynchronous adapter never detaches a completion call.
"""
from __future__ import annotations

import asyncio
import contextvars
import logging
import os
import queue
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import BinaryIO

from .sandbox.local import (
    _CREATE_SUSPENDED,
    _close_windows_kill_job,
    _create_windows_kill_job,
    _reap_process_group,
)

CHUNK_BYTES = 16384
PIPE_QUEUE_CHUNKS = 16
CLEANUP_SECONDS = 5.0
log = logging.getLogger(__name__)


class ProcessOutputLimit(RuntimeError):
    """A bounded child output exceeded its allowed bytes."""


class ProcessCleanupError(RuntimeError):
    """The owned child or its I/O did not finish cleanup in time."""


@dataclass
class PendingWrite:
    payload: bytes
    deadline: float
    close_after: bool = False
    started: threading.Event = field(default_factory=threading.Event)
    done: threading.Event = field(default_factory=threading.Event)
    error: BaseException | None = None


class OwnedProcess:
    """One process tree with bounded pipe queues and one serialized writer."""

    def __init__(self, command: list[str], *, env: dict[str, str], cwd: str | None = None,
                 hidden: bool = False):
        self.stdout: queue.Queue[bytes | None] = queue.Queue(PIPE_QUEUE_CHUNKS)
        self.stderr: queue.Queue[bytes | None] = queue.Queue(PIPE_QUEUE_CHUNKS)
        self._writes: queue.Queue[PendingWrite] = queue.Queue(1)
        self._stopping = threading.Event()
        self._tree_lock = threading.Lock()
        self._tree_stopped = False
        self._job: int | None = None
        self._threads: list[threading.Thread] = []
        self.proc = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, bufsize=0, env=env, cwd=cwd,
            start_new_session=os.name != "nt",
            creationflags=(subprocess.CREATE_NEW_PROCESS_GROUP | _CREATE_SUSPENDED
                           | (subprocess.CREATE_NO_WINDOW if hidden else 0))
            if os.name == "nt" else 0,
        )
        try:
            # A Windows child is still suspended here. No descendant can escape
            # containment between CreateProcess and assignment to the kill-job.
            self._job = _create_windows_kill_job(self.proc)
            assert self.proc.stdout is not None and self.proc.stderr is not None
            for name, pipe, output in (
                ("stdout", self.proc.stdout, self.stdout),
                ("stderr", self.proc.stderr, self.stderr),
            ):
                self._start_thread(name, self._read, pipe, output)
            self._start_thread("stdin", self._write)
        except BaseException:
            self.close()
            raise

    def _start_thread(self, name: str, target: Callable, *args: object) -> None:
        thread = threading.Thread(
            name=f"owned-child-{self.proc.pid}-{name}", target=target,
            args=args, daemon=True,
        )
        thread.start()
        self._threads.append(thread)

    def _put(self, output: queue.Queue, value: bytes | None) -> None:
        while not self._stopping.is_set():
            try:
                output.put(value, timeout=0.05)
                return
            except queue.Full:
                continue

    def _read(self, pipe: BinaryIO, output: queue.Queue) -> None:
        try:
            while not self._stopping.is_set():
                chunk = pipe.read(CHUNK_BYTES)
                if not chunk:
                    break
                self._put(output, chunk)
        except (OSError, ValueError):
            pass  # Broken pipes are EOF; callers still require a final reply.
        finally:
            self._put(output, None)

    def _write(self) -> None:
        assert self.proc.stdin is not None
        while not self._stopping.is_set():
            try:
                operation = self._writes.get(timeout=0.05)
            except queue.Empty:
                continue
            try:
                if self._stopping.is_set() or time.monotonic() >= operation.deadline:
                    raise TimeoutError("child input deadline exceeded before dispatch")
                # Once a write starts, a broken pipe cannot prove that the child
                # received no bytes. Callers must treat the outcome as unknown.
                operation.started.set()
                remaining = memoryview(operation.payload)
                while remaining:
                    if self._stopping.is_set() or time.monotonic() >= operation.deadline:
                        raise TimeoutError("child input deadline exceeded")
                    written = self.proc.stdin.write(remaining[:CHUNK_BYTES])
                    if not written:
                        raise BrokenPipeError("child input closed")
                    remaining = remaining[written:]
                if operation.close_after:
                    self.proc.stdin.close()
            except (OSError, ValueError, TimeoutError) as exc:
                operation.error = exc
            finally:
                operation.payload = b""
                operation.done.set()

    def write(self, payload: bytes, *, deadline: float, close_after: bool = False) -> PendingWrite:
        if self._stopping.is_set():
            raise BrokenPipeError("child is closing")
        operation = PendingWrite(payload, deadline, close_after)
        self._writes.put_nowait(operation)
        return operation

    def stop_tree(self) -> None:
        """Terminate only this invocation's containment group, once."""
        with self._tree_lock:
            if self._tree_stopped:
                return
            if self._job is not None:
                _close_windows_kill_job(self._job)
                self._job = None
            elif os.name != "nt":
                _reap_process_group(self.proc)
                _kill_pipe_holders(self.proc)
            if self.proc.poll() is None:
                self.proc.kill()
            self._tree_stopped = True

    def _begin_close(self) -> None:
        self._stopping.set()
        self.stop_tree()
        while True:
            try:
                operation = self._writes.get_nowait()
            except queue.Empty:
                break
            operation.error = BrokenPipeError("child closed before dispatch")
            operation.payload = b""
            operation.done.set()

    def _reaped(self) -> bool:
        return self.proc.poll() is not None and all(not t.is_alive() for t in self._threads)

    def _finish_close(self) -> None:
        if not self._reaped():
            raise ProcessCleanupError("owned child cleanup incomplete; execution must not be replayed")
        self.proc.wait(timeout=0)
        for thread in self._threads:
            thread.join(timeout=0)
        for pipe in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            if pipe is not None:
                pipe.close()

    def close(self) -> None:
        self._begin_close()
        deadline = time.monotonic() + CLEANUP_SECONDS
        while not self._reaped() and time.monotonic() < deadline:
            time.sleep(0.005)
        self._finish_close()

    async def aclose(self) -> None:
        self._begin_close()
        deadline = time.monotonic() + CLEANUP_SECONDS
        while not self._reaped() and time.monotonic() < deadline:
            await asyncio.sleep(0.005)
        self._finish_close()


def _kill_pipe_holders(proc: subprocess.Popen) -> None:
    """Kill any other process still holding this child's output pipes (Linux).

    Group containment ends at ``setsid``: a descendant that started its own
    session escapes ``killpg`` and, if it keeps stdout or stderr open, the pipe
    never reaches EOF -- a finished child then reads as a timeout and its
    reader threads leak. Such a process can be found exactly: it holds our
    pipe. (One that closed its pipes has no lineage left to find; run
    untrusted commands in a container sandbox for that.) Best effort: no
    /proc means nothing to scan."""
    targets = set()
    for pipe in (proc.stdout, proc.stderr):
        try:
            targets.add(f"pipe:[{os.fstat(pipe.fileno()).st_ino}]")
        except (AttributeError, OSError, ValueError):
            continue
    if not targets or not os.path.isdir("/proc"):
        return
    me = os.getpid()
    try:
        pids = [int(p) for p in os.listdir("/proc") if p.isdigit() and int(p) != me]
    except OSError:
        return
    for pid in pids:
        try:
            fds = os.listdir(f"/proc/{pid}/fd")
        except OSError:
            continue  # gone, or not ours to inspect
        for fd in fds:
            try:
                if os.readlink(f"/proc/{pid}/fd/{fd}") in targets:
                    os.kill(pid, 9)
                    break
            except OSError:
                continue


async def _join_cleanup(child: OwnedProcess) -> None:
    cleanup = asyncio.create_task(child.aclose())
    cancelled = False
    while not cleanup.done():
        try:
            await asyncio.shield(cleanup)
        except asyncio.CancelledError:
            cancelled = True
    cleanup.result()
    if cancelled:
        raise asyncio.CancelledError


async def run_owned(
    command: list[str], *, input: str, deadline: float, env: dict[str, str],
    cwd: str | None = None, stdout_limit: int = 8 * 1024 * 1024,
    stderr_limit: int = 1024 * 1024, check: Callable[[], None] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run once; cancellation, output overflow and deadlines terminate and reap.

    Process creation is a synchronous OS call. The deadline covers elapsed spawn
    time but cannot preempt an OS that blocks inside CreateProcess/fork itself.
    """
    if check is not None:
        check()
    if time.monotonic() >= deadline:
        raise TimeoutError("child deadline exceeded before launch")
    child = OwnedProcess(command, env=env, cwd=cwd)
    try:
        write = child.write(input.encode("utf-8", errors="replace"), deadline=deadline, close_after=True)
        buffers = [bytearray(), bytearray()]
        ended = [False, False]
        while True:
            if check is not None:
                check()
            if time.monotonic() >= deadline:
                raise TimeoutError("child deadline exceeded")
            for index, (output, limit) in enumerate(((child.stdout, stdout_limit), (child.stderr, stderr_limit))):
                for _ in range(PIPE_QUEUE_CHUNKS):
                    try:
                        chunk = output.get_nowait()
                    except queue.Empty:
                        break
                    if chunk is None:
                        ended[index] = True
                        break
                    if len(buffers[index]) + len(chunk) > limit:
                        raise ProcessOutputLimit("child output exceeded its byte limit")
                    buffers[index].extend(chunk)
            if child.proc.poll() is not None:
                child.stop_tree()  # Also reap descendants retaining a pipe.
                if all(ended):
                    break
            if write.done.is_set() and write.error is not None:
                raise write.error
            await asyncio.sleep(0.005)
        return subprocess.CompletedProcess(
            command, child.proc.returncode,
            stdout=buffers[0].decode("utf-8", errors="replace"),
            stderr=buffers[1].decode("utf-8", errors="replace"),
        )
    finally:
        original = sys.exc_info()[1]
        try:
            await _join_cleanup(child)
        except asyncio.CancelledError:
            if original is None:
                raise
        except BaseException:
            if original is None:
                raise
            # A cleanup failure must not turn Budget/halt/cancellation into an
            # ordinary, potentially retried exception. Keep evidence explicit.
            original.cleanup_incomplete = True
            log.error("owned child cleanup failed while propagating the original stop")


def run_sync(factory: Callable[[], object]):
    """Synchronous compatibility, including callers already owning an event loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(factory())
    # A synchronous API cannot yield its caller's loop. Keep its separate loop
    # owned and join it; never leave a detached completion worker behind.
    result: list[object] = []
    errors: list[BaseException] = []

    def invoke() -> None:
        try:
            result.append(asyncio.run(factory()))
        except BaseException as exc:
            errors.append(exc)

    context = contextvars.copy_context()
    thread = threading.Thread(target=context.run, args=(invoke,), name="owned-sync-adapter")
    thread.start()
    thread.join()
    if errors:
        raise errors[0]
    return result[0]
