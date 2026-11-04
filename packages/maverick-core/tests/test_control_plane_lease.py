"""One control plane per data root, proven rather than documented.

The single-replica invariant was asserted in eleven places -- the chart, two
raw manifests, six docs, a runbook -- and enforced in exactly one: a
``helm template`` guard. Build-time only, and itself untested and absent from
CI. ``kubectl apply`` on a hand-edited manifest, ``compose up --scale``, or a
second ``maverick dashboard`` on one host all walked past it.

The failure mode is why this matters more than a crash would. Individual
writes are already serialized, so two writers do not tear a record; they
interleave *valid* records into append-only hash chains that assume one
author. The result verifies clean and cannot be reconstructed.

These tests use real processes and real file locks. A mocked lock would prove
the code calls a function, which was never the thing in doubt.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
from maverick import control_plane_lease as lease


@pytest.fixture(autouse=True)
def _isolated_root(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv(lease.OVERRIDE_ENV, raising=False)
    lease.release()
    yield
    lease.release()


def _child(root: Path, *, hold_seconds: float = 0.0) -> subprocess.CompletedProcess:
    """Acquire the lease in a REAL separate process.

    Threads share a file-descriptor table and POSIX ``flock`` is per-open-file,
    so a same-process attempt could pass while genuine cross-process exclusion
    is broken. The case that matters is two OS processes.
    """
    code = textwrap.dedent(f"""
        import json, os, sys, time
        os.environ["MAVERICK_HOME"] = {str(root)!r}
        from maverick import control_plane_lease as lease
        try:
            got = lease.acquire()
        except lease.ControlPlaneBusy as e:
            print(json.dumps({{"result": "busy", "message": str(e)}}))
            sys.exit(0)
        except lease.LeaseUnavailable as e:
            print(json.dumps({{"result": "unavailable", "message": str(e)}}))
            sys.exit(0)
        print(json.dumps({{
            "result": "acquired" if got else "overridden",
            "token": got.fencing_token if got else None,
            "pid": os.getpid(),
        }}))
        sys.stdout.flush()
        time.sleep({hold_seconds})
    """)
    return subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=60,
    )


def _result(proc: subprocess.CompletedProcess) -> dict:
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout.strip().splitlines()[-1])


# -- the invariant ---------------------------------------------------------

def test_the_first_process_acquires_the_root(tmp_path) -> None:
    held = lease.acquire()
    assert held is not None
    assert held.holder.pid == os.getpid()
    assert lease.lock_path().exists()


def test_a_second_process_is_refused(tmp_path) -> None:
    """The whole point. A real second OS process must not get the root."""
    lease.acquire()
    out = _result(_child(tmp_path))
    assert out["result"] == "busy", out


def test_the_refusal_names_the_holder_and_what_is_at_stake(tmp_path) -> None:
    """An operator meeting this at 3am needs to know who and why.

    "Could not acquire lock" would send them looking for a stuck process; the
    actual cause is usually a replica count someone raised on purpose.
    """
    lease.acquire()
    message = _result(_child(tmp_path))["message"]
    assert str(os.getpid()) in message, message
    assert "hash-chained" in message or "single author" in message, message
    assert "MAVERICK_HOME" in message, message


def test_the_root_is_released_when_the_holder_dies(tmp_path) -> None:
    """No stale-lock problem: the kernel drops the lock with the process.

    This is the reason the mechanism is a lock and not a timed lease -- there
    is no expiry to tune and no reaper to get wrong.
    """
    first = _result(_child(tmp_path, hold_seconds=0.0))
    assert first["result"] == "acquired", first
    second = _result(_child(tmp_path))
    assert second["result"] == "acquired", second


def test_two_data_roots_do_not_contend(tmp_path, monkeypatch) -> None:
    """Negative control: the lock must be per-root, not global.

    A guard that refused every second process regardless of root would pass
    every test above and break every multi-deployment host.
    """
    other = tmp_path / "other"
    other.mkdir()
    lease.acquire()
    assert _result(_child(other))["result"] == "acquired"


def test_same_process_cannot_reuse_one_roots_lease_for_another(tmp_path):
    first = lease.acquire()
    with pytest.raises(lease.LeaseUnavailable, match="different control-plane"):
        lease.acquire(tmp_path / "another")
    assert lease.current() is first
    assert lease.posture(tmp_path / "another")["state"] == "unavailable"


def test_direct_release_cannot_leave_cached_ownership_success(tmp_path):
    first = lease.acquire()
    first.release()
    assert lease.current() is None
    assert lease.posture()["single_writer_enforced"] is False
    replacement = lease.acquire()
    assert replacement is not first
    assert replacement.fencing_token == first.fencing_token + 1


@pytest.mark.parametrize("count", ["2", "0", "-1", "true", "garbage", "01", ""])
def test_declared_multi_replica_or_invalid_count_refused_before_override(tmp_path, monkeypatch, count):
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", count)
    monkeypatch.setenv(lease.OVERRIDE_ENV, "1")
    with pytest.raises(lease.LeaseUnavailable, match="must remain 1"):
        lease.acquire()
    assert lease.posture()["state"] == "unavailable"
    assert not lease.lock_path().exists()


def test_declared_replica_change_cannot_reuse_cached_lease(tmp_path, monkeypatch):
    lease.acquire()
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "2")
    with pytest.raises(lease.LeaseUnavailable, match="must remain 1"):
        lease.acquire()
    assert lease.posture()["single_writer_enforced"] is False


def test_concurrent_same_process_admission_shares_one_owner(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=4) as executor:
        owners = list(executor.map(lambda _: lease.acquire(tmp_path), range(8)))
    assert all(owner is owners[0] for owner in owners)
    assert owners[0].fencing_token == 1


def test_a_different_process_identity_cannot_use_cached_ownership(tmp_path, monkeypatch):
    held = lease.acquire()
    original_pid = os.getpid()
    monkeypatch.setattr(lease.os, "getpid", lambda: original_pid + 1)
    with pytest.raises(lease.LeaseUnavailable, match="another process"):
        held.assert_owned()
    with pytest.raises(lease.LeaseUnavailable, match="another process"):
        lease.acquire()
    assert lease.posture()["single_writer_enforced"] is False


@pytest.mark.skipif(not hasattr(os, "fork"), reason="native fork unavailable on this platform")
def test_native_fork_cannot_inherit_control_plane_admission(tmp_path):
    code = textwrap.dedent(f"""
        import os
        from maverick import control_plane_lease as lease
        lease.acquire({str(tmp_path)!r})
        child = os.fork()
        if child == 0:
            try:
                lease.acquire({str(tmp_path)!r})
            except lease.LeaseUnavailable:
                os._exit(0)
            os._exit(5)
        _, status = os.waitpid(child, 0)
        assert os.waitstatus_to_exitcode(status) == 0
        lease.current().assert_owned()
        lease.release()
    """)
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


# -- the fencing token -----------------------------------------------------

def test_the_fencing_token_advances_across_restarts(tmp_path) -> None:
    first = _result(_child(tmp_path))["token"]
    second = _result(_child(tmp_path))["token"]
    assert second == first + 1, (first, second)


def test_the_token_starts_at_one_on_a_fresh_root(tmp_path) -> None:
    assert lease.acquire().fencing_token == 1


def test_the_holder_record_is_readable_by_another_process(tmp_path) -> None:
    """The refusal message is only useful if the record is parseable."""
    held = lease.acquire()
    data = json.loads(lease.holder_path().read_text(encoding="utf-8"))
    assert data["pid"] == os.getpid()
    assert data["fencing_token"] == held.fencing_token
    assert data["role"] == "control-plane"


# -- the override ----------------------------------------------------------

def test_the_override_permits_a_second_process(tmp_path, monkeypatch) -> None:
    lease.acquire()
    env = dict(os.environ, **{lease.OVERRIDE_ENV: "1"})
    proc = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(f"""
            import json, os
            os.environ["MAVERICK_HOME"] = {str(tmp_path)!r}
            from maverick import control_plane_lease as lease
            print(json.dumps({{"got": lease.acquire() is None}}))
        """)], capture_output=True, text=True, env=env, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout.strip())["got"] is True


def test_the_override_is_reported_not_silent(tmp_path, monkeypatch) -> None:
    """An unenforced invariant that still claims to hold is the worse failure."""
    monkeypatch.setenv(lease.OVERRIDE_ENV, "1")
    state = lease.posture()
    assert state["state"] == "unenforced"
    assert state["single_writer_enforced"] is False
    assert lease.OVERRIDE_ENV in state["detail"]


def test_an_unreadable_config_does_not_grant_the_override(
    tmp_path, monkeypatch,
) -> None:
    """Fail closed: "we cannot tell" must read as "enforcement stays on"."""
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("broken toml")))
    assert lease.override_enabled() is False


@pytest.mark.parametrize("value,expected", [
    ("1", True), ("true", True), ("YES", True), ("on", True),
    ("0", False), ("false", False), ("", False), ("maybe", False),
])
def test_override_parsing(monkeypatch, value, expected) -> None:
    monkeypatch.setenv(lease.OVERRIDE_ENV, value)
    assert lease.override_enabled() is expected


# -- posture reporting -----------------------------------------------------

def test_posture_distinguishes_owned_from_unknown(tmp_path) -> None:
    """"Nothing acquired" must not render the same as "we own it"."""
    assert lease.posture()["state"] == "unknown"
    lease.acquire()
    owned = lease.posture()
    assert owned["state"] == "owned"
    assert owned["single_writer_enforced"] is True
    assert owned["fencing_token"] == 1


def test_posture_never_raises_on_a_corrupt_record(tmp_path) -> None:
    """/metrics and /readyz are reached when things are already wrong."""
    lease.holder_path().write_text("{not json", encoding="utf-8")
    assert lease.posture()["state"] == "unknown"


def test_acquire_refuses_to_reset_a_corrupt_fencing_record(tmp_path) -> None:
    """Corruption cannot silently turn a mature deployment back into token 1."""
    record = lease.holder_path()
    record.write_text("{not json", encoding="utf-8")

    with pytest.raises(lease.LeaseUnavailable, match="fencing token cannot be proven"):
        lease.acquire()

    assert record.read_text(encoding="utf-8") == "{not json"


def test_acquire_is_idempotent_within_a_process(tmp_path) -> None:
    """Two components asking for the root must not deadlock the process."""
    first = lease.acquire()
    assert lease.acquire() is first


# -- fail closed when the filesystem cannot lock ---------------------------

def test_a_filesystem_without_locking_refuses_to_start(tmp_path, monkeypatch) -> None:
    """The one outcome worse than refusing: believing you are alone.

    Some NFS and overlay mounts return ENOLCK. Treating that as success would
    mean shipping the exact corruption this module exists to prevent, while
    reporting single-writer safety on /readyz.
    """
    def _enolck(fd, op):
        raise OSError(38, "Function not implemented")

    if os.name == "nt":
        import msvcrt

        monkeypatch.setattr(
            msvcrt,
            "locking",
            lambda fd, mode, n: _enolck(fd, mode),
        )
    else:
        import fcntl

        monkeypatch.setattr(fcntl, "flock", _enolck)
    with pytest.raises(lease.LeaseUnavailable) as exc:
        lease.acquire()
    assert "cannot provide advisory locking" in str(exc.value)
    assert lease.OVERRIDE_ENV in str(exc.value), "must name the escape hatch"


def test_a_contended_lock_is_not_mistaken_for_a_broken_filesystem(
    tmp_path, monkeypatch,
) -> None:
    """Negative control for the branch above.

    EAGAIN means "someone else holds it" and must raise ControlPlaneBusy;
    only a genuine backend failure may raise LeaseUnavailable. Collapsing the
    two would turn every second replica into a filesystem bug report.
    """
    import errno as _errno

    if os.name == "nt":
        import msvcrt

        def _contended(fd, mode, n):
            raise OSError(_errno.EACCES, "Permission denied")

        monkeypatch.setattr(msvcrt, "locking", _contended)
    else:
        import fcntl

        def _contended(fd, op):
            raise OSError(_errno.EAGAIN, "Resource temporarily unavailable")

        monkeypatch.setattr(fcntl, "flock", _contended)
    with pytest.raises(lease.ControlPlaneBusy):
        lease.acquire()


# -- the deployment guard the chart relies on ------------------------------

REPO_ROOT = Path(__file__).resolve().parents[3]
CHART = REPO_ROOT / "deploy" / "helm" / "maverick"


@pytest.mark.skipif(not CHART.is_dir(), reason="chart absent")
def test_the_chart_guard_is_wired_into_the_deployment_template() -> None:
    """The build-time guard is only effective if the template invokes it.

    It was never tested: no `helm lint`/`helm template` step exists in any
    workflow, so a refactor could drop this include and nothing would notice
    until a `replicaCount: 2` reached a cluster.
    """
    helpers = (CHART / "templates" / "_helpers.tpl").read_text(encoding="utf-8")
    assert "maverick.validate" in helpers
    assert "replicaCount" in helpers and "fail" in helpers

    deployment = (CHART / "templates" / "deployment.yaml").read_text(
        encoding="utf-8")
    first = deployment.lstrip().splitlines()[0]
    assert "maverick.validate" in first, (
        f"deployment.yaml must invoke the validation guard first; got {first!r}")


@pytest.mark.skipif(not CHART.is_dir(), reason="chart absent")
def test_the_chart_still_defaults_to_one_replica() -> None:
    values = (CHART / "values.yaml").read_text(encoding="utf-8")
    assert "replicaCount: 1" in values
