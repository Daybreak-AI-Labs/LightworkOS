"""eBPF syscall monitor: program generation, parsing, supervision (all offline)."""
from __future__ import annotations

import pytest
from maverick import ebpf_monitor
from maverick.ebpf_monitor import (
    DEFAULT_WATCHLIST,
    BpftraceUnavailable,
    EbpfMonitor,
    SyscallEvent,
    generate_program,
    parse_line,
)

# ---- program generation ------------------------------------------------------

def test_program_seeds_and_follows_the_pid_tree():
    prog = generate_program(4242)
    assert "@tracked[4242] = 1;" in prog
    assert "tracepoint:sched:sched_process_fork" in prog
    assert "@tracked[args->child_pid] = 1;" in prog          # children join the tree
    assert "tracepoint:sched:sched_process_exit" in prog     # exited pids drop out
    assert "delete(@tracked[pid]);" in prog


def test_program_traces_base_syscalls_with_filenames():
    prog = generate_program(1)
    for name in ("execve", "connect", "openat"):
        assert f"tracepoint:syscalls:sys_enter_{name} /@tracked[pid]/" in prog
    assert 'printf("MAVEBPF|execve|%d|%s|%s\\n", pid, comm, str(args->filename));' in prog
    assert 'printf("MAVEBPF|openat|%d|%s|%s\\n", pid, comm, str(args->filename));' in prog
    assert 'printf("MAVEBPF|connect|%d|%s|%s\\n", pid, comm, "");' in prog


def test_program_adds_watchlist_tracepoints_once():
    prog = generate_program(1, watchlist=("ptrace", "execve", "ptrace"))
    assert prog.count("sys_enter_ptrace") == 1
    assert prog.count("sys_enter_execve") == 1  # deduped against the base set


def test_program_rejects_code_injection_in_watchlist():
    for bad in ("rm -rf /", 'x"; system("id', "PTRACE", "", "a" * 33):
        with pytest.raises(ValueError, match="invalid syscall name"):
            generate_program(1, watchlist=(bad,))


def test_program_rejects_bad_pid():
    for bad in (0, -5, True, "12", None):
        with pytest.raises(ValueError, match="pid must be a positive integer"):
            generate_program(bad)


# ---- parsing -------------------------------------------------------------------

def test_parse_well_formed_line():
    ev = parse_line("MAVEBPF|execve|321|bash|/usr/bin/curl\n")
    assert ev == SyscallEvent(
        syscall="execve", pid=321, comm="bash", detail="/usr/bin/curl", suspicious=False,
    )


def test_parse_flags_watchlist_hits():
    ev = parse_line("MAVEBPF|ptrace|9|gdb|")
    assert ev is not None and ev.suspicious
    ev = parse_line("MAVEBPF|openat|9|cat|/etc/shadow", watchlist=("openat",))
    assert ev is not None and ev.suspicious


def test_parse_rejects_noise_and_torn_lines():
    for junk in (
        "Attaching 5 probes...",          # bpftrace banner
        "MAVEBPF|execve|321",             # torn line
        "OTHER|execve|321|bash|x",        # wrong prefix
        "MAVEBPF|exec ve|321|bash|x",     # invalid syscall token
        "MAVEBPF|execve|NaN|bash|x",      # non-integer pid
        "MAVEBPF|execve|-1|bash|x",       # nonsense pid
        "",
        None,
    ):
        assert parse_line(junk) is None


def test_parse_keeps_pipes_in_detail():
    ev = parse_line("MAVEBPF|openat|7|sh|/tmp/a|b|c")
    assert ev is not None and ev.detail == "/tmp/a|b|c"


# ---- supervision ----------------------------------------------------------------

OUTPUT = [
    "Attaching 7 probes...",
    "MAVEBPF|execve|100|bash|/usr/bin/python3",
    "MAVEBPF|openat|100|python3|/etc/hosts",
    "MAVEBPF|ptrace|101|python3|",
    "garbage line",
    "MAVEBPF|connect|101|python3|",
]


def test_monitor_collects_events_and_alerts_on_watchlist():
    alerts = []
    mon = EbpfMonitor(100, runner=lambda prog: iter(OUTPUT), alert=alerts.append)
    events = mon.run()
    assert [e.syscall for e in events] == ["execve", "openat", "ptrace", "connect"]
    assert [a.syscall for a in alerts] == ["ptrace"]
    assert mon.alerts == alerts
    assert "@tracked[100] = 1;" in mon.program  # the runner got the real program


def test_monitor_passes_program_to_runner():
    seen = []

    def runner(prog):
        seen.append(prog)
        return iter(())

    EbpfMonitor(55, runner=runner).run()
    assert seen == [generate_program(55)]


def test_monitor_survives_broken_alert_callback(caplog):
    def bad_alert(event):
        raise RuntimeError("pager down")

    mon = EbpfMonitor(100, runner=lambda prog: iter(OUTPUT), alert=bad_alert)
    with caplog.at_level("WARNING"):
        events = mon.run()
    assert len(events) == 4                       # kept monitoring
    assert any("alert callback failed" in r.message for r in caplog.records)


def test_monitor_max_events_bound():
    mon = EbpfMonitor(100, runner=lambda prog: iter(OUTPUT))
    assert len(mon.run(max_events=2)) == 2


def test_custom_watchlist_drives_alerts():
    mon = EbpfMonitor(
        100, watchlist=("connect",), runner=lambda prog: iter(OUTPUT),
    )
    mon.run()
    assert [a.syscall for a in mon.alerts] == ["connect"]
    # ptrace is not on this watchlist, so it is traced... only if in program;
    # with a custom watchlist the program traces base + connect only.
    assert "sys_enter_ptrace" not in mon.program


# ---- live-attach refusals (polite, no execution) ---------------------------------

def test_default_runner_refuses_without_bpftrace(monkeypatch):
    monkeypatch.setattr(ebpf_monitor.shutil, "which", lambda name: None)
    mon = EbpfMonitor(100)
    with pytest.raises(BpftraceUnavailable, match="bpftrace is not installed"):
        mon.run()


def test_default_runner_refuses_without_root(monkeypatch):
    import os

    monkeypatch.setattr(ebpf_monitor.shutil, "which", lambda name: "/usr/bin/bpftrace")
    monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
    with pytest.raises(BpftraceUnavailable, match="needs root"):
        EbpfMonitor(100).run()


# ---- default OFF + CLI ------------------------------------------------------------

def test_disabled_by_default(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "missing.toml"))
    assert ebpf_monitor.enabled() is False


def test_cli_program_prints_inert_text(capsys):
    rc = ebpf_monitor.main(["program", "--pid", "77", "--watch", "ptrace,mount"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "@tracked[77] = 1;" in out and "sys_enter_mount" in out


def test_cli_run_refused_when_disabled(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "missing.toml"))
    rc = ebpf_monitor.main(["run", "--pid", "77"])
    assert rc == 2
    assert "off by default" in capsys.readouterr().err


def test_cli_run_enabled_but_no_bpftrace_fails_politely(tmp_path, monkeypatch, capsys):
    cfg = tmp_path / "config.toml"
    cfg.write_text("[ebpf_monitor]\nenable = true\n", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    monkeypatch.setattr(ebpf_monitor.shutil, "which", lambda name: None)
    rc = ebpf_monitor.main(["run", "--pid", "77"])
    assert rc == 2
    assert "bpftrace is not installed" in capsys.readouterr().err


def test_cli_rejects_default_watchlist_tampering(capsys):
    rc = ebpf_monitor.main(["program", "--pid", "77", "--watch", "ptrace;rm"])
    assert rc == 2
    assert "invalid syscall name" in capsys.readouterr().err


def test_default_watchlist_is_sane():
    assert "ptrace" in DEFAULT_WATCHLIST and "init_module" in DEFAULT_WATCHLIST
    # every default entry survives validation (the program builds)
    generate_program(1, watchlist=DEFAULT_WATCHLIST)
