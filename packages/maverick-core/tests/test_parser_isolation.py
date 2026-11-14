"""Memory-safe parsing: whitelist, caps, real child round-trip, pdf wiring."""
from __future__ import annotations

import subprocess

import pytest
from maverick import parser_isolation as pi


def _answer_through_file(kwargs, payload):
    # Resource-limited parsers read the child's stdout from a regular file.
    if hasattr(kwargs.get("stdout"), "write"):
        kwargs["stdout"].write(payload)


def test_whitelist_enforced():
    with pytest.raises(ValueError, match="unknown parser"):
        pi.parse_isolated("arbitrary.module:evil", b"x")


def test_size_cap_enforced_before_child(monkeypatch):
    called = []
    monkeypatch.setattr(subprocess, "run",
                        lambda *a, **k: called.append(1))
    big = b"x" * (pi.MAX_INPUT_BYTES + 1)
    with pytest.raises(ValueError, match="exceeds"):
        pi.parse_isolated("pdf_text", big)
    assert called == []  # the child never saw the oversized input


def test_child_uses_isolated_mode_and_neutral_cwd(monkeypatch):
    captured = {}

    class _OK:
        returncode = 0
        stdout = b'{"ok": true, "result": null}'
        stderr = b""

    def _run(args, **kwargs):
        captured["args"] = args
        captured.update(kwargs)
        _answer_through_file(kwargs, _OK.stdout)
        return _OK()

    monkeypatch.setattr(subprocess, "run", _run)
    pi.parse_isolated("pdf_text", b"%PDF-fake")
    assert captured["args"][:2] == [pi.sys.executable, "-I"]
    assert captured["cwd"] == pi.os.path.abspath(pi.os.sep)


def test_child_imports_real_package_not_attacker_cwd(monkeypatch, tmp_path):
    attacker_module = tmp_path / "maverick" / "tools"
    attacker_module.mkdir(parents=True)
    marker = tmp_path / "PWNED"
    (tmp_path / "maverick" / "__init__.py").write_text("")
    (attacker_module / "__init__.py").write_text("")
    (attacker_module / "pdf_reader.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('imported')\n"
        "def extract_text_from_bytes(data, **kwargs):\n"
        "    return 'attacker controlled'\n"
    )

    monkeypatch.chdir(tmp_path)
    try:
        result = pi.parse_isolated("pdf_text", b"%PDF-1.4 fake")
    except RuntimeError:
        result = None

    assert result != "attacker controlled"
    assert not marker.exists()


def test_real_child_roundtrip(monkeypatch):
    # a pure-python whitelisted entry: json.loads(bytes) -> the parsed value
    entry = pi.ParserEntry(name="jsonval", module="json", func="loads",
                           feeds="test", memory_safe=True)
    monkeypatch.setitem(pi.PARSERS, "jsonval", entry)
    result = pi.parse_isolated("jsonval", b'{"a": [1, 2]}')
    assert result == {"a": [1, 2]}


@pytest.mark.skipif(pi.os.name != "posix", reason="evidence PDF limits require POSIX")
def test_evidence_child_roundtrip_with_resource_limits(monkeypatch):
    entry = pi.ParserEntry(name="evidence_pdf_text", module="json", func="loads",
                           feeds="test", memory_safe=True)
    monkeypatch.setitem(pi.PARSERS, "evidence_pdf_text", entry)
    assert pi.parse_isolated("evidence_pdf_text", b'"bounded"') == "bounded"


def test_evidence_child_refuses_unsupported_platform(monkeypatch):
    monkeypatch.setattr(pi, "_POSIX_RESOURCE_LIMITS", False)
    with pytest.raises(RuntimeError, match="requires POSIX"):
        pi.parse_isolated("evidence_pdf_text", b"document")


@pytest.mark.skipif(pi.os.name != "posix", reason="evidence PDF limits require POSIX")
def test_evidence_output_is_file_bounded_and_stderr_discarded(monkeypatch):
    seen = {}

    def fake_run(args, **kwargs):
        seen.update(kwargs)
        assert "RLIMIT_FSIZE" in args[-1]
        kwargs["stdout"].write(b'{"ok": true, "result": "ok"}')
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert pi.parse_isolated("evidence_pdf_text", b"document") == "ok"
    assert seen["stderr"] == subprocess.DEVNULL
    assert "capture_output" not in seen


@pytest.mark.skipif(pi.os.name != "posix", reason="evidence PDF limits require POSIX")
@pytest.mark.parametrize("name", ["pdf_text", "image_meta"])
def test_channel_document_parsers_get_resource_limits(monkeypatch, name):
    # A compression-bomb PDF or image must meet the same RLIMIT_AS/CPU/FSIZE
    # bounds and file-backed stdout as the evidence parser.
    seen = {}

    def fake_run(args, **kwargs):
        seen.update(kwargs)
        assert "RLIMIT_AS" in args[-1] and "RLIMIT_FSIZE" in args[-1]
        kwargs["stdout"].write(b'{"ok": true, "result": "ok"}')
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert pi.parse_isolated(name, b"document") == "ok"
    assert "capture_output" not in seen


@pytest.mark.skipif(pi.os.name != "posix", reason="evidence PDF limits require POSIX")
def test_evidence_worker_resource_limits_bound_regular_file(tmp_path):
    output = tmp_path / "output"
    with output.open("wb") as target:
        subprocess.run(
            [pi.sys.executable, "-I", "-c", pi._EVIDENCE_LIMITS +
             "\nimport os\nos.write(1, b'x' * (17 * 1024 * 1024))\n"],
            stdout=target, stderr=subprocess.DEVNULL, timeout=15,
        )
    assert 0 < output.stat().st_size <= pi._EVIDENCE_OUTPUT_LIMIT


def test_child_parser_error_surfaces(monkeypatch):
    # json.dumps(bytes) raises inside the child -> ok:False -> RuntimeError
    entry = pi.ParserEntry(name="boom", module="json", func="dumps",
                           feeds="test", memory_safe=True)
    monkeypatch.setitem(pi.PARSERS, "boom", entry)
    with pytest.raises(RuntimeError, match="TypeError"):
        pi.parse_isolated("boom", b"\x00\x01")


def test_child_death_is_runtime_error(monkeypatch):
    class _Dead:
        returncode = -11
        stdout = b""
        stderr = b"Segmentation fault"

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _Dead())
    with pytest.raises(RuntimeError, match="died"):
        pi.parse_isolated("pdf_text", b"%PDF-fake")


def test_timeout_is_runtime_error(monkeypatch):
    def _hang(*a, **k):
        raise subprocess.TimeoutExpired(cmd="python", timeout=1)

    monkeypatch.setattr(subprocess, "run", _hang)
    with pytest.raises(RuntimeError, match="timed out"):
        pi.parse_isolated("pdf_text", b"%PDF-fake", timeout=1)


def test_child_env_is_scrubbed(monkeypatch):
    captured = {}

    class _OK:
        returncode = 0
        stdout = b'{"ok": true, "result": null}'
        stderr = b""

    def _run(*a, **k):
        captured.update(k)
        _answer_through_file(k, _OK.stdout)
        return _OK()

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-secret")  # pragma: allowlist secret
    monkeypatch.setattr(subprocess, "run", _run)
    pi.parse_isolated("pdf_text", b"%PDF-fake")
    assert "ANTHROPIC_API_KEY" not in captured["env"]


def test_should_isolate_off_by_default(monkeypatch):
    monkeypatch.delenv("MAVERICK_ISOLATE_PARSERS", raising=False)
    monkeypatch.setattr("maverick.config.load_config", dict)
    assert pi.should_isolate() is False
    monkeypatch.setenv("MAVERICK_ISOLATE_PARSERS", "1")
    assert pi.should_isolate() is True


def test_should_isolate_stays_on_when_config_is_unreadable(monkeypatch, tmp_path):
    monkeypatch.delenv("MAVERICK_ISOLATE_PARSERS", raising=False)
    cfg = tmp_path / "config.toml"
    cfg.write_text('[security]\nisolate_parsers = "false"\n', encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    assert pi.should_isolate() is False  # the string "false" is not truthy
    cfg.write_text("[security]\nisolate_parsers = true\nx = [\n", encoding="utf-8")
    assert pi.should_isolate() is True


def test_inventory_renders_policy():
    out = pi.inventory()
    assert "pdf_text" in out and "ISOLATE" in out


def test_pdf_reader_routes_through_isolation(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_ISOLATE_PARSERS", "1")
    import maverick.parser_isolation as real_pi

    calls = {}

    def fake_isolated(name, data, **kw):
        calls["name"] = name
        return "ISOLATED TEXT"

    monkeypatch.setattr(real_pi, "parse_isolated", fake_isolated)
    monkeypatch.chdir(tmp_path)  # pdf_reader confines paths to cwd
    (tmp_path / "x.pdf").write_bytes(b"%PDF-1.4 fake")
    from maverick.tools.pdf_reader import _run_read_pdf
    out = _run_read_pdf({"source": "x.pdf"})
    assert out == "ISOLATED TEXT"
    assert calls["name"] == "pdf_text"


def test_pdf_reader_isolated_failure_refuses_inprocess_fallback(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_ISOLATE_PARSERS", "1")
    import maverick.parser_isolation as real_pi
    monkeypatch.setattr(real_pi, "parse_isolated",
                        lambda *a, **k: (_ for _ in ()).throw(
                            RuntimeError("child died (exit -11)")))
    monkeypatch.chdir(tmp_path)  # pdf_reader confines paths to cwd
    (tmp_path / "x.pdf").write_bytes(b"%PDF-1.4 hostile")
    from maverick.tools.pdf_reader import _run_read_pdf
    out = _run_read_pdf({"source": "x.pdf"})
    assert out.startswith("ERROR: isolated PDF parse failed")


def test_channel_parsers_without_posix_limits_keep_bounded_output(monkeypatch):
    # Without POSIX rlimits (Windows) channel PDFs/images still parse, with the
    # file-backed bounded output and timeout but no rlimit preamble.
    monkeypatch.setattr(pi, "_POSIX_RESOURCE_LIMITS", False)
    seen = {}

    def fake_run(args, **kwargs):
        seen.update(kwargs)
        assert "RLIMIT_AS" not in args[-1]
        kwargs["stdout"].write(b'{"ok": true, "result": "ok"}')
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert pi.parse_isolated("pdf_text", b"document") == "ok"
    assert seen["stderr"] == subprocess.DEVNULL and "timeout" in seen
