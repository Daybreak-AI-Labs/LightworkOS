"""Tool subprocesses must run with secrets scrubbed and freeform media args
filtered.

A tool that shells out with the full os.environ leaks provider keys to the
child, and one that appends a model-controlled freeform args[] to argv allows
code execution or arbitrary file reads (pandoc --lua-filter, ffmpeg -i
/etc/passwd). The controls:
  - tools.scrub_child_env(): child env via sandbox.local.scrub_env (no secrets)
  - tools.safe_media_args(): drop dangerous flags from freeform args by
    default; MAVERICK_ALLOW_RAW_MEDIA_ARGS=1 opts back in.
"""
from __future__ import annotations

import pytest
from maverick.tools import safe_media_args, scrub_child_env


def test_scrub_child_env_strips_secrets(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-secret")
    monkeypatch.setenv("STRIPE_API_KEY", "sk_live_x")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_x")
    monkeypatch.setenv("PATH", "/usr/bin")
    env = scrub_child_env()
    assert "ANTHROPIC_API_KEY" not in env
    assert "STRIPE_API_KEY" not in env
    assert "GITHUB_TOKEN" not in env
    assert "PATH" in env  # benign infra var preserved


@pytest.mark.parametrize("bad", [
    "--lua-filter=/tmp/evil.lua",
    "--template=/tmp/t.html",
    "--pdf-engine=weasyprint",
    "concat:/etc/passwd|/etc/shadow",
    "--metadata-file=/tmp/m.yaml",
    "--include-in-header=/tmp/h",
    "--resource-path=/etc",
    "--extract-media=/tmp",
])
def test_safe_media_args_drops_selfcontained_dangerous_flags(bad, monkeypatch):
    monkeypatch.delenv("MAVERICK_ALLOW_RAW_MEDIA_ARGS", raising=False)
    out = safe_media_args(["-quality", "90", bad])
    assert bad not in out
    assert "-quality" in out and "90" in out  # benign survive


@pytest.mark.parametrize("flag,value", [
    ("-i", "/etc/passwd"),
    ("--input", "/etc/shadow"),
    ("--lua-filter", "/tmp/evil.lua"),
    ("-filter_complex", "movie=/etc/passwd"),
    ("--template", "/tmp/t.html"),
])
def test_safe_media_args_drops_flag_AND_its_value(flag, value, monkeypatch):
    """A bare dangerous flag takes the next token as its value -- both must go,
    or the path it points at is still smuggled onto argv."""
    monkeypatch.delenv("MAVERICK_ALLOW_RAW_MEDIA_ARGS", raising=False)
    out = safe_media_args(["-strip", flag, value, "-quality", "80"])
    assert flag not in out
    assert value not in out
    assert "-strip" in out and "-quality" in out and "80" in out


def test_safe_media_args_passthrough_when_opted_in(monkeypatch):
    monkeypatch.setenv("MAVERICK_ALLOW_RAW_MEDIA_ARGS", "1")
    raw = ["-i", "/etc/passwd", "--lua-filter=x.lua"]
    assert safe_media_args(raw) == raw


def test_safe_media_args_handles_none_and_empty():
    assert safe_media_args(None) == []
    assert safe_media_args([]) == []


def test_benign_resize_args_survive(monkeypatch):
    monkeypatch.delenv("MAVERICK_ALLOW_RAW_MEDIA_ARGS", raising=False)
    # A normal imagemagick operator chain must pass through untouched.
    out = safe_media_args(["-resize", "50%", "-rotate", "90", "-strip"])
    assert out == ["-resize", "50%", "-rotate", "90", "-strip"]


def test_subprocess_tools_import_scrub_helper():
    """Every shell-out tool must keep the child env scrubbed of secrets.

    Two acceptable ways now: (a) route through the sandbox chokepoint via
    ``sandbox_run`` (which scrubs the env / mediates exec), or (b) for tools
    that still shell out directly, reference the scrub helper. No tool may
    reintroduce raw ``os.environ`` inheritance."""
    import pathlib

    import maverick.tools as T
    tdir = pathlib.Path(T.__file__).parent
    for name in ["git_advanced", "preview_diff", "apply_patch", "ffmpeg_tool",
                 "imagemagick_tool", "pandoc_tool", "ocr", "a11y", "android", "ios_sim"]:
        src = (tdir / f"{name}.py").read_text(encoding="utf-8")
        assert (
            "sandbox_run" in src
            or "scrub_child_env" in src
            or "scrub_env" in src
            or "sandbox.exec" in src
            or (name == "ocr" and "run_document_job" in src)
        ), f"{name} no longer scrubs the child env nor routes through the sandbox"


class _RecordingSandbox:
    """Minimal sandbox stub: records exec() commands, returns a canned result."""

    def __init__(self, workdir, stdout="", exit_code=0):
        from pathlib import Path
        self.workdir = Path(workdir)
        self.commands: list[str] = []
        self._stdout = stdout
        self._exit = exit_code

    def exec(self, cmd, timeout=None):
        from maverick.sandbox.local import ExecResult
        self.commands.append(cmd)
        return ExecResult(stdout=self._stdout, stderr="", exit_code=self._exit)


def test_imagemagick_routes_command_through_sandbox_exec(tmp_path, monkeypatch):
    """With a sandbox wired in, the tool must drive sandbox.exec, not the host."""
    monkeypatch.setattr("shutil.which", lambda b: "/usr/bin/magick" if b == "magick" else None)

    def _boom(*a, **k):
        raise AssertionError("subprocess.run must not be called when a sandbox is wired in")

    monkeypatch.setattr("subprocess.run", _boom)
    from maverick.tools.imagemagick_tool import imagemagick_tool

    sb = _RecordingSandbox(tmp_path)
    out = imagemagick_tool(sb).fn({
        "op": "resize", "input_path": "a.png", "output_path": "b.png", "width": 800,
    })
    assert "wrote" in out
    assert len(sb.commands) == 1
    assert "magick" in sb.commands[0] and "-resize" in sb.commands[0]


def test_pandoc_string_op_feeds_stdin_through_sandbox(tmp_path, monkeypatch):
    """markdown_to_html feeds text via the base64 stdin pipe, through the sandbox."""
    monkeypatch.setattr("shutil.which", lambda b: "/usr/bin/pandoc")
    monkeypatch.setattr("subprocess.run", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("must route through sandbox.exec")))
    from maverick.tools.pandoc_tool import pandoc_tool

    sb = _RecordingSandbox(tmp_path, stdout="<p>Hello</p>\n")
    out = pandoc_tool(sb).fn({"op": "markdown_to_html", "text": "Hello"})
    assert "<p>Hello</p>" in out
    assert sb.commands and "base64 -d" in sb.commands[0] and "pandoc" in sb.commands[0]


def test_media_tools_route_through_sandbox_chokepoint():
    """The sandboxable media tools must mediate shell via ``sandbox_run``,
    not call subprocess directly (CLAUDE.md rule #4). The host-local tools
    (clipboard/android/ios_sim) are intentionally excluded — they drive
    host-only resources and cannot run inside the sandbox."""
    import pathlib

    import maverick.tools as T
    tdir = pathlib.Path(T.__file__).parent
    for name in ["ffmpeg_tool", "imagemagick_tool", "pandoc_tool", "ocr", "a11y"]:
        src = (tdir / f"{name}.py").read_text(encoding="utf-8")
        if name == "ocr":
            # OCR now owns an immutable staged document job. The common job
            # service, not the caller, invokes the explicitly selected backend.
            assert "run_document_job" in src
            jobs = (tdir / "document_processing.py").read_text()
            assert 'worker.exec(command, timeout=request["timeout"])' in jobs
            assert "subprocess.run(" not in jobs
        else:
            assert "sandbox_run" in src, f"{name} must route shell through sandbox_run"
        # No leftover direct host subprocess invocation.
        assert "subprocess.run(" not in src, (
            f"{name} still calls subprocess.run directly; route via sandbox_run"
        )


# ---------- host_exec: explicit host-bound (NOT sandbox-mediated) path ----------
# Device/clipboard tools act on host hardware (USB adb device, iOS
# simulator, desktop clipboard) that the sandbox container can't reach, so they
# are intentionally direct. host_exec makes that choice auditable + scrubs env.

def test_host_exec_scrubs_env(monkeypatch):
    import sys

    from maverick.tools import host_exec
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-secret")
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    # Print whether the secret leaked into the child env.
    code, out, err = host_exec(
        [sys.executable, "-c",
         "import os; print('LEAK' if os.environ.get('ANTHROPIC_API_KEY') else 'clean')"],
        timeout=15,
    )
    assert code == 0
    assert "clean" in out and "LEAK" not in out


def test_host_exec_timeout_returns_124():
    import sys

    from maverick.tools import host_exec
    code, out, err = host_exec(
        [sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.5,
    )
    assert code == 124
    assert "TIMEOUT" in err


def test_host_exec_binary_mode_returns_bytes():
    import sys

    from maverick.tools import host_exec
    code, out, err = host_exec(
        [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'\\x89PNG')"],
        timeout=15, text=False,
    )
    assert code == 0
    assert out == b"\x89PNG"


def test_android_adb_routes_through_host_exec(monkeypatch):
    """android._adb must dispatch via host_exec (the auditable host-bound path),
    not a bare subprocess.run."""
    import maverick.tools as tools_pkg
    from maverick.tools import android
    calls = {}

    def fake_host_exec(argv, *, timeout=60.0, text=True):
        calls["argv"] = argv
        return 0, "device-list", ""

    monkeypatch.setattr(tools_pkg, "host_exec", fake_host_exec)
    code, out, err = android._adb(["devices", "-l"])
    assert code == 0 and out == "device-list"
    assert calls["argv"][0] == "adb"


def test_ios_simctl_routes_through_host_exec(monkeypatch):
    import maverick.tools as tools_pkg
    from maverick.tools import ios_sim
    calls = {}

    def fake_host_exec(argv, *, timeout=60.0, text=True):
        calls["argv"] = argv
        return 0, "booted", ""

    monkeypatch.setattr(tools_pkg, "host_exec", fake_host_exec)
    code, out, err = ios_sim._simctl(["list", "devices"])
    assert code == 0 and out == "booted"
    assert calls["argv"][:2] == ["xcrun", "simctl"]


# ---------- option-injection / path hardening ----------

import importlib  # noqa: E402


@pytest.mark.parametrize("mod", ["ffmpeg_tool", "imagemagick_tool", "pandoc_tool"])
def test_safe_path_blocks_leading_dash_without_sandbox(mod):
    """When sandbox is None, _safe_path returned the path verbatim -- so
    input_path="-i" / "-write ..." became a flag to ffmpeg/convert/pandoc.
    A leading-dash path must now be rejected. Pandoc also needs a workspace."""
    m = importlib.import_module(f"maverick.tools.{mod}")
    with pytest.raises(ValueError, match="may not begin with '-'"):
        m._safe_path(None, "-i")
    if mod in {"pandoc_tool", "imagemagick_tool", "ffmpeg_tool"}:
        with pytest.raises(ValueError, match="requires a workspace"):
            m._safe_path(None, "in.png")
    else:
        assert m._safe_path(None, "in.png") == "in.png"


@pytest.mark.parametrize("overrides", [
    {"from_": "reader.lua"}, {"to": "writer.lua"}, {"from_": "markdown+raw_tex"},
    {"args": ["-L", "filter.lua"]}, {"args": ["--defaults=evil.yml"]},
    {"args": ["-H", "/etc/passwd"]}, {"args": ["-o", "/tmp/evil"]},
    {"args": ["--embed-resources"]}, {"args": ["/tmp/evil"]},
    {"args": "--standalone"}, {"args": ["--output=/tmp/evil"]},
    {"input_path": "input.unknown"}, {"output_path": "result.unknown"}, {"to": "pdf"},
    {"output_path": "result.PDF"}, {"output_path": "result.pdf", "to": "html"},
])
def test_pandoc_refuses_unreviewed_writers_flags_and_pdf(tmp_path, monkeypatch, overrides):
    from maverick.tools.pandoc_tool import pandoc_tool

    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/pandoc")
    monkeypatch.setenv("MAVERICK_ALLOW_RAW_MEDIA_ARGS", "1")
    sandbox = _RecordingSandbox(tmp_path)
    params = {"op": "convert", "input_path": "input.md", "output_path": "output.html", **overrides}
    assert pandoc_tool(sandbox).fn(params).startswith("ERROR:")
    assert sandbox.commands == []


def test_pandoc_allows_builtin_conversion_with_basic_options(tmp_path, monkeypatch):
    from maverick.tools.pandoc_tool import pandoc_tool

    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/pandoc")
    sandbox = _RecordingSandbox(tmp_path)
    result = pandoc_tool(sandbox).fn({
        "op": "convert", "input_path": "input.md", "output_path": "output.html",
        "args": ["--standalone"],
    })
    assert result.startswith("wrote ")
    assert len(sandbox.commands) == 1 and "--standalone" in sandbox.commands[0]


def test_pandoc_converts_simple_markdown_to_html_and_docx(tmp_path):
    import shutil
    import zipfile

    from maverick.sandbox import LocalBackend
    from maverick.tools.pandoc_tool import pandoc_tool

    if shutil.which("pandoc") is None:
        pytest.skip("pandoc is unavailable")
    (tmp_path / "input.md").write_text("# Hello\n\nA plain document.\n", encoding="utf-8")
    tool = pandoc_tool(LocalBackend(workdir=tmp_path))
    for output in ("output.html", "output.docx"):
        assert tool.fn({"op": "convert", "input_path": "input.md", "output_path": output}).startswith("wrote ")
    assert "A plain document." in (tmp_path / "output.html").read_text(encoding="utf-8")
    with zipfile.ZipFile(tmp_path / "output.docx") as archive:
        assert b"A plain document." in archive.read("word/document.xml")


def test_pandoc_document_cannot_include_files_outside_the_workspace(tmp_path):
    import shutil

    from maverick.sandbox import LocalBackend
    from maverick.tools.pandoc_tool import pandoc_tool

    if shutil.which("pandoc") is None:
        pytest.skip("pandoc is unavailable")
    outside = tmp_path / "outside.txt"
    outside.write_text("OUTSIDE-SECRET\n", encoding="utf-8")
    work = tmp_path / "work"
    work.mkdir()
    (work / "a.rst").write_text(f"Title\n=====\n\n.. include:: {outside}\n", encoding="utf-8")
    (work / "b.md").write_text(f"![x]({outside})\n", encoding="utf-8")
    tool = pandoc_tool(LocalBackend(workdir=work))
    tool.fn({"op": "convert", "input_path": "a.rst", "output_path": "a.html"})
    written = work / "a.html"
    assert not written.exists() or "OUTSIDE-SECRET" not in written.read_text(encoding="utf-8")
    assert tool.fn({"op": "convert", "input_path": "b.md", "output_path": "b.docx"}).startswith("ERROR:")
    assert sorted(p.name for p in work.iterdir()) == ["a.html", "a.rst", "b.md"]


def test_pandoc_docx_round_trip_keeps_images_and_allows_data_uris(tmp_path):
    """docx -> docx went through a JSON AST that names images inside the
    package without their bytes, so the output silently lost them; data:
    images were refused for containing ':'."""
    import base64
    import shutil
    import struct
    import zipfile
    import zlib

    from maverick.sandbox import LocalBackend
    from maverick.tools.pandoc_tool import pandoc_tool

    if shutil.which("pandoc") is None:
        pytest.skip("pandoc is unavailable")

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
           + chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00")) + chunk(b"IEND", b""))
    (tmp_path / "p.png").write_bytes(png)
    (tmp_path / "a.md").write_text("# T\n\n![x](p.png)\n", encoding="utf-8")
    tool = pandoc_tool(LocalBackend(workdir=tmp_path))
    assert tool.fn({"op": "convert", "input_path": "a.md", "output_path": "in.docx"}).startswith("wrote ")
    assert tool.fn({"op": "convert", "input_path": "in.docx", "output_path": "out.docx"}).startswith("wrote ")
    with zipfile.ZipFile(tmp_path / "out.docx") as archive:
        assert any(name.startswith("word/media/") for name in archive.namelist())
    assert not any(p.name.startswith(".pandoc") for p in tmp_path.iterdir())

    inline = "data:image/png;base64," + base64.b64encode(png).decode()
    (tmp_path / "d.md").write_text(f"![x]({inline})\n", encoding="utf-8")
    assert tool.fn({"op": "convert", "input_path": "d.md", "output_path": "d.docx"}).startswith("wrote ")


def test_pandoc_without_sandbox_support_names_the_required_version(tmp_path, monkeypatch):
    from maverick.tools.pandoc_tool import pandoc_tool

    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/pandoc")

    class _OldPandoc(_RecordingSandbox):
        def exec(self, cmd, timeout=None):
            from maverick.sandbox.local import ExecResult
            return ExecResult(stdout="", stderr="Unknown option --sandbox.\nTry pandoc --help", exit_code=2)

    out = pandoc_tool(_OldPandoc(tmp_path)).fn({"op": "markdown_to_html", "text": "hi"})
    assert out == "ERROR: pandoc 2.15 or newer is required (it must support --sandbox)"


@pytest.mark.parametrize("options", [
    ["-write", "/tmp/out"], ["text:/etc/passwd"], ["-script", "@bad"],
    ["-format", "info:"], ["-resize", "@secret"], ["-quality", "101"],
    ["-rotate", "nan"], ["-strip", "/tmp/out"],
])
def test_imagemagick_refuses_file_and_operator_injection(tmp_path, monkeypatch, options):
    from maverick.tools.imagemagick_tool import imagemagick_tool

    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/magick")
    monkeypatch.setenv("MAVERICK_ALLOW_RAW_MEDIA_ARGS", "1")
    sandbox = _RecordingSandbox(tmp_path)
    result = imagemagick_tool(sandbox).fn({"op": "convert", "input_path": "input.png",
                                           "output_path": "output.png", "args": options})
    assert result.startswith("ERROR:")
    assert sandbox.commands == []


def test_imagemagick_accepts_bounded_options(tmp_path, monkeypatch):
    from maverick.tools.imagemagick_tool import imagemagick_tool

    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/magick")
    sandbox = _RecordingSandbox(tmp_path)
    result = imagemagick_tool(sandbox).fn({"op": "convert", "input_path": "input.png",
                                           "output_path": "output.png",
                                           "args": ["-resize", "800x600", "-quality", "80", "-strip"]})
    assert result.startswith("wrote ") and len(sandbox.commands) == 1


def test_imagemagick_converts_a_simple_raster_in_workspace(tmp_path):
    import shutil

    from maverick.sandbox import LocalBackend
    from maverick.tools.imagemagick_tool import imagemagick_tool

    if not (shutil.which("magick") or shutil.which("convert")):
        pytest.skip("ImageMagick is unavailable")
    (tmp_path / "input.ppm").write_text("P3\n1 1\n255\n255 0 0\n", encoding="ascii")
    result = imagemagick_tool(LocalBackend(workdir=tmp_path)).fn({
        "op": "convert", "input_path": "input.ppm", "output_path": "output.png",
        "args": ["-resize", "200%", "-rotate", "90", "-strip"],
    })
    assert result.startswith("wrote ")
    assert (tmp_path / "output.png").read_bytes().startswith(b"\x89PNG\r\n\x1a\n")


@pytest.mark.parametrize("geometry", ["-write", "@secret", "+1", "1x2+3", "+0+0 -write /tmp/x"])
def test_imagemagick_composite_rejects_invalid_geometry(tmp_path, monkeypatch, geometry):
    from maverick.tools.imagemagick_tool import imagemagick_tool

    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/magick")
    sandbox = _RecordingSandbox(tmp_path)
    result = imagemagick_tool(sandbox).fn({"op": "composite", "base_path": "base.png",
                                           "overlay_path": "overlay.png", "output_path": "out.png",
                                           "geometry": geometry})
    assert result.startswith("ERROR:") and sandbox.commands == []


@pytest.mark.parametrize("options", [
    ["-filter:v", "drawtext=textfile=/etc/passwd"], ["-filter_script:v", "/tmp/script"],
    ["-passlogfile", "/tmp/out"], ["-protocol_whitelist", "http"],
    ["/tmp/extra"], ["-c:v", "@file"], ["-crf", "NaN"], ["-b:a", "999999m"],
])
def test_ffmpeg_rejects_untrusted_options(tmp_path, monkeypatch, options):
    from maverick.tools.ffmpeg_tool import ffmpeg_tool

    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/ffmpeg")
    monkeypatch.setenv("MAVERICK_ALLOW_RAW_MEDIA_ARGS", "1")
    sandbox = _RecordingSandbox(tmp_path)
    result = ffmpeg_tool(sandbox).fn({"op": "convert", "input_path": "input.mp4",
                                     "output_path": "output.mp4", "args": options})
    assert result.startswith("ERROR:") and sandbox.commands == []


@pytest.mark.parametrize("time_value,width", [("-i", 640), ("1; rm", 640), ("00:60:00", 640), ("1", 99999)])
def test_ffmpeg_thumbnail_rejects_unsafe_parameters(tmp_path, monkeypatch, time_value, width):
    from maverick.tools.ffmpeg_tool import ffmpeg_tool

    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/ffmpeg")
    sandbox = _RecordingSandbox(tmp_path)
    result = ffmpeg_tool(sandbox).fn({"op": "thumbnail", "input_path": "in.mp4",
                                     "output_path": "out.png", "time": time_value, "width": width})
    assert result.startswith("ERROR:") and sandbox.commands == []


def test_ffmpeg_converts_simple_audio_in_workspace(tmp_path):
    import shutil
    import wave

    from maverick.sandbox import LocalBackend
    from maverick.tools.ffmpeg_tool import ffmpeg_tool

    if shutil.which("ffmpeg") is None:
        pytest.skip("ffmpeg is unavailable")
    with wave.open(str(tmp_path / "input.wav"), "wb") as source:
        source.setnchannels(1)
        source.setsampwidth(2)
        source.setframerate(8000)
        source.writeframes(b"\0\0" * 80)
    result = ffmpeg_tool(LocalBackend(workdir=tmp_path)).fn({
        "op": "convert", "input_path": "input.wav", "output_path": "output.wav",
        "args": ["-c:a", "pcm_s16le"],
    })
    assert result.startswith("wrote ")
    with wave.open(str(tmp_path / "output.wav"), "rb") as output:
        assert output.getnchannels() == 1 and output.getnframes() == 80


@pytest.mark.parametrize("tool_name,source,output", [
    ("pandoc", "input.md", ".GIT/config.html"),
    ("imagemagick", "input.png", ".Git /config.png"),
    ("ffmpeg", "input.wav", ".git/config.wav"),
])
def test_media_tools_refuse_git_metadata_writes(tmp_path, monkeypatch, tool_name, source, output):
    from maverick.tools.ffmpeg_tool import ffmpeg_tool
    from maverick.tools.imagemagick_tool import imagemagick_tool
    from maverick.tools.pandoc_tool import pandoc_tool

    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/tool")
    sandbox = _RecordingSandbox(tmp_path)
    tool = {"pandoc": pandoc_tool, "imagemagick": imagemagick_tool, "ffmpeg": ffmpeg_tool}[tool_name](sandbox)
    result = tool.fn({"op": "convert", "input_path": source, "output_path": output})
    assert "refusing to write under .git" in result
    assert sandbox.commands == []


@pytest.mark.parametrize("tool_name,source", [("pandoc", "input.md"), ("imagemagick", "input.png"),
                                              ("ffmpeg", "input.wav")])
def test_media_tools_refuse_git_symlink_destination(tmp_path, monkeypatch, tool_name, source):
    from maverick.tools.ffmpeg_tool import ffmpeg_tool
    from maverick.tools.imagemagick_tool import imagemagick_tool
    from maverick.tools.pandoc_tool import pandoc_tool

    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/tool")
    (tmp_path / "git-data").mkdir()
    try:
        (tmp_path / ".git").symlink_to(tmp_path / "git-data", target_is_directory=True)
    except OSError:
        pytest.skip("symlinks are unavailable")
    sandbox = _RecordingSandbox(tmp_path)
    tool = {"pandoc": pandoc_tool, "imagemagick": imagemagick_tool, "ffmpeg": ffmpeg_tool}[tool_name](sandbox)
    result = tool.fn({"op": "convert", "input_path": source, "output_path": ".git/config.html"})
    assert "refusing to write under .git" in result and sandbox.commands == []


def _capture_sandbox_run(monkeypatch, *, ret=(0, "", "")):
    """Patch the tools.sandbox_run chokepoint and capture the argv it's given."""
    import maverick.tools as T
    captured: dict = {}

    def _rec(sandbox, cmd, **kw):
        captured["cmd"] = cmd
        return ret

    monkeypatch.setattr(T, "sandbox_run", _rec)
    return captured


def test_axe_target_protected_by_double_dash(monkeypatch):
    """The axe target was positional with no `--`, so a target like
    `--config=/tmp/evil.js` was parsed as an axe flag (pa11y was already
    fixed). `--` must end option parsing with the target as the sole
    positional after it."""
    captured = _capture_sandbox_run(monkeypatch, ret=(0, "[]", ""))
    from maverick.tools.a11y import _run_axe
    _run_axe("--config=/tmp/evil.js", None)
    cmd = captured["cmd"]
    assert "--" in cmd
    assert cmd[-1] == "--config=/tmp/evil.js"
    assert cmd[: cmd.index("--")] == ["axe", "--no-reporter", "--save", "/dev/stdout"]


def test_a11y_check_html_confines_path(tmp_path):
    from maverick.tools.a11y import _confine_path
    sb = _RecordingSandbox(tmp_path)
    with pytest.raises(ValueError, match="may not begin with '-'"):
        _confine_path(sb, "-x.html")
    with pytest.raises(ValueError, match="escapes the workspace"):
        _confine_path(sb, "../../etc/passwd")
    assert _confine_path(sb, "page.html") == str((tmp_path / "page.html").resolve())
    # No sandbox: pass through (still leading-dash guarded above).
    assert _confine_path(None, "page.html") == "page.html"


def test_imagemagick_composite_uses_magick_on_im7(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which",
                        lambda b: f"/usr/bin/{b}" if b == "magick" else None)
    captured = _capture_sandbox_run(monkeypatch)
    from maverick.tools.imagemagick_tool import imagemagick_tool
    out = imagemagick_tool(_RecordingSandbox(tmp_path)).fn({
        "op": "composite", "base_path": "b.png",
        "overlay_path": "o.png", "output_path": "out.png",
    })
    assert "wrote" in out
    assert captured["cmd"][:2] == ["magick", "composite"]


def test_imagemagick_composite_uses_im6_composite_binary(tmp_path, monkeypatch):
    """IM6 has no `magick`; compositing needs the separate `composite` binary,
    NOT `convert` (which _magick_or_convert would have wrongly picked)."""
    present = {"convert", "composite", "identify"}
    monkeypatch.setattr("shutil.which",
                        lambda b: f"/usr/bin/{b}" if b in present else None)
    captured = _capture_sandbox_run(monkeypatch)
    from maverick.tools.imagemagick_tool import imagemagick_tool
    out = imagemagick_tool(_RecordingSandbox(tmp_path)).fn({
        "op": "composite", "base_path": "b.png",
        "overlay_path": "o.png", "output_path": "out.png",
    })
    assert "wrote" in out
    assert captured["cmd"][0] == "composite"
    assert "convert" not in captured["cmd"]
