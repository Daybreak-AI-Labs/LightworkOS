from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import sys
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest


def test_imagemagick_pins_raster_decoders_and_resource_limits(monkeypatch, tmp_path):
    from maverick.tools import imagemagick_tool as module

    seen = []
    monkeypatch.setattr(module, "_bin", lambda *names: names[0])
    monkeypatch.setattr(module, "_run_cmd", lambda sb, cmd, **kw: (seen.append(cmd) or (0, "1 1 PNG 1B image\n", "")))
    sandbox = SimpleNamespace(workdir=tmp_path)
    for args in (
        {"op": "resize", "input_path": "image.png", "output_path": "out.png"},
        {"op": "convert", "input_path": "image.jpg", "output_path": "out.png"},
        {"op": "identify", "input_path": "image.webp"},
        {"op": "composite", "base_path": "base.png", "overlay_path": "overlay.ppm", "output_path": "out.png"},
    ):
        assert not module.imagemagick_tool(sandbox).fn(args).startswith("ERROR")
    for cmd in seen:
        assert "-limit" in cmd
        inputs = [value for value in cmd if any(name in value for name in ("image.", "base.png", "overlay.ppm"))]
        assert inputs and all(value.startswith(("png:", "jpeg:", "webp:", "ppm:")) for value in inputs)
    seen.clear()
    assert module.imagemagick_tool(sandbox).fn({"op": "identify", "input_path": "image.svg"}).startswith("ERROR")
    assert not seen


@pytest.mark.parametrize("ext, coder", [(".ico", "ico"), (".pdf", "pdf")])
def test_imagemagick_writes_ico_and_pdf_outputs_but_never_reads_them(monkeypatch, tmp_path, ext, coder):
    from maverick.tools import imagemagick_tool as module

    seen = []
    monkeypatch.setattr(module, "_bin", lambda *names: names[0])
    monkeypatch.setattr(module, "_run_cmd", lambda sb, cmd, **kw: (seen.append(cmd) or (0, "", "")))
    tool = module.imagemagick_tool(SimpleNamespace(workdir=tmp_path))
    for args in (
        {"op": "resize", "input_path": "image.png", "output_path": f"out{ext}", "width": 32},
        {"op": "convert", "input_path": "image.png", "output_path": f"out{ext.upper()}"},
        {"op": "composite", "base_path": "base.png", "overlay_path": "o.png", "output_path": f"out{ext}"},
    ):
        assert not tool.fn(args).startswith("ERROR")
        assert seen.pop()[-1] == f"{coder}:{tmp_path / ('out' + args['output_path'][3:])}"
    for args in (
        {"op": "identify", "input_path": f"image{ext}"},
        {"op": "convert", "input_path": f"image{ext}", "output_path": "out.png"},
        {"op": "composite", "base_path": f"base{ext}", "overlay_path": "o.png", "output_path": "out.png"},
    ):
        assert tool.fn(args).startswith("ERROR")
    assert not seen


def test_voice_conversion_uses_bound_workspace_sandbox(monkeypatch, tmp_path):
    from maverick import tools
    from maverick.tools import voice

    audio = tmp_path / "clip.webm"
    audio.write_bytes(b"synthetic audio")
    sandbox = SimpleNamespace(workdir=tmp_path)
    seen = []
    monkeypatch.setattr(voice, "_default_stt_backend", lambda: "local")
    monkeypatch.setattr(voice.shutil, "which", lambda _: "/usr/bin/ffmpeg")
    monkeypatch.setattr(voice, "_whisper_local", lambda *_: None)

    def convert(path, _language):
        converted = voice._to_wav16k(path)
        assert converted is not None
        converted.unlink()
        return "converted"

    def run(backend, argv, **kwargs):
        seen.append((backend, argv))
        target = Path(argv[-1])
        (target if target.is_absolute() else tmp_path / target).write_bytes(b"RIFFfixture")
        return 0, "", ""

    monkeypatch.setattr(voice, "_whisper_pywhispercpp", convert)
    monkeypatch.setattr(tools, "sandbox_run", run)
    assert voice.transcribe_audio(sandbox).fn({"source": str(audio)}) == "converted"
    assert seen[0][0] is sandbox
    assert not Path(seen[0][1][-1]).is_absolute()
    assert not Path(seen[0][1][seen[0][1].index("-i") + 1]).is_absolute()


@pytest.mark.parametrize("missing", ["exit127", "raises"])
@pytest.mark.parametrize("suffix", [".wav", ".webm"])
def test_voice_conversion_without_sandbox_ffmpeg_keeps_wav_and_cleans_up(monkeypatch, tmp_path, missing, suffix):
    from maverick import tools
    from maverick.tools import voice

    audio = tmp_path / f"clip{suffix}"
    audio.write_bytes(b"RIFFfixture")

    def run(_backend, argv, **_kwargs):
        if missing == "raises":
            raise FileNotFoundError(2, "No such file or directory", argv[0])
        return 127, "", f"sh: {argv[0]}: not found"

    monkeypatch.setattr(tools, "sandbox_run", run)
    token = voice._TRANSCRIBE_CONTEXT.set((SimpleNamespace(workdir=tmp_path), tmp_path))
    try:
        converted = voice._to_wav16k(audio)
    finally:
        voice._TRANSCRIBE_CONTEXT.reset(token)
    assert converted == (audio if suffix == ".wav" else None)
    assert sorted(p.name for p in tmp_path.iterdir()) == [audio.name]


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink race probe")
def test_hosted_voice_refuses_swapped_audio_parent(monkeypatch, tmp_path):
    import openai
    from maverick.tools import voice

    root = tmp_path / "workspace"
    root.mkdir()
    folder = root / "audio"
    folder.mkdir()
    (folder / "clip.wav").write_bytes(b"allowed")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "clip.wav").write_bytes(b"private outside bytes")
    sent = []

    def upload(**kwargs):
        value = kwargs["file"]
        stream = value[1] if isinstance(value, tuple) else value
        sent.append(stream.read())
        return SimpleNamespace(text="transcribed")

    def client(**kwargs):
        folder.rename(root / "old-audio")
        folder.symlink_to(outside, target_is_directory=True)
        return SimpleNamespace(audio=SimpleNamespace(transcriptions=SimpleNamespace(
            create=upload)))

    monkeypatch.setenv("OPENAI_API_KEY", "synthetic")  # pragma: allowlist secret -- synthetic provider fixture
    monkeypatch.setattr(voice, "_default_stt_backend", lambda: "openai")
    monkeypatch.setattr(openai, "OpenAI", client)
    from maverick.budget import Budget

    # A paid hosted call is charged to a run budget; one is passed here.
    result = voice.transcribe_audio(SimpleNamespace(workdir=root), budget=Budget()).fn({"source": "audio/clip.wav"})
    assert result.startswith("ERROR")
    assert not sent
    folder.unlink()
    (root / "old-audio").rename(folder)
    monkeypatch.setattr(openai, "OpenAI", lambda **kw: SimpleNamespace(
        audio=SimpleNamespace(transcriptions=SimpleNamespace(create=upload))))
    assert voice.transcribe_audio(SimpleNamespace(workdir=root), budget=Budget()).fn(
        {"source": "audio/clip.wav"}) == "transcribed"
    assert sent == [b"allowed"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX sandbox interpreter probe")
def test_notebook_runs_once_when_only_python3_exists(monkeypatch, tmp_path):
    from maverick import safety
    from maverick.tools.notebook_exec import notebook_exec

    programs = tmp_path / "bin"
    programs.mkdir()
    (programs / "sh").symlink_to("/bin/sh")
    (programs / "python3").symlink_to(sys.executable)
    (programs / "base64").symlink_to(shutil.which("base64"))
    notebook = tmp_path / "work.ipynb"
    notebook.write_text(json.dumps({"cells": [{"cell_type": "code", "source": ["print('ran once')"]}]}))
    calls = []

    class Sandbox:
        workdir = tmp_path

        def exec(self, command, timeout=None):
            calls.append(command)
            result = subprocess.run(["/bin/sh", "-c", command], cwd=tmp_path,
                                    env={**os.environ, "PATH": str(programs)}, capture_output=True,
                                    text=True, timeout=10)
            return SimpleNamespace(exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr)

    monkeypatch.setattr(safety, "require_operation_consent", lambda *a, **kw: object())
    monkeypatch.setattr(safety, "consume_operation_consent", lambda permit: nullcontext())
    result = notebook_exec(Sandbox()).fn({"path": str(notebook)})
    assert "exit_code: 0" in result and "ran once" in result
    assert len(calls) == 1


def test_repo_map_signature_tracks_hidden_entries(tmp_path):
    from maverick.cache.file import _workdir_signature
    from maverick.tools.repo_map import repo_map

    before = _workdir_signature(tmp_path)
    (tmp_path / ".env").write_text("visible name")
    assert _workdir_signature(tmp_path) != before
    hidden = tmp_path / ".settings"
    hidden.mkdir()
    (hidden / "config").write_text("one")
    before = _workdir_signature(tmp_path)
    (hidden / "config").write_text("changed length")
    assert _workdir_signature(tmp_path) != before

    tool = repo_map(SimpleNamespace(workdir=tmp_path))
    for name in (".gradle", ".ruff_cache", ".hg", ".svn"):
        assert name + "/" not in tool.fn({})
        before = _workdir_signature(tmp_path)
        visible = tmp_path / name
        visible.mkdir()
        child = visible / "metadata"
        child.write_text("shown child")
        assert _workdir_signature(tmp_path) != before
        assert name + "/    metadata" in tool.fn({})
        child.rename(visible / "updated")
        assert name + "/    updated" in tool.fn({})
        (visible / "updated").unlink()
        visible.rmdir()
        assert name + "/" not in tool.fn({})


def test_repo_map_signature_walks_hidden_directories_only_to_rendered_depth(monkeypatch, tmp_path):
    from maverick.cache import file as file_cache
    from maverick.tools.repo_map import _IGNORE_DIRS

    assert file_cache._SIG_SKIP_DIRS == _IGNORE_DIRS
    deep = tmp_path / ".gradle" / "caches" / "8.5" / "fileHashes"
    deep.mkdir(parents=True)
    (deep / "hashes.bin").write_text("x")
    (tmp_path / "src" / ".next" / "cache").mkdir(parents=True)
    (tmp_path / "src" / "pkg").mkdir()
    (tmp_path / ".vscode" / "sub").mkdir(parents=True)
    visits = []
    real_walk = os.walk

    def counting_walk(top, *args, **kwargs):
        for item in real_walk(top, *args, **kwargs):
            visits.append(Path(item[0]).relative_to(tmp_path).as_posix())
            yield item

    monkeypatch.setattr(file_cache.os, "walk", counting_walk)
    before = file_cache._workdir_signature(tmp_path)
    assert sorted(visits) == [".", ".gradle", "src", "src/pkg"]
    (deep / "more.bin").write_text("build cache write")
    (deep.parent / "transforms").mkdir()
    assert file_cache._workdir_signature(tmp_path) == before
    (tmp_path / ".gradle" / "shown").write_text("rendered child")
    assert file_cache._workdir_signature(tmp_path) != before


def test_quorum_assigns_only_first_role_per_person():
    from maverick.tools.quorum_approval import quorum_approval

    result = quorum_approval().fn({"approvals": [
        {"approver": "A", "role": "x"}, {"approver": "a", "role": "y"}, {"approver": "B"},
    ], "required": 2, "require_distinct_roles": True})
    assert result.startswith("BLOCKED")


def test_intake_agent_rejects_document_outside_upload_workspace(monkeypatch, tmp_path):
    from maverick import agent, intake

    class StubAgent:
        def __init__(self, **kwargs):
            pass

    monkeypatch.setattr(agent, "Agent", StubAgent)
    root = tmp_path / "uploads"
    root.mkdir()
    outside = tmp_path / "private.txt"
    outside.write_text("private")
    ctx = SimpleNamespace(sandbox=SimpleNamespace(workdir=root), llm=None, knowledge=None)
    interviewer, session = intake.build_intake_agent(ctx)
    tool = next(tool for tool in interviewer.tools.all() if tool.name == "add_document")
    result = asyncio.run(tool.fn({"path": str(outside)}))
    assert result.startswith("ERROR") and not session.doc_paths
    inside = root / "uploaded.txt"
    inside.write_text("uploaded")
    assert "Attached" in asyncio.run(tool.fn({"path": "uploaded.txt"}))
    assert session.doc_paths == [str(inside)]
