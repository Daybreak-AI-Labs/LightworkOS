"""voice transcribe/speak must confine model-supplied paths to the workspace:
transcribe reads the file and ships its bytes to a Whisper API (arbitrary read +
exfiltration), and speak writes audio (arbitrary write). The trusted internal
view_video caller passes sandbox=None and stays unconfined."""
from __future__ import annotations

from pathlib import Path

from maverick.tools.voice import _next_output_path, _run_speak, _run_transcribe


class _SB:
    def __init__(self, workdir):
        self.workdir = str(workdir)


def test_transcribe_rejects_traversal(tmp_path):
    out = _run_transcribe({"source": "../../etc/passwd"}, _SB(tmp_path))
    assert out.startswith("ERROR") and "escapes the workspace" in out


def test_transcribe_rejects_absolute_under_sandbox(tmp_path):
    out = _run_transcribe({"source": "/etc/passwd"}, _SB(tmp_path))
    assert out.startswith("ERROR") and "escapes the workspace" in out


def test_transcribe_in_workspace_path_passes_confinement(tmp_path):
    # An in-workspace relative path clears confinement (then is simply missing).
    out = _run_transcribe({"source": "nope.mp3"}, _SB(tmp_path))
    assert out.startswith("ERROR") and "not found" in out
    assert "escapes" not in out


def test_transcribe_without_sandbox_rejects_absolute_path(tmp_path):
    missing = tmp_path / "audio.wav"
    out = _run_transcribe({"source": str(missing)})  # sandbox defaults to None
    assert out.startswith("ERROR") and "requires a workspace" in out


def test_speak_rejects_traversal_output(tmp_path):
    out = _run_speak({"text": "hi", "output": "../evil.mp3"}, _SB(tmp_path))
    assert out.startswith("ERROR") and "escapes the workspace" in out


def test_speak_default_output_lands_in_workspace(tmp_path):
    assert _next_output_path(_SB(tmp_path)) == Path(tmp_path) / "speech-1.mp3"
