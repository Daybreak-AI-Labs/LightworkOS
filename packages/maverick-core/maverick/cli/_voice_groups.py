"""Voice CLI group: set up and check the built-in local speech-to-text.

Registered by importing this module at the end
of the package __init__ so the @main.group decorators fire on package import.
"""
from __future__ import annotations

import os
from pathlib import Path

import click

from . import main

_GREEN = click.style("✓", fg="green")
_YELLOW = click.style("•", fg="yellow")
_RED = click.style("✗", fg="red")


@main.group("voice")
def voice_group() -> None:
    """Speech-to-text setup: local Whisper models, backend status."""


@voice_group.command("status")
def voice_status_cmd() -> None:
    """Show which STT backends this install can actually use."""
    import shutil as _shutil

    from ..tools.voice import _default_stt_backend, _find_whisper_cpp
    from ..voice_models import installed_models, models_dir, verify_model

    click.echo(click.style("Speech-to-text backends", bold=True))
    click.echo(f"  {_GREEN if os.environ.get('OPENAI_API_KEY') else _YELLOW} "
               "OpenAI Whisper API "
               f"({'key set' if os.environ.get('OPENAI_API_KEY') else 'no OPENAI_API_KEY'})")
    click.echo(f"  {_GREEN if os.environ.get('GROQ_API_KEY') else _YELLOW} "
               "Groq Whisper API "
               f"({'key set' if os.environ.get('GROQ_API_KEY') else 'no GROQ_API_KEY'})")
    try:
        import faster_whisper  # noqa: F401
        click.echo(f"  {_GREEN} faster-whisper (installed)")
    except ImportError:
        click.echo(f"  {_YELLOW} faster-whisper (not installed — "
                   "pip install -e './packages/maverick-core[voice]')")

    try:
        import pywhispercpp  # noqa: F401
        have_pywhisper = True
        click.echo(f"  {_GREEN} pywhispercpp engine (installed)")
    except ImportError:
        have_pywhisper = False
        click.echo(f"  {_YELLOW} pywhispercpp engine (not installed — "
                   "ships with maverick-dashboard)")

    binary = _find_whisper_cpp()
    if binary:
        click.echo(f"  {_GREEN} whisper.cpp binary: {binary}")
    else:
        click.echo(f"  {_YELLOW} whisper.cpp binary not found "
                   "(brew install whisper-cpp / apt install whisper.cpp, "
                   "or set MAVERICK_WHISPER_CPP)")
    models = installed_models()
    if models:
        for m in models:
            ok = verify_model(m)
            mark = _GREEN if ok else (_YELLOW if ok is None else _RED)
            note = ("" if ok else
                    "  (unpinned file — operator-supplied)" if ok is None else
                    "  (CHECKSUM MISMATCH — re-run `maverick voice setup --force`)")
            click.echo(f"  {mark} model: {m}{note}")
    else:
        click.echo(f"  {_YELLOW} no local Whisper model in {models_dir()} "
                   "(run `maverick voice setup`)")
    if not _shutil.which("ffmpeg"):
        click.echo(f"  {_YELLOW} ffmpeg not on PATH — local engines read only "
                   ".wav without it (the dashboard mic is unaffected: it "
                   "uploads 16 kHz WAV)")
    click.echo("")
    click.echo(f"  default backend: {_default_stt_backend()} "
               "(MAVERICK_VOICE_STT_BACKEND / [voice] stt_backend)")
    from ..voice_models import auto_fetch_enabled
    if not models and auto_fetch_enabled():
        click.echo("  model auto-fetch: on (first transcription or dashboard "
                   "startup fetches it; `maverick voice setup` prefetches)")
    local_ok = bool(models and (binary or have_pywhisper))
    have_any = (local_ok or os.environ.get("OPENAI_API_KEY")
                or os.environ.get("GROQ_API_KEY")
                or (have_pywhisper and auto_fetch_enabled()))
    try:
        import faster_whisper  # noqa: F401
        have_any = True
    except ImportError:
        pass
    if have_any:
        click.echo(click.style("  Speech-to-text is ready.", fg="green"))
    else:
        click.echo(click.style(
            "  No working STT backend — run `maverick voice setup`.", fg="red"))


@voice_group.command("setup")
@click.option("--model", "model_name", default=None,
              help="Model size (tiny/base/small/medium/large-v3[-turbo], "
                   "'.en' variants). Default: [voice] stt_model or 'base'.")
@click.option("--force", is_flag=True, help="Re-download even if present.")
def voice_setup_cmd(model_name: str | None, force: bool) -> None:
    """Fetch the local Whisper model (checksum-verified) for offline STT."""
    from ..voice_models import (
        KNOWN_MODELS,
        configured_model,
        download_model,
        model_path,
    )

    name = model_name or configured_model()
    try:
        dest = model_path(name)
    except ValueError as e:
        raise click.ClickException(str(e)) from e
    filename, _sha, size = KNOWN_MODELS[name]
    if dest.exists() and not force:
        click.echo(f"{_GREEN} {filename} already installed at {dest}")
    else:
        click.echo(f"Fetching {filename} ({size / 1e6:.0f} MB, "
                   "checksum-verified) ...")
        with click.progressbar(length=size, label=filename) as bar:
            last = 0

            def _tick(done: int, _total: int) -> None:
                nonlocal last
                bar.update(done - last)
                last = done

            try:
                dest = download_model(name, force=force, progress=_tick)
            except Exception as e:
                raise click.ClickException(
                    f"download failed: {e}. Air-gapped? Fetch "
                    f"https://huggingface.co/ggerganov/whisper.cpp/resolve/main/{filename} "
                    f"elsewhere and copy it to {dest}."
                ) from e
        click.echo(f"{_GREEN} installed {dest}")

    from ..tools.voice import _find_whisper_cpp
    if not _find_whisper_cpp():
        click.echo(click.style(
            "! whisper.cpp binary not found.", fg="yellow"
        ) + " Install it (brew install whisper-cpp, apt install whisper.cpp,"
            " or a release from github.com/ggml-org/whisper.cpp) or set"
            " MAVERICK_WHISPER_CPP to the binary.")
    else:
        click.echo(f"{_GREEN} whisper.cpp binary: {_find_whisper_cpp()}")
    click.echo("Check with:  maverick voice status")


@voice_group.command("transcribe")
@click.argument("audio_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--language", default=None, help="ISO 639-1 code (e.g. 'en').")
@click.option("--backend", default=None,
              type=click.Choice(["auto", "openai", "groq", "local"]),
              help="Force a backend (default: configured / auto).")
def voice_transcribe_cmd(audio_file: str, language: str | None,
                         backend: str | None) -> None:
    """Transcribe an audio file (smoke test for the STT pipeline)."""
    from ..tools.voice import _run_transcribe_internal

    args: dict = {"source": str(Path(audio_file).resolve())}
    if language:
        args["language"] = language
    if backend:
        args["backend"] = backend
    out = _run_transcribe_internal(args)
    from ..tool_results import tool_result_failed

    if tool_result_failed(out):
        message = out[len("ERROR:"):].strip() if out.startswith("ERROR:") else str(out)
        raise click.ClickException(message)
    click.echo(out)
