"""Download a missing container image before a command's time limit starts.

``docker run`` / ``podman run`` pull a missing image themselves, but inside the
command's own limit (60 s by default), so on a fresh computer the first command
timed out while the image was still downloading. The image is now checked once
per backend and, when missing, pulled under its own limit first. Nothing new is
reached: ``run`` would have pulled the same image from the same registry.
"""
from __future__ import annotations

import subprocess
import threading

from .local import scrub_env

PULL_SECONDS = 600.0
_CHECK_SECONDS = 15.0
# (engine, image) pairs already found or downloaded in this process, so each
# image is checked once rather than before every command.
_READY: set[tuple[str, str]] = set()
_READY_LOCK = threading.Lock()


def missing_image_note(engine: str, image: str, pull_policy: str | None) -> str | None:
    """None when the image is ready (or ``run`` should decide); otherwise a plain
    sentence saying the image could not be downloaded and nothing ran."""
    if str(pull_policy or "").lower() == "never":
        return None  # ``run --pull never`` refuses a missing image itself
    with _READY_LOCK:
        if (engine, image) in _READY:
            return None
    check = [engine, "image", "exists", image] if engine == "podman" else [engine, "image", "inspect", image]
    try:
        if subprocess.run(check, capture_output=True, timeout=_CHECK_SECONDS, check=False).returncode == 0:
            _remember(engine, image)
            return None
    except (OSError, subprocess.TimeoutExpired):
        return None  # leave the decision to ``run``, as before
    try:
        pulled = subprocess.run([engine, "pull", image], capture_output=True, text=True,
                                timeout=PULL_SECONDS, check=False, env=scrub_env())
    except subprocess.TimeoutExpired:
        return (f"Downloading the {image} environment took longer than {int(PULL_SECONDS)} seconds, "
                "so the command did not run. Try again.")
    except OSError:
        return None
    if pulled.returncode != 0:
        lines = (pulled.stderr or pulled.stdout or "").strip().splitlines()
        reason = lines[-1].strip()[:300] if lines else f"{engine} pull failed"
        return f"The {image} environment could not be downloaded, so the command did not run: {reason}"
    _remember(engine, image)
    return None


def _remember(engine: str, image: str) -> None:
    with _READY_LOCK:
        _READY.add((engine, image))
