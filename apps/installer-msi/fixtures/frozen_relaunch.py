"""Synthetic onefile lifetime fixture; no installer or application imports."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path


def private_environment():
    return {key: value for key, value in os.environ.items()
            if key.startswith("_PYI_") or key == "PYINSTALLER_RESET_ENVIRONMENT"}


def mediator(mode, output, executable, extraction, python, source):
    output, extraction = Path(output), Path(extraction)
    record = {
        "mediator_frozen": bool(getattr(sys, "frozen", False)),
        "inherited_environment": private_environment(),
        "original_extraction": str(extraction),
    }
    deadline = time.monotonic() + 30
    while extraction.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    record["original_extraction_deleted"] = not extraction.exists()
    if extraction.exists():
        record["error"] = "Original extraction did not disappear; relaunch refused."
    else:
        # The independent process inherits unchanged. The production repair is
        # applied by the frozen parent before launching this nonfrozen mediator.
        try:
            result = subprocess.run(
                [executable, "child", mode, str(output), python, source],
                env=os.environ.copy(), stdin=subprocess.DEVNULL,
                capture_output=True, timeout=20,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            record.update(returncode=result.returncode,
                          stdout=result.stdout.decode("utf-8", errors="replace")[-4096:],
                          stderr=result.stderr.decode("utf-8", errors="replace")[-4096:])
        except subprocess.TimeoutExpired:
            record["error"] = "Relaunch timed out."
    pending = output / "result.pending"
    pending.write_text(json.dumps(record), encoding="utf-8")
    pending.replace(output / "result.json")


def main():
    phase = sys.argv[1]
    if phase == "mediator":
        mediator(*sys.argv[2:])
        return
    mode, destination, python, source = sys.argv[2:]
    output = Path(destination)
    extraction = Path(sys._MEIPASS)
    record = {
        "frozen": bool(getattr(sys, "frozen", False)),
        "extraction": str(extraction),
        "extraction_exists": extraction.is_dir(),
        "payload": (extraction / "proof.txt").read_text(encoding="utf-8"),
    }
    if phase == "child":
        (output / "child.json").write_text(json.dumps(record), encoding="utf-8")
        print("RELAUNCH_OK", flush=True)
        return
    if phase != "launch" or mode not in {"legacy", "reset"}:
        raise ValueError("Invalid synthetic fixture mode")
    before = os.environ.copy()
    environment = os.environ.copy()
    if mode == "reset":
        environment["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    record["initial_environment"] = private_environment()
    with (output / "mediator.stdout").open("wb") as stdout, (output / "mediator.stderr").open("wb") as stderr:
        subprocess.Popen(
            [python, source, "mediator", mode, str(output), sys.executable,
             str(extraction), python, source],
            stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
            close_fds=True, env=environment, creationflags=subprocess.CREATE_NO_WINDOW,
        )
    record["parent_environment_unchanged"] = os.environ == before
    (output / "initial.json").write_text(json.dumps(record), encoding="utf-8")
    # Deliberately do not wait: bootloader cleanup must complete before the
    # independent process tries the retained executable again.
    print("ORIGINAL_HELPER_EXITING", flush=True)


if __name__ == "__main__":
    main()
