"""A selected-backend contract fake; never native-engine qualification."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from maverick.sandbox.docker import DockerBackend
from maverick.sandbox.local import ExecResult


def install_backend(monkeypatch, tmp_path, *, mode="success"):
    state = {"mode": mode, "calls": [], "stages": [], "requests": []}
    monkeypatch.setattr(DockerBackend, "_verify_docker", lambda self: None)

    def execute(self, command, timeout=None):
        stage = Path(self.workdir)
        state["calls"].append((command, timeout))
        state["stages"].append(stage)
        request = json.loads((stage / "request.json").read_text())
        state["requests"].append(request)
        assert not self.allow_network and not self.reuse_container
        source = (stage / request["input_name"]).read_bytes()
        assert hashlib.sha256(source).hexdigest() == request["input_sha256"]
        assert len(source) == request["input_bytes"]
        mode = state["mode"]
        if mode in {"timeout", "missing_engine"}:
            return ExecResult("", "TIMEOUT" if mode == "timeout" else "engine not installed in selected backend", 124 if mode == "timeout" else 127)
        if mode == "io_error":
            raise OSError("backend unavailable")
        blob = (b"%PDF-1.4 fixture" if request["output_type"] == "application/pdf" else b"OCR text 120000")
        output = {"name": request["output_name"], "bytes": len(blob),
                  "sha256": hashlib.sha256(blob).hexdigest(), "media_type": request["output_type"]}
        response = {"schema": request["schema"], "job_id": request["job_id"],
                    "input_sha256": request["input_sha256"], "engine": "fixture engine",
                    "engine_version": "test-only-1", "output": output}
        if mode == "bad_digest":
            response["output"]["sha256"] = "0" * 64
        elif mode == "stale_job":
            response["job_id"] = "0" * 32
        elif mode == "wrong_type":
            response["output"]["media_type"] = "image/png"
        elif mode == "changed_input":
            (stage / request["input_name"]).write_bytes(b"changed input")
        if mode != "missing_output":
            (stage / request["output_name"]).write_bytes(blob)
        (stage / "result.json").write_text(json.dumps(response), encoding="utf-8")
        if callable(state.get("during_job")):
            state["during_job"]()
        return ExecResult("", "engine nonzero" if mode == "nonzero" else "", 1 if mode == "nonzero" else 0)

    monkeypatch.setattr(DockerBackend, "exec", execute)
    backend = DockerBackend(workdir=tmp_path, allow_network=True, reuse_container=True)
    return backend, state
