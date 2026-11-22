"""Offline native document work in a separate, private sandbox workspace."""
from __future__ import annotations

import hashlib
import importlib
import io
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, replace
from importlib import resources
from pathlib import Path

from ..config import get_document_tools
from ..file_lock import cross_process_lock, ensure_private_directory
from ..paths import data_dir
from ..sandbox.docker import DockerBackend
from ..sandbox.image_pull import local_image_missing
from ..sandbox.kubernetes import KubernetesBackend
from ..sandbox.local import LocalBackend
from ..sandbox.podman import PodmanBackend
from ..sandbox.workspace_transfer import _read, _relative, _write

log = logging.getLogger(__name__)

_JOB_SCHEMA = "lightwork.document-job.v1"
_MAX_OUTPUT_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class DocumentJob:
    job_id: str
    operation: str
    timeout: float
    input_name: str
    output_name: str
    output_type: str

    @classmethod
    def create(cls, request: dict) -> DocumentJob:
        operation = request["operation"]
        suffix = request.get("input_suffix", "")
        if suffix and not re.fullmatch(r"[a-z0-9]{1,10}", suffix):
            raise ValueError("Invalid document input type")
        if operation in {"ocr", "image_ocr"}:
            source, output, kind = ("input.pdf" if operation == "ocr" else f"input.{suffix}"), "ocr.txt", "text/plain"
        elif operation == "recalculate":
            source, output, kind = "input.xlsx", "calculated.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        elif operation == "latex":
            source, output, kind = "input.tex", "rendered.pdf", "application/pdf"
        elif operation == "convert":
            target = request.get("target", "").split(":", 1)[0].lower()
            if target not in {"pdf", "txt", "html", "csv", "docx", "odt", "xlsx", "png"}:
                raise ValueError("Unsupported document output type")
            source, output = f"input.{suffix}", f"converted.{target}"
            kind = {"pdf": "application/pdf", "png": "image/png", "txt": "text/plain",
                    "csv": "text/csv", "html": "text/html"}.get(target, "application/zip")
        else:
            raise ValueError("Unsupported document job operation")
        return cls(uuid.uuid4().hex, operation, float(get_document_tools()["timeout"]), source, output, kind)

    def manifest(self) -> dict:
        return {"schema": _JOB_SCHEMA, "job_id": self.job_id, "timeout": self.timeout,
                "input_name": self.input_name, "output_name": self.output_name,
                "output_type": self.output_type, "max_output_bytes": _MAX_OUTPUT_BYTES}


def verify_release_document_runtime() -> None:
    """Check real parser imports and worker source in wheel/frozen artifacts.

    This does not start an engine or claim a configured Docker/Kubernetes host.
    """
    for name, attribute in (("openpyxl", "load_workbook"), ("lxml.etree", "fromstring"),
                            ("pypdf", "PdfReader"), ("pdfplumber", "open")):
        if not callable(getattr(importlib.import_module(name), attribute, None)):
            raise RuntimeError(f"Document parser {name}.{attribute} is unavailable")
    source = resources.files("maverick.sandbox").joinpath("document_engine.py").read_bytes()
    if not source:
        raise RuntimeError("Document worker source is missing from this release")
    compile(source, "document_engine.py", "exec")


NO_LOCAL_ISOLATION = (
    "Office conversion is off on this computer, because a document could make it fetch web addresses. "
    "Choose the Docker, Podman or Kubernetes sandbox backend to convert documents; "
    "see docs/document-processing.md.")
NO_LOCAL_UNO = (
    "Office conversion is off on this computer, because LibreOffice's Python bridge is not available to "
    "this Python. Install LibreOffice with its Python bridge (python3-uno), or choose the Docker, Podman "
    "or Kubernetes sandbox backend; see docs/document-processing.md.")
NO_CONTAINER = ("Native document processing needs a Docker, Podman or Kubernetes sandbox; "
                "see docs/document-processing.md")
_FAILURE_RETRY_SECONDS = 300.0
_LOCAL_LAUNCH: dict[str, tuple[float, tuple[str, ...] | None, str | None]] = {}


def _uno_pythons() -> list[str]:
    """Interpreters that may run the self-contained worker, in order of preference."""
    candidates = [sys.executable]
    soffice = shutil.which("soffice")
    if soffice:
        # Bundled LibreOffice builds (Windows, macOS, AppImage) ship their own Python.
        program = Path(soffice).resolve().parent
        candidates += [str(program / name) for name in ("python", "python3", "python.exe")]
    candidates.append(shutil.which("python3") or "")
    found: list[str] = []
    for candidate in candidates:
        if candidate and candidate not in found and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            found.append(candidate)
    return found


def _probe_local_convert() -> tuple[tuple[str, ...] | None, str | None, bool]:
    """(launch, reason, settled): ``settled`` is False when a probe timed out or broke."""
    unshare = shutil.which("unshare") if sys.platform.startswith("linux") else None
    if unshare is None:
        return None, NO_LOCAL_ISOLATION, True
    with tempfile.TemporaryDirectory(prefix="netns-probe-") as directory:
        backend = LocalBackend(workdir=Path(directory), timeout=10)
        namespace = backend.exec([unshare, "-rn", "true"]).exit_code
        if namespace:
            return None, NO_LOCAL_ISOLATION, namespace != 124
        timed_out = False
        for python in _uno_pythons():
            code = backend.exec([unshare, "-rn", python, "-I", "-c", "import uno"]).exit_code
            if code == 0:
                return (unshare, "-rn", python, "-I"), None, True
            timed_out = timed_out or code == 124
    return None, NO_LOCAL_UNO, not timed_out


def local_convert_launch() -> tuple[tuple[str, ...] | None, str | None]:
    """The argv prefix that runs the document worker with no network, or (None, reason).

    LibreOffice fetches a document's linked images, stylesheets and objects,
    and no profile setting stops every kind. ``unshare -rn`` starts the worker
    in a new user and network namespace whose only interface is a down
    loopback. The worker is a standalone stdlib script, so any interpreter
    that can import LibreOffice's ``uno`` bridge inside that namespace may run
    it, isolated (``-I``). Success is kept for the process; a failure is
    retried after a few minutes, and a timed-out probe is not remembered.
    """
    now = time.monotonic()
    cached = _LOCAL_LAUNCH.get("convert")
    if cached is not None and (cached[1] is not None or now < cached[0]):
        return cached[1], cached[2]
    try:
        launch, reason, settled = _probe_local_convert()
    except Exception:  # failure-policy: fail_closed -- no proof of isolation means no local conversion
        log.warning("document worker: local conversion probe failed", exc_info=True)
        return None, NO_LOCAL_ISOLATION
    if settled:
        _LOCAL_LAUNCH["convert"] = (now + _FAILURE_RETRY_SECONDS, launch, reason)
    return launch, reason


def conversion_unavailable(sandbox) -> str | None:
    """Why office conversion cannot run with ``sandbox``, or None when it can."""
    if sandbox is None or isinstance(sandbox, LocalBackend):
        return local_convert_launch()[1]
    if isinstance(sandbox, (DockerBackend, PodmanBackend)):
        image = get_document_tools()["engine_image"]
        engine = "podman" if isinstance(sandbox, PodmanBackend) else "docker"
        if local_image_missing(engine, image):
            # Offered anyway, every conversion failed and the agent fell back
            # to a shell command that waited for approval.
            return (f"Office conversion needs the document engine image {image}, which is not "
                    f"built on this computer. An administrator can build it with: docker build "
                    f"-f deploy/docker/Dockerfile.documents -t {image} . "
                    "(see docs/document-processing.md).")
        return None
    if isinstance(sandbox, KubernetesBackend):
        return None
    return NO_CONTAINER


@contextmanager
def _worker(sandbox, request, *, allow_local=False):
    cfg = get_document_tools()
    local = allow_local and (sandbox is None or isinstance(sandbox, LocalBackend))
    if local and request.get("operation") == "convert" and (reason := local_convert_launch()[1]):
        raise RuntimeError(reason)
    if not local and not isinstance(sandbox, (DockerBackend, PodmanBackend, KubernetesBackend)):
        raise RuntimeError(NO_CONTAINER)
    parent = ensure_private_directory(data_dir("document-processing"))
    with tempfile.TemporaryDirectory(prefix="job-", dir=parent) as directory:
        stage = Path(directory)
        if stage.resolve().parent != parent.resolve():
            raise RuntimeError("Document staging directory is outside private storage")
        if local:
            # Preserve an explicitly selected legacy local tool path. The PDF
            # OCR/recalculation entry points never pass allow_local=True.
            worker = LocalBackend(workdir=stage, timeout=cfg["timeout"])
        else:
            changes = {"workdir": stage, "allow_network": False, "image": cfg["engine_image"], "timeout": cfg["timeout"]}
            if isinstance(sandbox, DockerBackend):
                changes.update(reuse_container=False, read_only_paths=())
            worker = replace(sandbox, **changes)
        job = DocumentJob.create(request)
        (stage / "engine.py").write_bytes(resources.files("maverick.sandbox").joinpath("document_engine.py").read_bytes())
        (stage / "request.json").write_text(json.dumps({**request, **job.manifest()}), encoding="utf-8")
        from ..sandbox.workspace_guard import _document_stage_scope

        with _document_stage_scope(stage):
            yield stage, worker


def _execute(stage, worker):
    request = json.loads(_read(stage, "request.json"))
    source = _read(stage, request["input_name"])
    request["input_sha256"] = hashlib.sha256(source).hexdigest()
    request["input_bytes"] = len(source)
    if (stage / "result.json").exists() or (stage / request["output_name"]).exists():
        raise RuntimeError("Document job has stale output; start a fresh job")
    (stage / "request.json").write_text(json.dumps(request), encoding="utf-8")
    if isinstance(worker, LocalBackend):
        argv = [sys.executable, "engine.py"]
        if request["operation"] == "convert":
            launch, reason = local_convert_launch()
            if launch is None:
                raise RuntimeError(reason)
            argv = [*launch, "engine.py"]
        command = subprocess.list2cmdline(argv) if os.name == "nt" else shlex.join(argv)
    else:
        command = "/usr/bin/python3 engine.py"
    result = worker.exec(command, timeout=request["timeout"])
    try:
        raw = _read(stage, "result.json")
    except FileNotFoundError as exc:
        raise RuntimeError("Document engine produced no result; build/configure its image and check the sandbox. "
                           + result.stderr[-400:]) from exc
    if len(raw) > 4 * 1024 * 1024:
        raise RuntimeError("Document engine result exceeds its output limit")
    response = json.loads(raw)
    if not isinstance(response, dict):
        raise RuntimeError("Document engine result is malformed")
    if result.exit_code or response.get("error"):
        raise RuntimeError(str(response.get("error") or "Document engine failed; original retained"))
    if hashlib.sha256(_read(stage, request["input_name"])).hexdigest() != request["input_sha256"]:
        raise RuntimeError("Document engine changed its immutable input")
    if (response.get("schema") != _JOB_SCHEMA or response.get("job_id") != request["job_id"]
            or response.get("input_sha256") != request["input_sha256"]
            or not isinstance(response.get("engine"), str) or not response["engine"]
            or not isinstance(response.get("engine_version"), str) or not response["engine_version"]):
        raise RuntimeError("Document engine returned a stale or unbound manifest")
    output = response.get("output")
    if (not isinstance(output, dict) or output.get("name") != request["output_name"]
            or output.get("media_type") != request["output_type"]):
        raise RuntimeError("Document engine output manifest is invalid")
    blob = _read(stage, request["output_name"])
    if (len(blob) > _MAX_OUTPUT_BYTES or output.get("bytes") != len(blob)
            or output.get("sha256") != hashlib.sha256(blob).hexdigest()):
        raise RuntimeError("Document output size or digest does not match its manifest")
    if request["output_type"] == "application/pdf" and not blob.startswith(b"%PDF-"):
        raise RuntimeError("Document engine did not return a PDF")
    if request["output_type"] == "image/png" and not blob.startswith(b"\x89PNG\r\n\x1a\n"):
        raise RuntimeError("Document engine did not return a PNG")
    if (request["output_type"] in {"application/zip", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}
            and not blob.startswith(b"PK\x03\x04")):
        raise RuntimeError("Document engine did not return an Office package")
    if request["output_type"].startswith("text/"):
        response["text"] = blob.decode("utf-8", errors="strict")
    return response


def workspace_path(sandbox, path: str) -> tuple[Path, str]:
    if not path or path.startswith("-"):
        raise ValueError("path must be nonempty and may not begin with '-'")
    root = Path(sandbox.workdir if sandbox is not None else Path.cwd()).resolve()
    target = (root / path).resolve()
    try:
        relative = target.relative_to(root).as_posix()
    except ValueError as exc:
        raise ValueError("path escapes the sandbox workdir") from exc
    return root, _relative(relative)


def _existing_output(root: Path, relative: str) -> bytes | None:
    try:
        return _read(root, relative)
    except FileNotFoundError:
        return None


def run_document_job(request: dict, data: bytes, sandbox, *, destination: str | None = None) -> str:
    """Stage one immutable input, run the selected backend, verify then publish."""
    if len(data) > _MAX_OUTPUT_BYTES:
        raise ValueError("Document input exceeds the 64 MiB limit")
    target = workspace_path(sandbox, destination) if destination is not None else None
    baseline = _existing_output(*target) if target is not None else None
    with _worker(sandbox, request, allow_local=True) as (stage, worker):
        job = json.loads(_read(stage, "request.json"))
        (stage / job["input_name"]).write_bytes(data)
        response = _execute(stage, worker)
        if target is None:
            return response.get("text", "") or "(empty OCR result)"
        output = _read(stage, job["output_name"])
        root, relative = target
        with cross_process_lock(root / relative, strict=True):
            if _existing_output(root, relative) != baseline:
                raise RuntimeError("Document destination changed during processing; newer file retained")
            _write(root, relative, output, 0o600)
        return (f"wrote {root / relative} ({len(output)} bytes; SHA-256 "
                f"{response['output']['sha256']}; {response['engine']} {response['engine_version']})")


def ocr_pdf(data: bytes, pages: str, sandbox) -> str:
    cfg = get_document_tools()
    if not cfg["pdf_ocr"]:
        raise RuntimeError("Scanned PDF OCR is disabled; enable documents.pdf_ocr and configure the document engine image")
    if len(data) > 64 * 1024 * 1024:
        raise ValueError("OCR input exceeds the 64 MiB limit; split the PDF")
    request = {"operation": "ocr", "pages": pages, "language": cfg["ocr_language"], "max_pages": cfg["ocr_max_pages"]}
    with _worker(sandbox, request) as (stage, worker):
        (stage / "input.pdf").write_bytes(data)
        response = _execute(stage, worker)
        if not isinstance(response.get("text"), str) or not response["text"].strip():
            raise RuntimeError("OCR returned no readable text")
        return response["text"]


def recalculate(path: Path, sandbox) -> str:
    from .office_package import WorkbookPackage
    from .spreadsheet import _atomic_destination, _openpyxl, _xlsx_snapshot

    if not get_document_tools()["native_recalculation"]:
        raise RuntimeError("Native recalculation is disabled; enable documents.native_recalculation and configure the document engine image")
    original_bytes = _xlsx_snapshot(path)
    package = WorkbookPackage(original_bytes)
    package.check_recalculable()
    formulas = package.formulas()
    if not any(formulas.values()):
        return "No formulas to recalculate"
    original = hashlib.sha256(original_bytes).digest()
    with _worker(sandbox, {"operation": "recalculate", "formulas": formulas}) as (stage, worker):
        # The engine receives an ordinary XLSX copy without VBA; the original
        # ZIP and all VBA/formatting parts stay in the trusted harness.
        workbook = _openpyxl().load_workbook(io.BytesIO(original_bytes), keep_vba=False, keep_links=False)
        try:
            workbook.save(stage / "input.xlsx")
        finally:
            workbook.close()
        _execute(stage, worker)
        count = package.import_caches(WorkbookPackage(_read(stage, "calculated.xlsx")))
        if hashlib.sha256(_xlsx_snapshot(path)).digest() != original:
            raise RuntimeError("Workbook changed during recalculation; newer file retained")
        with _atomic_destination(path) as temporary:
            package.write(temporary)
    return f"Recalculated {count} formula cell(s) with LibreOffice Calc; original formulas, formatting and VBA preserved"
