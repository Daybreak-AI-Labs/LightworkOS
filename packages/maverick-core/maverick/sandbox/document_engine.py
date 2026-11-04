"""Standalone helper copied into an isolated, offline document worker.

Requires Debian's python3-uno, libreoffice-calc, poppler-utils and tesseract-ocr.
Never import this helper to start a process in the credential-bearing harness.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

_JOB_SCHEMA = "lightwork.document-job.v1"
_deadline: float | None = None
_MAX_COMMAND_OUTPUT = 2 * 1024 * 1024


def _run(argv, timeout=30):
    if _deadline is not None:
        timeout = min(timeout, max(0.001, _deadline - time.monotonic()))
    exceeded = threading.Event()
    output = bytearray()
    errors = []
    # Bound both pipes while they are produced, before collecting OCR text.
    with subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          stdin=subprocess.DEVNULL) as process:
        def drain(stream, *, keep):
            count = 0
            try:
                while chunk := stream.read(65536):
                    count += len(chunk)
                    if count > _MAX_COMMAND_OUTPUT:
                        exceeded.set()
                        process.kill()
                        return
                    if keep:
                        output.extend(chunk)
            except (OSError, ValueError) as exc:
                errors.append(exc)
                process.kill()

        readers = [threading.Thread(target=drain, args=(stream,), kwargs={"keep": keep}, daemon=True)
                   for stream, keep in ((process.stdout, True), (process.stderr, False))]
        for reader in readers:
            reader.start()
        try:
            process.wait(timeout=timeout)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            for reader in readers:
                reader.join(timeout=5)
        if any(reader.is_alive() for reader in readers):
            raise RuntimeError("Document engine command pipes did not close")
        if exceeded.is_set() or errors:
            raise ValueError("Document engine command output exceeds its boundary or cannot be read")
        if process.returncode:
            raise RuntimeError(f"{Path(argv[0]).name} failed with exit code {process.returncode}")
        return bytes(output).decode("utf-8", errors="strict")


def _pages(spec, total, limit):
    if not spec:
        if total > limit:
            raise ValueError(f"OCR is limited to {limit} pages per call; select a page range")
        return list(range(1, total + 1))
    selected = set()
    for part in spec.split(","):
        match = re.fullmatch(r"\s*([1-9][0-9]*)(?:-([1-9][0-9]*)?)?\s*", part)
        if match is None:
            raise ValueError("Invalid OCR page range")
        start = int(match[1])
        end = int(match[2]) if match[2] else (total if "-" in part else start)
        end = min(total, end)
        if end - start + 1 > limit:
            raise ValueError(f"OCR is limited to {limit} pages per call")
        selected.update(range(start, end + 1))
        if len(selected) > limit:
            raise ValueError(f"OCR is limited to {limit} pages per call")
    if not selected:
        raise ValueError("No PDF pages match the selection")
    return sorted(selected)


def ocr(request):
    info = _run(["pdfinfo", "input.pdf"])
    match = re.search(r"^Pages:\s+([0-9]+)\s*$", info, re.MULTILINE)
    if match is None:
        raise ValueError("PDF page count is unavailable")
    total = int(match[1])
    language = request["language"]
    if not re.fullmatch(r"[A-Za-z0-9_]+(?:\+[A-Za-z0-9_]+)*", language):
        raise ValueError("Invalid OCR language selection")
    chunks = []
    for page in _pages(request["pages"], total, request["max_pages"]):
        _run(["pdftoppm", "-f", str(page), "-l", str(page), "-singlefile",
              "-scale-to", "2200", "-png", "input.pdf", "page"])
        try:
            text = _run(["tesseract", "page.png", "stdout", "-l", language]).strip()
        finally:
            Path("page.png").unlink(missing_ok=True)
        chunks.append(f"=== Page {page} of {total} [OCR] ===\n{text}")
        if sum(map(len, chunks)) > 1_000_000:
            raise ValueError("OCR text exceeds the one-million character limit")
    if not any(chunk.split("===\n", 1)[-1].strip() for chunk in chunks):
        raise ValueError("OCR found no readable text in the selected pages")
    return {"text": "\n\n".join(chunks), "engine": "Tesseract", "pages": len(chunks)}


def _property(uno, name, value):
    prop = uno.createUnoStruct("com.sun.star.beans.PropertyValue")
    prop.Name, prop.Value = name, value
    return prop


def _connect(uno, pipe):
    context = uno.getComponentContext()
    resolver = context.ServiceManager.createInstanceWithContext("com.sun.star.bridge.UnoUrlResolver", context)
    deadline = min(time.monotonic() + 30, _deadline or float("inf"))
    while time.monotonic() < deadline:
        try:
            return resolver.resolve(f"uno:pipe,name={pipe};urp;StarOffice.ComponentContext")
        except Exception:
            time.sleep(.1)
    raise RuntimeError("LibreOffice did not start within 30 seconds")


@contextmanager
def _office_document(source, *, readonly=False):
    import uno

    pipe = "lightwork_" + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix="lightwork-office-") as profile:
        args = ["soffice", "--headless", "--norestore", "--nodefault", "--nofirststartwizard",
                "-env:UserInstallation=" + Path(profile).as_uri(),
                f"--accept=pipe,name={pipe};urp;StarOffice.ComponentContext"]
        process = subprocess.Popen(args, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        document = None
        try:
            context = _connect(uno, pipe)
            desktop = context.ServiceManager.createInstanceWithContext("com.sun.star.frame.Desktop", context)
            properties = tuple(_property(uno, name, value) for name, value in [
                ("Hidden", True), ("ReadOnly", readonly),
                # SDK constants: MacroExecMode.NEVER_EXECUTE = 0;
                # UpdateDocMode.NO_UPDATE = 0. Never execute workbook macros.
                ("MacroExecutionMode", 0), ("UpdateDocMode", 0),
            ])
            document = desktop.loadComponentFromURL(Path(source).resolve().as_uri(), "_blank", 0, properties)
            if document is None:
                raise ValueError("LibreOffice could not open the document")
            yield document, uno
        finally:
            try:
                if document is not None:
                    document.close(True)
            finally:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def recalculate(request):
    with _office_document("input.xlsx") as (document, uno):
        if not hasattr(document, "calculateAll"):
            raise ValueError("LibreOffice could not open the spreadsheet")
        document.calculateAll()
        errors = []
        for name, cells in request["formulas"].items():
            sheet = document.getSheets().getByName(name)
            for address in cells:
                cell = sheet.getCellRangeByName(address)
                if cell.getError():
                    errors.append(f"{name}!{address}: {cell.getString()} (error {cell.getError()})")
                    if len(errors) >= 20:
                        break
        if errors:
            raise ValueError("Formula calculation errors; original retained: " + "; ".join(errors))
        document.storeAsURL(Path("calculated.xlsx").resolve().as_uri(), (
            _property(uno, "FilterName", "Calc MS Excel 2007 XML"), _property(uno, "Overwrite", True),
        ))
        return {"engine": "LibreOffice Calc", "formula_count": sum(map(len, request["formulas"].values()))}


def convert(request):
    target, _, explicit_filter = request["target"].partition(":")
    target = target.lower()
    with _office_document(request["input_name"], readonly=True) as (document, uno):
        calc = document.supportsService("com.sun.star.sheet.SpreadsheetDocument")
        impress = document.supportsService("com.sun.star.presentation.PresentationDocument")
        filters = {
            "pdf": "calc_pdf_Export" if calc else ("impress_pdf_Export" if impress else "writer_pdf_Export"),
            "txt": "Text - txt - csv (StarCalc)" if calc else "Text (encoded)",
            "csv": "Text - txt - csv (StarCalc)", "html": "HTML (StarCalc)" if calc else "HTML (StarWriter)",
            "docx": "Office Open XML Text", "xlsx": "Calc MS Excel 2007 XML",
            "odt": "writer8", "png": "draw_png_Export",
        }
        if target not in filters:
            raise ValueError("Unsupported document conversion type")
        document.storeToURL(Path(request["output_name"]).resolve().as_uri(), (
            _property(uno, "FilterName", explicit_filter or filters[target]),
            _property(uno, "Overwrite", False),
        ))
    return {"engine": "LibreOffice"}


def image_ocr(request):
    language = request["language"]
    if not re.fullmatch(r"[A-Za-z0-9_]+(?:\+[A-Za-z0-9_]+)*", language):
        raise ValueError("Invalid OCR language selection")
    text = _run(["tesseract", request["input_name"], "stdout", "-l", language, "--psm", "3"], timeout=120)
    if len(text) > 1_000_000:
        raise ValueError("OCR text exceeds its output boundary")
    return {"engine": "Tesseract", "text": text.strip()}


# A plain workspace image is the one file a document may name.
_TEX_IMAGE = re.compile(r"\\includegraphics\s*(?:\[[^\]\n]{0,200}\])?\s*\{([A-Za-z0-9_][A-Za-z0-9_./-]{0,200})\}")
# TeX can rename or synthesise any command (\csname, catcodes, ^^ escapes,
# @-internals), so a list of forbidden names is never complete. Refuse the
# renaming machinery itself, and any command whose name reaches files or
# processes.
_TEX_OUTSIDE = re.compile(
    r"\^\^|\\(?:csname|catcode|scantokens|endlinechar|makeatletter|string)\b"
    r"|\\[A-Za-z]*@"
    r"|\\[A-Za-z]*(?:input|include|read|open|write|file|immediate|shellesc|pipe|special)"
    r"|\\usepackage\s*(?:\[[^\]]*\])?\s*\{[^}]*shellesc", re.IGNORECASE)


def _tex_reaches_outside(source: str) -> bool:
    def image(match):
        path = match.group(1)
        return "" if ".." not in path.split("/") else match.group(0)
    return bool(_TEX_OUTSIDE.search(_TEX_IMAGE.sub(image, source)))


def latex(request):
    engine = request["engine"]
    if engine not in {"tectonic", "pdflatex"}:
        raise ValueError("Unsupported TeX engine")
    source = Path(request["input_name"]).read_text(encoding="utf-8")
    if _tex_reaches_outside(source):
        raise ValueError("TeX external file/process directives require a separately reviewed artifact job")
    # Engine-level restrictions supplement the isolated workspace/network policy.
    os.environ.update(openin_any="p", openout_any="p", shell_escape="f")
    if engine == "tectonic":
        argv = [engine, "--untrusted", "--only-cached", "--outdir", ".", request["input_name"]]
    else:
        argv = [engine, "-no-shell-escape", "-halt-on-error", "-interaction=nonstopmode",
                "-output-directory", ".", request["input_name"]]
    _run(argv, timeout=request["timeout"])
    Path("input.pdf").replace(request["output_name"])
    return {"engine": engine}


def _validate_job(request):
    if (request.get("schema") != _JOB_SCHEMA or not re.fullmatch(r"[a-f0-9]{32}", request.get("job_id", ""))
            or not 0 < float(request.get("timeout", 0)) <= 1800):
        raise ValueError("Document job contract is invalid")
    for field in ("input_name", "output_name"):
        if not re.fullmatch(r"[a-z]+\.[a-z0-9]{1,10}", request.get(field, "")):
            raise ValueError("Document job artifact path is invalid")
    source = Path(request["input_name"])
    if source.is_symlink() or not stat.S_ISREG(source.stat().st_mode) or source.stat().st_size > 64 * 1024 * 1024:
        raise ValueError("Document job input exceeds its boundary")
    data = source.read_bytes()
    if len(data) != request.get("input_bytes") or hashlib.sha256(data).hexdigest() != request.get("input_sha256"):
        raise ValueError("Document job input changed before processing")
    if Path(request["output_name"]).exists():
        raise ValueError("Document job output already exists")


def _capabilities(request):
    operation = request["operation"]
    names = {"ocr": ["pdfinfo", "pdftoppm", "tesseract"], "image_ocr": ["tesseract"],
             "convert": ["soffice"], "recalculate": ["soffice"],
             "latex": [request.get("engine", "tectonic")]}.get(operation)
    if names is None:
        raise ValueError("Unsupported document operation")
    for name in names:
        if not shutil.which(name):
            raise RuntimeError(f"{name} is not installed in the selected document backend")
    version = _run([names[-1], "--version"]).strip().splitlines()
    return version[0][:200] if version else "version unavailable"


def main():
    global _deadline
    request = {}
    try:
        with Path("request.json").open("rb") as stream:
            raw = stream.read(8 * 1024 * 1024 + 1)
        if len(raw) > 8 * 1024 * 1024:
            raise ValueError("Document job request exceeds its boundary")
        request = json.loads(raw)
        _validate_job(request)
        _deadline = time.monotonic() + float(request["timeout"])
        version = _capabilities(request)
        operation = {"ocr": ocr, "image_ocr": image_ocr, "recalculate": recalculate,
                     "convert": convert, "latex": latex}[request["operation"]]
        result = operation(request)
        if "text" in result:
            Path(request["output_name"]).write_text(result.pop("text"), encoding="utf-8")
        output = Path(request["output_name"])
        if (output.is_symlink() or not stat.S_ISREG(output.stat().st_mode)
                or output.stat().st_size > request["max_output_bytes"]):
            raise ValueError("Document output exceeds its artifact boundary")
        blob = output.read_bytes()
        result.update(schema=_JOB_SCHEMA, job_id=request["job_id"], input_sha256=request["input_sha256"],
                      engine_version=version, output={"name": output.name, "bytes": len(blob),
                      "sha256": hashlib.sha256(blob).hexdigest(), "media_type": request["output_type"]})
    except Exception as exc:
        Path("result.json").write_text(json.dumps({"error": str(exc)[:4000]}), encoding="utf-8")
        return 2
    Path("result.json").write_text(json.dumps(result), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
