"""Memory-safe parsing of untrusted bytes.

The parsers that touch **attacker-controllable bytes** — PDFs from
attachments, images from channels, HTML from fetched pages — are largely
C-extension-backed (pdfplumber/pdfminer, pypdf, Pillow, lxml). A memory-safety
bug there is an in-process RCE/corruption foothold fed directly by untrusted
input. Rewriting those parsers isn't realistic; **isolating** them is:

* :data:`PARSERS` — the inventory: each untrusted-input parser path, what
  feeds it, and whether its implementation is memory-safe (pure Python) or
  C-extension (isolate-worthy). The policy, in code.
* :func:`parse_isolated` — run a whitelisted parser entry point in a child
  Python process with the **secret-scrubbed env** (same posture as plugin
  isolation): a separate address space, so a heap bug or segfault on hostile
  bytes kills the child — never the kernel — and an exploited parser child
  holds no provider keys. Input goes over stdin (bytes), result over stdout
  (JSON), size caps enforced BEFORE the child sees the data, hard timeout.
* Opt-in: ``[security] isolate_parsers = true`` (env
  ``MAVERICK_ISOLATE_PARSERS``). Off by default — in-process behavior is
  byte-identical; turning it on routes the registered consumers through the
  child. ``should_isolate()`` is the gate consumers check.

Only entries in :data:`PARSERS` may run in the child (a whitelist keyed by
name — never an arbitrary dotted path from the model).
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

MAX_INPUT_BYTES = 64 * 1024 * 1024   # refuse absurd inputs before any parse
DEFAULT_TIMEOUT = 60.0
_EVIDENCE_OUTPUT_LIMIT = 16 * 1024 * 1024
_POSIX_RESOURCE_LIMITS = os.name == "posix"
_RESOURCE_LIMITED_PARSERS = {
    "evidence_pdf_text", "spreadsheet_read", "spreadsheet_info", "spreadsheet_set_cell",
}

# Applied inside the child, before loading data or importing the parser. A
# preexec_fn in the multi-threaded parent can deadlock after fork.
_EVIDENCE_LIMITS = '''\
import resource
def limit_resource(which, requested):
    soft, hard = resource.getrlimit(which)
    finite = [v for v in (soft, hard) if v != resource.RLIM_INFINITY]
    value = min([requested, *finite])
    resource.setrlimit(which, (value, value))
limit_resource(resource.RLIMIT_AS, 768 * 1024 * 1024)
limit_resource(resource.RLIMIT_CPU, 25)
limit_resource(resource.RLIMIT_FSIZE, 16 * 1024 * 1024)
limit_resource(resource.RLIMIT_CORE, 0)
'''


@dataclass(frozen=True)
class ParserEntry:
    name: str          # whitelist key
    module: str        # module imported INSIDE the child
    func: str          # function(data: bytes, **kwargs) -> JSON-able result
    feeds: str         # what untrusted source reaches it
    memory_safe: bool  # pure-Python (True) vs C-extension-backed (False)


# The inventory/policy: untrusted-input parsers and their safety class.
PARSERS: dict[str, ParserEntry] = {
    "pdf_text": ParserEntry(
        name="pdf_text",
        module="maverick.tools.pdf_reader",
        func="extract_text_from_bytes",
        feeds="attachments / channel uploads",
        memory_safe=False,  # pdfplumber(pdfminer)/pypdf C-accelerated paths
    ),
    "evidence_pdf_text": ParserEntry(
        name="evidence_pdf_text",
        module="maverick.ai_evidence_analysis",
        func="_isolated_evidence_pdf_text",
        feeds="AI evidence PDF uploads",
        memory_safe=False,
    ),
    "spreadsheet_read": ParserEntry(
        name="spreadsheet_read", module="maverick.tools.spreadsheet",
        func="_isolated_xlsx_read", feeds="workspace XLSX reads", memory_safe=False,
    ),
    "spreadsheet_info": ParserEntry(
        name="spreadsheet_info", module="maverick.tools.spreadsheet",
        func="_isolated_xlsx_info", feeds="workspace XLSX inspection", memory_safe=False,
    ),
    "spreadsheet_set_cell": ParserEntry(
        name="spreadsheet_set_cell", module="maverick.tools.spreadsheet",
        func="_isolated_xlsx_set_cell", feeds="workspace XLSX edits", memory_safe=False,
    ),
    "image_meta": ParserEntry(
        name="image_meta",
        module="maverick.parser_isolation",
        func="_probe_image_meta",
        feeds="channel image uploads",
        memory_safe=False,  # Pillow decoders are C
    ),
}


def should_isolate() -> bool:
    if os.environ.get("MAVERICK_ISOLATE_PARSERS", "").strip().lower() in {
        "1", "true", "yes", "on",
    }:
        return True
    try:
        from .config import load_config
        return bool(((load_config() or {}).get("security") or {})
                    .get("isolate_parsers", False))
    except Exception:  # pragma: no cover -- config never blocks parsing
        return False


_CHILD_TEMPLATE = """\
import json, sys
{resource_limits}
sys.path.insert(0, {import_root!r})
data = sys.stdin.buffer.read()
from importlib import import_module
fn = getattr(import_module({module!r}), {func!r})
kwargs = json.loads({kwargs_json!r})
try:
    result = fn(data, **kwargs)
    sys.stdout.write(json.dumps({{"ok": True, "result": result}}))
except Exception as e:
    sys.stdout.write(json.dumps({{"ok": False,
                                  "error": f"{{type(e).__name__}}: {{e}}"}}))
"""


def parse_isolated(name: str, data: bytes, *, timeout: float = DEFAULT_TIMEOUT,
                   **kwargs):
    """Run the whitelisted parser ``name`` on ``data`` in a scrubbed child.

    Returns the parser's JSON-able result. Raises ``ValueError`` for an
    unknown parser or oversized input, ``RuntimeError`` for a child that
    crashed/timed out/errored — the caller decides whether to fall back.
    """
    entry = PARSERS.get(name)
    if entry is None:
        raise ValueError(f"unknown parser {name!r}; whitelisted: {sorted(PARSERS)}")
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError(
            f"input of {len(data)} bytes exceeds the {MAX_INPUT_BYTES}-byte cap")
    # kwargs are baked as a JSON literal — nothing user-controlled becomes code.
    # The child runs in isolated mode with a neutral cwd, then imports Lightwork
    # from the same trusted package root as this parent module.  That keeps
    # python -c from resolving whitelisted dotted names through an attacker
    # controlled workspace package.
    import_root = str(Path(__file__).resolve().parents[1])
    code = _CHILD_TEMPLATE.format(
        import_root=import_root, module=entry.module, func=entry.func,
        kwargs_json=json.dumps(kwargs, default=str),
        resource_limits=_EVIDENCE_LIMITS if name in _RESOURCE_LIMITED_PARSERS else "",
    )
    from .tools import scrub_child_env
    try:
        if name in _RESOURCE_LIMITED_PARSERS:
            if not _POSIX_RESOURCE_LIMITS:
                raise RuntimeError("isolated document parsing requires POSIX resource limits")
            # stdout is a regular file so the child's RLIMIT_FSIZE bounds it;
            # stderr is discarded rather than buffered into the parent. Even an
            # erroring parser cannot fill the parent's memory through either.
            with tempfile.TemporaryFile() as output:
                proc = subprocess.run(
                    [sys.executable, "-I", "-c", code], input=data,
                    stdout=output, stderr=subprocess.DEVNULL, timeout=timeout,
                    env=scrub_child_env(), cwd=os.path.abspath(os.sep),
                )
                output.seek(0)
                stdout = output.read(_EVIDENCE_OUTPUT_LIMIT + 1)
            if len(stdout) > _EVIDENCE_OUTPUT_LIMIT:
                raise RuntimeError("document parser output exceeded its bound")
            stderr = b""
        else:
            proc = subprocess.run(
                [sys.executable, "-I", "-c", code],
                input=data, capture_output=True, timeout=timeout,
                env=scrub_child_env(), cwd=os.path.abspath(os.sep),
            )
            stdout, stderr = proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"parser {name!r} timed out after {timeout}s") from e
    if proc.returncode != 0:
        # a segfault/abort on hostile bytes lands HERE, not in the kernel
        raise RuntimeError(
            f"parser child {name!r} died (exit {proc.returncode}): "
            f"{stderr.decode('utf-8', 'replace')[-200:]}")
    try:
        payload = json.loads(stdout.decode("utf-8"))
    except ValueError as e:
        raise RuntimeError(f"parser {name!r} returned non-JSON output") from e
    if not payload.get("ok"):
        raise RuntimeError(f"parser {name!r} failed: {payload.get('error')}")
    return payload.get("result")


def _probe_image_meta(data: bytes) -> dict:
    """Child-side image probe: format/size via Pillow without full decode."""
    import io
    try:
        from PIL import Image
    except ImportError as e:  # pragma: no cover -- optional extra
        raise RuntimeError("Pillow not installed ([computer-use] extra)") from e
    with Image.open(io.BytesIO(data)) as im:
        return {"format": im.format, "width": im.width, "height": im.height,
                "mode": im.mode}


def inventory() -> str:
    """Render the parser policy table (the auditable inventory)."""
    lines = ["untrusted-input parsers:"]
    for e in sorted(PARSERS.values(), key=lambda e: e.name):
        safety = "memory-safe (pure python)" if e.memory_safe else \
            "C-extension — ISOLATE"
        lines.append(f"  {e.name:<12} {e.module}.{e.func}")
        lines.append(f"      feeds: {e.feeds}; {safety}")
    state = "ON" if should_isolate() else \
        "off (opt in via [security] isolate_parsers)"
    lines.append(f"isolation: {state}")
    return "\n".join(lines)


__all__ = ["PARSERS", "ParserEntry", "parse_isolated", "should_isolate",
           "inventory", "MAX_INPUT_BYTES"]
