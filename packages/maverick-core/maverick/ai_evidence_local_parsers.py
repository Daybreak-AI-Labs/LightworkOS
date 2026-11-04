"""Attested, offline OCR and legacy-XLS routes for AI Evidence Analysis.

The generic evidence adapter intentionally leaves production dependency policy
to a deployment composition.  This module supplies that policy without
persisting source bytes or extracted text:

* OCR invokes one absolute, SHA-256-pinned Tesseract executable with exact
  trained-data, runtime-library, and Pillow package manifests inside an
  attested Bubblewrap network namespace, a private transient input directory,
  and process time/memory/output limits.
* legacy XLS parsing runs out of process under the same limits, requires exact
  ``xlrd`` and ``olefile`` versions, validates a conservative BIFF8 record
  allowlist before parsing, and refuses formulas, macros, external references,
  encryption, embedded objects, errors, and unsupported records.

The worker is intentionally narrow.  A workbook it does not understand is an
error, never a best-effort parse.  Unsupported platforms remain unready rather
than claiming isolation.  Operator configuration, governed and inherited
implementation digests, and dependency manifests are included in adapter
authority identity so ordinary authority rotation/revocation continues to
protect the composition.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import importlib.metadata
import json
import os
import re
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time
import warnings
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, replace
from io import BytesIO
from pathlib import Path
from typing import BinaryIO

from . import ai_evidence_analysis as evidence

_ZERO_DIGEST = "0" * 64
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}\Z")
_TESSERACT_VERSION_RE = re.compile(r"tesseract[ \t]+([^\s]+)", re.IGNORECASE)
_WORKER_ERROR_RE = re.compile(r"xls_[a-z_]{1,63}\Z")
_IMAGE_WORKER_ERROR_RE = re.compile(r"image_[a-z_]{1,63}\Z")
_ADAPTER_ID = "local-bounded-extraction"
_ADAPTER_REVISION = 4
_XLS_WORKER_MODULE = "maverick.ai_evidence_local_parsers"
_BWRAP_VERSION_RE = re.compile(r"(?:bubblewrap|bwrap)[ \t]+([^\s]+)", re.IGNORECASE)

# BIFF8 only.  Unknown records fail closed; this is intentionally a smaller
# contract than everything Excel historically allowed.
_BIFF_BOF = 0x0809
_BIFF_EOF = 0x000A
_BIFF_FORMULA_RECORDS = frozenset({0x0006, 0x0206, 0x0406, 0x0021, 0x0221, 0x04BC, 0x0236})
_BIFF_MACRO_OR_ACTIVE_RECORDS = frozenset(
    {
        0x005D,  # OBJ
        0x007F,  # IMDATA
        0x00EC,  # MSODRAWING
        0x00ED,  # MSODRAWINGGROUP
        0x01B6,  # TXO
        0x01B8,  # HLINK
    }
)
_BIFF_EXTERNAL_OR_ENCRYPTED_RECORDS = frozenset(
    {
        0x0016,  # EXTERNCOUNT
        0x0017,  # EXTERNSHEET
        0x0018,  # NAME (includes external/function names)
        0x0023,  # EXTERNNAME
        0x002F,  # FILEPASS
        0x01AE,  # SUPBOOK
    }
)
_BIFF_SAFE_RECORDS = frozenset(
    {
        _BIFF_BOF,
        _BIFF_EOF,
        0x000C,  # CALCCOUNT
        0x000D,  # CALCMODE
        0x000E,  # PRECISION
        0x000F,  # REFMODE
        0x0010,  # DELTA
        0x0011,  # ITERATION
        0x0012,  # PROTECT
        0x0013,  # PASSWORD
        0x0014,  # HEADER
        0x0015,  # FOOTER
        0x0019,  # WINDOWPROTECT
        0x001A,  # VERTICALPAGEBREAKS
        0x001B,  # HORIZONTALPAGEBREAKS
        0x001D,  # SELECTION
        0x0022,  # DATEMODE
        0x0026,  # LEFTMARGIN
        0x0027,  # RIGHTMARGIN
        0x0028,  # TOPMARGIN
        0x0029,  # BOTTOMMARGIN
        0x002A,  # PRINTHEADERS
        0x002B,  # PRINTGRIDLINES
        0x0031,  # FONT
        0x003C,  # CONTINUE
        0x003D,  # WINDOW1
        0x0040,  # BACKUP
        0x0041,  # PANE
        0x0042,  # CODEPAGE
        0x0055,  # DEFCOLWIDTH
        0x005B,  # FILESHARING
        0x005C,  # WRITEACCESS
        0x005F,  # SAVERECALC
        0x0063,  # OBJECTPROTECT
        0x007D,  # COLINFO
        0x0080,  # GUTS
        0x0081,  # WSBOOL
        0x0082,  # GRIDSET
        0x0083,  # HCENTER
        0x0084,  # VCENTER
        0x0085,  # BOUNDSHEET
        0x0086,  # WRITEPROT
        0x008C,  # COUNTRY
        0x008D,  # HIDEOBJ
        0x0092,  # PALETTE
        0x0099,  # STANDARDWIDTH
        0x009C,  # FNGROUPCOUNT
        0x00A1,  # SETUP
        0x00BD,  # MULRK
        0x00BE,  # MULBLANK
        0x00C1,  # MMS
        0x00D6,  # RSTRING
        0x00D7,  # DBCELL
        0x00DA,  # BOOKBOOL
        0x00DD,  # SCENPROTECT
        0x00E0,  # XF
        0x00E1,  # INTERFACEHDR
        0x00E2,  # INTERFACEEND
        0x00E5,  # MERGEDCELLS
        0x00FC,  # SST
        0x00FD,  # LABELSST
        0x013D,  # TABID
        0x0160,  # USESELFS
        0x0161,  # DSF
        0x01AF,  # PROT4REV
        0x01B7,  # REFRESHALL (refresh execution is not performed)
        0x01BC,  # PROT4REVPASS
        0x01C0,  # XL9FILE
        0x01C1,  # RECALCID
        0x0200,  # DIMENSIONS
        0x0201,  # BLANK
        0x0203,  # NUMBER
        0x0204,  # LABEL
        0x0205,  # BOOLERR (errors are rejected after parse)
        0x0208,  # ROW
        0x020B,  # INDEX
        0x0225,  # DEFAULTROWHEIGHT
        0x023E,  # WINDOW2
        0x027E,  # RK
        0x0293,  # STYLE
        0x041E,  # FORMAT
    }
)
_CELL_RECORDS = frozenset({0x0201, 0x0203, 0x0204, 0x0205, 0x027E, 0x00D6, 0x00FD})
_MULTI_CELL_RECORDS = frozenset({0x00BD, 0x00BE})


class LocalParserAttestationError(evidence.EvidenceAnalysisConfigError):
    """A configured local dependency or isolation control is not exact."""


@dataclass(frozen=True, slots=True)
class TesseractOCRConfig:
    executable: str
    executable_sha256: str
    tesseract_version: str
    traineddata_path: str
    traineddata_sha256: str
    runtime_library_paths: tuple[str, ...]
    runtime_libraries_sha256: str
    pillow_version: str
    pillow_manifest_sha256: str
    timeout_seconds: int = 30
    max_pixels: int = 40_000_000
    max_output_bytes: int = 1_048_576
    max_memory_bytes: int = 536_870_912


@dataclass(frozen=True, slots=True)
class LegacyXLSConfig:
    xlrd_version: str
    xlrd_manifest_sha256: str
    olefile_version: str
    olefile_manifest_sha256: str
    timeout_seconds: int = 15
    max_workbook_stream_bytes: int = 33_554_432
    max_record_bytes: int = 8_388_608
    max_records: int = 500_000
    max_sheets: int = 200
    max_rows_per_sheet: int = 200_000
    max_columns_per_sheet: int = 256
    max_cells: int = 200_000
    max_output_bytes: int = 1_048_576
    max_memory_bytes: int = 536_870_912


@dataclass(frozen=True, slots=True)
class LocalParserSandboxConfig:
    """Exact Bubblewrap launcher used to provide a network namespace."""

    launcher: str
    launcher_sha256: str
    launcher_version: str
    mode: str = "bubblewrap"


@dataclass(frozen=True, slots=True)
class _ProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes


class _OutputBoundExceeded(Exception):
    pass


class _ProcessTimeExceeded(Exception):
    pass


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _file_sha256(path: Path, *, maximum_bytes: int = 536_870_912) -> str:
    try:
        size = path.stat().st_size
        if size <= 0 or size > maximum_bytes or not path.is_file() or path.is_symlink():
            raise LocalParserAttestationError("local parser executable is not an exact regular file")
        digest = hashlib.sha256()
        consumed = 0
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                consumed += len(chunk)
                if consumed > maximum_bytes:
                    raise LocalParserAttestationError(
                        "local parser executable exceeds its attestation bound"
                    )
                digest.update(chunk)
        if consumed != size:
            raise LocalParserAttestationError("local parser executable changed during attestation")
        return digest.hexdigest()
    except LocalParserAttestationError:
        raise
    except OSError as exc:
        raise LocalParserAttestationError("local parser executable is unavailable") from exc


def _resolved_or_none(path: Path) -> Path | None:
    try:
        return path.resolve(strict=True)
    except OSError:
        return None


def _manifest_file_sha256(path: Path, *, maximum_bytes: int = 536_870_912) -> str:
    """Hash an attested package file; empty marker files are legitimate."""

    try:
        size = path.stat().st_size
        if size < 0 or size > maximum_bytes or not path.is_file() or path.is_symlink():
            raise LocalParserAttestationError("package manifest file is invalid")
        digest = hashlib.sha256()
        consumed = 0
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                consumed += len(chunk)
                if consumed > maximum_bytes:
                    raise LocalParserAttestationError(
                        "package manifest file exceeds its attestation bound"
                    )
                digest.update(chunk)
        if consumed != size:
            raise LocalParserAttestationError(
                "package manifest file changed during attestation"
            )
        return digest.hexdigest()
    except LocalParserAttestationError:
        raise
    except OSError as exc:
        raise LocalParserAttestationError("package manifest file is unavailable") from exc


def _implementation_components() -> dict[str, str]:
    """Hash both the governed override and every inherited parser branch.

    ``GovernedLocalExtractionAdapter`` deliberately delegates PDF, XLSX, text,
    and non-OCR image behavior to ``BoundedLocalExtractionAdapter``.  Enrolling
    only this module would let that inherited implementation change without an
    authority rotation, so the combined implementation identity binds both
    source files.
    """

    local_path = Path(__file__).resolve(strict=True)
    base_path = Path(evidence.__file__).resolve(strict=True)
    return {
        "base_parser_sha256": _file_sha256(base_path, maximum_bytes=8 * 1024 * 1024),
        "governed_parser_sha256": _file_sha256(
            local_path, maximum_bytes=4 * 1024 * 1024
        ),
    }


def _implementation_sha256() -> str:
    return _canonical_sha256(_implementation_components())


def _manifest_sha256(paths: Sequence[str | Path], label: str) -> str:
    if (
        isinstance(paths, (str, bytes))
        or not isinstance(paths, Sequence)
        or not 1 <= len(paths) <= 512
    ):
        raise LocalParserAttestationError(f"{label} manifest path set is invalid")
    entries: list[dict[str, object]] = []
    seen: set[str] = set()
    total_bytes = 0
    for raw_path in paths:
        if not isinstance(raw_path, (str, Path)):
            raise LocalParserAttestationError(f"{label} manifest path is invalid")
        path = Path(raw_path)
        if not path.is_absolute():
            raise LocalParserAttestationError(f"{label} manifest paths must be absolute")
        try:
            if path.is_symlink():
                raise LocalParserAttestationError(
                    f"{label} manifest symlinks are unsupported"
                )
            resolved = path.resolve(strict=True)
            size = resolved.stat().st_size
        except LocalParserAttestationError:
            raise
        except OSError as exc:
            raise LocalParserAttestationError(
                f"{label} manifest dependency is unavailable"
            ) from exc
        canonical = os.path.normcase(str(resolved))
        if canonical in seen or not resolved.is_file() or size <= 0:
            raise LocalParserAttestationError(f"{label} manifest path set is invalid")
        seen.add(canonical)
        total_bytes += size
        if total_bytes > 1_073_741_824:
            raise LocalParserAttestationError(f"{label} manifest exceeds its byte bound")
        entries.append(
            {
                "path": str(resolved),
                "size": size,
                "sha256": _manifest_file_sha256(resolved),
            }
        )
    entries.sort(key=lambda item: os.path.normcase(str(item["path"])))
    return _canonical_sha256(entries)


def _distribution_manifest_sha256(distribution: str) -> str:
    """Hash installed package files while excluding generated bytecode."""

    try:
        selected = importlib.metadata.distribution(distribution)
    except importlib.metadata.PackageNotFoundError as exc:
        raise LocalParserAttestationError(
            f"{distribution} local parser dependency is unavailable"
        ) from exc
    files = selected.files
    if files is None:
        raise LocalParserAttestationError(
            f"{distribution} package manifest is unavailable"
        )
    entries: list[dict[str, object]] = []
    total_bytes = 0
    for package_path in sorted(files, key=lambda item: str(item).replace("\\", "/")):
        logical = str(package_path).replace("\\", "/")
        if "/__pycache__/" in f"/{logical}" or logical.endswith((".pyc", ".pyo")):
            continue
        try:
            candidate = Path(selected.locate_file(package_path))
            if candidate.is_symlink():
                raise LocalParserAttestationError(
                    f"{distribution} package manifest contains a symlink"
                )
            resolved = candidate.resolve(strict=True)
            if not resolved.is_file():
                continue
            size = resolved.stat().st_size
        except OSError as exc:
            raise LocalParserAttestationError(
                f"{distribution} package manifest is unavailable"
            ) from exc
        total_bytes += size
        if len(entries) >= 4_096 or total_bytes > 536_870_912:
            raise LocalParserAttestationError(
                f"{distribution} package manifest exceeds its bound"
            )
        entries.append(
            {
                "path": logical,
                "size": size,
                "sha256": _manifest_file_sha256(resolved),
            }
        )
    if not entries:
        raise LocalParserAttestationError(
            f"{distribution} package manifest is unavailable"
        )
    return _canonical_sha256(entries)


def _exact_version(value: object, label: str) -> str:
    if not isinstance(value, str) or _VERSION_RE.fullmatch(value) is None:
        raise LocalParserAttestationError(f"{label} must be an exact bounded version")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise LocalParserAttestationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise LocalParserAttestationError(f"{label} is outside its bound")
    return value


def _installed_version(distribution: str) -> str:
    try:
        return importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError as exc:
        raise LocalParserAttestationError(
            f"{distribution} local parser dependency is unavailable"
        ) from exc


def _check_dependency(distribution: str, expected: str) -> None:
    expected = _exact_version(expected, f"{distribution} version")
    if _installed_version(distribution) != expected:
        raise LocalParserAttestationError(f"{distribution} local parser version mismatch")


def _check_distribution_manifest(
    distribution: str,
    expected: str,
) -> str:
    selected = _digest(expected, f"{distribution} manifest_sha256")
    actual = _distribution_manifest_sha256(distribution)
    if actual != selected:
        raise LocalParserAttestationError(
            f"{distribution} local parser package manifest mismatch"
        )
    return actual


def _validate_sandbox_config(
    config: LocalParserSandboxConfig,
    *,
    enforce_platform: bool,
) -> LocalParserSandboxConfig:
    if type(config) is not LocalParserSandboxConfig:
        raise LocalParserAttestationError("local parser sandbox contract is invalid")
    if config.mode != "bubblewrap":
        raise LocalParserAttestationError("local parser sandbox mode is unsupported")
    launcher = Path(config.launcher)
    if not launcher.is_absolute():
        raise LocalParserAttestationError("sandbox launcher must be an absolute path")
    try:
        if launcher.is_symlink():
            raise LocalParserAttestationError("sandbox launcher symlinks are unsupported")
        resolved = launcher.resolve(strict=True)
    except LocalParserAttestationError:
        raise
    except OSError as exc:
        raise LocalParserAttestationError("sandbox launcher is unavailable") from exc
    expected = _digest(config.launcher_sha256, "sandbox launcher_sha256")
    if _file_sha256(resolved) != expected:
        raise LocalParserAttestationError("sandbox launcher digest mismatch")
    _exact_version(config.launcher_version, "sandbox launcher version")
    if enforce_platform and not _network_sandbox_supported():
        raise LocalParserAttestationError(
            "enforceable local parser network isolation is unsupported on this platform"
        )
    return replace(config, launcher=str(resolved))


def _network_sandbox_supported() -> bool:
    return os.name == "posix" and Path("/proc/self/ns/net").exists()


def _offline_environment(temp_directory: str | None = None) -> dict[str, str]:
    # Tesseract and the XLS worker do not need an operator environment.  In
    # particular, proxy variables and credentials are never inherited.
    environment = {
        "PATH": "",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
    }
    if temp_directory:
        environment.update(
            {
                "HOME": temp_directory,
                "LOCALAPPDATA": temp_directory,
                "TEMP": temp_directory,
                "TMP": temp_directory,
                "TMPDIR": temp_directory,
                "USERPROFILE": temp_directory,
            }
        )
    return environment


def _apply_windows_memory_limit(process: subprocess.Popen[bytes], maximum_bytes: int) -> int:
    from ctypes import wintypes

    class _IOCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class _BasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _ExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _BasicLimitInformation),
            ("IoInfo", _IOCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    handle = kernel32.CreateJobObjectW(None, None)
    if not handle:
        raise OSError(ctypes.get_last_error(), "CreateJobObjectW failed")
    details = _ExtendedLimitInformation()
    details.BasicLimitInformation.LimitFlags = 0x00000100 | 0x00002000
    details.ProcessMemoryLimit = maximum_bytes
    if not kernel32.SetInformationJobObject(
        handle,
        9,
        ctypes.byref(details),
        ctypes.sizeof(details),
    ):
        kernel32.CloseHandle(handle)
        raise OSError(ctypes.get_last_error(), "SetInformationJobObject failed")
    process_handle = wintypes.HANDLE(process._handle)  # noqa: SLF001
    if not kernel32.AssignProcessToJobObject(handle, process_handle):
        kernel32.CloseHandle(handle)
        raise OSError(ctypes.get_last_error(), "AssignProcessToJobObject failed")
    return int(handle)


def _posix_memory_limiter(maximum_bytes: int) -> Callable[[], None]:
    """Return the minimal pre-exec limiter used before worker code can run."""

    # Import in the parent.  The post-fork callback only performs the two
    # async-signal-safe setrlimit syscalls; it does not import or allocate
    # module state in a possibly multi-threaded child.
    import resource

    def apply() -> None:
        resource.setrlimit(resource.RLIMIT_AS, (maximum_bytes, maximum_bytes))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    return apply


def _close_job(handle: int | None) -> None:
    if handle is None or os.name != "nt":
        return
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle(wintypes.HANDLE(handle))


def _terminate_containment(
    process: subprocess.Popen[bytes],
    job_handle: int | None,
) -> None:
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            if process.poll() is None:
                process.kill()
        return
    if job_handle is not None:
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel32.TerminateJobObject.restype = wintypes.BOOL
        if kernel32.TerminateJobObject(wintypes.HANDLE(job_handle), 1):
            return
    if process.poll() is None:
        process.kill()


def _sandbox_command(
    sandbox: LocalParserSandboxConfig,
    command: Sequence[str],
    *,
    cwd: str | None,
) -> tuple[str, ...]:
    if not _network_sandbox_supported() or sandbox.mode != "bubblewrap":
        raise LocalParserAttestationError(
            "enforceable local parser network isolation is unavailable"
        )
    if _file_sha256(Path(sandbox.launcher)) != sandbox.launcher_sha256:
        raise LocalParserAttestationError("sandbox launcher changed before execution")
    working_directory = str(Path(cwd).resolve(strict=True)) if cwd else "/"
    prefix = [
        sandbox.launcher,
        "--die-with-parent",
        "--new-session",
        "--unshare-net",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--ro-bind",
        "/",
        "/",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
    ]
    if cwd:
        prefix.extend(("--bind", working_directory, working_directory))
    prefix.extend(("--chdir", working_directory, "--"))
    return (*prefix, *command)


def _bounded_reader(
    stream: BinaryIO,
    output: bytearray,
    maximum_bytes: int,
    overflow: threading.Event,
) -> None:
    try:
        while chunk := stream.read(8_192):
            if len(output) + len(chunk) > maximum_bytes:
                overflow.set()
                return
            output.extend(chunk)
    finally:
        stream.close()


def _bounded_writer(stream: BinaryIO, content: bytes) -> None:
    try:
        stream.write(content)
        stream.flush()
    except (BrokenPipeError, OSError):
        pass
    finally:
        stream.close()


def _bounded_process(
    command: Sequence[str],
    *,
    input_bytes: bytes = b"",
    timeout_seconds: int,
    max_stdout_bytes: int,
    max_stderr_bytes: int = 4_096,
    max_memory_bytes: int,
    cwd: str | None = None,
    sandbox: LocalParserSandboxConfig | None = None,
) -> _ProcessResult:
    if (
        not command
        or any(not isinstance(item, str) or not item or "\x00" in item for item in command)
        or not isinstance(input_bytes, bytes)
    ):
        raise LocalParserAttestationError("local parser process contract is invalid")
    timeout_seconds = _integer(timeout_seconds, "process timeout_seconds", 1, 120)
    max_stdout_bytes = _integer(
        max_stdout_bytes, "process max_stdout_bytes", 1_024, 10_485_760
    )
    max_stderr_bytes = _integer(max_stderr_bytes, "process max_stderr_bytes", 256, 65_536)
    max_memory_bytes = _integer(
        max_memory_bytes,
        "process max_memory_bytes",
        67_108_864,
        2_147_483_648,
    )
    process: subprocess.Popen[bytes] | None = None
    job_handle: int | None = None
    try:
        selected_command = (
            _sandbox_command(sandbox, command, cwd=cwd)
            if sandbox is not None
            else tuple(command)
        )
        process = subprocess.Popen(  # noqa: S603 - absolute, attested binaries only
            selected_command,
            cwd=(cwd if sandbox is None else None),
            env=_offline_environment(cwd),
            shell=False,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0),
            start_new_session=(os.name == "posix"),
            preexec_fn=(
                _posix_memory_limiter(max_memory_bytes) if os.name == "posix" else None
            ),
        )
        # Enabled production workers are POSIX/Bubblewrap-only.  The Windows
        # job path remains available for bounded trusted probes/tests, but does
        # not satisfy parser readiness because it cannot deny network access.
        if os.name == "nt":
            job_handle = _apply_windows_memory_limit(process, max_memory_bytes)
        if process.stdin is None or process.stdout is None or process.stderr is None:
            raise LocalParserAttestationError("local parser process pipes are unavailable")
        stdout = bytearray()
        stderr = bytearray()
        overflow = threading.Event()
        stdout_reader = threading.Thread(
            target=_bounded_reader,
            args=(process.stdout, stdout, max_stdout_bytes, overflow),
            daemon=True,
        )
        stderr_reader = threading.Thread(
            target=_bounded_reader,
            args=(process.stderr, stderr, max_stderr_bytes, overflow),
            daemon=True,
        )
        stdin_writer = threading.Thread(
            target=_bounded_writer,
            args=(process.stdin, input_bytes),
            daemon=True,
        )
        stdout_reader.start()
        stderr_reader.start()
        stdin_writer.start()
        deadline = time.monotonic() + timeout_seconds
        while process.poll() is None:
            if overflow.is_set():
                _terminate_containment(process, job_handle)
                raise _OutputBoundExceeded
            if time.monotonic() >= deadline:
                _terminate_containment(process, job_handle)
                raise _ProcessTimeExceeded
            time.sleep(0.005)
        stdout_reader.join(timeout=1)
        stderr_reader.join(timeout=1)
        stdin_writer.join(timeout=1)
        if overflow.is_set():
            raise _OutputBoundExceeded
        if stdout_reader.is_alive() or stderr_reader.is_alive() or stdin_writer.is_alive():
            raise LocalParserAttestationError("local parser pipe shutdown failed closed")
        return _ProcessResult(process.returncode, bytes(stdout), bytes(stderr))
    except (_OutputBoundExceeded, _ProcessTimeExceeded):
        raise
    except LocalParserAttestationError:
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        raise LocalParserAttestationError("local parser process is unavailable") from exc
    finally:
        if process is not None:
            _terminate_containment(process, job_handle)
            if process.poll() is None:
                try:
                    process.wait(timeout=1)
                except subprocess.SubprocessError:
                    pass
        _close_job(job_handle)


def _validate_ocr_config(config: TesseractOCRConfig) -> TesseractOCRConfig:
    if type(config) is not TesseractOCRConfig:
        raise LocalParserAttestationError("OCR configuration contract is invalid")
    executable = Path(config.executable)
    if not executable.is_absolute():
        raise LocalParserAttestationError("OCR executable must be an absolute path")
    try:
        if executable.is_symlink():
            raise LocalParserAttestationError("OCR executable symlinks are unsupported")
        resolved = executable.resolve(strict=True)
    except LocalParserAttestationError:
        raise
    except OSError as exc:
        raise LocalParserAttestationError("OCR executable is unavailable") from exc
    expected_digest = _digest(config.executable_sha256, "OCR executable_sha256")
    if _file_sha256(resolved) != expected_digest:
        raise LocalParserAttestationError("OCR executable digest mismatch")
    _exact_version(config.tesseract_version, "Tesseract version")
    traineddata = Path(config.traineddata_path)
    if not traineddata.is_absolute() or traineddata.name != "eng.traineddata":
        raise LocalParserAttestationError(
            "OCR traineddata_path must be an absolute eng.traineddata path"
        )
    try:
        if traineddata.is_symlink():
            raise LocalParserAttestationError("OCR traineddata symlinks are unsupported")
        traineddata = traineddata.resolve(strict=True)
    except LocalParserAttestationError:
        raise
    except OSError as exc:
        raise LocalParserAttestationError("OCR traineddata is unavailable") from exc
    expected_traineddata = _digest(
        config.traineddata_sha256, "OCR traineddata_sha256"
    )
    if _file_sha256(traineddata) != expected_traineddata:
        raise LocalParserAttestationError("OCR traineddata digest mismatch")
    if type(config.runtime_library_paths) is not tuple:
        raise LocalParserAttestationError(
            "OCR runtime_library_paths must be an exact immutable path set"
        )
    runtime_paths = config.runtime_library_paths
    actual_runtime_manifest = _manifest_sha256(runtime_paths, "OCR runtime libraries")
    expected_runtime_manifest = _digest(
        config.runtime_libraries_sha256, "OCR runtime_libraries_sha256"
    )
    if actual_runtime_manifest != expected_runtime_manifest:
        raise LocalParserAttestationError("OCR runtime library manifest mismatch")
    _exact_version(config.pillow_version, "Pillow version")
    _check_distribution_manifest("Pillow", config.pillow_manifest_sha256)
    _integer(config.timeout_seconds, "OCR timeout_seconds", 1, 120)
    _integer(config.max_pixels, "OCR max_pixels", 1, 100_000_000)
    _integer(config.max_output_bytes, "OCR max_output_bytes", 1_024, 10_485_760)
    _integer(
        config.max_memory_bytes,
        "OCR max_memory_bytes",
        67_108_864,
        2_147_483_648,
    )
    if _installed_version("Pillow") != config.pillow_version:
        raise LocalParserAttestationError("Pillow local parser version mismatch")
    return replace(
        config,
        executable=str(resolved),
        traineddata_path=str(traineddata),
        runtime_library_paths=tuple(
            str(Path(path).resolve(strict=True)) for path in runtime_paths
        ),
    )


def _validate_xls_config(config: LegacyXLSConfig) -> LegacyXLSConfig:
    if type(config) is not LegacyXLSConfig:
        raise LocalParserAttestationError("legacy XLS configuration contract is invalid")
    _check_dependency("xlrd", config.xlrd_version)
    _check_dependency("olefile", config.olefile_version)
    _check_distribution_manifest("xlrd", config.xlrd_manifest_sha256)
    _check_distribution_manifest("olefile", config.olefile_manifest_sha256)
    _integer(config.timeout_seconds, "legacy XLS timeout_seconds", 1, 120)
    _integer(
        config.max_workbook_stream_bytes,
        "legacy XLS max_workbook_stream_bytes",
        1_024,
        67_108_864,
    )
    _integer(
        config.max_record_bytes,
        "legacy XLS max_record_bytes",
        1_024,
        16_777_215,
    )
    _integer(config.max_records, "legacy XLS max_records", 1, 1_000_000)
    _integer(config.max_sheets, "legacy XLS max_sheets", 1, 256)
    _integer(
        config.max_rows_per_sheet,
        "legacy XLS max_rows_per_sheet",
        1,
        1_048_576,
    )
    _integer(
        config.max_columns_per_sheet,
        "legacy XLS max_columns_per_sheet",
        1,
        256,
    )
    _integer(config.max_cells, "legacy XLS max_cells", 1, 1_000_000)
    _integer(config.max_output_bytes, "legacy XLS max_output_bytes", 1_024, 10_485_760)
    _integer(
        config.max_memory_bytes,
        "legacy XLS max_memory_bytes",
        67_108_864,
        2_147_483_648,
    )
    return config


def _tesseract_version(
    config: TesseractOCRConfig,
    runner: Callable[..., _ProcessResult],
    sandbox: LocalParserSandboxConfig,
) -> str:
    try:
        result = runner(
            (config.executable, "--version"),
            timeout_seconds=min(config.timeout_seconds, 10),
            max_stdout_bytes=16_384,
            max_stderr_bytes=16_384,
            max_memory_bytes=config.max_memory_bytes,
            sandbox=sandbox,
        )
    except _ProcessTimeExceeded as exc:
        raise LocalParserAttestationError("OCR version check exceeded its time bound") from exc
    except _OutputBoundExceeded as exc:
        raise LocalParserAttestationError("OCR version output exceeded its byte bound") from exc
    if result.returncode != 0:
        raise LocalParserAttestationError("OCR version check failed closed")
    try:
        combined = (result.stdout + b"\n" + result.stderr).decode(
            "utf-8", errors="strict"
        )
    except UnicodeDecodeError as exc:
        raise LocalParserAttestationError("OCR version output encoding is invalid") from exc
    match = _TESSERACT_VERSION_RE.search(combined)
    if match is None:
        raise LocalParserAttestationError("OCR version output is unsupported")
    return match.group(1)


def _require_tesseract_english(
    config: TesseractOCRConfig,
    runner: Callable[..., _ProcessResult],
    sandbox: LocalParserSandboxConfig,
) -> None:
    try:
        result = runner(
            (config.executable, "--list-langs"),
            timeout_seconds=min(config.timeout_seconds, 10),
            max_stdout_bytes=65_536,
            max_stderr_bytes=16_384,
            max_memory_bytes=config.max_memory_bytes,
            sandbox=sandbox,
        )
    except _ProcessTimeExceeded as exc:
        raise LocalParserAttestationError(
            "OCR language check exceeded its time bound"
        ) from exc
    except _OutputBoundExceeded as exc:
        raise LocalParserAttestationError(
            "OCR language output exceeded its byte bound"
        ) from exc
    if result.returncode != 0:
        raise LocalParserAttestationError("OCR language dependency check failed closed")
    try:
        lines = {
            line.strip()
            for line in result.stdout.decode("utf-8", errors="strict").splitlines()
        }
    except UnicodeDecodeError as exc:
        raise LocalParserAttestationError("OCR language output encoding is invalid") from exc
    if "eng" not in lines:
        raise LocalParserAttestationError("OCR English language dependency is unavailable")


def _sandbox_launcher_version(
    config: LocalParserSandboxConfig,
    runner: Callable[..., _ProcessResult],
) -> str:
    try:
        result = runner(
            (config.launcher, "--version"),
            timeout_seconds=10,
            max_stdout_bytes=16_384,
            max_stderr_bytes=16_384,
            max_memory_bytes=134_217_728,
        )
    except (_OutputBoundExceeded, _ProcessTimeExceeded) as exc:
        raise LocalParserAttestationError(
            "sandbox launcher version probe failed its bound"
        ) from exc
    if result.returncode != 0:
        raise LocalParserAttestationError("sandbox launcher version probe failed closed")
    try:
        output = (result.stdout + b"\n" + result.stderr).decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise LocalParserAttestationError(
            "sandbox launcher version output encoding is invalid"
        ) from exc
    match = _BWRAP_VERSION_RE.search(output)
    if match is None:
        raise LocalParserAttestationError("sandbox launcher version output is unsupported")
    return match.group(1)


def _network_namespace_identity() -> str:
    if not _network_sandbox_supported():
        raise LocalParserAttestationError("network namespace identity is unavailable")
    try:
        identity = os.readlink("/proc/self/ns/net")
    except OSError as exc:
        raise LocalParserAttestationError("network namespace identity is unavailable") from exc
    if not identity or len(identity) > 128 or "\x00" in identity:
        raise LocalParserAttestationError("network namespace identity is invalid")
    return identity


class GovernedLocalExtractionAdapter(evidence.BoundedLocalExtractionAdapter):
    """Byte-bounded extraction with independently gated production OCR/XLS."""

    def __init__(
        self,
        *,
        maximum_bytes: int,
        sandbox: LocalParserSandboxConfig | None = None,
        ocr: TesseractOCRConfig | None = None,
        legacy_xls: LegacyXLSConfig | None = None,
        _runner: Callable[..., _ProcessResult] = _bounded_process,
    ) -> None:
        self.maximum_bytes = _integer(
            maximum_bytes,
            "max_extracted_text_bytes",
            1_024,
            10_485_760,
        )
        if not callable(_runner):
            raise LocalParserAttestationError("local parser runner is unavailable")
        self._runner = _runner
        self.ocr = _validate_ocr_config(ocr) if ocr is not None else None
        self.legacy_xls = _validate_xls_config(legacy_xls) if legacy_xls is not None else None
        workers_enabled = self.ocr is not None or self.legacy_xls is not None
        if workers_enabled and sandbox is None:
            raise LocalParserAttestationError(
                "enabled local parser workers require an enforceable network sandbox"
            )
        if not workers_enabled and sandbox is not None:
            raise LocalParserAttestationError("unused local parser sandbox is unsupported")
        self.sandbox = (
            _validate_sandbox_config(
                sandbox,
                enforce_platform=_runner is _bounded_process,
            )
            if sandbox is not None
            else None
        )
        self._implementation_components = _implementation_components()
        self._implementation_digest = _implementation_sha256()
        # Launch through the interpreter path this process runs as, so a
        # virtual environment (whose python is a symlink to the base
        # interpreter) keeps its own site-packages; attest the file it
        # resolves to, and refuse later if the link is repointed.
        self._python_launch = Path(sys.executable).absolute()
        self._python_executable = self._python_launch.resolve(strict=True)
        self._python_executable_sha256 = _file_sha256(self._python_executable)
        if self.sandbox is not None:
            if _sandbox_launcher_version(self.sandbox, self._runner) != (
                self.sandbox.launcher_version
            ):
                raise LocalParserAttestationError("sandbox launcher version mismatch")
            self._probe_network_sandbox()
        if self.ocr is not None:
            assert self.sandbox is not None
            if _tesseract_version(self.ocr, self._runner, self.sandbox) != (
                self.ocr.tesseract_version
            ):
                raise LocalParserAttestationError("OCR executable version mismatch")
            _require_tesseract_english(self.ocr, self._runner, self.sandbox)
            self._probe_image_worker()
        if self.legacy_xls is not None:
            self._probe_xls_worker()
        super().__init__(
            enable_ocr=False,
            maximum_characters=min(self.maximum_bytes, 1_000_000),
        )

    def _probe_network_sandbox(self) -> None:
        sandbox = self.sandbox
        if sandbox is None:
            raise LocalParserAttestationError("local parser sandbox is unavailable")
        parent_namespace = (
            _network_namespace_identity()
            if self._runner is _bounded_process
            else "net:[unit-test-parent]"
        )
        result = self._runner(
            (
                str(self._python_launch),
                "-I",
                "-m",
                _XLS_WORKER_MODULE,
                "--sandbox-self-test",
                "--parent-network-namespace",
                parent_namespace,
                "--implementation-sha256",
                self._implementation_digest,
            ),
            timeout_seconds=10,
            max_stdout_bytes=1_024,
            max_stderr_bytes=1_024,
            max_memory_bytes=134_217_728,
            sandbox=sandbox,
        )
        if result != _ProcessResult(0, b"sandbox-ok", b""):
            raise LocalParserAttestationError("network sandbox self-test failed closed")

    def _probe_image_worker(self) -> None:
        config = self.ocr
        sandbox = self.sandbox
        if config is None or sandbox is None:
            raise LocalParserAttestationError("OCR worker probe contract is invalid")
        result = self._runner(
            (
                str(self._python_launch),
                "-I",
                "-m",
                _XLS_WORKER_MODULE,
                "--image-worker",
                "--self-test",
                "--pillow-version",
                config.pillow_version,
                "--pillow-manifest-sha256",
                config.pillow_manifest_sha256,
                "--implementation-sha256",
                self._implementation_digest,
            ),
            timeout_seconds=min(config.timeout_seconds, 10),
            max_stdout_bytes=1_024,
            max_stderr_bytes=1_024,
            max_memory_bytes=config.max_memory_bytes,
            sandbox=sandbox,
        )
        if result != _ProcessResult(0, b"self-test-ok", b""):
            raise LocalParserAttestationError("OCR image worker self-test failed closed")

    def _probe_xls_worker(self) -> None:
        config = self.legacy_xls
        sandbox = self.sandbox
        if config is None or sandbox is None:
            raise LocalParserAttestationError("legacy XLS worker probe contract is invalid")
        result = self._runner(
            self._xls_worker_command(config, self_test=True),
            timeout_seconds=min(config.timeout_seconds, 10),
            max_stdout_bytes=1_024,
            max_stderr_bytes=1_024,
            max_memory_bytes=config.max_memory_bytes,
            sandbox=sandbox,
        )
        if result != _ProcessResult(0, b"self-test-ok", b""):
            raise LocalParserAttestationError("legacy XLS worker self-test failed closed")

    def _bounded(self, text: str) -> str:
        if not isinstance(text, str) or "\x00" in text:
            raise evidence.EvidenceAnalysisValidationError(
                "extracted text contract is invalid"
            )
        if len(text.encode("utf-8")) > self.maximum_bytes:
            raise evidence.EvidenceAnalysisValidationError(
                "extracted text exceeds its byte bound"
            )
        return super()._bounded(text)

    def _xls_worker_command(
        self,
        config: LegacyXLSConfig,
        *,
        self_test: bool,
    ) -> tuple[str, ...]:
        command = [
            str(self._python_launch),
            "-I",
            "-m",
            _XLS_WORKER_MODULE,
            "--xls-worker",
            "--xlrd-version",
            config.xlrd_version,
            "--xlrd-manifest-sha256",
            config.xlrd_manifest_sha256,
            "--olefile-version",
            config.olefile_version,
            "--olefile-manifest-sha256",
            config.olefile_manifest_sha256,
            "--max-workbook-stream-bytes",
            str(config.max_workbook_stream_bytes),
            "--max-record-bytes",
            str(config.max_record_bytes),
            "--max-records",
            str(config.max_records),
            "--max-sheets",
            str(config.max_sheets),
            "--max-rows-per-sheet",
            str(config.max_rows_per_sheet),
            "--max-columns-per-sheet",
            str(config.max_columns_per_sheet),
            "--max-cells",
            str(config.max_cells),
            "--max-output-bytes",
            str(min(config.max_output_bytes, self.maximum_bytes)),
            "--implementation-sha256",
            self._implementation_digest,
        ]
        if self_test:
            command.append("--self-test")
        return tuple(command)

    def authority(self, *, valid_until: float) -> evidence.EvidenceAdapterAuthority:
        # The v3 identity is distinct from the historical metadata-only image /
        # no-XLS adapter. Existing registry records remain append-only and are
        # not silently reinterpreted after an upgrade.
        if self._runner is not _bounded_process:
            raise LocalParserAttestationError(
                "non-stock local parser runner cannot issue production authority"
            )
        configuration = {
            "schema": "lightwork.ai-evidence.governed-local-extraction-config.v3",
            "maximum_bytes": self.maximum_bytes,
            "sandbox": asdict(self.sandbox) if self.sandbox is not None else None,
            "ocr": asdict(self.ocr) if self.ocr is not None else None,
            "legacy_xls": asdict(self.legacy_xls) if self.legacy_xls is not None else None,
            "implementation_components": self._implementation_components,
            "parser_versions": {
                name: (
                    importlib.metadata.version(name)
                    if self._distribution_available(name)
                    else "unavailable"
                )
                for name in ("openpyxl", "Pillow", "pypdf")
            },
            "python_executable_sha256": self._python_executable_sha256,
            "python_version": sys.version.split()[0],
        }
        base = super().authority(valid_until=valid_until)
        raw = replace(
            base,
            adapter_id=_ADAPTER_ID,
            revision=_ADAPTER_REVISION,
            implementation_sha256=self._implementation_digest,
            configuration_sha256=_canonical_sha256(configuration),
            authority_sha256=_ZERO_DIGEST,
        )
        return replace(raw, authority_sha256=evidence.adapter_authority_sha256(raw))

    @staticmethod
    def _distribution_available(name: str) -> bool:
        try:
            importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            return False
        return True

    def _verify_static_identity(self) -> None:
        if (
            _implementation_components() != self._implementation_components
            or
            _implementation_sha256() != self._implementation_digest
            or _file_sha256(self._python_executable) != self._python_executable_sha256
            or _resolved_or_none(self._python_launch) != self._python_executable
        ):
            raise LocalParserAttestationError("local parser implementation changed")
        if self.sandbox is not None:
            if _file_sha256(Path(self.sandbox.launcher)) != self.sandbox.launcher_sha256:
                raise LocalParserAttestationError("sandbox launcher changed")
        if self.ocr is not None:
            if (
                _file_sha256(Path(self.ocr.traineddata_path))
                != self.ocr.traineddata_sha256
                or _manifest_sha256(
                    self.ocr.runtime_library_paths, "OCR runtime libraries"
                )
                != self.ocr.runtime_libraries_sha256
            ):
                raise LocalParserAttestationError("OCR runtime dependency changed")
            _check_distribution_manifest("Pillow", self.ocr.pillow_manifest_sha256)
        if self.legacy_xls is not None:
            _check_distribution_manifest("xlrd", self.legacy_xls.xlrd_manifest_sha256)
            _check_distribution_manifest("olefile", self.legacy_xls.olefile_manifest_sha256)

    def _ocr_text(self, content: bytes, media_type: str) -> str:
        config = self.ocr
        if config is None:
            return super()._image_text(content)
        sandbox = self.sandbox
        if sandbox is None:
            raise LocalParserAttestationError("OCR network sandbox is unavailable")
        self._verify_static_identity()
        if _file_sha256(Path(config.executable)) != config.executable_sha256:
            raise LocalParserAttestationError("OCR executable digest mismatch")
        if _installed_version("Pillow") != config.pillow_version:
            raise LocalParserAttestationError("Pillow local parser version mismatch")
        if _tesseract_version(config, self._runner, sandbox) != config.tesseract_version:
            raise LocalParserAttestationError("OCR executable version mismatch")
        _require_tesseract_english(config, self._runner, sandbox)
        validation_command = (
            str(self._python_launch),
            "-I",
            "-m",
            _XLS_WORKER_MODULE,
            "--image-worker",
            "--pillow-version",
            config.pillow_version,
            "--pillow-manifest-sha256",
            config.pillow_manifest_sha256,
            "--media-type",
            media_type,
            "--max-pixels",
            str(config.max_pixels),
            "--implementation-sha256",
            self._implementation_digest,
        )
        try:
            validation = self._runner(
                validation_command,
                input_bytes=content,
                timeout_seconds=config.timeout_seconds,
                max_stdout_bytes=1_024,
                max_stderr_bytes=1_024,
                max_memory_bytes=config.max_memory_bytes,
                sandbox=sandbox,
            )
        except _ProcessTimeExceeded as exc:
            raise evidence.EvidenceAnalysisValidationError(
                "OCR image validation exceeded its time bound"
            ) from exc
        except _OutputBoundExceeded as exc:
            raise evidence.EvidenceAnalysisValidationError(
                "OCR image validation exceeded its output bound"
            ) from exc
        if validation.returncode != 0 or validation.stdout != b"ok":
            try:
                code = validation.stderr.decode("ascii", errors="strict").strip()
            except UnicodeDecodeError:
                code = ""
            if _IMAGE_WORKER_ERROR_RE.fullmatch(code) is None:
                code = "image_validation_failed"
            if code in {"image_dependency_mismatch", "image_implementation_mismatch"}:
                raise LocalParserAttestationError(
                    "OCR image parser attestation mismatch"
                )
            raise evidence.EvidenceAnalysisValidationError(
                "OCR image validation failed closed"
            )
        suffix = ".jpg" if media_type == evidence.MEDIA_JPEG else ".png"
        with tempfile.TemporaryDirectory(prefix="lightwork-evidence-ocr-") as directory:
            input_path = Path(directory, f"artifact{suffix}")
            try:
                input_path.write_bytes(content)
                if os.name != "nt":
                    input_path.chmod(0o600)
                result = self._runner(
                    (
                        config.executable,
                        str(input_path),
                        "stdout",
                        "--psm",
                        "6",
                        "-l",
                        "eng",
                        "--tessdata-dir",
                        str(Path(config.traineddata_path).parent),
                    ),
                    timeout_seconds=config.timeout_seconds,
                    max_stdout_bytes=config.max_output_bytes,
                    max_stderr_bytes=16_384,
                    max_memory_bytes=config.max_memory_bytes,
                    cwd=directory,
                    sandbox=sandbox,
                )
            except _ProcessTimeExceeded as exc:
                raise evidence.EvidenceAnalysisValidationError(
                    "OCR process exceeded its time bound"
                ) from exc
            except _OutputBoundExceeded as exc:
                raise evidence.EvidenceAnalysisValidationError(
                    "OCR process exceeded its output bound"
                ) from exc
        if result.returncode != 0:
            raise evidence.EvidenceAnalysisValidationError("OCR process failed closed")
        if _file_sha256(Path(config.executable)) != config.executable_sha256:
            raise LocalParserAttestationError("OCR executable changed during extraction")
        self._verify_static_identity()
        try:
            return self._bounded(result.stdout.decode("utf-8", errors="strict"))
        except UnicodeDecodeError as exc:
            raise evidence.EvidenceAnalysisValidationError(
                "OCR output encoding is invalid"
            ) from exc

    def _legacy_xls_text(self, content: bytes) -> str:
        config = self.legacy_xls
        if config is None:
            raise LocalParserAttestationError("legacy XLS runtime is disabled")
        self._verify_static_identity()
        sandbox = self.sandbox
        if sandbox is None:
            raise LocalParserAttestationError("legacy XLS network sandbox is unavailable")
        _check_dependency("xlrd", config.xlrd_version)
        _check_dependency("olefile", config.olefile_version)
        command = self._xls_worker_command(config, self_test=False)
        try:
            result = self._runner(
                command,
                input_bytes=content,
                timeout_seconds=config.timeout_seconds,
                max_stdout_bytes=min(config.max_output_bytes, self.maximum_bytes),
                max_stderr_bytes=4_096,
                max_memory_bytes=config.max_memory_bytes,
                sandbox=sandbox,
            )
        except _ProcessTimeExceeded as exc:
            raise evidence.EvidenceAnalysisValidationError(
                "legacy XLS parser exceeded its time bound"
            ) from exc
        except _OutputBoundExceeded as exc:
            raise evidence.EvidenceAnalysisValidationError(
                "legacy XLS parser exceeded its output bound"
            ) from exc
        if result.returncode != 0:
            try:
                code = result.stderr.decode("ascii", errors="strict").strip()
            except UnicodeDecodeError:
                code = ""
            if _WORKER_ERROR_RE.fullmatch(code) is None:
                code = "xls_parse_failed"
            messages = {
                "xls_dependency_unavailable": "legacy XLS parser dependency is unavailable",
                "xls_dependency_mismatch": "legacy XLS parser dependency version mismatch",
                "xls_formula_unsupported": "legacy XLS formulas are unsupported",
                "xls_macro_unsupported": "legacy XLS macros are unsupported",
                "xls_external_unsupported": "legacy XLS external references or encryption are unsupported",
                "xls_feature_unsupported": "legacy XLS feature is unsupported",
                "xls_resource_bound": "legacy XLS resource bound exceeded",
                "xls_invalid_container": "legacy XLS container is invalid",
                "xls_cell_error": "legacy XLS error cells are unsupported",
                "xls_implementation_mismatch": "legacy XLS parser implementation changed",
            }
            message = messages.get(code, "legacy XLS parsing failed closed")
            error_type = (
                LocalParserAttestationError
                if code
                in {
                    "xls_dependency_unavailable",
                    "xls_dependency_mismatch",
                    "xls_implementation_mismatch",
                }
                else evidence.EvidenceAnalysisValidationError
            )
            raise error_type(message)
        try:
            self._verify_static_identity()
            return self._bounded(result.stdout.decode("utf-8", errors="strict"))
        except UnicodeDecodeError as exc:
            raise evidence.EvidenceAnalysisValidationError(
                "legacy XLS output encoding is invalid"
            ) from exc

    def _extract_text(self, artifact: evidence.EvidenceArtifact) -> str:
        if artifact.media_type == evidence.MEDIA_XLS:
            return self._legacy_xls_text(artifact.content)
        if artifact.media_type in {evidence.MEDIA_JPEG, evidence.MEDIA_PNG}:
            return self._ocr_text(artifact.content, artifact.media_type)
        return super()._extract_text(artifact)


class _WorkerFailure(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class _XLSLimits:
    max_workbook_stream_bytes: int
    max_record_bytes: int
    max_records: int
    max_sheets: int
    max_rows_per_sheet: int
    max_columns_per_sheet: int
    max_cells: int
    max_output_bytes: int


def _read_bounded_stdin(maximum_bytes: int = 20 * 1024 * 1024) -> bytes:
    content = sys.stdin.buffer.read(maximum_bytes + 1)
    if not content or len(content) > maximum_bytes:
        raise _WorkerFailure("xls_resource_bound")
    return content


def _workbook_stream(content: bytes, limits: _XLSLimits) -> bytes:
    try:
        import olefile
    except ImportError as exc:
        raise _WorkerFailure("xls_dependency_unavailable") from exc
    try:
        with olefile.OleFileIO(BytesIO(content), raise_defects=olefile.DEFECT_INCORRECT) as ole:
            paths = [tuple(item) for item in ole.listdir(streams=True, storages=False)]
            allowed = {
                ("Workbook",),
                ("Book",),
                ("\x05SummaryInformation",),
                ("\x05DocumentSummaryInformation",),
            }
            if any(path not in allowed for path in paths):
                raise _WorkerFailure("xls_macro_unsupported")
            candidates = [path for path in paths if path in {("Workbook",), ("Book",)}]
            if len(candidates) != 1:
                raise _WorkerFailure("xls_invalid_container")
            stream = ole.openstream(candidates[0])
            workbook = stream.read(limits.max_workbook_stream_bytes + 1)
            if not workbook or len(workbook) > limits.max_workbook_stream_bytes:
                raise _WorkerFailure("xls_resource_bound")
            return workbook
    except _WorkerFailure:
        raise
    except Exception as exc:
        raise _WorkerFailure("xls_invalid_container") from exc


def _cell_extent(record_id: int, payload: bytes) -> tuple[int, int, int] | None:
    if record_id in _CELL_RECORDS:
        if len(payload) < 4:
            raise _WorkerFailure("xls_invalid_container")
        row, column = struct.unpack_from("<HH", payload)
        return row, column, 1
    if record_id in _MULTI_CELL_RECORDS:
        if len(payload) < 6:
            raise _WorkerFailure("xls_invalid_container")
        row, first_column = struct.unpack_from("<HH", payload)
        last_column = struct.unpack_from("<H", payload, len(payload) - 2)[0]
        if last_column < first_column:
            raise _WorkerFailure("xls_invalid_container")
        return row, last_column, last_column - first_column + 1
    return None


def _validate_biff8(workbook: bytes, limits: _XLSLimits) -> int:  # noqa: C901
    offset = 0
    records = 0
    sheets = 0
    cells = 0
    in_substream = False
    saw_globals = False
    while offset < len(workbook):
        if len(workbook) - offset < 4:
            # CFB sector padding is permitted only after the final EOF and must
            # be all zero bytes.
            if not in_substream and workbook[offset:] == b"\x00" * (len(workbook) - offset):
                break
            raise _WorkerFailure("xls_invalid_container")
        record_id, length = struct.unpack_from("<HH", workbook, offset)
        if record_id == 0 and length == 0 and not in_substream:
            if any(workbook[offset:]):
                raise _WorkerFailure("xls_invalid_container")
            break
        offset += 4
        records += 1
        if records > limits.max_records or length > limits.max_record_bytes:
            raise _WorkerFailure("xls_resource_bound")
        end = offset + length
        if end > len(workbook):
            raise _WorkerFailure("xls_invalid_container")
        payload = workbook[offset:end]
        offset = end
        if record_id in _BIFF_FORMULA_RECORDS:
            raise _WorkerFailure("xls_formula_unsupported")
        if record_id in _BIFF_MACRO_OR_ACTIVE_RECORDS:
            raise _WorkerFailure("xls_macro_unsupported")
        if record_id in _BIFF_EXTERNAL_OR_ENCRYPTED_RECORDS:
            raise _WorkerFailure("xls_external_unsupported")
        if record_id not in _BIFF_SAFE_RECORDS:
            raise _WorkerFailure("xls_feature_unsupported")
        if record_id == _BIFF_BOF:
            if in_substream or len(payload) < 4:
                raise _WorkerFailure("xls_invalid_container")
            version, substream_type = struct.unpack_from("<HH", payload)
            if version != 0x0600:
                raise _WorkerFailure("xls_feature_unsupported")
            if substream_type == 0x0005:
                if saw_globals:
                    raise _WorkerFailure("xls_invalid_container")
                saw_globals = True
            elif substream_type == 0x0010:
                sheets += 1
                if sheets > limits.max_sheets:
                    raise _WorkerFailure("xls_resource_bound")
            elif substream_type == 0x0040:
                raise _WorkerFailure("xls_macro_unsupported")
            else:
                raise _WorkerFailure("xls_feature_unsupported")
            in_substream = True
        elif record_id == _BIFF_EOF:
            if not in_substream or length != 0:
                raise _WorkerFailure("xls_invalid_container")
            in_substream = False
        elif not in_substream:
            raise _WorkerFailure("xls_invalid_container")
        extent = _cell_extent(record_id, payload)
        if extent is not None:
            row, column, count = extent
            if (
                row >= limits.max_rows_per_sheet
                or column >= limits.max_columns_per_sheet
            ):
                raise _WorkerFailure("xls_resource_bound")
            cells += count
            if cells > limits.max_cells:
                raise _WorkerFailure("xls_resource_bound")
    if in_substream or not saw_globals or sheets < 1:
        raise _WorkerFailure("xls_invalid_container")
    return sheets


def _render_xls(content: bytes, limits: _XLSLimits, expected_sheets: int) -> bytes:
    try:
        import xlrd
    except ImportError as exc:
        raise _WorkerFailure("xls_dependency_unavailable") from exc
    try:
        workbook = xlrd.open_workbook(
            file_contents=content,
            formatting_info=False,
            on_demand=True,
            ragged_rows=True,
        )
        try:
            if workbook.nsheets != expected_sheets or workbook.nsheets > limits.max_sheets:
                raise _WorkerFailure("xls_invalid_container")
            fragments: list[str] = []
            total_bytes = 0
            cells = 0
            for sheet in workbook.sheets():
                if (
                    sheet.nrows > limits.max_rows_per_sheet
                    or sheet.ncols > limits.max_columns_per_sheet
                ):
                    raise _WorkerFailure("xls_resource_bound")
                for row in range(sheet.nrows):
                    for cell in sheet.row(row):
                        if cell.ctype in {xlrd.XL_CELL_EMPTY, xlrd.XL_CELL_BLANK}:
                            continue
                        cells += 1
                        if cells > limits.max_cells:
                            raise _WorkerFailure("xls_resource_bound")
                        if cell.ctype == xlrd.XL_CELL_ERROR:
                            raise _WorkerFailure("xls_cell_error")
                        if cell.ctype == xlrd.XL_CELL_BOOLEAN:
                            rendered = "true" if bool(cell.value) else "false"
                        elif cell.ctype == xlrd.XL_CELL_DATE:
                            rendered = xlrd.xldate_as_datetime(
                                cell.value, workbook.datemode
                            ).isoformat()
                        elif cell.ctype in {xlrd.XL_CELL_TEXT, xlrd.XL_CELL_NUMBER}:
                            rendered = str(cell.value)
                        else:
                            raise _WorkerFailure("xls_feature_unsupported")
                        if rendered.startswith("="):
                            raise _WorkerFailure("xls_formula_unsupported")
                        encoded = rendered.encode("utf-8")
                        delimiter = 1 if fragments else 0
                        total_bytes += len(encoded) + delimiter
                        if total_bytes > limits.max_output_bytes:
                            raise _WorkerFailure("xls_resource_bound")
                        fragments.append(rendered)
            return "\n".join(fragments).encode("utf-8")
        finally:
            workbook.release_resources()
    except _WorkerFailure:
        raise
    except Exception as exc:
        raise _WorkerFailure("xls_parse_failed") from exc


def _worker_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--xls-worker", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--xlrd-version", required=True)
    parser.add_argument("--xlrd-manifest-sha256", required=True)
    parser.add_argument("--olefile-version", required=True)
    parser.add_argument("--olefile-manifest-sha256", required=True)
    parser.add_argument("--max-workbook-stream-bytes", type=int, required=True)
    parser.add_argument("--max-record-bytes", type=int, required=True)
    parser.add_argument("--max-records", type=int, required=True)
    parser.add_argument("--max-sheets", type=int, required=True)
    parser.add_argument("--max-rows-per-sheet", type=int, required=True)
    parser.add_argument("--max-columns-per-sheet", type=int, required=True)
    parser.add_argument("--max-cells", type=int, required=True)
    parser.add_argument("--max-output-bytes", type=int, required=True)
    parser.add_argument("--implementation-sha256", required=True)
    return parser


def _image_worker_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--image-worker", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--pillow-version", required=True)
    parser.add_argument("--pillow-manifest-sha256", required=True)
    parser.add_argument("--media-type")
    parser.add_argument("--max-pixels", type=int)
    parser.add_argument("--implementation-sha256", required=True)
    return parser


def _sandbox_worker_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--sandbox-self-test", action="store_true")
    parser.add_argument("--parent-network-namespace", required=True)
    parser.add_argument("--implementation-sha256", required=True)
    return parser


def _run_sandbox_worker(argv: Sequence[str]) -> int:
    try:
        arguments = _sandbox_worker_parser().parse_args(tuple(argv))
        if not arguments.sandbox_self_test:
            raise _WorkerFailure("sandbox_self_test_failed")
        if _implementation_sha256() != arguments.implementation_sha256:
            raise _WorkerFailure("sandbox_self_test_failed")
        current = _network_namespace_identity()
        if current == arguments.parent_network_namespace:
            raise _WorkerFailure("sandbox_self_test_failed")
        # Bubblewrap's new network namespace contains no external interface.
        # A non-blocking connect must fail immediately with an isolation error;
        # success, timeout, or a routable socket is fail-closed.
        import socket

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.setblocking(False)
            status = client.connect_ex(("192.0.2.1", 9))
        if status not in {
            errno.ENETUNREACH,
            errno.EHOSTUNREACH,
            errno.ENETDOWN,
            errno.EACCES,
            errno.EPERM,
        }:
            raise _WorkerFailure("sandbox_self_test_failed")
        sys.stdout.buffer.write(b"sandbox-ok")
        return 0
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        sys.stderr.write("sandbox_self_test_failed")
        return 2


def _run_image_worker(argv: Sequence[str]) -> int:
    try:
        arguments = _image_worker_parser().parse_args(tuple(argv))
        if not arguments.image_worker:
            raise _WorkerFailure("image_validation_failed")
        if _implementation_sha256() != arguments.implementation_sha256:
            raise _WorkerFailure("image_implementation_mismatch")
        if _installed_version("Pillow") != arguments.pillow_version:
            raise _WorkerFailure("image_dependency_mismatch")
        if (
            _distribution_manifest_sha256("Pillow")
            != arguments.pillow_manifest_sha256
        ):
            raise _WorkerFailure("image_dependency_mismatch")
        if arguments.self_test:
            from PIL import Image
            from PIL import __version__ as pillow_runtime_version

            if pillow_runtime_version != arguments.pillow_version or Image is None:
                raise _WorkerFailure("image_dependency_mismatch")
            sys.stdout.buffer.write(b"self-test-ok")
            return 0
        if arguments.media_type not in {evidence.MEDIA_JPEG, evidence.MEDIA_PNG}:
            raise _WorkerFailure("image_feature_unsupported")
        maximum_pixels = _integer(
            arguments.max_pixels, "max_pixels", 1, 100_000_000
        )
        content = _read_bounded_stdin(12 * 1024 * 1024)
        from PIL import Image

        warnings.simplefilter("error", Image.DecompressionBombWarning)
        with Image.open(BytesIO(content)) as image:
            actual_format = str(image.format or "").upper()
            expected_format = (
                "JPEG" if arguments.media_type == evidence.MEDIA_JPEG else "PNG"
            )
            width, height = image.size
            frames = int(getattr(image, "n_frames", 1))
            if (
                actual_format != expected_format
                or frames != 1
                or width <= 0
                or height <= 0
                or width * height > maximum_pixels
            ):
                raise _WorkerFailure("image_feature_unsupported")
            image.verify()
        sys.stdout.buffer.write(b"ok")
        return 0
    except LocalParserAttestationError:
        code = "image_dependency_mismatch"
    except _WorkerFailure as exc:
        code = exc.code
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        code = "image_validation_failed"
    sys.stderr.write(code)
    return 2


def _run_xls_worker(argv: Sequence[str]) -> int:
    try:
        arguments = _worker_parser().parse_args(tuple(argv))
        if not arguments.xls_worker:
            raise _WorkerFailure("xls_invalid_container")
        if _implementation_sha256() != arguments.implementation_sha256:
            raise _WorkerFailure("xls_implementation_mismatch")
        if (
            _installed_version("xlrd") != arguments.xlrd_version
            or _installed_version("olefile") != arguments.olefile_version
        ):
            raise _WorkerFailure("xls_dependency_mismatch")
        if (
            _distribution_manifest_sha256("xlrd")
            != arguments.xlrd_manifest_sha256
            or _distribution_manifest_sha256("olefile")
            != arguments.olefile_manifest_sha256
        ):
            raise _WorkerFailure("xls_dependency_mismatch")
        limits = _XLSLimits(
            max_workbook_stream_bytes=_integer(
                arguments.max_workbook_stream_bytes, "max_workbook_stream_bytes", 1_024, 67_108_864
            ),
            max_record_bytes=_integer(
                arguments.max_record_bytes, "max_record_bytes", 1_024, 16_777_215
            ),
            max_records=_integer(arguments.max_records, "max_records", 1, 1_000_000),
            max_sheets=_integer(arguments.max_sheets, "max_sheets", 1, 256),
            max_rows_per_sheet=_integer(
                arguments.max_rows_per_sheet, "max_rows_per_sheet", 1, 1_048_576
            ),
            max_columns_per_sheet=_integer(
                arguments.max_columns_per_sheet, "max_columns_per_sheet", 1, 256
            ),
            max_cells=_integer(arguments.max_cells, "max_cells", 1, 1_000_000),
            max_output_bytes=_integer(
                arguments.max_output_bytes, "max_output_bytes", 1_024, 10_485_760
            ),
        )
        if arguments.self_test:
            import olefile
            import xlrd

            if xlrd is None or olefile is None:
                raise _WorkerFailure("xls_dependency_mismatch")
            sys.stdout.buffer.write(b"self-test-ok")
            return 0
        content = _read_bounded_stdin()
        stream = _workbook_stream(content, limits)
        sheets = _validate_biff8(stream, limits)
        sys.stdout.buffer.write(_render_xls(content, limits, sheets))
        return 0
    except LocalParserAttestationError as exc:
        code = (
            "xls_dependency_unavailable"
            if "unavailable" in str(exc)
            else "xls_dependency_mismatch"
        )
    except _WorkerFailure as exc:
        code = exc.code
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        code = "xls_parse_failed"
    sys.stderr.write(code)
    return 2


def main(argv: Sequence[str] | None = None) -> int:
    selected = tuple(sys.argv[1:] if argv is None else argv)
    if selected and selected[0] == "--sandbox-self-test":
        return _run_sandbox_worker(selected)
    if selected and selected[0] == "--image-worker":
        return _run_image_worker(selected)
    return _run_xls_worker(selected)


if __name__ == "__main__":  # pragma: no cover - exercised through subprocess
    raise SystemExit(main())


__all__ = [
    "GovernedLocalExtractionAdapter",
    "LegacyXLSConfig",
    "LocalParserSandboxConfig",
    "LocalParserAttestationError",
    "TesseractOCRConfig",
]
