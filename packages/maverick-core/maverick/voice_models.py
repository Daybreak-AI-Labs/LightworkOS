"""Local Whisper (whisper.cpp GGML) model management — the built-in STT path.

Speech-to-text has to work inside customer environments and on desktops:
no provider API key, no Python ML stack, optionally no network at all.
``tools/voice.py`` gets that from the whisper.cpp backend, which needs a
GGML weights file on disk. This module owns where those files live
(``<maverick_home>/models/whisper``), which releases are trusted (pinned
SHA-256), and how they are fetched:

- ``maverick voice setup`` — explicit, operator-driven download (air-gapped
  deployments run it wherever there IS network and copy the file in).
- auto-fetch on first use — opt-in via ``MAVERICK_VOICE_AUTO_FETCH=1`` or
  ``[voice] auto_fetch_model = true`` (the installer wizard offers it).

A download that does not hash to the pinned digest is discarded, never
installed: model weights execute math, not code, but a swapped file still
controls every transcript the platform acts on.
"""
from __future__ import annotations

import hashlib
import logging
import os
import tempfile
import threading
import urllib.request
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlparse

log = logging.getLogger(__name__)

DEFAULT_MODEL = "base"

# name -> (filename, sha256, size_bytes). Digests are the Hugging Face LFS
# oids for ggerganov/whisper.cpp; ``.en`` variants are English-only (slightly
# better English accuracy), the rest are multilingual.
KNOWN_MODELS: dict[str, tuple[str, str, int]] = {
    "tiny": (
        "ggml-tiny.bin",
        "be07e048e1e599ad46341c8d2a135645097a538221678b7acdd1b1919c6e1b21",  # pragma: allowlist secret
        77_691_713,
    ),
    "tiny.en": (
        "ggml-tiny.en.bin",
        "921e4cf8686fdd993dcd081a5da5b6c365bfde1162e72b08d75ac75289920b1f",  # pragma: allowlist secret
        77_704_715,
    ),
    "base": (
        "ggml-base.bin",
        "60ed5bc3dd14eea856493d334349b405782ddcaf0028d4b5df4088345fba2efe",  # pragma: allowlist secret
        147_951_465,
    ),
    "base.en": (
        "ggml-base.en.bin",
        "a03779c86df3323075f5e796cb2ce5029f00ec8869eee3fdfb897afe36c6d002",  # pragma: allowlist secret
        147_964_211,
    ),
    "small": (
        "ggml-small.bin",
        "1be3a9b2063867b937e64e2ec7483364a79917e157fa98c5d94b5c1fffea987b",  # pragma: allowlist secret
        487_601_967,
    ),
    "small.en": (
        "ggml-small.en.bin",
        "c6138d6d58ecc8322097e0f987c32f1be8bb0a18532a3f88f734d1bbf9c41e5d",  # pragma: allowlist secret
        487_614_201,
    ),
    "medium": (
        "ggml-medium.bin",
        "6c14d5adee5f86394037b4e4e8b59f1673b6cee10e3cf0b11bbdbee79c156208",  # pragma: allowlist secret
        1_533_763_059,
    ),
    "medium.en": (
        "ggml-medium.en.bin",
        "cc37e93478338ec7700281a7ac30a10128929eb8f427dda2e865faa8f6da4356",  # pragma: allowlist secret
        1_533_774_781,
    ),
    "large-v3": (
        "ggml-large-v3.bin",
        "64d182b440b98d5203c4f9bd541544d84c605196c4f7b845dfa11fb23594d1e2",  # pragma: allowlist secret
        3_095_033_483,
    ),
    "large-v3-turbo": (
        "ggml-large-v3-turbo.bin",
        "1fc70f774d38eb169993ac391eea357ef47c88757ef72ee5943879b7e8e2bc69",  # pragma: allowlist secret
        1_624_555_275,
    ),
}

_BASE_URL = "https://huggingface.co/ggerganov/whisper.cpp/resolve/main/"
_CHUNK = 1 << 20  # 1 MiB
_DOWNLOAD_LOCK = threading.Lock()


class DownloadCancelled(RuntimeError):
    """The operator cancelled before the verified file was installed."""


def _check_cancel(cancel: threading.Event | None) -> None:
    if cancel is not None and cancel.is_set():
        raise DownloadCancelled("Speech model setup was cancelled.")


def download_egress_permitted(url: str) -> bool:
    """A shared model never weakens deployment policy through a tenant overlay."""
    from .config import config_source_errors, load_global_config
    from .enterprise import deployment_enterprise_enabled, egress_permitted

    try:
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            return False
        global_config = load_global_config()
        if config_source_errors(include_tenant=True):
            return False
        if deployment_enterprise_enabled():
            allowed = (global_config.get("enterprise") or {}).get("allowed_hosts") or []
            if not isinstance(allowed, list) or not all(isinstance(host, str) for host in allowed):
                return False
            if parsed.hostname.lower().rstrip(".") not in {host.lower().strip().rstrip(".") for host in allowed}:
                return False
        return egress_permitted(url)
    except Exception:
        return False


class _ModelRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not download_egress_permitted(newurl):
            raise PermissionError("Speech model redirect is blocked by network policy.")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _open_model_url(url: str, *, timeout: float):
    if not download_egress_permitted(url):
        raise PermissionError("Speech model source is blocked by network policy.")
    # OpenerDirector.open remains covered by the shared urllib egress guard;
    # this extra handler preserves the deployment floor on every redirect.
    return urllib.request.build_opener(_ModelRedirect()).open(url, timeout=timeout)  # noqa: S310


def _voice_cfg() -> dict:
    try:
        from .config import load_config
        return dict(load_config().get("voice") or {})
    except Exception:  # config must never break voice paths
        return {}


def models_dir() -> Path:
    """Where GGML weights live. NOT tenant-scoped: weights are shared
    read-only artifacts, not tenant data."""
    from .paths import maverick_home
    return maverick_home() / "models" / "whisper"


def configured_model() -> str:
    """The model size setup/auto-fetch should install:
    ``MAVERICK_WHISPER_MODEL`` env > ``[voice] stt_model`` > ``base``."""
    env = (os.environ.get("MAVERICK_WHISPER_MODEL") or "").strip()
    if env:
        return env
    cfg = str(_voice_cfg().get("stt_model") or "").strip()
    return cfg or DEFAULT_MODEL


def model_path(name: str) -> Path:
    if name not in KNOWN_MODELS:
        raise ValueError(
            f"unknown Whisper model {name!r}; known: "
            + ", ".join(sorted(KNOWN_MODELS))
        )
    return models_dir() / KNOWN_MODELS[name][0]


# whisper.cpp program names Lightwork recognises (a ".exe" suffix is allowed).
PROGRAM_NAMES = ("whisper-cli", "whisper-cpp", "whisper.cpp")


def programs_dir() -> Path:
    """The installation's own programs folder, where desktop installers drop
    the bundled whisper.cpp program. NOT tenant-scoped, like the weights."""
    from .paths import maverick_home
    return maverick_home() / "bin"


def _checked_file(candidate: Path, root: Path) -> bool:
    """True when ``candidate`` is a regular file whose real location, after
    following any link, stays inside ``root``."""
    try:
        real_root = root.resolve(strict=True)
        real = candidate.resolve(strict=True)
        real.relative_to(real_root)
    except (OSError, RuntimeError, ValueError):
        return False
    return real.is_file()


def approved_programs() -> list[Path]:
    """whisper.cpp programs Settings may choose: files in :func:`programs_dir`
    with a recognised name that stay inside it (a link out is refused) and
    can be executed."""
    root = programs_dir()
    if not root.is_dir():
        return []
    out = []
    for cand in sorted(root.iterdir()):
        name = cand.name[:-4] if cand.name.lower().endswith(".exe") else cand.name
        if name in PROGRAM_NAMES and _checked_file(cand, root) \
                and os.access(cand.resolve(), os.X_OK):
            out.append(cand)
    return out


def approved_model_files() -> list[Path]:
    """GGML files Settings may choose: ``ggml-*.bin`` files in
    :func:`models_dir` that stay inside it (a link out is refused); a file with
    a pinned name must also have the pinned size."""
    root = models_dir()
    if not root.is_dir():
        return []
    sizes = {filename: size for filename, _sha, size in KNOWN_MODELS.values()}
    out = []
    for cand in sorted(root.glob("ggml-*.bin")):
        if not _checked_file(cand, root):
            continue
        size = sizes.get(cand.name)
        if size is None or cand.resolve().stat().st_size == size:
            out.append(cand)
    return out


def checked_program(name: object) -> Path | None:
    """The approved program called ``name`` (a file name, as All settings
    stores it), checked again now; None when it is not, or no longer, in
    :func:`approved_programs`."""
    return next((p for p in approved_programs() if p.name == str(name or "").strip()), None)


def checked_model_file(name: object) -> Path | None:
    """The approved model file called ``name``, checked again now, or None."""
    return next((p for p in approved_model_files() if p.name == str(name or "").strip()), None)


def installed_models() -> list[Path]:
    """GGML files present on disk (any ``ggml-*.bin``, including ones an
    operator copied in by hand). A link that leads out of the folder is not
    used; ``MAVERICK_WHISPER_CPP_MODEL`` names a file elsewhere."""
    d = models_dir()
    if not d.is_dir():
        return []
    return sorted(p for p in d.glob("ggml-*.bin") if _checked_file(p, d))


def verify_model(path: Path, *, cancel: threading.Event | None = None) -> bool | None:
    """True/False when ``path`` matches/violates a pinned digest; None when
    the filename isn't one we pin (operator-supplied model — allowed)."""
    pinned = {fn: sha for fn, sha, _ in KNOWN_MODELS.values()}
    sha = pinned.get(path.name)
    if sha is None:
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK), b""):
            _check_cancel(cancel)
            h.update(chunk)
    return h.hexdigest() == sha


def model_fingerprint(stat) -> tuple[int, int, int, int, int]:
    # Windows ctime is creation time, not inode change time. NTFS tunneling
    # after replacement can expose different creation times through a held
    # descriptor and Path.stat for the SAME file id. POSIX ctime is useful.
    changed = 0 if os.name == "nt" else stat.st_ctime_ns
    return stat.st_size, stat.st_mtime_ns, stat.st_dev, stat.st_ino, changed


def verified_model_fingerprint(path: Path, *, cancel: threading.Event | None = None):
    """Bind verification to a stable opened file, never a later replacement."""
    pinned = next(((sha, size) for fn, sha, size in KNOWN_MODELS.values() if fn == path.name), None)
    if pinned is None:
        return None
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        before = model_fingerprint(os.fstat(stream.fileno()))
        if before[0] != pinned[1]:
            return None
        for chunk in iter(lambda: stream.read(_CHUNK), b""):
            _check_cancel(cancel)
            digest.update(chunk)
        after = model_fingerprint(os.fstat(stream.fileno()))
    _check_cancel(cancel)
    if before != after or after != model_fingerprint(path.stat()) or digest.hexdigest() != pinned[0]:
        return None
    return after


def auto_fetch_enabled() -> bool:
    """Runtime download of the configured model on first use / warm-up.

    OFF unless the operator opted in. Opening the app is not consent to a
    large model download. An explicit
    ``MAVERICK_VOICE_AUTO_FETCH`` env or ``[voice] auto_fetch_model`` config
    value always wins, in either direction."""
    raw = (os.environ.get("MAVERICK_VOICE_AUTO_FETCH") or "").strip().lower()
    if raw:
        return raw not in {"0", "false", "no", "off"}
    cfg = _voice_cfg()
    if "auto_fetch_model" in cfg:
        return bool(cfg["auto_fetch_model"])
    return False


def download_model(
    name: str | None = None,
    *,
    force: bool = False,
    progress: Callable[[int, int], None] | None = None,
    timeout: float = 60.0,
    cancel: threading.Event | None = None,
    verify_existing: bool = False,
    before_install: Callable[[], None] | None = None,
) -> Path:
    """Fetch a GGML model into :func:`models_dir`, verifying the pinned
    SHA-256 before install (download to a temp file, hash, atomic rename).

    Raises ``ValueError`` for an unknown name or a digest mismatch, and
    ``OSError``/``URLError`` on network failure. Returns the installed path.
    """
    # Serialize startup, explicit setup, and transcription in this process.
    # Waiting remains cancellable; the explicit setup controller is single-flight.
    while not _DOWNLOAD_LOCK.acquire(timeout=0.1):
        _check_cancel(cancel)
    try:
        return _download_model(name or configured_model(), force=force, progress=progress,
                               timeout=timeout, cancel=cancel, verify_existing=verify_existing,
                               before_install=before_install)
    finally:
        _DOWNLOAD_LOCK.release()


def _download_model(name, *, force, progress, timeout, cancel, verify_existing, before_install):
    _check_cancel(cancel)
    dest = model_path(name)  # raises on unknown name
    filename, want_sha, want_size = KNOWN_MODELS[name]
    if dest.exists() and not force:
        if not verify_existing or (dest.stat().st_size == want_size and verify_model(dest, cancel=cancel) is True):
            _check_cancel(cancel)
            if before_install:
                before_install()
            return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    url = _BASE_URL + filename

    # Temp file in the destination dir so the final rename is atomic (same fs).
    fd, tmp_name = tempfile.mkstemp(prefix=filename + ".", suffix=".part",
                                    dir=dest.parent)
    tmp = Path(tmp_name)
    h = hashlib.sha256()
    done = 0
    try:
        with os.fdopen(fd, "wb") as out, _open_model_url(
            url, timeout=timeout
        ) as resp:
            while True:
                _check_cancel(cancel)
                chunk = resp.read(_CHUNK)
                _check_cancel(cancel)
                if not chunk:
                    break
                if done + len(chunk) > want_size:
                    raise ValueError(f"size exceeds the pinned limit for {filename}")
                out.write(chunk)
                h.update(chunk)
                done += len(chunk)
                if progress:
                    progress(done, want_size)
        _check_cancel(cancel)
        if done != want_size:
            raise ValueError(f"size mismatch for {filename}: expected {want_size} bytes")
        if h.hexdigest() != want_sha:
            raise ValueError(
                f"checksum mismatch for {filename}: got {h.hexdigest()}, "
                f"expected {want_sha} — refusing to install"
            )
        if before_install:
            before_install()
        _check_cancel(cancel)
        tmp.replace(dest)
    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)
    log.info("installed whisper model %s (%d bytes)", dest, done)
    return dest


def locate_model(*, cancel: threading.Event | None = None, timeout: float = 60.0) -> Path | None:
    """The GGML file the whisper.cpp backend should load, or None.

    Order: ``MAVERICK_WHISPER_CPP_MODEL`` env path > ``[voice]
    whisper_cpp_model`` (a file in :func:`models_dir` chosen on the All
    settings page, checked again here by :func:`checked_model_file`) > the
    configured size if installed > any installed GGML file (so a hand-copied
    model Just Works) > auto-fetch of the configured size when enabled.
    """
    raw = os.environ.get("MAVERICK_WHISPER_CPP_MODEL")
    if raw:
        p = Path(str(raw)).expanduser()
        if p.is_file():
            return p
        log.warning("configured whisper model %s not found", p)
    chosen = _voice_cfg().get("whisper_cpp_model")
    if chosen:
        checked = checked_model_file(chosen)
        if checked is not None:
            return checked
        log.warning("[voice] whisper_cpp_model %r is not an approved file in the "
                    "speech model folder; ignoring it (MAVERICK_WHISPER_CPP_MODEL "
                    "names a file elsewhere)", chosen)
    name = configured_model()
    try:
        preferred = model_path(name)
    except ValueError:
        log.warning("unknown [voice] stt_model %r; known: %s",
                    name, ", ".join(sorted(KNOWN_MODELS)))
        preferred = None
    if preferred is not None and preferred.is_file():
        return preferred
    installed = installed_models()
    if installed:
        return installed[0]
    if preferred is not None and auto_fetch_enabled():
        try:
            return download_model(name, cancel=cancel, timeout=timeout)
        except Exception as e:
            log.warning("whisper model auto-fetch failed: %s", e)
    return None
