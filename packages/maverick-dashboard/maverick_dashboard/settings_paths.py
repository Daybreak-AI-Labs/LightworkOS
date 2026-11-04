"""Server locations chosen on Settings > All settings (the ``path`` control).

A location is only accepted when, on the server Lightwork runs on, it is a
full location, stays inside the allowed places, exists, is the right kind
(file or folder) and Lightwork may use it: read it, save into it when the
setting needs that, and -- for key files -- nobody else on the server can
read it. Every refusal is one plain sentence for the page.

The allowed places are Lightwork's own folders, the folder of its settings
file, the home folder of the account it runs as, and the server's usual
places for settings, certificates and mounted secrets. A deployment can
replace that list with ``MAVERICK_SETTINGS_PATH_ROOTS`` (locations separated
by the system path separator); the page itself can never widen it.

A setting may narrow the places further: ``scope="data"`` accepts only
Lightwork's data folder (its home), unless the deployment's own list above
allows more. A file Lightwork creates itself (``new_ok``) may not exist yet:
then its folder must exist and Lightwork must be able to save into it.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

ROOTS_ENV = "MAVERICK_SETTINGS_PATH_ROOTS"
_POSIX_ROOTS = ("/etc", "/run/secrets", "/var/lib", "/srv", "/opt")
# Where the server keeps installed programs (a ``program`` location may also
# be there, unless the deployment set its own list of places).
_POSIX_PROGRAM_ROOTS = ("/usr/bin", "/usr/local/bin", "/bin")


class PathRefused(ValueError):
    """A location the page explains in one plain sentence."""


def allowed_roots(scope: str = "", *, programs: bool = False) -> list[Path]:
    """The places a setting may point into (resolved, so links can't escape)."""
    raw = os.environ.get(ROOTS_ENV, "").strip()
    if scope == "data" and not raw:
        from maverick.paths import maverick_home

        items = [str(maverick_home())]
    elif raw:
        items = [part for part in raw.split(os.pathsep) if part.strip()]
    elif programs and os.name != "nt":
        base = allowed_roots(scope)
        return base + [root for root in (Path(p).resolve() for p in _POSIX_PROGRAM_ROOTS)
                       if root not in base]
    else:
        from maverick import config
        from maverick.paths import maverick_home

        items = [str(maverick_home()), str(config.config_path().parent), str(Path.home())]
        if os.name == "nt":
            program_data = os.environ.get("PROGRAMDATA", "").strip()
            if program_data:
                items.append(program_data)
        else:
            items.extend(_POSIX_ROOTS)
    roots: list[Path] = []
    for item in items:
        try:
            root = Path(item).expanduser().resolve()
        except (OSError, RuntimeError, ValueError):
            continue
        if root not in roots:
            roots.append(root)
    return roots


def _inside(path: Path, roots: list[Path]) -> bool:
    return any(path == root or root in path.parents for root in roots)


def _outside_message(scope: str) -> str:
    if scope == "data":
        from maverick.paths import maverick_home

        return (f"Lightwork keeps this inside its own data folder, {maverick_home()}. "
                "Choose a location there.")
    return ("Lightwork only uses locations inside its own folders and the server's usual "
            "places for settings, certificates and secrets.")


def _check_new_file(real: Path, normalized: Path) -> str:
    """A file Lightwork will create: its folder must exist and take new files."""
    folder = real.parent
    if not folder.is_dir():
        raise PathRefused("the folder for that file was not found on the server.")
    if not os.access(folder, os.R_OK | os.W_OK | os.X_OK):
        raise PathRefused("Lightwork isn't allowed to save files in that folder.")
    return str(normalized)


def _others_can_replace(info: os.stat_result, *folders: Path) -> bool:
    """A program everyone may change, or swap in a folder everyone may change
    (a shared folder with the sticky bit only lets owners swap their own)."""
    if info.st_mode & stat.S_IWOTH:
        return True
    for folder in folders:
        try:
            mode = folder.stat().st_mode
        except OSError:
            return True
        if mode & stat.S_IWOTH and not mode & stat.S_ISVTX:
            return True
    return False


def _check_program(real: Path, normalized: Path, info) -> None:
    if os.name == "nt" and real.suffix.lower() not in {".exe", ".com", ".cmd", ".bat"}:
        raise PathRefused("choose a Windows program, not a document. Put script files in the separate script field.")
    if not os.access(real, os.X_OK):
        raise PathRefused("that file is not a program Lightwork is allowed to run.")
    if os.name != "nt" and _others_can_replace(info, real.parent, normalized.parent):
        raise PathRefused("anyone on the server can change that program or its folder. Limit who can change them, then try again.")


def check(value: str, *, kind: str, writable: bool = False, private: bool = False,
          new_ok: bool = False, scope: str = "", program: bool = False) -> str:
    """Validate one location; return it as it will be stored.

    ``program``: a file Lightwork will run, so it may also be in the server's
    program folders and must be a program Lightwork may run.
    Raises :class:`PathRefused` with a sentence a person can act on.
    """
    text = str(value or "").strip()
    if not text or "\x00" in text:
        raise PathRefused("enter a location on the server.")
    entered = Path(text).expanduser()
    if not entered.is_absolute():
        raise PathRefused("enter the full location, starting from the top folder of the server.")
    normalized = Path(os.path.normpath(str(entered)))
    try:
        real = entered.resolve()
        # "link/.." names one file to the server and another once stored:
        # store only a location that leads to the file checked below.
        if normalized.resolve() != real:
            raise PathRefused("that location goes through a link and then back up with \"..\". "
                              "Enter the location without \"..\".")
    except (OSError, RuntimeError) as exc:
        raise PathRefused("that location could not be checked on the server.") from exc
    roots = allowed_roots(scope, programs=program)
    if not (_inside(normalized, roots) and _inside(real, roots)):
        raise PathRefused(_outside_message(scope))
    try:
        info = real.stat()
    except FileNotFoundError as exc:
        if new_ok and kind == "file":
            return _check_new_file(real, normalized)
        raise PathRefused("nothing was found at that location on the server.") from exc
    except OSError as exc:
        raise PathRefused("Lightwork isn't allowed to look at that location.") from exc
    if kind == "folder":
        if not stat.S_ISDIR(info.st_mode):
            raise PathRefused("that location is a file. Choose a folder.")
        if not os.access(real, os.R_OK | os.X_OK):
            raise PathRefused("Lightwork isn't allowed to open that folder.")
        if writable and not os.access(real, os.W_OK):
            raise PathRefused("Lightwork isn't allowed to save files in that folder.")
    else:
        if stat.S_ISDIR(info.st_mode):
            raise PathRefused("that location is a folder. Choose a file.")
        if not stat.S_ISREG(info.st_mode):
            raise PathRefused("that location is not an ordinary file.")
        if not os.access(real, os.R_OK):
            raise PathRefused("Lightwork isn't allowed to read that file.")
        if writable and not os.access(real, os.W_OK):
            raise PathRefused("Lightwork isn't allowed to save changes to that file.")
        if program:
            _check_program(real, normalized, info)
        if private and os.name != "nt" and info.st_mode & stat.S_IROTH:
            raise PathRefused(
                "anyone on the server can read that key file. Limit who can read it, "
                "then try again."
            )
    return str(normalized)


def describe_ok(kind: str, *, created_later: bool = False) -> str:
    """The sentence a successful check shows."""
    if kind == "folder":
        return "Found. Lightwork can use this folder."
    if created_later:
        return "The folder was found. Lightwork will create this file there when it first needs it."
    return "Found. Lightwork can read this file."


__all__ = ["PathRefused", "ROOTS_ENV", "allowed_roots", "check", "describe_ok"]
