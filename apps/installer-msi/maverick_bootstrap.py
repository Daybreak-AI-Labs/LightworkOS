"""First-run and upgrade helper for the engineering-only Windows MSI launcher.

This bootstrap is not an offline platform installer: the MSI carries only the
core wheel and pip resolves its dependencies from live PyPI. ``maverick.cmd``
invokes this stdlib-only helper before dispatching the CLI. A successful import
is not a version check: an MSI upgrade can otherwise keep running an older
user-site package indefinitely.
"""
from __future__ import annotations

import argparse
import importlib.metadata
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

_DISTRIBUTION = "maverick-agent"
_WHEEL_RE = re.compile(
    r"^maverick_agent-(?P<version>[^-]+)"
    r"(?:-(?P<build>\d[^-]*))?"
    r"-(?P<python>[A-Za-z0-9_.]+)"
    r"-(?P<abi>[A-Za-z0-9_.]+)"
    r"-(?P<platform>[A-Za-z0-9_.]+)\.whl$"
)


class BootstrapError(RuntimeError):
    """The bundled MSI payload cannot safely establish its exact version."""


def bundled_wheel(wheel_dir: Path, product_version: str) -> Path:
    """Return the one valid staged wheel matching the MSI ProductVersion."""
    candidates = sorted(wheel_dir.glob("maverick_agent-*.whl"))
    if len(candidates) != 1:
        raise BootstrapError(
            f"expected one bundled maverick-agent wheel, found {len(candidates)}"
        )
    wheel = candidates[0]
    match = _WHEEL_RE.fullmatch(wheel.name)
    if match is None:
        raise BootstrapError(f"invalid PEP 427 wheel filename: {wheel.name}")
    if match.group("version") != product_version:
        raise BootstrapError(
            f"bundled wheel version {match.group('version')} does not match "
            f"MSI ProductVersion {product_version}"
        )
    return wheel


def installed_version() -> str | None:
    """Installed maverick-agent version visible to the launcher interpreter."""
    try:
        return importlib.metadata.version(_DISTRIBUTION)
    except importlib.metadata.PackageNotFoundError:
        return None


def _install(wheel: Path, python: str) -> None:
    subprocess.run(
        [
            python,
            "-m",
            "pip",
            "install",
            "--user",
            "--quiet",
            "--no-input",
            "--upgrade",
            "--force-reinstall",
            str(wheel),
        ],
        check=True,
    )


def _verify(product_version: str, python: str) -> bool:
    # Verify in a fresh interpreter so import/metadata caches from before pip
    # cannot turn a successful upgrade into a false mismatch.
    result = subprocess.run(
        [
            python,
            "-c",
            (
                "import importlib.metadata as m,sys;"
                "sys.exit(0 if m.version('maverick-agent')==sys.argv[1] else 1)"
            ),
            product_version,
        ],
        check=False,
    )
    return result.returncode == 0


def bootstrap(
    product_version: str,
    wheel_dir: Path,
    *,
    python: str = sys.executable,
    version_reader: Callable[[], str | None] = installed_version,
    installer: Callable[[Path, str], None] = _install,
    verifier: Callable[[str, str], bool] = _verify,
) -> str:
    """Ensure the launcher interpreter sees exactly ``product_version``.

    Returns ``"current"``, ``"installed"``, or ``"upgraded"`` for diagnostics.
    """
    wheel = bundled_wheel(wheel_dir, product_version)
    before = version_reader()
    if before == product_version:
        return "current"
    installer(wheel, python)
    if not verifier(product_version, python):
        raise BootstrapError(
            f"pip completed but {_DISTRIBUTION} {product_version} is not visible"
        )
    return "installed" if before is None else "upgraded"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--product-version", required=True)
    parser.add_argument("--wheel-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        outcome = bootstrap(args.product_version, args.wheel_dir)
    except (BootstrapError, OSError, subprocess.SubprocessError) as exc:
        print(f"maverick: {exc}", file=sys.stderr)
        return 1
    if outcome != "current":
        print(f"maverick: {outcome} maverick-agent {args.product_version}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
