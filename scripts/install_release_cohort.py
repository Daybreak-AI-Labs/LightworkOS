#!/usr/bin/env python3
"""Install or wheel a reviewed Lightwork release cohort in one transaction."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CohortPackage:
    distribution: str
    source: Path
    runtime_module: str


def _parse_toml_with_python(path: Path, python: str) -> dict:
    script = """
import json
from pathlib import Path
import pip
from pip._vendor import tomli

pip_root = Path(pip.__file__).resolve().parent
parser_path = Path(tomli.__file__).resolve()
if not parser_path.is_relative_to(pip_root) or not callable(tomli.loads):
    raise SystemExit("pip's vendored TOML parser failed provenance validation")
value = tomli.loads(Path(__import__("sys").argv[1]).read_text(encoding="utf-8"))
print(json.dumps(value, sort_keys=True))
"""
    try:
        result = subprocess.run(
            [python, "-c", script, str(path)],
            check=True,
            capture_output=True,
            text=True,
        )
        value = json.loads(result.stdout)
        if not isinstance(value, dict):
            raise ValueError("TOML document root is not a table")
        return value
    except (OSError, ValueError, subprocess.CalledProcessError):
        # A minimal Python 3.10 environment may have neither stdlib tomllib nor
        # an importable pip vendor. Bootstrap the exact reviewed tomli pin into
        # an isolated temporary target before parsing any repository metadata.
        with tempfile.TemporaryDirectory(prefix="lightwork-tomli-") as tmp:
            requirements = Path(tmp) / "requirements.txt"
            requirements.write_text(
                "tomli==2.5.0 --hash=sha256:"
                "32a7b79ac57a2e83670ce329ccf675798bc5a2094783a63676866b70503f2e2b\n",
                encoding="utf-8",
            )
            subprocess.run(
                [
                    python,
                    "-m",
                    "pip",
                    "install",
                    "--disable-pip-version-check",
                    "--no-deps",
                    "--require-hashes",
                    "--only-binary=:all:",
                    "--platform=any",
                    "--implementation=py",
                    "--abi=none",
                    "--target",
                    tmp,
                    "--requirement",
                    str(requirements),
                ],
                check=True,
            )
            fallback = """
import json
from pathlib import Path
import sys

sys.path.insert(0, sys.argv[1])
import tomli

if (
    getattr(tomli, "__version__", "") != "2.5.0"
    or not Path(tomli.__file__).resolve().is_relative_to(Path(sys.argv[1]).resolve())
):
    raise SystemExit("unexpected tomli bootstrap provenance")
value = tomli.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
print(json.dumps(value, sort_keys=True))
"""
            result = subprocess.run(
                [python, "-c", fallback, tmp, str(path)],
                check=True,
                capture_output=True,
                text=True,
            )
            value = json.loads(result.stdout)
            if not isinstance(value, dict):
                raise ValueError(
                    "TOML document root is not a table"
                ) from None
            return value


def _read_toml(path: Path, python: str) -> dict:
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover - Python 3.10
        try:
            import tomli
        except ModuleNotFoundError:
            return _parse_toml_with_python(path, python)
        if getattr(tomli, "__version__", "") != "2.5.0":
            return _parse_toml_with_python(path, python)
        return tomli.loads(path.read_text(encoding="utf-8"))
    return tomllib.loads(path.read_text(encoding="utf-8"))


def load_cohort(
    source_root: Path,
    target_python: str = sys.executable,
) -> tuple[str, list[CohortPackage]]:
    """Load and validate the repository's lockstep release manifest."""
    root = source_root.resolve()
    manifest_path = root / "release-cohort.toml"
    raw = _read_toml(manifest_path, target_python)
    version = str(raw.get("version") or "")
    if not version:
        raise ValueError("release-cohort.toml must declare a version")
    packages: list[CohortPackage] = []
    seen_distributions: set[str] = set()
    seen_modules: set[str] = set()
    for item in raw.get("packages") or []:
        distribution = str(item.get("distribution") or "")
        runtime_module = str(item.get("runtime_module") or "")
        relative = Path(str(item.get("path") or ""))
        source = (root / relative).resolve()
        if (
            not distribution
            or not runtime_module
            or relative.is_absolute()
            or ".." in relative.parts
            or not source.is_relative_to(root)
        ):
            raise ValueError(f"invalid release cohort entry: {item!r}")
        if distribution in seen_distributions or runtime_module in seen_modules:
            raise ValueError(f"duplicate release cohort entry: {distribution}")
        seen_distributions.add(distribution)
        seen_modules.add(runtime_module)
        packages.append(CohortPackage(distribution, source, runtime_module))
    if len(packages) != 8:
        raise ValueError(
            f"release cohort must contain exactly 8 packages, found {len(packages)}"
        )
    return version, packages


def validate_source_metadata(
    version: str,
    packages: list[CohortPackage],
    target_python: str,
) -> None:
    """Bind every selected local path to the manifest name and version."""
    for package in packages:
        project_path = package.source / "pyproject.toml"
        if not project_path.is_file():
            raise ValueError(f"selected cohort source is missing: {package.source}")
        raw = _read_toml(project_path, target_python)
        project = raw.get("project")
        if not isinstance(project, dict):
            raise ValueError(f"{project_path}: missing [project] table")
        actual_name = str(project.get("name") or "")
        actual_version = str(project.get("version") or "")
        if actual_name != package.distribution:
            raise ValueError(
                f"{project_path}: project name {actual_name!r} does not match "
                f"cohort distribution {package.distribution!r}"
            )
        if actual_version != version:
            raise ValueError(
                f"{project_path}: version {actual_version!r} does not match "
                f"cohort version {version!r}"
            )


def select_packages(
    packages: list[CohortPackage],
    requested: list[str] | None,
) -> list[CohortPackage]:
    """Return manifest-order packages and reject unknown/duplicate selections."""
    if not requested:
        return packages
    if len(requested) != len(set(requested)):
        raise ValueError("--only contains a duplicate distribution")
    by_name = {package.distribution: package for package in packages}
    unknown = sorted(set(requested) - set(by_name))
    if unknown:
        raise ValueError(f"unknown cohort distribution(s): {', '.join(unknown)}")
    requested_set = set(requested)
    if "maverick-agent" not in requested_set:
        raise ValueError(
            "--only subsets must include maverick-agent as the runtime root"
        )
    return [
        package for package in packages if package.distribution in requested_set
    ]


def validate_core_extra(
    core_extra: str | None,
    packages: list[CohortPackage],
    target_python: str,
) -> None:
    """Reject misspelled extras before pip can downgrade them to warnings."""
    if not core_extra:
        return
    core = next(
        (
            package
            for package in packages
            if package.distribution == "maverick-agent"
        ),
        None,
    )
    if core is None:
        raise ValueError("--core-extra requires maverick-agent in the cohort")
    raw = _read_toml(core.source / "pyproject.toml", target_python)
    project = raw.get("project")
    optional = (
        project.get("optional-dependencies")
        if isinstance(project, dict)
        else None
    )
    if not isinstance(optional, dict):
        raise ValueError("maverick-agent declares no optional dependencies")
    requested = set(core_extra.split(","))
    unknown = sorted(requested - set(optional))
    if unknown:
        raise ValueError(
            "unknown maverick-agent extra(s): " + ", ".join(unknown)
        )


def pip_install_command(
    python: str,
    constraint: Path,
    packages: list[CohortPackage],
    core_extra: str | None = None,
    *,
    editable: bool = False,
) -> list[str]:
    requirements = [
        (
            f"{package.source}[{core_extra}]"
            if core_extra and package.distribution == "maverick-agent"
            else str(package.source)
        )
        for package in packages
    ]
    install_requirements = (
        [argument for requirement in requirements for argument in ("-e", requirement)]
        if editable else requirements
    )
    return [
        python,
        "-m",
        "pip",
        "install",
        "--constraint",
        str(constraint),
        *install_requirements,
    ]


def pip_wheel_command(
    python: str,
    constraint: Path,
    packages: list[CohortPackage],
    wheel_dir: Path,
    core_extra: str | None = None,
) -> list[str]:
    requirements = [
        (
            f"{package.source}[{core_extra}]"
            if core_extra and package.distribution == "maverick-agent"
            else str(package.source)
        )
        for package in packages
    ]
    return [
        python,
        "-m",
        "pip",
        "wheel",
        "--constraint",
        str(constraint),
        "--wheel-dir",
        str(wheel_dir),
        *requirements,
    ]


def verify_installed(
    python: str,
    version: str,
    packages: list[CohortPackage],
) -> None:
    subprocess.run([python, "-m", "pip", "check"], check=True)
    expected = [
        [package.distribution, package.runtime_module, version]
        for package in packages
    ]
    script = (
        "import importlib, importlib.metadata, json\n"
        f"expected = json.loads({json.dumps(json.dumps(expected))})\n"
        "for distribution, module, version in expected:\n"
        "    actual = importlib.metadata.version(distribution)\n"
        "    if actual != version:\n"
        "        raise SystemExit("
        "f'{distribution}: expected {version}, installed {actual}')\n"
        "    importlib.import_module(module)\n"
        "print(f'verified {len(expected)} Lightwork distributions')\n"
    )
    subprocess.run([python, "-c", script], check=True)


def native_source_path(root: Path) -> Path:
    """Resolve the optional native source before starting installation."""
    source = root / "rust" / "mvk-scan-py"
    if not (source / "pyproject.toml").is_file() or not (source / "Cargo.toml").is_file():
        raise ValueError(f"native extension source is incomplete: {source}")
    return source


def install_native_source(python: str, constraint: Path, root: Path) -> None:
    """Build and verify the optional native extension from this checkout."""
    source = native_source_path(root)
    subprocess.run(
        [python, "-m", "pip", "install", "--constraint", str(constraint), str(source)],
        check=True,
    )
    script = (
        "import maverick_native\n"
        "from maverick import perceptual_hash\n"
        "from maverick.safety import unicode_filter\n"
        "if not callable(getattr(maverick_native, 'average_hash_from_pixels', None)):\n"
        "    raise SystemExit('native image hash is unavailable')\n"
        "if not callable(getattr(maverick_native, 'normalize', None)):\n"
        "    raise SystemExit('native unicode scanner is unavailable')\n"
        "if perceptual_hash._native is None or unicode_filter._native is None:\n"
        "    raise SystemExit('native runtime wrappers did not load')\n"
        "print('native scanner and image hash available:', maverick_native.__file__)\n"
    )
    subprocess.run([python, "-c", script], check=True)


def _verify_wheel_outputs(
    wheel_dir: Path,
    version: str,
    packages: list[CohortPackage],
) -> None:
    for package in packages:
        prefix = package.distribution.replace("-", "_")
        if not list(wheel_dir.glob(f"{prefix}-{version}-*.whl")):
            raise RuntimeError(
                f"wheel command produced no {package.distribution} {version} wheel"
            )


def _locked_wheel_requirements(
    version: str,
    packages: list[CohortPackage],
    core_extra: str | None,
) -> str:
    """Return exact requirements that preserve the requested core runtime."""
    requirements: list[str] = []
    for package in packages:
        extra = (
            f"[{core_extra}]"
            if core_extra and package.distribution == "maverick-agent"
            else ""
        )
        requirements.append(
            f"{package.distribution}{extra}=={version}\n"
        )
    return "".join(requirements)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--target-python", default=sys.executable)
    parser.add_argument("--constraint", type=Path, default=None)
    parser.add_argument(
        "--core-extra",
        help="optional maverick-agent extra, for example 'all'",
    )
    parser.add_argument(
        "--only",
        nargs="+",
        metavar="DISTRIBUTION",
        help="install a deliberately reduced manifest subset",
    )
    parser.add_argument(
        "--native-source", action="store_true",
        help="also build and verify the optional native extension (requires Rust)",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--wheel-dir", type=Path)
    mode.add_argument("--verify-only", action="store_true")
    mode.add_argument("--validate-only", action="store_true")
    mode.add_argument(
        "--editable", action="store_true",
        help="install the selected local cohort in editable mode",
    )
    args = parser.parse_args(argv)

    root = args.source_root.resolve()
    constraint = (
        args.constraint.resolve()
        if args.constraint is not None
        else root / "requirements" / "ci.txt"
    )
    try:
        if args.core_extra and not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.-]*(,[A-Za-z0-9][A-Za-z0-9_.-]*)*",
            args.core_extra,
        ):
            raise ValueError("--core-extra must contain valid PEP 508 extra names")
        version, cohort = load_cohort(root, args.target_python)
        selected = select_packages(cohort, args.only)
        validate_core_extra(args.core_extra, selected, args.target_python)
        if args.native_source and (args.verify_only or args.validate_only or args.wheel_dir is not None):
            raise ValueError("--native-source requires a source or editable install")
        if args.native_source:
            native_source_path(root)
        if not args.verify_only:
            validate_source_metadata(version, selected, args.target_python)
        if not args.verify_only and not args.validate_only and not constraint.is_file():
            raise ValueError(f"constraint file does not exist: {constraint}")
        if args.validate_only:
            print(f"validated {len(selected)} Lightwork cohort source projects")
        elif args.verify_only:
            verify_installed(args.target_python, version, selected)
        elif args.wheel_dir is not None:
            wheel_dir = args.wheel_dir.resolve()
            wheel_dir.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                pip_wheel_command(
                    args.target_python,
                    constraint,
                    selected,
                    wheel_dir,
                    args.core_extra,
                ),
                check=True,
            )
            _verify_wheel_outputs(wheel_dir, version, selected)
            requirements = _locked_wheel_requirements(
                version,
                selected,
                args.core_extra,
            )
            (wheel_dir / "cohort-requirements.txt").write_text(
                requirements,
                encoding="utf-8",
                newline="\n",
            )
        else:
            subprocess.run(
                pip_install_command(
                    args.target_python,
                    constraint,
                    selected,
                    args.core_extra,
                    editable=args.editable,
                ),
                check=True,
            )
            verify_installed(args.target_python, version, selected)
            if args.native_source:
                install_native_source(args.target_python, constraint, root)
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"release cohort installation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
