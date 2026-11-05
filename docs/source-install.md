# Install from source

Lightwork is installed from a clone of its Git repository. No prebuilt binary,
PyPI package or container image is currently published; this guide is the
supported installation path, and a fresh clone is on `main`, the version to
install until a release is published.

## Requirements

- Python 3.11 or 3.12 (the versions tested in CI).
- Git.
- An account with a model provider, or a self-hosted model, to run tasks. You
  can install and open the dashboard without one.
- Optional: Docker or Podman. The setup wizard (`lightwork init`) switches
  file changes and program execution off when Docker is not running, and the
  dashboard's initial settings start with them off. If you skip both, the
  default `local` sandbox backend runs commands directly on this computer; read
  the [execution posture](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/SECURITY.md#execution-posture) before running
  untrusted goals.

Lightwork requires Python 3.11 or 3.12. If an existing virtual environment was
created with Python 3.10, recreate it with 3.11 or 3.12 before installing.

The repository root is not a pip project, so `pip install -e .` at the root
does not work. `scripts/install_release_cohort.py` installs the eight Lightwork
packages from `release-cohort.toml` together, in one pip transaction,
against the pinned constraints in `requirements/ci.txt`.

## macOS and Linux

```bash
git clone https://github.com/Daybreak-AI-Labs/LightworkOS
cd LightworkOS
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python scripts/install_release_cohort.py --core-extra release-runtime,evidence-analysis
lightwork doctor
lightwork dashboard
```

## Windows (PowerShell)

```powershell
git clone https://github.com/Daybreak-AI-Labs/LightworkOS
Set-Location LightworkOS
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe scripts/install_release_cohort.py --core-extra release-runtime,evidence-analysis
.\.venv\Scripts\lightwork.exe doctor
.\.venv\Scripts\lightwork.exe dashboard
```

`py -3.12` selects Python 3.12; use `py -3.11` instead if that is the
supported version you have installed.

Calling the virtual environment's executables by path avoids changing the
PowerShell execution policy to run the activation script.

## Check the installation

Run these with the same environment's Python (on Windows, use the
`.\.venv\Scripts\` paths shown above):

```bash
python scripts/install_release_cohort.py --verify-only
python -m pip check
lightwork version
lightwork doctor
```

`--verify-only` runs `pip check` and then confirms that each of the eight
distributions is installed at the version in `release-cohort.toml` and that
its module imports. `lightwork doctor` runs a health check of the installation
and configuration, with remediation hints for anything it flags, such as a
missing provider key.

## Open the dashboard

`lightwork dashboard` serves the dashboard and its REST API at
<http://127.0.0.1:8765>. The dashboard guides first-owner sign-in and provider
setup. To bind any address other than loopback, set a bearer token first
(`MAVERICK_DASHBOARD_TOKEN`); the command refuses to start without one.

The command-line tool is installed under two names, `lightwork` and
`maverick`, which run the same program. `lightwork init` runs the setup wizard
in the terminal instead of the dashboard.

## Optional native scanner

The normal installation uses Python implementations of the safety scanners and
image hash. To build the optional Rust extension from this checkout, install
the Rust toolchain using [rustup](https://rustup.rs/) and make sure `cargo` is
on your `PATH`. The repository's `rust-toolchain.toml` selects the Rust version.
From the repository root, using the same Python environment as Lightwork, run:

```bash
python scripts/install_release_cohort.py --native-source
lightwork version
```

On Windows, use `.\.venv\Scripts\python.exe` for the first command and
`.\.venv\Scripts\lightwork.exe version` for the second. The first command builds and installs a wheel for
your machine, installs it alongside the cohort, and verifies that the Unicode
and image hash shims can use it. The version output reports whether each uses a
native wrapper or Python. A native wrapper can fall back to Python on an
individual call. The profile needs a working Rust toolchain and build dependencies;
regular cohort installation does not require either. Native artifacts are
released separately from the eight-package cohort, so `--verify-only` verifies
the cohort but does not install or verify this optional extension. If the
extension is absent, Lightwork uses its Python implementations. Native secret
and PII scans are not the active Python paths; the built-in Python regex
implementations are used for those scans.

If you use `--only` to install a subset of the cohort with `--native-source`,
include `maverick-agent` so the installer can verify the native runtime wrappers.

## Next steps

- [Getting started](getting-started.md): first-owner setup and a first task.
- [Configuration](configuration.md): providers, models, budgets and channels.
- [Deployment](deployment.md): Docker, VPS and server installations.
