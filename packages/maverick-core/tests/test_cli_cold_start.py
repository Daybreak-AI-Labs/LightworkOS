"""Cold-start guard for the CLI.

`maverick --help` must stay fast: the win is that importing the CLI defers
every heavy/optional dependency (httpx, the provider SDKs, vector stores,
numpy/pandas, fastapi, …) to the command that actually needs it. These tests
pin that property in a FRESH interpreter (a subprocess, so modules pulled in by
the rest of the suite don't mask a regression), so a stray module-level
`import httpx` in cli.py trips CI instead of quietly taxing every invocation.
"""
from __future__ import annotations

import subprocess
import sys
import time

# Heavy / optional modules that must NOT be imported merely by loading the CLI.
_HEAVY = [
    "httpx", "anthropic", "openai", "chromadb", "qdrant_client", "weaviate",
    "numpy", "pandas", "pyarrow", "fastapi", "psycopg", "sympy", "zstandard",
]


def _run(code: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-c", code], capture_output=True,
                          text=True, timeout=60)


def test_cli_import_loads_no_heavy_modules():
    code = (
        "import sys\n"
        "import maverick.cli\n"
        f"heavy=[m for m in {_HEAVY!r} if m in sys.modules]\n"
        "print(','.join(heavy))\n"
    )
    r = _run(code)
    assert r.returncode == 0, r.stderr
    loaded = [m for m in r.stdout.strip().split(",") if m]
    assert loaded == [], f"CLI import pulled in heavy modules: {loaded}"


def test_help_runs_and_is_fast():
    code = "from maverick.cli import main; main(['--help'])"
    t0 = time.time()
    r = _run(code)
    wall_ms = (time.time() - t0) * 1000.0
    assert r.returncode == 0, r.stderr
    assert "Usage" in r.stdout
    # Generous ceiling: the real cost is ~0.1s. This is a catastrophic-regression
    # backstop (a heavy module sneaking into the import path), not a microbenchmark.
    assert wall_ms < 2500, f"`--help` took {wall_ms:.0f}ms (cold-start regression?)"


def test_help_loads_no_heavy_modules():
    # Even after dispatching --help, no heavy dep should have been imported.
    code = (
        "import sys, io\n"
        "from maverick.cli import main\n"
        "import click\n"
        "_saved = sys.stdout\n"
        "sys.stdout = io.StringIO()\n"   # swallow the help text
        "try:\n"
        "    main(['--help'], standalone_mode=False)\n"
        "except (SystemExit, click.exceptions.Exit):\n"
        "    pass\n"
        "finally:\n"
        "    sys.stdout = _saved\n"
        f"heavy=[m for m in {_HEAVY!r} if m in sys.modules]\n"
        "print(','.join(heavy))\n"
    )
    r = _run(code)
    assert r.returncode == 0, r.stderr
    loaded = [m for m in r.stdout.strip().split(",") if m]
    assert loaded == [], f"--help pulled in heavy modules: {loaded}"
