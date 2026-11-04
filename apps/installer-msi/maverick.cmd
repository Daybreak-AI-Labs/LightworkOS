@echo off
rem Lightwork CLI launcher, installed by the engineering bootstrap MSI.
rem
rem Why this exists: the MSI cannot pip-install at install time without
rem custom actions, so it ships the wheel next to this script and bootstraps
rem lazily on first run. There is no maverick/__main__.py, so `py -m maverick`
rem does not work; the real entry point is the console script maverick.cli:main
rem (see packages/maverick-core/pyproject.toml [project.scripts]).
setlocal

rem Resolve a Python 3 interpreter: the py launcher first, plain python second.
set "PYCMD=py -3"
%PYCMD% -c "import sys" >nul 2>nul || set "PYCMD=python"
%PYCMD% -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>nul || (
  echo maverick: Python 3.11+ was not found. Install it from https://python.org
  echo           ^(check "Add python.exe to PATH"^) and run `maverick` again.
  exit /b 1
)

rem Read the exact MSI ProductVersion. Import success alone is not enough:
rem after an MSI upgrade an older maverick-agent can still import cleanly.
set "PRODUCT_VERSION="
for /f "tokens=2,*" %%A in ('reg query "HKCU\Software\Maverick\CLI" /v wheel 2^>nul') do if /I "%%A"=="REG_SZ" set "PRODUCT_VERSION=%%B"
if not defined PRODUCT_VERSION (
  echo maverick: the MSI product version is missing; repair the engineering bootstrap.
  exit /b 1
)

rem The stdlib-only bootstrap finds the staged PEP 427 wheel, skips pip only
rem when importlib.metadata reports this exact ProductVersion, and installs or
rem upgrades otherwise.
%PYCMD% "%~dp0maverick_bootstrap.py" --product-version "%PRODUCT_VERSION%" --wheel-dir "%~dp0..\wheels" || (
  echo maverick: bootstrap of the bundled wheel failed.
  exit /b 1
)

rem Invoke the click entry point directly; argv[1:] is forwarded unchanged.
%PYCMD% -c "from maverick.cli import main; main()" %*
exit /b %ERRORLEVEL%
