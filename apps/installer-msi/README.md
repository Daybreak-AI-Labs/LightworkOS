# maverick-installer-msi (engineering bootstrap)

The separate [Windows desktop package candidate](CUSTOMER.md) combines the
complete frozen runtime, desktop app, and offline WebView2 installer. Its build,
maintenance, signing, and acceptance workflow does not use this engineering
bootstrap. That package has its own release acceptance; the distinction below
applies to `Package.wxs` and `build.ps1`.

WiX Toolset v4 authoring for an **engineering-only** Windows bootstrap. It
installs a `maverick.cmd` launcher on the per-user PATH plus one
`maverick-agent` wheel, then asks pip to resolve that wheel's dependencies from
live PyPI on first launch.

This is not a complete Lightwork platform installer. It omits the other seven
packages in `release-cohort.toml`, does not bundle Python or a dependency
wheelhouse, is not offline-capable, and is not a release artifact.

## What's in the package

| Piece | What it does |
|---|---|
| `Package.wxs` | WiX v4 product/package definition: per-user scope, stable `UpgradeCode`, `MajorUpgrade` rule, PATH environment component |
| `maverick.cmd` + `maverick_bootstrap.py` | Launcher installed to `%LOCALAPPDATA%\Programs\Maverick\bin`. Installs the bundled core wheel (`--user`) on first run and whenever its installed version differs from the MSI cohort; pip resolves dependencies from live PyPI |
| `build.ps1` | `wix build` invocation; takes the wheel path and version |
| `test_wxs.py` | Static contract test (XML well-formed, UpgradeCode pinned, perUser scope, no hardcoded user paths) |

Design notes:

- **Per-user by default** (`Scope="perUser"`): no UAC, installs under
  `%LOCALAPPDATA%\Programs\Maverick`, and the PATH component edits the *user*
  PATH only (`System="no"`).
- **`UpgradeCode` is a constant** (`9E2B7C41-6A8D-4F3B-8E5A-2C90D17B4F6E`).
  Never change it: `MajorUpgrade` uses it to find and replace older versions.
  `test_wxs.py` pins the exact value so a drive-by edit fails CI.
- **The launcher uses the console-script entry point.** `py -m maverick`
  does not work — `packages/maverick-core/maverick/` has no `__main__.py` —
  so `maverick.cmd` runs `python -c "from maverick.cli import main; main()"`
  (the same target as the `maverick` console script in
  `packages/maverick-core/pyproject.toml`).
- **The wheel keeps its PEP 427 filename.** The MSI preserves the built
  `maverick_agent-<version>-<python>-<abi>-<platform>.whl` basename because pip
  rejects a renamed `maverick_agent.whl` before reading it. The launcher reads
  the MSI ProductVersion and skips bootstrap only when
  `importlib.metadata.version("maverick-agent")` matches it exactly; upgrades
  therefore cannot silently continue running an older user-site package.
- **Python and network access are prerequisites, not bundled capabilities.**
  The MSI does not embed a Python runtime, a locked dependency wheelhouse, or
  the full eight-package release cohort. `maverick.cmd` prints an actionable
  error if Python 3.11+ is missing; pip otherwise resolves runtime dependencies
  from live PyPI without a shipped constraints file. This bootstrap is not an
  offline MSI; the separate desktop package candidate is.

## Building

Requires a **Windows host**, the **WiX v4 CLI**, and a **built wheel**:

```powershell
dotnet tool install --global wix
python -m pip install build
python -m build --wheel packages/maverick-core
cd apps\installer-msi
.\build.ps1 -Wheel ..\..\packages\maverick-core\dist\maverick_agent-0.1.7-py3-none-any.whl
```

There is also a manual-dispatch engineering workflow
(`.github/workflows/build-msi.yml`) that builds the core wheel and bootstrap
MSI on `windows-2022`. Its artifact name and metadata identify it as an
unsigned engineering bootstrap requiring live PyPI.

## Status

- **Engineering-only:** this bootstrap is deliberately excluded from release
  completeness claims. A complete Windows delivery must install an offline
  artifact containing the whole release cohort without running pip against
  live package indexes.
- The staged wheel filename and first-install/upgrade bootstrap have an offline
  `--no-deps --no-index` filename smoke test. That test validates only wheel
  staging; it does not make the real first-launch dependency install offline.
- The `.wxs`, launcher, and build script are statically validated by
  `test_wxs.py`, which runs on any platform. Building or installing the MSI
  requires WiX v4 on a Windows host; treat the first `build.ps1` run as a
  release candidate to smoke-test.
- The produced MSI ships **UNSIGNED**. SmartScreen can show an "unknown
  publisher" warning until an Authenticode signing path exists.

## Testing

```bash
python -m pytest apps/installer-msi/test_wxs.py -q
```
