<#
  Lightwork desktop bootstrap (Windows).

  It installs Python 3.12 if missing, requires a trusted pipx installation,
  checks out an exact
  Lightwork commit into an isolated pipx environment, and launches the wizard
  (`maverick init`). There is deliberately no public-package-index fallback.

  Set $env:MAVERICK_REF to a reviewed, lowercase, full 40-character commit
  SHA. Mutable refs and an omitted ref fail before the script changes the
  machine.

  If Python is already installed but not detected, point straight at it:
    $env:MAVERICK_PYTHON = "C:\path\to\python.exe"
#>

$ErrorActionPreference = 'Stop'

$Repo   = if ($env:MAVERICK_REPO) { $env:MAVERICK_REPO } else { 'Daybreak-AI-Labs/LightworkOS' }
$Ref    = if ($env:MAVERICK_REF)  { $env:MAVERICK_REF }  else { '' }
$SrcDir = Join-Path $env:LOCALAPPDATA 'Lightwork\src'

# How to call the resolved Python: $PyExe + $PyPre (e.g. 'py' + '-3').
$script:PyExe = $null
$script:PyPre = @()

function Write-Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Write-Warn($m) { Write-Host "!!  $m" -ForegroundColor Yellow }
function Die($m) { throw "Lightwork install failed: $m" }
function Have($cmd) { [bool](Get-Command $cmd -ErrorAction SilentlyContinue) }
function Py { & $script:PyExe @($script:PyPre + $args) }

function Test-PinnedRef($ref) {
  return ($ref -cmatch '^[0-9a-f]{40}$')
}

function Ensure-SourcePin {
  if (-not $Ref) {
    Die "MAVERICK_REF is required. Set it to a reviewed, full 40-character Lightwork commit SHA; public-index fallback is disabled."
  }
  if (Test-PinnedRef $Ref) { return }
  Die "MAVERICK_REF must be a lowercase, full 40-character commit SHA; got '$Ref'."
}

function Ensure-RepoSlug {
  # $Repo is interpolated into https://github.com/$Repo for the git clone/fetch
  # below. Constrain it to a GitHub "owner/repo" slug so a hostile or typo'd
  # value can't point the install at a different repo or smuggle URL/shell
  # metacharacters into the git command. Mirrors validate_repo in install.sh.
  # (Only the source path uses $Repo.)
  if ($Repo -notmatch '^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$') {
    Die "MAVERICK_REPO must be a GitHub 'owner/repo' slug (letters, digits, '.', '_', '-'); got '$Repo'."
  }
}


function Refresh-Path {
  # Merge the live machine + user PATH from the registry into this
  # session WITHOUT dropping entries already added here (a freshly
  # installed Python dir, or pipx's bin dir below). Overwriting $env:Path
  # would silently undo those additions, and `maverick init` would then fail
  # to launch in the same window.
  $parts = @(
    [Environment]::GetEnvironmentVariable('Path', 'Machine'),
    [Environment]::GetEnvironmentVariable('Path', 'User'),
    $env:Path
  ) | Where-Object { $_ } | ForEach-Object { $_ -split ';' } | Where-Object { $_ }
  $seen = New-Object System.Collections.Generic.HashSet[string]
  $env:Path = (@($parts | Where-Object { $seen.Add($_) }) -join ';')
}

function Ensure-Winget {
  if (Have winget) { return }
  Die @"
winget is not available (older Windows 10). Install these by hand, then re-run:
  Python 3.12 : https://www.python.org/downloads/  (tick 'Add python.exe to PATH')
  Git         : https://git-scm.com/download/win
"@
}

function Winget-Install($id, $override) {
  Write-Step "Installing $id ..."
  # An $override replaces winget's default installer args entirely, so it
  # must carry its own quiet flag. Used to force Python onto PATH.
  if ($override) {
    winget install -e --id $id --accept-source-agreements --accept-package-agreements --override $override
  } else {
    winget install -e --id $id --accept-source-agreements --accept-package-agreements --silent
  }
  Refresh-Path
}

# Validate one interpreter: run it and confirm it reports >= 3.11. On
# success, record how to invoke it ($script:PyExe / $script:PyPre).
#
# Probe with `--version`, NOT `-c "..."`. Windows PowerShell 5.1 mangles
# embedded double quotes when passing args to a native exe, so a quoted
# -c snippet fails even when the interpreter is perfectly fine -- which
# made every detection path (PATH, registry, disk) report "not found".
function Test-PyCandidate($exe, $pre) {
  try {
    $out = (& $exe @($pre + @('--version')) 2>&1) | Out-String
    if ($out -match 'Python\s+(\d+)\.(\d+)' -and
        ([int]$Matches[1] -gt 3 -or ([int]$Matches[1] -eq 3 -and [int]$Matches[2] -ge 11))) {
      $script:PyExe = $exe; $script:PyPre = $pre
      return $true
    }
  } catch { }
  return $false
}

# Full paths to every Python registered under PEP 514. The python.org
# installer (what winget runs) always writes these keys with the exact
# install location, regardless of PATH or install dir -- so this finds
# Python even when winget never put it on PATH.
function Get-RegistryPythons {
  $found = @()
  $roots = @(
    'HKCU:\SOFTWARE\Python\PythonCore',
    'HKLM:\SOFTWARE\Python\PythonCore',
    'HKLM:\SOFTWARE\WOW6432Node\Python\PythonCore'
  )
  foreach ($root in $roots) {
    if (-not (Test-Path $root)) { continue }
    foreach ($ver in (Get-ChildItem $root -ErrorAction SilentlyContinue)) {
      try {
        $ip  = Get-ItemProperty -Path (Join-Path $ver.PSPath 'InstallPath') -ErrorAction Stop
        $exe = $ip.ExecutablePath
        if (-not $exe -and $ip.'(default)') { $exe = Join-Path $ip.'(default)' 'python.exe' }
        if ($exe -and (Test-Path $exe)) { $found += $exe }
      } catch { }
    }
  }
  return $found
}

# Find a usable Python >= 3.11. PATH first, then the registry (winget
# runs the python.org installer, which does NOT add Python to PATH
# unless PrependPath is set), then a scan of well-known install dirs.
function Resolve-Python {
  # An explicit override wins -- the escape hatch when detection fails.
  if ($env:MAVERICK_PYTHON -and (Test-PyCandidate $env:MAVERICK_PYTHON @())) { return $true }

  if ((Have py)     -and (Test-PyCandidate 'py'     @('-3'))) { return $true }
  if ((Have python) -and (Test-PyCandidate 'python' @()))     { return $true }

  foreach ($exe in (Get-RegistryPythons | Sort-Object -Descending -Unique)) {
    if (Test-PyCandidate $exe @()) { return $true }
  }

  $parents = @(
    (Join-Path $env:LOCALAPPDATA 'Programs\Python'),
    $env:ProgramFiles,
    (Join-Path $env:ProgramFiles 'Python')
  )
  if (${env:ProgramFiles(x86)}) { $parents += ${env:ProgramFiles(x86)} }
  foreach ($p in $parents) {
    if (-not $p -or -not (Test-Path $p)) { continue }
    foreach ($d in (Get-ChildItem -LiteralPath $p -Directory -Filter 'Python3*' -ErrorAction SilentlyContinue)) {
      $exe = Join-Path $d.FullName 'python.exe'
      if ((Test-Path $exe) -and (Test-PyCandidate $exe @())) { return $true }
    }
  }
  return $false
}

Write-Host ""
Write-Host "Lightwork desktop installer (Windows)" -ForegroundColor Green
Write-Host ""
Ensure-SourcePin

# 1. Python 3.11+
if (-not (Resolve-Python)) {
  Ensure-Winget
  # PrependPath puts python.org's install on PATH for future sessions;
  # Resolve-Python also locates it on disk for the current one.
  Winget-Install 'Python.Python.3.12' '/quiet PrependPath=1 InstallLauncherAllUsers=0'
  if (-not (Resolve-Python)) {
    Die @"
Python was installed but couldn't be located (PATH + registry + disk all came up empty).
Reinstall from https://www.python.org/downloads/ with 'Add python.exe to PATH' ticked, then re-run this command.
"@
  }
}
Write-Step ("Using " + ((Py --version | Out-String).Trim()))

# 2. pipx
Write-Step "Ensuring pipx ..."
$pipxAvailable = $false
try {
  Py -m pipx --version 2>$null | Out-Null
  $pipxAvailable = ($LASTEXITCODE -eq 0)
} catch { $pipxAvailable = $false }
if (-not $pipxAvailable) {
  Die "Install pipx for the selected Python from a trusted source, then re-run."
}
Py -m pipx ensurepath | Out-Null

function Ensure-GitForSource {
  if (-not $Ref) { return }
  if (-not (Have git)) { Ensure-Winget; Winget-Install 'Git.Git' }
  if (-not (Have git)) { Die "Git installed, but it isn't on PATH. Open a NEW PowerShell window and re-run." }
}

function Fetch-Source {
  Ensure-SourcePin
  Ensure-RepoSlug
  Ensure-GitForSource
  Write-Step "Downloading a fresh Lightwork source tree ($Repo@$Ref) ..."
  $srcParent = Split-Path $SrcDir
  New-Item -ItemType Directory -Force -Path $srcParent | Out-Null
  $stageDir = Join-Path $srcParent ("src.stage." + [Guid]::NewGuid().ToString('N'))
  try {
    git clone --no-checkout --filter=blob:none "https://github.com/$Repo" $stageDir
    if ($LASTEXITCODE -ne 0) { Die "Could not clone the Lightwork source repository." }
    git -C $stageDir fetch --depth 1 origin $Ref
    if ($LASTEXITCODE -ne 0) { Die "Could not fetch required Lightwork commit '$Ref'." }
    git -C $stageDir -c advice.detachedHead=false checkout --detach FETCH_HEAD | Out-Null
    if ($LASTEXITCODE -ne 0) { Die "Could not check out required Lightwork commit '$Ref'." }
    $actualRef = ((git -C $stageDir rev-parse HEAD 2>$null) | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $actualRef -cne $Ref) {
      Die "Checked-out source is at '$actualRef', not required ref '$Ref'."
    }
    $dirty = ((git -C $stageDir status --porcelain --untracked-files=all 2>$null) | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $dirty) {
      Die "Fresh pinned Lightwork checkout is unexpectedly dirty."
    }
    if (-not (Test-Path (Join-Path $stageDir 'packages\maverick-core\pyproject.toml'))) {
      Die "Pinned checkout is not a complete Lightwork source tree."
    }
    Remove-Item -Recurse -Force -LiteralPath $SrcDir -ErrorAction SilentlyContinue
    Move-Item -LiteralPath $stageDir -Destination $SrcDir
    $stageDir = $null
  } finally {
    if ($stageDir -and (Test-Path -LiteralPath $stageDir)) {
      Remove-Item -Recurse -Force -LiteralPath $stageDir -ErrorAction SilentlyContinue
    }
  }
}

# 3. Install the complete release cohort into one pipx venv.
Write-Step "Installing the complete Lightwork package cohort (this can take a minute) ..."
Fetch-Source
Py -m pipx install --force --pip-args=--no-deps (Join-Path $SrcDir 'packages\maverick-core')
if ($LASTEXITCODE -ne 0) { Die "pipx could not install the pinned Lightwork core source." }
$venvsDir = (Py -m pipx environment --value PIPX_LOCAL_VENVS).Trim()
$venvPython = Join-Path $venvsDir 'maverick-agent\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
  Die "pipx created no maverick-agent environment at '$venvPython'."
}
Py (Join-Path $SrcDir 'scripts\install_release_cohort.py') `
  --source-root $SrcDir `
  --target-python $venvPython `
  --core-extra release-runtime
if ($LASTEXITCODE -ne 0) { Die "The constrained Lightwork cohort install failed." }

# 4. Locate the maverick shim and launch the wizard.
$binDir = $null
try { $binDir = (Py -m pipx environment --value PIPX_BIN_DIR).Trim() } catch { }
if (-not $binDir) { $binDir = Join-Path $env:USERPROFILE '.local\bin' }
$env:Path = "$binDir;$env:Path"
Refresh-Path

Write-Host ""
# The desktop GUI installer sets MAVERICK_NO_WIZARD: install but skip the
# interactive wizard (the app then points the user at `maverick init`).
if ($env:MAVERICK_NO_WIZARD) {
  Write-Host "Lightwork installed. Run 'maverick init' to configure it." -ForegroundColor Green
} else {
  Write-Host "Lightwork installed." -ForegroundColor Green
  Write-Host "Launching the setup wizard..." -ForegroundColor Green
  Write-Host ""
  if (Have maverick) {
    maverick init
  } else {
    Write-Warn "Installed, but 'maverick' isn't on this window's PATH yet."
    Write-Host "Open a NEW PowerShell window and run:  maverick init"
  }
}
