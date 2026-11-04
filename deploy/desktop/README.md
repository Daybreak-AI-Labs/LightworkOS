# Desktop deployment

## Terminal install

The standard installation path is the
[source install guide](../../docs/source-install.md). Lightwork is not published
on PyPI and its distribution names are not reserved there, so do not install
those names from the public index. These scripts install a pinned source
commit:

```bash
export MAVERICK_REF=<full-40-character-commit-sha>
bash deploy/desktop/install.sh
```

On Windows, set `$env:MAVERICK_REF` and run `deploy/desktop/install.ps1`.
The Windows bootstrap requires `pipx` to be installed for the selected Python
from a source you trust. On Unix systems, install `pipx` with a supported system
package manager when it is not already present. The bootstrap does not install
or upgrade pip or pipx from a Python package index.
Both scripts fail before changing the machine when the ref is missing or
mutable, and neither falls back to installing Lightwork from a public index.
The cohort installer still resolves third-party dependencies from its configured
package index with version constraints, not artifact hashes.

## Source bootstrap (advanced)

Download `install.sh` or `install.ps1` from the same commit you intend to
install, verify the script, and set `MAVERICK_REF` to that lowercase, full
40-character commit SHA before running it. Mutable branch/tag refs are always
rejected.

## Windows desktop package candidate

The implemented Windows x64 path is a Tauri **MSI** containing a PyInstaller
frozen runtime with all eight Lightwork packages and an offline WebView2
installer. It opens the local dashboard and has native update, repair and
guarded recovery controls. The target machine does not need Python, Git,
Node or a source checkout for this candidate.

See [`apps/installer-msi/CUSTOMER.md`](../../apps/installer-msi/CUSTOMER.md)
for the implementation, CI evidence and remaining publisher/clean-machine
acceptance. A passed synthetic CI installer is not an accepted release;
the source-bootstrap scripts above are a separate engineering installation.

The macOS and Linux desktop projects have their own build and device acceptance
requirements. This page does not establish a notarized macOS release or
qualified Linux native package.
