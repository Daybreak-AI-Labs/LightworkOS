# Signing a plugin: packaging and load checks

When plugin signing is required, Lightwork verifies the installed plugin before
loading its entry point. The signature must chain to the configured CA root,
and the publisher certificate must be current and not revoked. See the
[plugin guide](plugins.md) for entry points and configuration.

## What the signature covers

The `maverick_plugin.sig.json` bundle contains a signed manifest binding the
distribution name, entry-point name, module path, and file paths with SHA-256
digests. The file set comes from the installed distribution's `RECORD` through
`importlib.metadata`: every listed file under the entry point's top-level
package, the entry-point module itself, and listed top-level `.pth` files.
This includes native extensions and data files, not just Python source.
The signature bundle itself is excluded because it contains the manifest.

At load time, Lightwork recomputes this manifest. Adding, removing, or changing
a covered file after signing makes verification fail; editing `RECORD` does
not update the signature.

## The additional on-disk scan

Lightwork also walks the actual package tree to find executable files omitted
from `RECORD`. A directory belongs to this plugin for this check when it holds
a signed file; all its descendant directories belong to it too. In those
directories, every file ending in `.py`, `.pyc`, `.pyw`, `.so`, `.pyd`, `.dylib`,
or `.pth` must appear in the manifest. Suffix matching is case-insensitive.

For example, signing `acme/widgets/plugin.py` covers the `acme/widgets/` tree.
Another distribution's `acme/reports/` namespace package is outside that tree.
Signing `acme/__init__.py` instead makes the whole `acme/` tree subject to the
check. A single-module plugin such as `myplugin.py`, with no corresponding
package directory, has no additional package tree to scan.

The extra-file scan skips `__pycache__`, non-files, and files with other
suffixes, such as unlisted `.csv` data. It does **not** ignore all non-Python
files: native libraries and `.pth` hooks are checked. These scan exclusions
do not remove a `RECORD`-listed file from the signed manifest or its digest
verification. Failure to inspect the required files refuses the plugin.

## Recognizing and fixing a refusal

An extra file in an owned directory produces a warning like:

```text
plugin package 'myplugin' carries un-signed file myplugin/generated.py on disk; refusing to load (not covered by the signed manifest)
```

The loader also reports that signature verification failed. Inspect the named
file and the installed package contents. Rebuild and re-sign the distribution
when its intended contents change; remove stale files by reinstalling into a
clean environment.

Ship tests or generated modules by including them in the distribution's
`RECORD` before producing the manifest and signature. They receive the same
checks as other package files. Keep development-only tests and build outputs
that are not shipped outside the installed package tree. Generate shipped
code during the build, before signing; generating new `.py` files inside an
owned directory after installation will cause a later load to refuse them.

The implementation is in
[`plugins.py`](../packages/maverick-core/maverick/plugins.py)
(`_ep_importable_files`, `_ondisk_files_covered`, `_plugin_signature_ok`), with
examples in
[`test_plugin_signature_gate.py`](../packages/maverick-core/tests/test_plugin_signature_gate.py).
