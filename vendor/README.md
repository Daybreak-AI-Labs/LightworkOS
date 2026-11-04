# Reviewed dependency patches

These source copies keep the desktop applications compatible with GTK3 while
fixing the advisories listed below. They are maintained
here until compatible upstream releases make them unnecessary. They are not
unmodified registry packages, and a clean registry scan alone does not assess
these local sources.

| Source | Change | Reason |
| --- | --- | --- |
| `glib` 0.18.5 | Backport [gtk-rs/gtk-rs-core#1343](https://github.com/gtk-rs/gtk-rs-core/pull/1343): pass a mutable out-pointer in `VariantStrIter::impl_get`. | RUSTSEC-2024-0429 / GHSA-wrw7-89jp-8q8g; fixes undefined behavior in optimized iteration without changing the GTK3 ABI. |
| `glib-macros` 0.18.5 and `gtk3-macros` 0.18.2 | Replace `proc-macro-error` with the maintained `proc-macro-error3` 3.1.1 with its Syn 2 integration. | RUSTSEC-2024-0370; removes the abandoned macro implementation and its attribute crate. |
| `deepmerge` 4.3.1 | Local private package `@lightwork/deepmerge`; reject `__proto__`, `constructor`, and `prototype` while copying either operand, including nested objects. | GHSA-gcqx-w48m-w2h4; prevents target-side and null-prototype-source poisoning while preserving the merge API used by Svelte. |

The Tauri utility lock is separately updated to 2.10.2, which uses `urlpattern`
0.6 and ICU instead of the abandoned `unic-*` dependency family.

`provenance.json` records upstream archive URLs, SHA-256 checksums, retained
licenses, and hashes of every local source file. `scripts/check_vendor_patches.py`
checks that inventory and that both applications resolve the reviewed copies.
The OSV job still scans every registry dependency, including the regression
harness lock. OSV identifies the local GLib copy as the affected registry
version. `scripts/check_osv_results.py` records that finding as repaired only
for the three reviewed local lock entries, after checking every source hash
and confirming Cargo resolves a path dependency. Any registry GLib copy,
unrelated advisory, changed source, or scanner error still fails. CI retains
both the raw OSV report and this explicit remediation record. No blanket
advisory exception or registry version relabeling is used.

Validation includes optimized GLib string-iterator operations, macro-derived
GLib types, Unicode URL patterns, prototype-poisoning regressions, the Svelte
build and tests, and native compilation of both Tauri applications. Desktop CI
runs the same regression harness on Linux. The GLib iterator regression must
run with `--release`: optimizer behavior is part of the reported defect.

To update a copy, review the upstream source and license, apply the smallest
necessary patch, regenerate the file inventory intentionally, and run the
regressions and full dependency audit. Keep original version metadata for Rust
compatibility. Remove each path override when the corresponding maintained
upstream release is compatible and no longer affected. Do not edit the
inventory merely to accept unexplained source changes.
