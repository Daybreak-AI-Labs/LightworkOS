# Releasing Lightwork

This is the maintainer procedure for publishing a release. It describes what
`.github/workflows/release.yml` and `.github/workflows/publish.yml` do, using
`release-cohort.toml`, `scripts/release_version.py` and
`scripts/github_release_state.py`.

No release is currently published, and PyPI publishing is switched off (see
[PyPI publishing](#pypi-publishing)).

Before enabling public releases, a repository administrator must configure and
verify the repository's GitHub protections. Require an independent approving
review on `main`, dismiss stale approvals, require approval of the latest push
and resolution of review conversations, and require code-owner review for
release and workflow changes. The current owner list needs enough eligible
reviewers for maintainers to review one another's changes.

Restrict creation of `v*`, `native-v*`, and `desktop-v*` tags to designated
release maintainers and prevent routine tag updates or deletion. Protect the
release and publishing environments with independent reviewers and appropriate
branch/tag restrictions, then attach every publication and signing job to the
correct protected environment. The `workflow_run` publisher uses the default
branch ref, while tag-triggered jobs use tag refs; configure and verify both
cases before release. Environment names in workflow files do not themselves
create approval rules. Check inherited organization rules and classic branch
protection as well as repository rulesets, and test the complete release path
before relying on these controls.

## Versions and tags

The eight Python distributions are released together, at one version, as a
cohort. `release-cohort.toml` lists them and holds the cohort version:

| Distribution | Source |
| --- | --- |
| `maverick-agent` | `packages/maverick-core` |
| `maverick-shield` | `packages/maverick-shield` |
| `maverick-channels` | `packages/maverick-channels` |
| `maverick-evolve` | `packages/maverick-evolve` |
| `maverick-dashboard` | `packages/maverick-dashboard` |
| `maverick-mcp-server` | `packages/maverick-mcp` |
| `maverick-knowledge` | `packages/maverick-knowledge` |
| `maverick-installer` | `apps/installer-cli` |

A release tag is `v` followed by a canonical version of the form
`MAJOR.MINOR.PATCH[aN|bN|rcN][.postN][.devN]`, for example `v0.1.7` or
`v0.2.0rc1`. Other spellings, such as `v0.1.07` or `v0.2.0-rc1`, are rejected.
A version with an `a`, `b` or `rc` part, or a `.devN` part, is published as a
GitHub pre-release. Check a tag before you create it:

```bash
python scripts/release_version.py --tag v0.1.7
```

## Before you tag

1. Set the new version in `release-cohort.toml` (`version`) and in the
   `version` field of each of the eight `pyproject.toml` files it lists. The
   workflows refuse a tag whose version differs from any of them, and refuse a
   cohort that does not list exactly eight packages or whose package names do
   not match the `distribution` entries.
2. Merge that change to `main` through a pull request. The tagged commit must be
   reachable from `main`.

## Start the release

Tag the release commit on `main` and push the tag:

```bash
git tag v0.1.7 <commit-on-main>
git push origin v0.1.7
```

Pushing a `v*` tag starts the **Release** workflow (`release.yml`). To rerun a
release for a tag that already exists, run the workflow manually with the `tag`
input, and choose that tag (not `main`) under **Use workflow from**; the
workflow refuses a manual run from any other ref, because the signing identity
is bound to the tag.

`release.yml` and `publish.yml` share one concurrency group per tag and never
cancel each other, so a release run, its publish run and any rerun do not
overlap.

## What `release.yml` does

1. **Validate the tag.** Checks the tag with `scripts/release_version.py`,
   confirms the tag exists, that its commit is reachable from `main` and is the
   commit being built, and that `release-cohort.toml` and every package's
   `pyproject.toml` match the tag's version. It then reads the state of the
   GitHub release for that tag with `scripts/github_release_state.py`:
   `absent`, `draft` or `published`. The script fails on any API error instead
   of guessing.
2. **If the release is already published**, the workflow only re-downloads and
   verifies its assets and signatures, and changes nothing.
3. **Otherwise it builds, in parallel:**
   - the container image from `deploy/docker/Dockerfile`, pushed to a staging
     tag `ghcr.io/<owner>/lightworkos:sha-<commit>` with provenance and an SBOM;
   - single-file `maverick` binaries built with PyInstaller for Linux x86_64,
     macOS arm64 and Windows x86_64, each smoke-tested before upload;
   - a CycloneDX SBOM of the release runtime.
4. **Assemble, sign and draft.** The `release` job checks that each build
   produced exactly the expected files, writes a container promotion plan
   (`maverick-container-<tag>.json`) and a checksum manifest
   (`maverick-release-<tag>.sha256`), signs the container digest and every
   file with keyless Sigstore signing (cosign; a `.sig` and a `.pem` per file),
   and creates the GitHub release as a **draft** with generated release notes.
   If a draft for the tag already exists, its assets are deleted and uploaded
   again.

## What `publish.yml` does

`publish.yml` starts when the Release workflow completes. It continues only if
that run succeeded, came from a tag push or a manual run in the same
repository, and the tag still resolves to the commit that was built.

1. **Build the Python distributions.** Builds a wheel and an sdist for each of
   the eight packages twice, from two clean copies of the tagged commit, and
   requires the two builds to be byte-identical. It then checks for exactly one
   wheel and one sdist per package at the cohort version and writes
   `SHA256SUMS` and `release-manifest.json`. If a version already exists on
   PyPI, every file there must match this build's digest, so an interrupted
   publish can be resumed safely.
2. **Sign.** While the GitHub release is still a draft, signs the 16
   distribution files and the two manifests with keyless Sigstore signing and
   attaches them, with their `.cosign.bundle` files, to the draft. If the
   release is already published, it verifies the attached files instead.
3. **Publish to PyPI**, only when enabled (see below).
4. **Finalize.** Downloads every asset of the release and verifies its bytes and
   signatures, verifies the container signature, and promotes the staged image
   digest to `ghcr.io/<owner>/lightworkos:<version>` (the version without the
   leading `v`). It refuses to move an existing tag to a different digest. It
   then publishes the GitHub release and verifies the published bytes and
   signatures again.

Running `publish.yml` manually only builds the distributions; it never signs
or publishes them.

## PyPI publishing

The PyPI jobs run only when the repository variable
`MAVERICK_PUBLIC_PYPI_ENABLED` is `true`, and only for a successful tag
release. The workflow notes that the public package names are not all reserved
yet; until a maintainer has reserved them and set up trusted publishing, leave
the variable unset. While it is unset, the PyPI jobs are skipped and the GitHub
release is still finalized.

When it is enabled, each distribution is uploaded by its own job in the `pypi`
environment through PyPI trusted publishing (OIDC; no API token is stored),
with attestations. Files that already exist with matching bytes are skipped. A
final job then reads PyPI back and requires every filename and SHA-256 digest
to match the release manifest. To enable it:

1. Reserve each of the eight distribution names on PyPI.
2. Register this repository's `publish.yml` workflow and the `pypi`
   environment as a trusted publisher for each project.
3. Set the repository variable `MAVERICK_PUBLIC_PYPI_ENABLED` to `true`.

## What a release contains

- A GitHub release for the tag with the three binaries, the SBOMs, the
  container promotion plan, the checksum files and a `.sig` and `.pem` for
  each; plus the eight wheels, eight sdists,
  `SHA256SUMS`, `release-manifest.json` and a `.cosign.bundle` for each of
  those.
- The container image `ghcr.io/<owner>/lightworkos:<version>`.
- When PyPI publishing is enabled, the eight distributions on PyPI.

Users can verify a downloaded binary, checksum manifest or SBOM with
`deploy/verify-release.sh <file> <tag>`, which checks its signature against
the release workflow's identity for that tag.

## If something fails

Fix the cause and rerun the failed workflow. The workflows are designed to be
rerun: an already-published release is only verified, a draft has its assets
replaced, and a partial PyPI upload resumes only when the files already on
PyPI match the new build byte for byte.
