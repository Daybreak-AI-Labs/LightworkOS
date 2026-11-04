# Homebrew tap

[`maverick.rb`](./maverick.rb) is the Homebrew formula for the `maverick`
CLI. This directory is the **source of truth**; it's mirrored into a tap
repository so macOS/Linux users can install with Homebrew.

## Install (for users)

The tap is not deployed yet; once it is, the install is:

```bash
brew install Daybreak-AI-Labs/tap/maverick
maverick init
```

`brew install Daybreak-AI-Labs/tap/maverick` is shorthand for tapping
`github.com/Daybreak-AI-Labs/homebrew-tap` and installing the `maverick`
formula from it. The formula drops `maverick-agent[installer]` into an isolated
virtualenv and links the `maverick` command onto your PATH.

## How the tap is maintained

Homebrew taps live in a repo named `homebrew-<name>` (e.g.
`Daybreak-AI-Labs/homebrew-tap`). Keep this monorepo copy authoritative and sync it
to the tap repo on release:

1. **One-time:** create `Daybreak-AI-Labs/homebrew-tap` and copy this `maverick.rb`
   into its `Formula/` directory.
2. **Each release:** [`/.github/workflows/homebrew-bump.yml`](../../.github/workflows/homebrew-bump.yml)
   runs when a GitHub Release is published. It resolves the freshly
   published `maverick-agent` sdist from PyPI, rewrites the formula's `url`
   and `sha256`, generates hash-locked requirements for the installer
   dependency set, and opens a PR here. Merge it, then copy the updated
   formula to the tap repo (or point the action at the tap repo once it
   exists).

The workflow runs only when the repository variable
`MAVERICK_PUBLIC_PYPI_ENABLED` is `true`, the same switch that enables PyPI
publishing (see [RELEASING.md](../../RELEASING.md#pypi-publishing)). While it is
unset, the bump is skipped and the formula keeps its placeholder checksum.

The committed `sha256` is a zeroed placeholder until the first
`homebrew-bump` run fills it in — the formula is intentionally not
installable against a hand-typed checksum.

## Notes

- This is a third-party tap, not homebrew-core, so the formula keeps the
  dependency list in an embedded, hash-locked `requirements.txt` section
  rather than vendoring every transitive `resource` block by hand. The
  formula installs the Homebrew-downloaded, checksum-verified sdist with
  `--no-deps` first, then installs only the hashed binary dependency artifacts
  listed in that generated requirements section. Installing the local sdist
  first keeps packages such as `maverick-installer` from resolving
  `maverick-agent` from PyPI while pip is in `--require-hashes` mode.
- **Needs a macOS `brew install --build-from-source maverick` smoke test**
  before the tap is announced — that can't run in this repo's Linux CI.
- Pinned to a real release (not `main`), so `brew upgrade` tracks tagged
  versions.
