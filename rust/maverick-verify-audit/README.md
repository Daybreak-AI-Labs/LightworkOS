# maverick-verify-audit

A standalone Rust binary that **independently verifies Lightwork's Ed25519
hash-chained NDJSON audit log** — the *same* chain `maverick audit verify`
checks — so an auditor or procurement reviewer can prove a day-file is intact
with **one binary and no Python**.

```text
maverick-verify-audit path/to/2026-06-18.ndjson
```

Exit `0` and `OK: N rows verified` if the chain is intact; non-zero plus a
human-readable report of the **first** break otherwise.

It is a **byte-exact port** of `maverick.audit.signing.verify_chain` (the Python
source of truth): same canonical JSON, same SHA-256 hashing, same Ed25519
verification, same chain linkage, and the same `ChainBreak` reason vocabulary.

## What it checks (per non-blank NDJSON row)

1. **parses** as a JSON object — else `malformed`;
2. **`prev_hash`** equals the previous row's `hash` (genesis = empty string) —
   else `chain_mismatch`;
3. **`hash`** equals `sha256(canonical_json(row without hash/sig))` — else
   `bad_hash`;
4. **`sig`** is a valid Ed25519 signature over the **32 raw bytes** of `hash`
   (not its hex text), under the public key for the row's `key_id` — else
   `bad_signature`; an unknown key is `no_pubkey`.

An entirely-**unsigned** log (no `hash`/`sig`/`key_id` on any row — the
signing-disabled default) is reported `UNVERIFIABLE` and exits **1**, exactly as
the `maverick audit verify` CLI does: a log with no chain cannot be *proven*
intact, so automation must not pass it as clean.

Reasons mirrored from Python: `malformed`, `unsigned`, `chain_mismatch`,
`bad_hash`, `bad_signature`, `no_pubkey`, plus file-level `missing_file` and
`unreadable_segment`.

## Key location

Matches the Python on-disk layout: each row carries a 16-hex `key_id`
(`sha256(pubkey)[:16]`), and the raw 32-byte Ed25519 public key lives at
`<keys_dir>/<key_id>.pub`.

- `--keys-dir <DIR>` — directory of `<key_id>.pub` files. Default:
  `~/.maverick/audit/keys` (honoring `MAVERICK_HOME`), the Python legacy default.
- `--pubkey <HEX>` — trust **exactly** this raw Ed25519 public key (hex),
  ignoring `key_id` lookups. **Use this for true third-party tamper-evidence:**
  hand the auditor the externally-held pubkey out of band so the verdict does not
  depend on any key file sitting next to the log. (Mirrors Python's
  `verify_chain(pubkey_hex=...)`.)
- `--all` — list every break, not just the first.

> Without `--pubkey`, the binary prints a warning that it is trusting local key
> files — the same caveat the Python CLI prints.

## Scope notes

- **Per-file chain only.** Like Python's `verify_chain`, this verifies one
  day-file's internal chain. The cross-file *anchor* tip-ledger
  (`anchors.ndjson`, which catches a wholly deleted/truncated day-file) is
  verified by `maverick audit verify`; re-running this binary against
  `anchors.ndjson` will verify that ledger's own chain, but it does not perform
  the cross-file tip/row-count reconciliation. (A future `--anchors <dir>` flag
  could add it.)
- **At-rest sealed segments.** A confidential day-file sealed with AES-256-GCM
  (header `MVKAR1`/`MVKAR2`/`MVKTEN1`) is reported `unreadable_segment` with a
  hint, rather than mis-read as plaintext — the seal key is host-local and not
  portable, so an external auditor verifies the (unsealed) plaintext NDJSON.

## Build & run

The crate is a member of the `rust/` Cargo workspace.

```bash
# from the repo's rust/ directory
cargo build -p maverick-verify-audit            # debug
cargo build -p maverick-verify-audit --release  # optimized binary

# binary lands at:
#   rust/target/debug/maverick-verify-audit
#   rust/target/release/maverick-verify-audit

# run it
rust/target/debug/maverick-verify-audit ~/.maverick/audit/2026-06-18.ndjson \
    --pubkey <externally-held-hex>
```

## Tests

Rust unit tests (canonical-JSON parity table + chain logic):

```bash
cargo test -p maverick-verify-audit
```

**Cross-language parity test** — drives the *real* Python `AuditSigner` to sign a
log, runs this binary on it, and asserts the Rust verdict matches Python's
`verify_chain` on the same file (intact → exit 0; one flipped byte → break at the
right row; deleted row → `chain_mismatch`; unsigned log → `UNVERIFIABLE`):

```bash
# requires `cryptography` installed for the Python side
python3 rust/maverick-verify-audit/tests/parity.py
# or, pinning a prebuilt binary:
MVK_VERIFY_BIN=rust/target/debug/maverick-verify-audit \
    python3 rust/maverick-verify-audit/tests/parity.py
```

## Dependencies

Minimal and pure-Rust: `ed25519-dalek` (strict verification), `sha2`, `hex`,
`serde_json` (with `arbitrary_precision` so number literals round-trip
byte-for-byte to match CPython's `repr`), and `clap` for argument parsing.
