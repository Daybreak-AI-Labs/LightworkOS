# Audit read coverage and bounded history

`maverick audit seal` uses the existing at-rest encryption setting and seals
closed day files as `MVKASF1` authenticated frame containers. The live day stays
plaintext for the signing writer. Each 1 MiB frame is encrypted through the
existing deployment or tenant key boundary, binds its position and random
segment identity, and authenticates before any plaintext is returned. An
encrypted manifest commits to dimensions, total length and the whole plaintext
digest. Sealing copies the original signed bytes exactly; it does not re-sign
historical evidence.

New history supports direct suffix reads. Plaintext tails seek backwards in
64 KiB reads; framed tails authenticate the manifest and necessary frames. The
tail limit is 10,000 rows and 16 MiB of suffix, with a 4 MiB individual row limit.
An over-limit or torn row is an explicit incomplete read, never a claimed empty
log. Full event iteration uses bounded chunks and rows, including UTF-8 that
crosses frame boundaries. A snapshot changing during a read becomes incomplete.

Existing monolithic `MVKAR1`, `MVKAR2` and `MVKTEN1` segments remain readable.
They must be decrypted completely before their plaintext can be returned; their
receipt sets `legacy_whole_blob: true`. Existing sealed files are not silently
rewritten. Whole-text compatibility consumers such as some checkpoint, WORM,
erasure and chain-verification operations may still materialize the segment;
not every forensic operation has bounded memory.
Upgrade audit readers before producing framed history: older releases do not
recognize `MVKASF1`. Retain existing encryption keys and signing public keys.

## Coverage is separate from evidence assurance

The API `GET /api/v1/audit/tail` returns the events and a `read_report`. Its scope
is `requested_tail`, so a complete tail says nothing about older unread rows.
The audit page displays an alert for partial or unreadable results.

The export CLI can write a separate receipt:

```console
maverick audit export --all --output events.jsonl --read-report coverage.json
maverick audit export --all --verify --output events.jsonl --read-report coverage.json
```

Both output files must be outside the protected audit directory. This includes
unselected days, anchors, checkpoints, WORM receipts and future paths inside
that directory. Hard-linked output destinations are refused. Malformed JSON,
including excessive nesting or integer length, produces failed coverage and a
nonzero exit instead of bypassing the requested receipt.

Receipt states:

| State | Meaning |
|---|---|
| `empty` | No events were found in the selected readable scope. |
| `readable_complete` | Selected snapshots were read and parsed, without signature verification. |
| `verified_complete` | All selected event rows also passed per-segment signature and chain verification. |
| `partial` | Iteration stopped early, a snapshot changed, or some evidence was unreadable. |
| `unreadable` | No selected segment could be completely read and no event was returned. |

`--verify` checks a bounded first pass and exports a second pass from the same
private descriptor under the writer's rewrite lock. Whole-byte digests must
match between passes. This can hold up writes to the selected live day; prefer
closed days for large verified exports. Verification failures do not become
successful empty exports. Receipt diagnostics contain segment names and error
types, not plaintext audit payloads or keys. Incomplete export and forwarding
exit nonzero, even when readable events were already emitted. Consumers must
inspect the exit code and receipt before accepting the output as complete.

The receipt always states whether anchors and independent checkpoints were
verified. This export mode only verifies segment chains: use `audit verify`,
checkpoint verification or the Audit Binder for their additional assurances.
No read result proves complete instrumentation or independent custody. Coverage
diagnostics are never inserted into event rows. Existing JSONL/CEF serialization
is unchanged; the on-disk signed evidence remains the source for forensic proof.

Framed history preserves existing key rotation, strict proof failure, erasure,
retention and WORM interfaces. Intentional erasure/re-anchoring keeps sealed
files encrypted. Sealing publishes a protected encrypted temporary file
atomically; failures retain the previous source and remove the unpublished
temporary file. No intermediate plaintext history file is written.
