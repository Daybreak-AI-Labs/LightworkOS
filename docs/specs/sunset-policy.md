# Sunset policy (safety surfaces)

How safety-relevant features, versions, and data formats retire — the policy
behind the mechanical pieces that already ship (the deprecation registry +
sunset CI gate, the LTS backport SLA tooling, the retention engine).

## Rules

1. **No silent removal of a safety control.** Removing or weakening a shield
   chokepoint, consent gate, capability check, audit guarantee, or sandbox
   mediation requires: a deprecation-registry entry (with `remove_in`), a
   CHANGELOG entry under a `Security` heading, and a replacement or an explicit
   recorded decision (docs/specs/) — never a quiet deletion.
2. **Windows.** Safety-surface deprecations get a minimum of TWO minor
   releases (vs one for ordinary API deprecations) before `remove_in`.
3. **LTS interaction.** A safety control may not be removed from an `lts/<v>`
   branch during its 2-year window, even if removed on `main`
   (docs/security-backports.md governs the flow of fixes, not removals).
4. **Data formats.** A retiring on-disk safety format (audit chain, consent
   ledger, revocation list) ships a migration (`maverick migrate`-style) one
   release before removal; readers stay for the full window.
5. **Enforcement.** `python -m maverick.deprecations --ci` (already a CI gate)
   holds removal dates; this policy adds the review bar for adding a safety
   entry to that registry in the first place.
