---
name: dependency-sbom-audit
triggers:
  - run a dependency audit
  - generate an SBOM for this service
  - assess our third-party / supply-chain risk
tools_needed:
  - code_exec
  - read_file
---
# What this skill does

Audits a project's third-party dependencies (direct and transitive) for supply-chain risk and produces a prioritized remediation list. Output: an SBOM-backed report enumerating each component with its version, known CVEs and severity, license, end-of-life/maintenance status, and a concrete upgrade or mitigation path ranked by exploitable risk.

# Steps

1. Locate the real manifests and lockfiles with read_file (e.g. `requirements.txt`/`uv.lock`/`poetry.lock`, `package-lock.json`, `go.sum`, `pom.xml`, `Cargo.lock`). Audit the LOCKFILE, not the loose manifest — pinned transitive versions are what actually ship. Note which ecosystems are present.
2. With code_exec, generate the SBOM and resolved dependency tree from the lockfiles (e.g. `cyclonedx`/`syft` for SBOM, `pip-audit`/`npm audit --json`/`osv-scanner` for vulnerabilities). Capture full transitive closure, not just top-level deps. Record the scanner name, version, and DB timestamp so findings are reproducible.
3. For each component join three signals: (a) CVEs with CVSS/severity and whether a fixed version exists, (b) declared license (flag copyleft/unknown/incompatible against the project's license policy), (c) EOL/maintenance status (last release date, archived repo, unsupported runtime). Mark anything the scanners could not resolve as `unverified` rather than clean.
4. Rank by exploitable risk (severity x reachability x fix availability), draft the remediation table (upgrade-to version, pin, replace, or accept-with-justification), and report. State assumptions (scanner DB date, ecosystems not scanned) and hand off — do not apply upgrades automatically.

# Notes

Output is wrong if it audits the manifest instead of the resolved lockfile (misses transitive CVEs), trusts a single scanner (each DB has gaps — cross-check OSV + ecosystem-native), or reports a CVE without checking whether the vulnerable code path is actually reachable, inflating severity. A clean scan only means "no KNOWN advisories as of the DB date" — never "secure"; always cite the DB timestamp. Severity scores and "fixed in" versions come from the advisory source; cite it, never invent CVE IDs. Dependency upgrades and removals are irreversible-ish changes that can break builds: stage them as recommendations for a human to test and merge. Not for first-party application code review or runtime/secrets scanning — this is supply-chain composition only.
