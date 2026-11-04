#!/usr/bin/env bash
# Verify a deployment's compliance posture (SOC 2 / ISO 27001 / ISO 42001).
#
# Runs the bundled Lightwork posture checks and aggregates their exit codes.
# Intended as a deploy gate or a periodic evidence-collection job: a non-zero
# exit means at least one required technical control is not in a ready state.
# See ./hardening-checklist.md. Read-only — it inspects posture, changes nothing.
#
# Usage:
#   ./verify-posture.sh            # human-readable, exits non-zero on any failure
#   ./verify-posture.sh --json     # capture maverick soc2 evidence as JSON too
set -uo pipefail

fail=0
run() {
  # run "<label>" cmd args...
  local label="$1"; shift
  echo "== ${label} =="
  if "$@"; then
    echo "   PASS: ${label}"
  else
    echo "   FAIL: ${label} (exit $?)"
    fail=1
  fi
  echo
}

# Required: SOC 2 technical-posture gate (exits non-zero unless all required
# controls are enabled, audit_log == ok, and a signing key is present).
run "SOC 2 posture (maverick soc2)" maverick soc2

# Required: regulated-deployment guarantees actively exercised.
run "Enterprise boundary (maverick enterprise verify --require)" \
  maverick enterprise verify --require

# Advisory: GDPR / EU AI Act control map (strict).
run "Compliance control map (maverick compliance --strict)" \
  maverick compliance --strict

# Advisory: environment sanity.
run "Environment (maverick doctor)" maverick doctor

# Optional: persist the evidence snapshot for the audit trail.
if [[ "${1:-}" == "--json" ]]; then
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  out="soc2-evidence-${ts}.json"
  if maverick soc2 --json > "${out}"; then
    echo "Evidence snapshot written: ${out}"
  fi
fi

if [[ "${fail}" -ne 0 ]]; then
  echo "RESULT: NOT compliant-ready — address the FAIL items above." >&2
  exit 1
fi
echo "RESULT: all posture checks passed."
