#!/usr/bin/env bash
# Verify a Lightwork release artifact's Sigstore (cosign keyless) signature.
#
# Every release binary, checksum manifest, and SBOM
# ships with a detached `.sig` (signature) and `.pem` (signing certificate).
# The signature is keyless: it was produced by the
# release workflow's OIDC identity and logged to the public Rekor transparency
# log, so verification proves the artifact was built by THIS repo's release
# workflow for the expected release tag -- no shared public key to distribute or
# trust on faith.
#
#   deploy/verify-release.sh maverick-linux-x86_64 v1.2.3
#   deploy/verify-release.sh maverick-sbom-v1.2.3.cdx.json v1.2.3
#   deploy/verify-release.sh maverick-linux-x86_64 v1.2.3 maverick-linux-x86_64.sig maverick-linux-x86_64.pem
#
# Pass the release tag you intend to install (for example, v1.2.3). Verification
# pins the signing certificate identity to that exact tag so older signed
# artifacts cannot be replayed as a different release.
set -euo pipefail

usage() {
  echo "usage: verify-release.sh <artifact> <release-tag> [sig] [cert]" >&2
}

if [ "$#" -lt 2 ] || [ "$#" -gt 4 ]; then
  usage
  exit 2
fi

ARTIFACT="$1"
TAG="$2"
SIG="${3:-$ARTIFACT.sig}"
CERT="${4:-$ARTIFACT.pem}"

case "$TAG" in
  v*) ;;
  *) echo "release tag must start with 'v' (got: $TAG)" >&2; exit 2 ;;
esac

# The signer is the release workflow in this repo for the exact release tag; the
# OIDC issuer is GitHub. Escape regex metacharacters in the user-supplied tag so
# the certificate identity is anchored to the literal tag value.
ESCAPED_TAG="$(printf '%s' "$TAG" | sed -e 's/[.[\\*^$()+?{}|]/\\&/g')"
# Daybreak-AI-Labs/LightworkOS is the only trusted signing repository. Its
# owner and name match without regard to letter case, as GitHub resolves them.
IDENTITY_REGEXP="^https://github.com/[Dd]aybreak-[Aa][Ii]-[Ll]abs/[Ll]ightwork[Oo][Ss]/\.github/workflows/release\.yml@refs/tags/${ESCAPED_TAG}$"
OIDC_ISSUER="${OIDC_ISSUER:-https://token.actions.githubusercontent.com}"

command -v cosign >/dev/null 2>&1 || {
  echo "cosign not found. Install: https://docs.sigstore.dev/cosign/installation/" >&2
  exit 1
}
for f in "$ARTIFACT" "$SIG" "$CERT"; do
  [ -f "$f" ] || { echo "missing file: $f" >&2; exit 1; }
done

echo "Verifying $ARTIFACT"
echo "  release tag: $TAG"
echo "  signature:   $SIG"
echo "  certificate: $CERT"
echo "  signer:      $IDENTITY_REGEXP"

cosign verify-blob \
  --signature "$SIG" \
  --certificate "$CERT" \
  --certificate-identity-regexp "$IDENTITY_REGEXP" \
  --certificate-oidc-issuer "$OIDC_ISSUER" \
  "$ARTIFACT"

echo "OK: $ARTIFACT signature is valid and was produced by the release workflow for $TAG."
