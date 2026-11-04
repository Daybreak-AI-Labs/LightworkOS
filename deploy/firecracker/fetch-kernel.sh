#!/usr/bin/env bash
# Fetch a Firecracker-compatible uncompressed Linux kernel (vmlinux) and place
# it where the firecracker sandbox backend looks: ~/.maverick/firecracker/kernel.img
#
# Firecracker boots an UNcompressed kernel (a raw vmlinux, not a bzImage). The
# Firecracker project publishes CI kernels in its S3 bucket. Because this kernel
# becomes a sandbox boot artifact, callers must provide KERNEL_SHA256 for the
# exact bytes they trust. Override KERNEL_URL / KERNEL_SHA256 / DEST as needed.
set -euo pipefail

DEST="${DEST:-$HOME/.maverick/firecracker/kernel.img}"
ARCH="$(uname -m)"

# A Firecracker CI kernel for the host architecture. KERNEL_SHA256 is mandatory
# so this script fails closed if the URL, bucket, or network path is poisoned.
case "$ARCH" in
  x86_64)  KERNEL_URL="${KERNEL_URL:-https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.10/x86_64/vmlinux-5.10.bin}" ;;
  aarch64) KERNEL_URL="${KERNEL_URL:-https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.10/aarch64/vmlinux-5.10.bin}" ;;
  *) echo "unsupported arch: $ARCH (set KERNEL_URL explicitly)" >&2; exit 2 ;;
esac

if [ -z "${KERNEL_SHA256:-}" ]; then
  cat >&2 <<EOF
KERNEL_SHA256 is required; refusing to install an unverifiable Firecracker kernel.
Set KERNEL_SHA256 to the expected SHA-256 digest for the exact KERNEL_URL bytes.
EOF
  exit 2
fi
if [[ ! "$KERNEL_SHA256" =~ ^[[:xdigit:]]{64}$ ]]; then
  echo "KERNEL_SHA256 must be exactly 64 hexadecimal characters" >&2
  exit 2
fi

mkdir -p "$(dirname "$DEST")"

echo "Fetching kernel for $ARCH:"
echo "  $KERNEL_URL"
echo "  sha256=$KERNEL_SHA256"
echo "  -> $DEST"

if command -v curl >/dev/null 2>&1; then
  curl -fSL --retry 3 -o "$DEST.tmp" "$KERNEL_URL"
elif command -v wget >/dev/null 2>&1; then
  wget -O "$DEST.tmp" "$KERNEL_URL"
else
  echo "need curl or wget" >&2; exit 1
fi

ACTUAL_SHA256="$(sha256sum "$DEST.tmp" | awk '{print $1}')"
if [ "${ACTUAL_SHA256,,}" != "${KERNEL_SHA256,,}" ]; then
  rm -f "$DEST.tmp"
  echo "kernel SHA-256 mismatch: expected $KERNEL_SHA256, got $ACTUAL_SHA256" >&2
  exit 1
fi

mv "$DEST.tmp" "$DEST"
chmod 0644 "$DEST"
echo "Kernel installed: $DEST"
