# Firecracker microVM sandbox — kernel + rootfs

The `firecracker` sandbox backend
(`maverick/sandbox/firecracker.py`, `provider="local"`) boots a one-shot
[Firecracker](https://github.com/firecracker-microvm/firecracker) microVM per
command via `firectl`, giving kernel-level isolation that a Docker namespace
boundary can't. It expects two artifacts, by convention, under
`~/.maverick/firecracker/`:

| File | What it is |
|------|------------|
| `kernel.img` | An uncompressed Linux kernel (`vmlinux`) Firecracker can boot. |
| `rootfs.img` | An `ext4` root filesystem image with a shell + your toolchain. |

These are host- and distro-specific, so they are **not** shipped in the wheel —
build them once with the scripts here. Until both exist, the backend returns a
clear `exit_code=127` pointing back at this README rather than silently
downgrading isolation.

## Prerequisites

- A Linux host with KVM (`/dev/kvm` present and accessible).
- `firecracker` and `firectl` on `PATH`
  ([getting-started](https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md)).
- `docker` (used by `build-rootfs.sh` to export a filesystem) and `e2fsprogs`
  (`mkfs.ext4`). Root (or `sudo`) is needed to populate the ext4 image.

## Build

```bash
# 1. Fetch a Firecracker-compatible uncompressed kernel -> ~/.maverick/firecracker/kernel.img
#    KERNEL_SHA256 is mandatory; set it to the digest for the exact KERNEL_URL bytes.
KERNEL_SHA256=<64-hex-digest> deploy/firecracker/fetch-kernel.sh

# 2. Build an ext4 rootfs from a digest-pinned container image -> ~/.maverick/firecracker/rootfs.img
IMAGE=ubuntu@sha256:<64-hex-digest> sudo -E deploy/firecracker/build-rootfs.sh
```

Then point the agent at it:

```toml
# ~/.maverick/config.toml
[sandbox]
backend  = "firecracker"
provider = "local"        # or "e2b" for E2B's hosted Firecracker (needs E2B_API_KEY)
network  = "egress-deny"  # egress-deny | egress-allow | bridge=<tap-name>
```

## Notes

- **Network.** `egress-deny` boots with `--no-network` (no NIC in the guest).
  `bridge=<name>` attaches a pre-created host TAP device; you own its firewall
  rules. `egress-allow` assumes the host default route is reachable.
- **Sizing.** The backend boots the VM with 1 vCPU / 512 MiB by default
  (`_firectl`). Adjust the rootfs size in `build-rootfs.sh` (`ROOTFS_MB`).
- **Hosted alternative.** If you don't want to operate Firecracker yourself,
  set `provider = "e2b"` and `E2B_API_KEY` — same `.exec()` interface, no
  kernel/rootfs to build.
- **Artifact integrity.** `fetch-kernel.sh` refuses to install a kernel unless
  `KERNEL_SHA256` matches the downloaded bytes, and `build-rootfs.sh` requires
  `IMAGE` to be pinned with an immutable `@sha256:` digest. These checks keep
  mutable URLs and registry tags from silently changing the guest that the
  sandbox boots.
