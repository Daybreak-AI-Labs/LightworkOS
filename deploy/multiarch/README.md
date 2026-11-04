# Multi-architecture reduced runtime

`Dockerfile.multiarch` and `build.sh` build a deliberately reduced Lightwork
runtime for exactly two supported targets:

- `linux/amd64`
- `linux/arm64`

The image contains the manifest-pinned `maverick-agent` and
`maverick-shield` cohort. Set `INSTALL_DASHBOARD=1` to add the matching
dashboard package. Use the standard container image when you need the complete
eight-package release cohort, provider runtime, setup wizard, channels, evolve,
MCP, or knowledge services.

The runtime uses uid and gid 1000, with state in `/home/maverick/.maverick`.
Mounted workspace and state directories must be writable by that user. Migrate
any state from the former `/root/.maverick` location explicitly. Custom base
images must leave uid and gid 1000 available.

```bash
# One time per host: register the QEMU handlers used for cross-builds.
docker run --privileged --rm tonistiigi/binfmt --install all

# Validate amd64 + arm64 (default).
deploy/multiarch/build.sh

# Push one tagged multi-architecture manifest.
PUSH=1 TAG=registry.example.com/maverick:0.1.7 \
  deploy/multiarch/build.sh

# Add the optional ARM64-capable dashboard surface.
INSTALL_DASHBOARD=1 deploy/multiarch/build.sh
```

## Native dependencies and the support boundary

The core is not pure Python. Its cryptography stack includes native C/OpenSSL
components, and the dashboard adds native packages such as `pydantic-core`.
The optional voice path uses `pywhispercpp`, which publishes tested Linux
ARM64 wheels for the pinned release. The build therefore relies on reviewed
wheels for both supported targets and verifies the installed distributions
before producing the image.

RISC-V is intentionally unsupported. The pinned cohort has no tested
`pywhispercpp` RISC-V wheel, and a reliable RISC-V source-build path would also
need a tested Rust/C/OpenSSL/Python-header toolchain. `build.sh` rejects
`linux/riscv64` rather than silently producing an unverified image.

## CI example

```yaml
- uses: docker/setup-qemu-action@c7c53464625b32c7a7e944ae62b3e17d2b600130 # v3
- uses: docker/setup-buildx-action@bb05f3f5519dd87d3ba754cc423b652a5edd6d2c # v4.2.0
- run: PLATFORMS=linux/amd64,linux/arm64 deploy/multiarch/build.sh
```

Multi-platform results cannot be loaded into the local Docker daemon in one
operation. By default the helper builds to cache for validation; set `PUSH=1`
only when `TAG` names the intended registry destination.

The repository contract tests validate the supported-platform gate and package
scope. A Docker-capable CI runner remains responsible for the actual
cross-architecture build and runtime smoke test.
