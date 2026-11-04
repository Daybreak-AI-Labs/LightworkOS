# Distribution and release artifacts

> What a tagged Lightwork release produces, how to verify it, how to build the
> same artifacts locally, and how to run the container on Azure, AWS or GCP.

**Current status:** no prebuilt binary, PyPI package or container image has
been published yet. Install from a clone of the repository with
[`source-install.md`](source-install.md). The rest of this page describes what
the release workflow is configured to produce once a release is cut, and how
to build the same artifacts yourself.

## What the release pipeline produces

One tagged `release.yml` run produces the artifacts below for
**macOS (Apple Silicon), Windows, and Linux**, plus a container image:

| Channel | Artifact | Typical use | Readable Python source? |
|---|---|---|---|
| **Single-file binary** | `maverick-macos-arm64`, `maverick-windows-x86_64.exe`, `maverick-linux-x86_64` | technical users / CI / servers | No — PyInstaller bundles Python bytecode |
| **Container image** | `ghcr.io/daybreak-ai-labs/lightworkos:<ver>` | **Azure / AWS / GCP**, k8s, on-prem Docker | **Yes** — installed Python remains readable |
| Supply-chain | Sigstore material for `release.yml` binaries, manifests, SBOMs, and the immutable container digest; `publish.yml` separately signs Python distributions/manifests | security review | n/a |

`publish.yml` separately contains an opt-in, allowlisted Trusted Publishing
path for the eight workspace Python distributions. The example agents under
`demo/` are not release artifacts; run them from a checkout.

`desktop.yml` separately builds an **unsigned source-bootstrap shell** (Tauri)
as a workflow artifact. It needs network access to clone a pinned commit and
installs readable source; it is neither self-contained nor attached to
releases.

---

## Verifying a release artifact

Each binary, checksum manifest and SBOM is published with a
detached `.sig` and `.pem`. `deploy/verify-release.sh` checks the keyless
Sigstore signature and pins the signing identity to the release tag you expect:

```bash
deploy/verify-release.sh maverick-linux-x86_64 <release-tag>
```

The container image is verified by digest; see
[Cut a release](#cut-a-release) below.

---

## macOS

**Option A — download a published single-file binary** (once a release
carries one):
1. Download `maverick-macos-arm64` and its `.sig`/`.pem` files from the release.
2. Verify the checksum and Sigstore identity with `deploy/verify-release.sh`.
3. Mark it executable and run it from Terminal.

**Option B — build it locally:** `scripts/build-macos-app.sh` installs the
packages non-editable from this source tree, compiles them into a `maverick`
binary with PyInstaller, and wraps it into a double-click `Lightwork.app` that
opens the local dashboard. See the script header for prerequisites (Homebrew
and `python@3.12`).

No GPU is needed. The model is called over an API (Anthropic / Azure OpenAI /
Bedrock) **or** run locally via Ollama for a fully air-gapped machine
(`maverick init` → choose Ollama).

---

## Windows and Linux

The release workflow builds the standalone binary on each OS:

- **Windows:** `maverick-windows-x86_64.exe`.
- **Linux:** `maverick-linux-x86_64`.

The Tauri `.msi` / NSIS `.exe` / `.AppImage` / `.deb` outputs remain
engineering-only source-bootstrap artifacts until a compiled payload, reliable
release attachment, platform signing, and real-machine tests exist.

To build locally on either OS, the recipe is identical to the Mac script:
install the packages non-editable, then `pyinstaller --clean --noconfirm
--distpath ../dist maverick.spec` (run from `build/`). PyInstaller must
run **on the target OS** — a Windows exe builds on Windows, a Linux binary on
Linux. CI's `release.yml` does all three on hosted runners.

`scripts/build-nuitka.sh` is an alternative local build that compiles the
Python to C and then to a native single-file binary with Nuitka. It is not a
cross-compiler either, and its output is unsigned.

---

## Cloud: Azure / AWS / GCP

The container image is the universal cloud artifact. It needs only a mounted
config directory and a model key (or a private model endpoint your cloud
already offers, e.g. Azure OpenAI / Bedrock).

The examples use the image name that `release.yml` publishes. Releases publish
exact-version tags only; there is no `latest` tag. Until a release image
exists, build the image yourself
(`docker build -f deploy/docker/Dockerfile -t <registry>/lightwork:<tag> .`),
push it to a registry your cloud can pull from, and substitute that name.

```bash
# the release image (staged by release.yml, promoted to :<version> by publish.yml)
docker pull ghcr.io/daybreak-ai-labs/lightworkos:<version>
```

**AWS** — ECS/Fargate task, or plain EC2. For remote access, put the EC2
loopback port behind an authenticated TLS-terminating proxy:
```bash
# Set ANTHROPIC_API_KEY or configure a provider such as Bedrock.
docker run -d -p 127.0.0.1:8765:8765 \
  -e MAVERICK_DASHBOARD_TOKEN=... \
  -e ANTHROPIC_API_KEY=... \
  -v /srv/maverick:/home/maverick/.maverick \
  ghcr.io/daybreak-ai-labs/lightworkos:<version> \
  dashboard --host 0.0.0.0 --port 8765
# Fargate: same image in a task definition.
```

**Azure** — Container Apps (serverless) or AKS:
```bash
az containerapp create -n lightwork -g <rg> --environment <env> \
  --image ghcr.io/daybreak-ai-labs/lightworkos:<version> \
  --target-port 8765 --ingress internal \
  --command maverick \
  --args dashboard --host 0.0.0.0 --port 8765 \
  --secrets model-key=... dashboard-token=... \
  --env-vars ANTHROPIC_API_KEY=secretref:model-key \
             MAVERICK_DASHBOARD_TOKEN=secretref:dashboard-token \
  --cpu 0.5 --memory 1Gi
# To keep model calls inside the tenant, configure Azure OpenAI instead of Anthropic.
```

**GCP** — Cloud Run:
```bash
gcloud run deploy lightwork \
  --image ghcr.io/daybreak-ai-labs/lightworkos:<version> \
  --port 8765 --cpu 1 --memory 2Gi --no-allow-unauthenticated \
  --command=maverick \
  --args=dashboard,--host,0.0.0.0,--port,8765 \
  --set-secrets=ANTHROPIC_API_KEY=lightwork-model-key:latest,MAVERICK_DASHBOARD_TOKEN=lightwork-dashboard-token:latest
# Use Vertex/Gemini provider config instead of ANTHROPIC_API_KEY if preferred.
```

All three examples explicitly start the dashboard rather than the image's
one-shot default help command. A non-loopback bind also requires
`MAVERICK_DASHBOARD_TOKEN`; cloud IAM or private ingress is defense in depth,
not a replacement for the application's bearer-token boundary.

**k8s / on-prem:** the same image in a single-replica control-plane Deployment;
mount a PVC at `/home/maverick/.maverick` for the world DB + audit chain.
SQLite is the default; Postgres adds database HA/isolation and supports separate
remote-worker scale, but not multiple dashboard/serve replicas yet.

Governance and data stay in your own cloud account; only the model call goes
out, and that can be an endpoint inside the same account.

---

## Cut a release

Downloads exist only once a release is cut. The pipeline runs on a tag:

```bash
# Manual dispatch must itself run from the exact tag. Checking out the tag later
# cannot change the GitHub OIDC identity used for keyless signing.
gh workflow run release.yml --ref v0.1.7 -f tag=v0.1.7
```

`release.yml` then builds the 3-OS binaries, stages the GHCR image by immutable
commit, generates checksums and SBOMs, keyless-signs the container digest and release artifacts,
and creates a draft GitHub Release. It does not dispatch or attach the
engineering Tauri source-bootstrap bundles. `publish.yml` starts when Release
completes. It builds and signs the Python distributions, publishes them to PyPI
only when enabled, promotes and verifies the exact-version GHCR tag, and then
publishes the verified draft (see
[RELEASING.md](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/RELEASING.md)).

The Release includes `maverick-container-v<version>.json`, which binds the
image, immutable digest, source revision, staging tag, and target-tag promotion
plan. The signed plan is created before mutable tags move; `publish.yml`
verifies that the target tag resolves to the signed digest before it publishes
the draft Release.
Verify that digest without trusting a mutable tag:

```bash
IMAGE=ghcr.io/daybreak-ai-labs/lightworkos
DIGEST=sha256:<digest-from-maverick-container-v0.1.7.json>
cosign verify "$IMAGE@$DIGEST" \
  --certificate-identity-regexp \
  '^https://github.com/Daybreak-AI-Labs/LightworkOS/\.github/workflows/release\.yml@refs/tags/v0\.1\.7$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

**Before cutting a release:** merge the intended code to `main`, decide on
platform signing (below), and bump the version. A release is public; cut it
deliberately.

---

## Signing and notarization

Release artifacts carry Sigstore identity/integrity material, but current
executables are **not platform code-signed or notarized**, so operating systems
may show an unknown-developer warning.

- **macOS:** platform signing needs an Apple Developer ID certificate and
  notarization. Wire the certificate and notary credentials as CI secrets;
  `tauri build` and the binary both get signed and stapled.
- **Windows:** platform signing needs an Authenticode code-signing certificate
  to sign the `.msi`/`.exe`.
- Already in place: **Sigstore** keyless signatures (`.sig`/`.pem`) on the raw
  release binaries, checksums, and SBOMs — verifiable with
  `cosign verify-blob` (`deploy/verify-release.sh`). The container digest is
  signed with `cosign sign`; the engineering Tauri bundles are not covered.

The local build scripts (`scripts/build-macos-app.sh`,
`scripts/build-nuitka.sh`) produce unsigned output; sign it as above before
distributing it.
