# Third-Party Notices

Lightwork is licensed under the Apache License, Version 2.0 (see `LICENSE`). It
includes, or depends on, third-party open-source software under its own
licences. This file lists:

1. third-party components whose files are included in this repository and in
   the `maverick-agent` (`maverick-core`) and `maverick-dashboard` packages
   (below); and
2. the **declared** runtime and optional dependencies of the `maverick-*`
   packages, with their best-known SPDX licence identifiers.

## Bundled components

Each bundled file's licence text or notice is kept next to it or in its header.

### `packages/maverick-dashboard/maverick_dashboard/static/` (included in the `maverick-dashboard` wheel)

| Component | Files | Licence | Copyright and notices |
|---|---|---|---|
| [Swagger UI](https://github.com/swagger-api/swagger-ui) 5.33.1 | `swagger-ui-5.33.1-bundle.js`, `swagger-ui-5.33.1.css` | Apache-2.0 | Copyright 2020-2021 SmartBear Software Inc. The licence is in `swagger-ui-5.33.1-LICENSE.txt` and the NOTICE in `swagger-ui-5.33.1-NOTICE.txt`; the NOTICE is reproduced in the repository's `NOTICE` file. |
| Components bundled inside Swagger UI | `swagger-ui-5.33.1-bundle.js`, `swagger-ui-5.33.1.css` | MIT, BSD-3-Clause, and Apache-2.0 OR MPL-2.0 (DOMPurify 3.4.13) | Licence notices for the bundled libraries, including React, DOMPurify, classnames, JSON-Patch, ieee754 and safe-buffer, are in `swagger-ui-bundle.js.LICENSE.txt`; the stylesheet includes normalize.css 7.0.0 (MIT). |
| [Cytoscape.js](https://js.cytoscape.org) 3.30.2 | `cytoscape-3.30.2.min.js` | MIT | Copyright (c) 2016-2024, The Cytoscape Consortium. The licence text is in the file header. |
| [JetBrains Mono](https://github.com/JetBrains/JetBrainsMono) 2.211 | `fonts/jbm-400.woff2`, `fonts/jbm-500.woff2` | OFL-1.1 | Copyright 2020 The JetBrains Mono Project Authors. The licence text is in `fonts/OFL.txt`; each font's metadata also carries the copyright notice and a link to the licence. |
| [Manrope](https://github.com/sharanda/manrope) 4.504 | `fonts/manrope-var.woff2` | OFL-1.1 | Copyright 2019 The Manrope Project Authors. The licence text is in `fonts/OFL.txt`; the font's metadata also carries the copyright notice and a link to the licence. |

### `docs/overrides/assets/brand/` (published with the documentation site)

| Component | Files | Licence | Copyright and notices |
|---|---|---|---|
| [JetBrains Mono](https://github.com/JetBrains/JetBrainsMono) 2.211 | `jbm-400.woff2` | OFL-1.1 | Copyright 2020 The JetBrains Mono Project Authors. The licence text is in `OFL.txt` in the same directory. |
| [Manrope](https://github.com/sharanda/manrope) 4.504 | `manrope-var.woff2` | OFL-1.1 | Copyright 2019 The Manrope Project Authors. The licence text is in `OFL.txt` in the same directory. |

### `packages/maverick-core/maverick/data/tokenizer/` (included in the `maverick-core` wheel)

| Component | Files | Licence | Copyright and notices |
|---|---|---|---|
| [tiktoken](https://github.com/openai/tiktoken) cl100k_base vocabulary (as defined by tiktoken 0.14.0) | `cl100k_base.tiktoken` | MIT | Copyright (c) 2022 OpenAI, Shantanu Jain. The licence text is in `TIKTOKEN_LICENSE.txt`; the source URL and SHA-256 are in `PROVENANCE.md`. |

## Declared dependencies

> **Provenance & scope.** This list is generated from the `dependencies` and
> `optional-dependencies` declared in each package's `pyproject.toml`; it does
> not include transitive dependencies. SPDX identifiers below are the commonly
> published licenses for each project and are provided for convenience — they
> are **not** a substitute for the canonical `LICENSE`/`NOTICE` shipped inside
> each distribution. Before redistributing a built artifact, regenerate an
> authoritative, transitive inventory from the CycloneDX SBOM produced in CI
> (`.github/workflows/ci.yml`) and reproduce each dependency's required license
> text and `NOTICE` (Apache-2.0) per its terms.

### Copyleft: review before redistribution

These carry obligations beyond permissive attribution (e.g. LGPL relink/notice,
GPL). Confirm each against the actual installed version and your distribution
model (the in-tree license scanner denies only *strong*-copyleft by default and
scans only the installed tree — optional extras can slip past it):

| Package | Likely license | Note |
|---|---|---|
| `psycopg` (psycopg 3) | LGPL-3.0 | Weak copyleft. Optional `[postgres]` extra in `maverick-core` and `maverick-knowledge`. LGPL notice/relink obligations apply. |
| `python-telegram-bot` | LGPL-3.0 | Weak copyleft. Optional channel dependency. |
| `caldav` | `GPL-3.0-or-later OR Apache-2.0` | **Verified against PyPI metadata (`license_expression`), July 2026: dual-licensed, so Apache-2.0 may be elected and there is no copyleft obligation.** Optional `[calendar]` extra, and `calendar_tool._get_caldav_calendar` imports it inside the function body, so it is never bundled. Not a redistribution risk; kept in this table only because the name recurs in scanner output. |
| `matrix-nio` | ISC (verify) | Generally permissive, but confirm — some optional crypto extras pull copyleft. |

### Permissive dependencies (attribution required)

The following are distributed under permissive licenses (MIT / BSD / Apache-2.0
/ ISC / PSF) that require reproducing their copyright and license notice on
redistribution. Identifiers are best-known and should be verified against the
installed version:

| Package | Likely license (SPDX) |
|---|---|
| anthropic | MIT |
| openai | Apache-2.0 |
| fastapi | MIT |
| starlette | BSD-3-Clause |
| uvicorn | BSD-3-Clause |
| pydantic (via fastapi) | MIT |
| httpx | BSD-3-Clause |
| requests | Apache-2.0 |
| urllib3 | MIT |
| idna | BSD-3-Clause |
| click | BSD-3-Clause |
| questionary | MIT |
| rich | MIT |
| jinja2 | BSD-3-Clause |
| orjson | Apache-2.0 / MIT |
| python-multipart | Apache-2.0 |
| websockets | BSD-3-Clause |
| pyjwt | MIT |
| cryptography | Apache-2.0 OR BSD-3-Clause |
| sigstore | Apache-2.0 |
| boto3 | Apache-2.0 |
| google-auth | Apache-2.0 |
| grpcio | Apache-2.0 |
| grpcio-tools | Apache-2.0 |
| redis | MIT |
| arq | MIT |
| pymongo | Apache-2.0 |
| psutil | BSD-3-Clause |
| prometheus-client | Apache-2.0 |
| opentelemetry-api | Apache-2.0 |
| opentelemetry-sdk | Apache-2.0 |
| opentelemetry-exporter-otlp-proto-http | Apache-2.0 |
| sentry-sdk | MIT |
| pandas | BSD-3-Clause |
| pyarrow | Apache-2.0 |
| numpy (via pandas) | BSD-3-Clause |
| duckdb | MIT |
| sympy | BSD-3-Clause |
| latex2mathml | MIT |
| torch | BSD-3-Clause |
| transformers | Apache-2.0 |
| sentence-transformers | Apache-2.0 |
| fastembed | Apache-2.0 |
| faster-whisper | MIT |
| chromadb | Apache-2.0 |
| qdrant-client | Apache-2.0 |
| weaviate-client | BSD-3-Clause |
| langchain-core | MIT |
| pdfplumber | MIT |
| pypdf | BSD-3-Clause |
| python-docx | MIT |
| openpyxl | MIT |
| lxml | BSD-3-Clause |
| pillow | MIT-CMU (HPND) |
| pytesseract | Apache-2.0 |
| playwright | Apache-2.0 |
| mss | MIT |
| pyautogui | BSD-3-Clause |
| pyperclip | BSD-3-Clause |
| pyserial | BSD-3-Clause |
| smbus2 | MIT |
| roslibpy | MIT |
| twilio | MIT |
| slack_sdk | MIT |
| discord.py | MIT |
| youtube-transcript-api | MIT |
| modal | Apache-2.0 |
| zstandard | BSD-3-Clause |
| tomli | MIT |
| stripe | MIT |

### Build, development and test tooling (not redistributed in runtime artifacts)

`ruff`, `pytest`, `pytest-asyncio`, `pre-commit` — used for development and CI
only; not bundled into distributed wheels.

### Optional, not distributed

`agent-shield` — declared as an optional extra; the kernel runs without it
(fail-open) and it is not bundled. If you ship it, add its license here.

## Design references (no code redistributed)

| Project | License | What was used |
|---|---|---|
| `anthropics/commerce-agents` (https://github.com/anthropics/commerce-agents) | Apache-2.0 | Design only, for the Commerce suite (`maverick.commerce`, `com_` packs): the shopper/merchant agent split, the `StorefrontBackend` / `MerchantBackend` interface shape, and the safety posture (storefront fencing, provenance gates, spend/quantity caps, staged writes behind human approval, and a checkout handoff in which the agent never sees payment details or the checkout URL). No source code was copied. |

---

_To regenerate this inventory authoritatively (including transitive deps and
exact installed-version licenses), use the CycloneDX SBOM from CI or run a
license tool such as `pip-licenses` against the installed environment._
