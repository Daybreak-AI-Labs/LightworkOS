# Governance

Lightwork is a maintainer-led open-source project developed by Daybreak Labs.
This document describes how decisions are made today and how contributors
become maintainers. It will change as the project grows; changes
to it are made through a pull request like any other change.

## Roles

**Contributors** are everyone who takes part: opening issues, answering
questions, reviewing pull requests, writing code or documentation. Anyone can
contribute; see [CONTRIBUTING.md](CONTRIBUTING.md).

**Maintainers** have write access to the repository. They review and merge pull
requests, triage issues, manage releases and enforce the
[Code of Conduct](CODE_OF_CONDUCT.md). The current maintainers are listed in
[MAINTAINERS.md](MAINTAINERS.md).

**The lead maintainer** is a maintainer who also resolves disagreements that the
maintainers cannot settle among themselves, and who is responsible for the
project's licensing, trademark and security-disclosure matters.

## How decisions are made

- **Everyday changes** (bug fixes, documentation, tests, small features) are
  decided in pull requests. A maintainer reviews the change and merges it once
  the required checks pass and review comments are resolved.
- **Significant changes** go through an RFC. A change is significant when it
  adds or breaks a public API, changes configuration or data formats in a way
  users must act on, adds a package or a top-level dependency, or changes how
  the project is run. The process is described in
  [docs/rfcs/README.md](docs/rfcs/README.md).
- **Disagreements** are discussed openly on the issue, pull request or RFC.
  Maintainers aim for consensus. When it cannot be reached, the lead maintainer
  makes the decision and records the reasoning where the discussion took place.
- **Security issues** are handled privately under [SECURITY.md](SECURITY.md)
  until a fix is available.

## Becoming a maintainer

Maintainers are added from among active contributors. The usual path is:

1. A record of substantive, merged contributions in an area of the project,
   such as code, tests or documentation.
2. Regular, constructive participation in reviews, issue triage or
   discussions.
3. A nomination by an existing maintainer, or a request from the contributor.

The maintainers decide on the nomination, and the lead maintainer makes the
final call. A new maintainer is added to [MAINTAINERS.md](MAINTAINERS.md) and to
[`.github/CODEOWNERS`](.github/CODEOWNERS) for the areas they review.

## Stepping down

A maintainer can step down at any time by opening a pull request that removes
them from [MAINTAINERS.md](MAINTAINERS.md). A maintainer who has been inactive
for an extended period, or who breaches the Code of Conduct, may be removed by
the other maintainers.

## Licensing and trademarks

The code is licensed under the [Apache License, Version 2.0](LICENSE).
Contributions are accepted under the [Contributor License Agreement](CLA.md).
The Lightwork name and logo are covered by the
[trademark policy](TRADEMARK.md).
