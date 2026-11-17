# Lightwork checker image

A container for the independent checkers of code changes (see
[docs/codebase.md](../../docs/codebase.md)). It lets a repository's tests
that need a database or a browser run during a check, and when Lightwork
re-runs a checker's repro command.

It holds:

- Python 3.12 (`python`, `python3`) and Python 3.11 (`python3.11`), each with
  pytest, Playwright and psycopg (`requirements.txt`);
- git;
- PostgreSQL 16. The entrypoint starts a throwaway server on `127.0.0.1:5432`
  with the empty database `lightwork_test`, then runs the command. The data
  lives in `/tmp` and is gone when the container ends;
- Chromium's headless shell for Playwright (`/opt/ms-playwright`).

Every base image and package is pinned. Nothing secret is stored: the
database trusts local connections only.

## Build and use

```bash
docker build -t lightwork-checker:1 deploy/checker
```

```toml
[codebase]
checker_image = "lightwork-checker:1"
```

Checks and repro re-runs then run in this image instead of the configured
work area: on Docker for the `local` and `docker` work areas, on Docker
with gVisor's runtime for `gvisor`, and on Podman for `podman`. Any other
work area cannot carry the image, so the check says it could not run. The
rest of `[sandbox]` still applies: no network unless `allow_network` is on,
and the memory cap. Lightwork never pulls the image: build it (or pull it)
on the computer that runs the checks first. If the image cannot be used,
the check is reported as "could not run" with the reason. It never runs on
this computer instead. Only the organisation's own config sets
`checker_image`; a workspace cannot.

Behind a proxy that inspects TLS, pass a certificate bundle that includes
the proxy's certificate while building. It is used for the build only and
is not stored in the image:

```bash
docker build --secret id=extra_ca,src=/path/to/ca-bundle.crt -t lightwork-checker:1 deploy/checker
```

## Database variables

The image sets these, so a repository's tests find the database:

| Variable | Value |
| --- | --- |
| `MAVERICK_PG_DSN`, `MAVERICK_CONSENT_PG_DSN` | `postgresql://postgres@127.0.0.1:5432/lightwork_test` (the names Lightwork's own Postgres tests read) |
| `DATABASE_URL` | the same address |
| `PGHOST`, `PGPORT`, `PGUSER`, `PGDATABASE` | `127.0.0.1`, `5432`, `postgres`, `lightwork_test` (read by `psql` and libpq) |

## Limits

- PostgreSQL does not run as root. When Lightwork itself runs as root, it
  runs the image as the image's ordinary user (`1000:1000`) and hands each
  throwaway copy to that user. Started some other way as root, the
  entrypoint stops with exit code 97 before the command.
- Exit code 97 always means the image's own setup failed, so Lightwork does
  not read it as the repro's result.
- Only the headless browser is installed: Playwright's default headless
  launch works, a visible browser window does not.
- Debian replaces superseded package versions on its mirrors. If a pinned
  version is no longer available, update the pin in the `Dockerfile`.
