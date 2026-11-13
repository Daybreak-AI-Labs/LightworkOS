# Translated documentation

Community-maintained translations of the Lightwork user docs. The English files under [`docs/`](../) are always authoritative; translations may lag behind them.

## Languages

| Code | Language | Translated so far |
|---|---|---|
| `es` | Español | [getting-started.md](./es/getting-started.md) |
| `ja` | 日本語 | [getting-started.md](./ja/getting-started.md) |
| `de` | Deutsch | [getting-started.md](./de/getting-started.md) |
| `fr` | Français | [getting-started.md](./fr/getting-started.md) |
| `pt-BR` | Português (Brasil) | [getting-started.md](./pt-BR/getting-started.md) |
| `ko` | 한국어 | [getting-started.md](./ko/getting-started.md) |
| `ru` | Русский | [getting-started.md](./ru/getting-started.md) |
| `it` | Italiano | [getting-started.md](./it/getting-started.md) |
| `hi` | हिन्दी | [getting-started.md](./hi/getting-started.md) |

Only `getting-started.md` is translated so far.

## How staleness is tracked

Every translated file starts with an HTML comment (in the target language) naming the source file and the short git commit hash of the English revision it was translated from. To check whether a translation is stale, compare that hash against the current hash of the English source:

```bash
git log -1 --format=%h -- docs/getting-started.md
```

If they differ, the English page changed after the recorded source revision. A
matching hash alone does not prove the whole translation is current: a partial
update must name the refreshed sections and disclose that other sections may
lag. When updating a translation, use a source hash that resolves in this
repository and refresh that scope note. The current first-run and monitor
updates use `b05c5ff`, the recorded English source revision; the former
`a7b9cee` marker did not resolve in this repository.

**Note on links:** link targets are kept byte-identical to the English source, so relative links inside a translation (for example `./configuration.md`) still refer to the English documentation until a translated counterpart exists.

## Contributing a new language

- **Docs (this directory):** copy the English page into `docs/i18n/<lang>/` (BCP 47 code, e.g. `es`, `pt-BR`), translate the prose, and leave code blocks, inline code, file paths, env var names, config keys, URLs, and product names untranslated. Add the source-commit header comment described above, and add your language to the table in this README. `packages/maverick-core/tests/test_docs_i18n_files.py` enforces the basics.
- **Dashboard UI strings:** these are not managed here. The catalogs live in `packages/maverick-dashboard/maverick_dashboard/i18n.py` and the `i18n_journey_*.py` tables; send changes as a pull request against those files.

## Machine translation for additional languages

Languages beyond this hand-maintained set ride the docs i18n pipeline module:

```bash
python -m maverick.docs_i18n
```

Machine output is a starting point only — have a native speaker review it against the quality bar of the translations in this directory before merging.
