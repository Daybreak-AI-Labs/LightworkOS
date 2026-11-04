# Employee journey localization

Interface language and response language are independent. The account preference
`interface_language` supports English, French, German, Japanese, Chinese and the
existing Arabic community seed. Its empty value follows response language for
compatibility. It inherits through existing organization/workspace/personal
layers and respects organization locks. A header choice can be device-only and
remains bound to the current account/workspace. Changing language saves without
reloading an editor; the next navigation uses the saved choice. Neither this
field nor its cookie enters a model prompt.

French, German, Japanese and Chinese journey catalogs are **draft, partial
translations**. They have not received native-language or consequence-copy
approval. Arabic's seed has not been machine-completed. `CONTENT_LANGS` remains
`{"en"}`: the page's English fallback body is declared honestly, and each
translated control declares its actual language. A visible notice describes
partial coverage. The product is not fully localized.

`ui(source, **values)` renders an escaped product-copy region; `ut(source)` and
`ul(source)` supply text and actual language for options and attributes. The
source key is a stable hash of the exact English source. Existing translation
portal validation checks the same catalog. New copy needs all four draft
translations with identical placeholders; untranslated text stays English.
Never call these helpers on an employee's source document, title, result, note,
draft or model output. Those regions retain their text, use `lang="und"` when
the content language is unknown, and have independent bidi direction.

The browser helper translates only explicit product bindings. It never scans
arbitrary text or observes streamed user content. Parameter values use escaped
`bdi` elements. Its formatters use the matching regional browser locale and
browser time zone; calendar dates are constructed locally to avoid UTC-day
drift. Typed product numbers, currency and review pagination use `Intl`.
Product validation adds a language-labelled error without modifying the draft.
`mvConfirm(..., {productCopy: true, values})` is the explicit confirmation-copy
path; ordinary caller messages remain unchanged.

Run `python scripts/journey_i18n_coverage.py --output
<path>/web-localization-coverage.json` from the repository root to generate the
engineering inventory (the output is a working file, not a tracked document). It reports literal HTML occurrences,
with source locations. It deliberately does **not** qualify dynamic labels,
shared includes, browser/API messages, linguistic quality or screen-reader
behavior, so a count of zero literal fragments does not mean that a journey is
fully localized.

Localization covers locale precedence and inheritance, account-bound cookies and
locks, Arabic fallback, escaped parameter/source text, explicit dialog/table
regions, streamed content, date/number/plural formatting and required-field error
recovery. Response prompts are not translated.

Workflow review binds publication/restoration effects, draft/version states,
sample checks, schedules and triggers explicitly. Stored schema labels/choices,
workflow names and version diffs retain their own language and exact values.
Generic request errors localize only classified product reasons; unknown server
copy stays explicitly English. A bounded page-local formatter record preserves
the actual language when a translated status is passed between controllers.
The three remaining literal workflow examples are canonical parameter/tool
identifiers, not prose. They remain unchanged because changing them would change
what the workflow references.

Conversation inbox controls use explicit product constructors; stored messages,
acknowledged payloads, file names and task briefs use a separate verbatim source
constructor. Localization never changes the operation ID, selected mode, reviewed
revision/snapshot or exact receipt retry. Restart review localizes its consequence
and USD display while keeping the task title isolated and its numeric limit
unchanged. Tests exercise the current inbox and restart controllers, including
permission loss and uncertain outcomes, with synthetic HTTP responses only.

## Live conversation and preference controls

The live conversation controller binds product messages explicitly: clarification changes, prepared-file state, exact answer receipts, stop and live-update recovery, work summaries and speech-input feedback. Source messages, tool output and filenames retain their own direction and remain verbatim. File counts, sizes, dates, step counts and the inherited restart ceiling use the selected regional formatter.

Preference reviews translate field/source labels and consequence copy while retaining exact before/after values and custom guidance. Saving interface language keeps the editor in place and records that the change applies on the next page load. Built-in theme labels are product copy; custom theme names are preserved exactly. Select options use text-only labels with explicit language metadata.

Draft catalogs remain subject to native-language and consequence-copy review; Arabic is still a community seed and English remains the only qualified complete-body language.
