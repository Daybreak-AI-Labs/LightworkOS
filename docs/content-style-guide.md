# Content style guide

Every word people read in Lightwork follows this guide: page text, labels,
buttons, messages, `aria-label`s, help topics, Copilot guidance and the
customer docs. It is written for business people, not for the people who
built the product.

## Voice

- Plain words, second person ("you"), present tense, active voice.
- Say what happened, then what to do next.
- No internal nouns. Field keys, module names, HTTP codes, exception text and
  database values never reach the page. If a developer word is the only
  accurate one, put it under a "Technical details" disclosure.
- Short sentences. Aim for a reading grade of 8 or lower.

## Glossary

One approved word for each idea. Use the word in the left column; never the
words in the right column.

| Use | Meaning | Instead of |
| --- | --- | --- |
| **specialist** | One of Lightwork's own built-in job specialists (the packs that ship with Lightwork). A workspace's customized copy is still a specialist, marked **Customized**. | agent (for a built-in pack), pack, compartment |
| **agent** | Everything else: an agent a customer built or drafted, an external or connected agent, an outside agent, and AI agents in general. | specialist (for anything not built in) |
| **agents and specialists** | A list or count that can hold both. Singular: "an agent or specialist". | specialists and agents, specialist agents |
| **task** | Work someone asks Lightwork to do, including background work. A batch has its own plain noun where the page already uses one ("bulk change", "rebuild"). | goal, job (keep **job** only for a person's job: job description, job role, job card) |
| **run** | One execution of a workflow, flow, schedule, automation, test or check. Keep "run" for this meaning only. | run (for a task: say "past tasks", "recent tasks", "per task") |
| **workspace** | The account boundary a team works in. | tenant; "client" except in an OAuth "client ID" field |
| **organization** | The company. | |
| **role** | A permission role only. | role (for an agent or specialist) |
| **approval** / **approve** | A gate a person must pass. A finished result waiting for a person is a "result approval". | decision, sign-off (a person confirming they read a policy "confirms" it) |
| **review** | Looking at something without a gate. | |
| **result** | What work produces. | deliverable, output, artifact |
| Plain name first, acronym in brackets on first use | e.g. "Data requests (DSAR)", "Privacy impact assessment (DPIA)" | a bare DSAR or DPIA |

### Choosing between specialist and agent

- Decide the word from the item's kind, never from its name. In code, use
  `agent_changelog.agent_kind(name)` (returns `"specialist"` for a built-in
  pack, a customized copy included, and `"agent"` for anything else), the
  effective-access `kind`/`label`/`customized` fields, or the
  `approval_private_cards` noun.
- A page or control that only ever shows built-in packs (the department
  catalog on Workforce, the fixed specialist test suite) says "specialist".
- A page or control that shows workspace-built agents only (business setup,
  drafting from a job description, the agent playbook builder) says "agent".
- A list that can hold both (the Agent Factory picker, Compartments,
  Assessments, team rosters) says "agents and specialists", or uses a neutral
  column heading such as "Name" when every row already shows its own name.
- Product names keep their own words: **Agent Factory**, **Action Center**.

## Casing

- Sentence case for everything: page titles, headings, table headers,
  buttons, tabs and menu items. Capitalize only the first word and proper
  nouns ("Open Agent Factory", "Send to ServiceNow").
- Acronyms keep their capitals ("Turn on AI evidence analysis").
- Section `h2`s may be shown in capitals by CSS; author them in sentence case.

## Buttons

- Verb first, at most 4 words, naming the object ("Save policy").
- Page names inside a label are allowed ("Open Settings").
- No leading "+" and no emoji. Use "→" or "↗" only when the link leaves the
  page.
- One word per action:
  - **Cancel** leaves without saving; **Close** shuts a read-only view.
  - **Save**, **Refresh**. "Try again" appears only in error recovery.
  - **Delete** is permanent; **Remove** takes something off a list.
- At most one primary button (`btn btn--primary`) per view, in the page
  header's actions slot.

## Errors

- Pattern: **[What happened]. [What to do next].**
  "The spending limits could not be read. Try again in a minute."
- Pick the next step from what will actually help: "Refresh the page and try
  again." after a read or check fails, "Try again." after a save or send fails,
  "Try again in a minute." when a service is busy or not available right now,
  "Check your connection and try again." when Lightwork cannot be reached,
  "Choose the file again, or try a different file." for unreadable files, and
  "Ask your administrator…" when only an administrator can change it.
- A sentence that reassures ("Your draft has been kept.") is not a next step;
  add one after it.
- Record fields shown to people get plain labels, never raw keys (see the
  `FIELD_LABELS` map in `_governance_operations.html`).
- In the browser, go through `mvErrorText(failure, 'do the thing')`. It writes
  "Could not do the thing." plus a plain next step for the status code.
- Show server text only after `mvPlainDetail` accepts it. Server messages
  meant for people start with a capital letter, end with a full stop and use
  no developer words; anything else falls back to `mvErrorText`.
- Never show HTTP codes, field keys, stack traces or raw exceptions.
- A turned-off feature says so through `X-Lightwork-Reason: feature-off`
  (`feature_gate.py`), not through a permission error.

## Empty states

- "[What will appear here]. [How to add the first one]." plus one button.
- Use the `empty_state` macro in templates or `window.mvEmpty` in scripts.

## Dates, times and numbers

- Dates and times: the `|datetime` filter, `data-mv-time`,
  `mvTimeAbsolute` or `mvTimeRelative`. Show the viewer's own zone; show the
  zone whenever it is not the viewer's.
- Relative times ("2 minutes ago", exact time on hover) for recent activity.
- No ISO strings and no numeric 10/4/2026 dates.
- Money: `|money` or `mvMoney` ("$1,234.56"). Four decimals only for labelled
  per-unit prices.
- Percentages: `|percent`, at most 1 decimal.
- Thousands separators always.
- Time ranges: "7 days / 30 days / 90 days / 1 year".

## Translations

When you change an English string that has a row in a
`maverick_dashboard/i18n_*.py` catalog, change the row's English key and
update every translation in the same row. If you cannot translate a language
accurately, follow the catalog's fallback convention and list the string in
your change description.
