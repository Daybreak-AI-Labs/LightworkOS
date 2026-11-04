# Information-flow control

Per-tool policy answers "may this agent call `email`?". It cannot answer "has
this agent read payroll first?". In a swarm, the answer also spreads between
agents:
- every agent's tool output is excerpted to the shared blackboard, which is
  rendered into every other agent's context each turn;
- children inherit their parent's brief and hand their answers back;
- peers message each other.

`maverick.ifc` tracks what each agent has seen, and decides at the tool gate
whether that data may leave.

## Labels

- A tool that reads tenant data labels the calling agent `data:<tool>`. The
  classification matches composition risk: files, attachments and PDFs,
  `knowledge_search`, `memory` and `kv_memory`, `database`, SQL and spreadsheet
  reads, the data-platform and SaaS tools (`salesforce`, `snowflake`,
  `bigquery`, `mongodb`, `notion`, `confluence`, `msgraph`, `gmail`, `s3` and
  others), enterprise connectors, `*_read` tools and `mcp_*`. `read_tool_result`
  is not a source: it re-reads output the agent was already labelled for.
- A run can start labelled. A codebase run is labelled `code:<repo>` from its
  first token.

## Propagation

Labels only accumulate. They are also kept per goal and per conversation, so a
resumed goal or a follow-up turn starts with every label an earlier run of it
saw.

| Channel | Rule |
|---|---|
| Blackboard | A reader absorbs the labels of every agent whose posts it is shown, both in its first brief and in each per-turn delta. |
| Spawn | A child inherits its parent's labels; the parent absorbs the child's when the child's answer returns. |
| Peer bus | The recipient of a delivered message (plain or signed handoff) absorbs the sender's labels. |

## Enforcement

A call to an external sink by a labelled agent is checked at the tool gate,
after org governance and before hooks. External sinks are tools that can send
to a destination chosen in the call: `email`, `gmail`, `sendgrid`, `mailgun`,
`twilio`, `notify`, `calendar`, `teams`, `slack_bot`, `discord_bot`,
`telegram`, `twitter`, `github_issues`, `http_fetch`, `openapi_runner`,
`git_advanced`, `web_search`, `browser`, public-data connectors and `mcp_*`.
`websocket`, `ses` and `sns` send too. `shell`, `notebook_exec` and
`code_exec` and `repl_exec` count when the sandbox can reach the network:
always on the default `local` backend (it runs on the host) and on `ssh` (a
remote host's network), and on a container backend only with `[sandbox]
allow_network` (firecracker: `network`). `wasm_run` never does. A
tool can be both a source and a sink (`gmail`). A remote MCP server is not
tainted by its own output: labels from `mcp_<server>__*` are ignored on calls
back to that server. What happens depends on the mode:

| Mode | Behaviour |
|---|---|
| `off` | No tracking. |
| `audit` (default) | Record an `ifc_flow` audit row and allow. |
| `approve` | A human approves through the consent path, shown the destination (URL query strings elided); auto-approve modes count as denial. A grant covers that sink, that destination and those labels for the rest of the run. A new destination (including any added `cc`/`bcc` recipient), a new label, or a literal copy the approver was not told about asks again, and so does every call whose destination cannot be identified from its arguments (search queries are data, not a destination) or has more parts than can be shown. |
| `block` | Refuse. The agent is told not to route the data through another external tool. |

`scope = "explicit"` acts only when the labelled data appears literally in the
outgoing arguments. The default `context` scope acts on anything the agent has
seen, because a model can paraphrase. Either way, each decision carries a
witness: sensitive outputs are fingerprinted, and any copied span of 47 or
more characters (compared case-folded, URL-decoded and whitespace-normalised)
is reported as an explicit flow. When a scan cap makes that unknowable (output
past 1M characters, arguments nested deeper than 32 levels or longer than 1M
characters, 200k fingerprints held), and for labels a run starts with (a
repository, or an earlier run's data, which carry no fingerprints here),
`explicit` scope acts as `context` does.

```toml
[ifc]
mode = "approve"             # off | audit | approve | block
scope = "context"            # context | explicit
allow_sinks = ["web_search"] # external tools exempt from the check
```

`MAVERICK_IFC_MODE` overrides `mode`. A codebase run enforces at least its
repository's protection mode whatever the global setting.

## Evidence

Each decision writes an `ifc_flow` audit row containing the tool, labels,
explicit labels, a short digest of the destination, mode and outcome
(`recorded`, `approved`, `denied`, `allowed_by_grant` or `blocked`), plus a
counts-only local projection for the dashboard. Neither records arguments or
data. A repeat of the same decision and outcome in one run is written once.

## Limits

- Memory recall is labelled because `memory`, `kv_memory` and
  `knowledge_search` are sources, but the label names the recall tool, not the
  run that wrote the data.
- Blackboard propagation is conservative: a reader absorbs a poster's labels
  even if the specific excerpt it was shown held none.
- The witness detects literal copies (after case-folding and URL-decoding),
  not other encodings such as base64, or paraphrase. That is why context taint
  is the default gate.
