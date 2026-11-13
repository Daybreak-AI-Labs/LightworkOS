# Provider configuration admission

Lightwork validates `[providers.<name>]` before constructing a cached client or
dispatching a model request. Each adapter declares the configuration fields it
can consume. An unsupported nonempty field produces an error naming the
provider and field; secret values are omitted from that error. Malformed header
tables, invalid HTTP header names/values, and duplicate case-insensitive header
names are refused.

| Adapter | Supported provider table fields |
| --- | --- |
| `anthropic`, `openai` | `api_key`, `base_url`, `default_headers` |
| `azure` | `api_key`, `base_url`, `default_headers`, `auth_mode`, `deployment`, `api_version` |
| `bedrock` | `api_key`, `base_url`, `default_headers`, `auth_mode`, `endpoint`, `region`, `model_id` |
| `vertex` | `base_url`, `default_headers`, `project_id`, `region`, `model_id`; no `api_key` (Google Application Default Credentials only) |
| `openrouter`, `gemini`, `moonshot`, `deepseek`, `xai`, `ollama`, `tgi`, `vllm`, `openai_compatible` | `api_key`, `base_url` |
| `codex_cli` | `api_key`, `binary`, `sandbox_mode`, `timeout_seconds`, `cwd` |

Headers remain supported by the same four adapters. Lightwork does not infer
header, reasoning, tool or streaming support from the phrase "OpenAI compatible"
or forward policy headers to additional endpoints. `codex_cli` cannot select a
backend with `base_url`; the external CLI owns that selection.

The dispatcher captures configuration and environment into an immutable
`ProviderConfig`. API keys, endpoint, accepted headers, authentication mode,
adapter options and the constructor environment participate in a one-way cache
fingerprint. Cache keys also include tenant identity; the bounded LRU and stale
rotation eviction remain in place. Header ordering/case and equivalent numeric
Codex timeout values reuse an existing client. Credentials do not appear in the
configuration's representation or cache keys. Per-tenant key precedence and the
exact requested provider/model remain unchanged.

Constructors receiving a dispatcher snapshot must not fill missing API keys or
endpoints from a later environment generation. SDK connect/read timeouts and
OpenAI organization/project metadata use the captured environment. Missing
organization/project values stay absent on the wire. Codex launch options and
its filtered subprocess environment are bound to its client generation; changes
rebuild the cached client. The CLI authentication file remains externally owned
and can change at its captured location.

Codex resolves and pins an absolute `CODEX_HOME` before checking authentication,
then supplies that same directory to login and execution. An explicit snapshot
without `CODEX_HOME` or its platform home variable is refused; a direct caller
that omits the snapshot can discover its home once at construction. On Windows,
snapshot executable lookup uses the captured `PATH` and `PATHEXT` only. It does
not implicitly search the current directory; configure an explicit binary path
or include the intended directory in `PATH`.

Azure uses its existing default API version when the admitted version is empty.
Bedrock pins the selected regional or configured endpoint. Its installed SDK is
checked after construction: if an ambient bearer token causes the SDK to select
bearer authentication while Lightwork selected IAM, construction fails before a
request and closes the constructed client. Remove the conflicting bearer token,
or explicitly configure `auth_mode = "api_key"` and the intended token. The
adapter does not rewrite private signing state to conceal that conflict.

Vertex AI takes no key. It signs in with Google Application Default Credentials;
the `vertex` extra provides google-auth. The project and region are checked
before any client exists. The model id must be the `name@version` form shown in
the Vertex AI Model Garden: any other id is refused before a request is built,
and before a cache warm-up is sent. `base_url` is accepted only from the server
configuration or environment, never from Settings, because the Google token is
sent to the endpoint. Constructor tests establish no live Google authentication.

IAM role/profile refresh and Azure Identity credential acquisition remain the
respective SDKs' credential authority. Immutable adapter configuration does not
freeze externally rotated role credentials, credential files, machine trust
stores or operating-system DNS. No live AWS/Azure authentication is established
by constructor tests.

Upgrading: provider fields that an adapter does not support fail visibly instead of being ignored. For a required
residency/retention header, choose a supported adapter and an explicitly reviewed
endpoint; deleting the field means removing that requested control. Azure
`deployment` and `api_version`, and Bedrock `region` and `model_id`,
are supported provider-table fields, including values saved by the dashboard.
The providers' documented environment overrides still take precedence. SDK
timeouts retain their environment interfaces; unsupported provider-table fields
are refused. Direct callers that supply `environment` must supply their complete
desired constructor snapshot; omitted values use adapter defaults, not live
environment fallback. Omitting that optional argument retains direct-constructor
environment discovery.

This admission contract does not replace provider-specific request shaping,
response normalization, model allowlists, egress checks, budgets or the bounded
retry authority. The reusable native synchronous and asynchronous SDK clients
remain separate, with SDK-level retries disabled.
