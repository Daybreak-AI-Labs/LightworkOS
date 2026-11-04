# Plugin API v2 reference

The current plugin contract is `MAVERICK_API_VERSION = "2"`. Declare it in your
`maverick-plugin.toml`:

```toml
[plugin]
name        = "my-plugin"
version     = "0.1.0"
api_version = "2"
```

## The v2 contract

- **Structured channel replies.** Channel handlers may return
  `maverick_channels.Reply` (text + attachments + thread_ref) instead of bare
  `str`. Adapters route through `Channel.dispatch` / `dispatch_text`, so a v2
  handler works on every adapter; platforms without a file API drop
  attachments with a debug note and always deliver the text.
- **Manifest permissions are enforced by default.** A plugin that requests an
  ungranted permission (`network` / `fs_write` / `subprocess` /
  `sensitive_envs`) is skipped unless the user grants it via
  `[plugins] grant = [...]`. (`enforce_permissions = false` downgrades to a
  load-with-warning.)
- **Lockfile pinning.** `maverick plugin lock` records each enabled plugin's
  distribution + version; under enforcement a drifted version is refused.
- **Isolation modes.** `[plugins] isolation = "subprocess" | "subinterpreter"`
  runs plugin tool *calls* outside the host interpreter (scrubbed env, fault
  isolation) while their schemas stay in-process.
- **TypeScript plugins.** `sdks/plugin-ts` (`@maverick/plugin-sdk`) authors a
  tool in TypeScript over the current `maverick-plugin/2` NDJSON stdio protocol.
  Add its installed program and plugin file in **All settings > TypeScript
  plugins**; the host retains support for legacy `maverick-plugin/1` programs.
  Tools use the same no-shadowing rule. The stdio protocol version is separate
  from the manifest's `api_version`.

## Compatibility

- `SUPPORTED_API_MAJORS = (1, 2)`: a v1 plugin **loads** during its deprecation
  window, with a deprecation warning in its manifest validation. Migrate by
  setting `api_version = "2"` (and adopting `Reply` if you ship a channel).
- A plugin declaring `api_version = "3"` (or malformed) is refused — the
  kernel never loads a contract it doesn't understand.

## Shared with v1

Entry-point groups (`maverick.tools` / `.channels` / `.skills` /
`.personas`), the allowlist (`[plugins] enabled`), and the name-squat defense
(`name@dist` pinning) work the same way for v1 and v2 plugins.
