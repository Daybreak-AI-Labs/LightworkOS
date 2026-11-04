# Plugin SDK

External Python packages can extend Lightwork by declaring entry points
in their `pyproject.toml`. Plugins are discovered at run-time and a
broken plugin can never take the swarm down — each load is wrapped in a
forgiving handler that logs and continues.

## What can be extended

| Slot | Entry-point group | What it does |
|---|---|---|
| Tools | `maverick.tools` | A callable that returns a `maverick.tools.Tool`. Registered in every agent's base registry. |
| Channels | `maverick.channels` | A `maverick_channels.Channel` subclass. Wired by `maverick serve` when enabled in config. |
| Skills | `maverick.skills` | A `maverick.skills.Skill` instance. Auto-included in skill retrieval. |
| Personas | `maverick.personas` | A renderer callable returning a system-prompt suffix. Referenced from `[persona] name = "..."`. |

## Tool plugin example

`my_plugin/pyproject.toml`:

```toml
[project]
name = "maverick-weather-plugin"
version = "0.1.0"
dependencies = ["maverick-agent>=0.1"]

[project.entry-points."maverick.tools"]
weather = "my_plugin:weather_tool"
```

`my_plugin/__init__.py`:

```python
from maverick.tools import Tool

def weather_tool():
    def fn(args):
        # ...call weather API with args["city"]...
        return "72°F, sunny"
    return Tool(
        name="weather",
        description="Look up current weather for a city.",
        input_schema={
            "type": "object",
            "properties": {"city": {"type": "string"}},
            "required": ["city"],
        },
        fn=fn,
    )
```

Install it from a reviewed local checkout, for example
`python -m pip install -e ./plugins/maverick-weather-plugin` — and on the next swarm
run, every agent gets a `weather` tool in its catalog. The tool passes
through `Shield.scan_tool_call` just like a built-in.

## TypeScript plugins

The bundled `sdks/plugin-ts` kit (`@maverick/plugin-sdk`) lets a publisher
provide a Node program exposing tools through the current
`maverick-plugin/2` NDJSON stdio contract. The host also accepts the legacy
`maverick-plugin/1` contract; these protocol versions are distinct from the
Python plugin manifest's supported API majors.

After the program is installed, an administrator can open **All settings**,
search for **TypeScript plugins**, and add its **Program**, **Plugin file**
and optional **Extra words** using the ordinary reviewed settings form.
Configuration does not require editing a file in a terminal. The program and
its runtime must already exist on the installation. Lightwork checks the
program's declared tools before exposing them, starts its process on first
use with a scrubbed environment, and retains an interrupted invocation as
unconfirmed rather than automatically repeating possible effects.

## Channel plugin example

```toml
[project.entry-points."maverick.channels"]
pager = "pager_channel:PagerChannel"
```

```python
from maverick_channels import Channel

class PagerChannel(Channel):
    name = "pager"

    @classmethod
    def from_config(cls, handler, config):
        # config is the [channels.pager] table without "enabled".
        channel = cls(handler)
        channel.url = config["url"]
        return channel

    async def start(self): ...
    async def send(self, user_id, text): ...
    async def stop(self): ...
```

Enable it in `~/.maverick/config.toml`:

```toml
[channels.pager]
enabled = true
url     = "https://pager.example.com"
```

`maverick serve` starts every enabled `[channels.<name>]` table whose name is
an installed channel plugin, exactly like a built-in channel: messages go
through the same handler (safety checks, workspace policy, AI disclosure,
task intake), and the server starts, sends through and stops the channel.
A plugin that defines `from_config(handler, config)` builds itself from its
table; otherwise it is constructed with the handler alone and receives the
table as `self.config`. A plugin that is missing or fails to load is skipped
with a warning and the other channels still start. Built-in channel names
(Mattermost is built in) always use the built-in adapter.

## Skill plugin example

```toml
[project.entry-points."maverick.skills"]
postgres_migration = "myplugin:POSTGRES_MIGRATION_SKILL"
```

```python
from maverick.skills import Skill

POSTGRES_MIGRATION_SKILL = Skill(
    name="postgres_migration",
    triggers=["alter table", "add column", "drop index"],
    tools_needed=["shell", "read_file"],
    body="When migrating a Postgres column, ...",
)
```

## Persona plugin example

```toml
[project.entry-points."maverick.personas"]
pirate = "myplugin:render_pirate"
```

```python
def render_pirate() -> str:
    return "\nSpeak like a friendly pirate, but stay accurate."
```

`~/.maverick/config.toml`:

```toml
[persona]
name = "pirate"
```

## Discovery API

```python
from maverick import plugins

plugins.discover_tools()      # -> list[(name, factory)]
plugins.discover_channels()   # -> list[(name, Channel subclass)]
plugins.discover_skills()     # -> list[Skill]
plugins.discover_personas()   # -> dict[name, renderer]
plugins.installed_plugins()   # -> {"tools": [...], "channels": [...], ...}
```

## Safety + fault isolation

- Each plugin loads in isolation; an exception during `entry_point.load()`
  is logged and that single plugin is skipped. Other plugins and the
  core keep working.
- Tool factories execute per-agent build; a factory that raises is
  logged and dropped. The agent runs without that tool.
- Plugin tools go through `Shield.scan_tool_call` like every other
  tool. There is no "trusted plugin" bypass.
