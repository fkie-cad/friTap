# Plugins & Custom Scripts

friTap is extensible without touching its source tree. You can drop a Python
file into a plugin directory, ship a plugin as a `pip`-installable package, or
hand friTap a raw Frida script on the command line. This page teaches the
plugin system from the ground up.

friTap exposes two plugin base classes, both living in
[`friTap/plugins/`](https://github.com/fkie-cad/friTap/tree/main/friTap/plugins):

- **`FriTapPlugin`** — a *host-side* plugin. It runs in the Python process,
  subscribes to the event bus, and can register parsers, sinks, and (experimentally)
  TUI columns/tabs.
- **`ScriptPlugin`** — a *Frida-side* plugin. It injects additional JavaScript
  into the target process alongside friTap's own agent, and can talk to that
  script bidirectionally.

!!! tip "Where this fits"
    For the in-process Frida agent itself, see
    [Standalone Agent Usage](../advanced/standalone-agent.md). For the overall
    host/agent split, see [Architecture](architecture.md). For the stable
    Python embedding API, see the [Python API reference](../api/python.md).

---

## Tutorial: write your first plugin

The fastest plugin is a host-side `FriTapPlugin` that reacts to parsed flows.

### 1. Find your plugin directory

friTap auto-creates a per-OS plugin directory on first run. Print the resolved
path:

```bash
python -c "from friTap.plugins.loader import _get_plugin_dir; print(_get_plugin_dir())"
```

The path is platform-native (see [Discovery paths](#discovery-paths) below). On
Linux it is `~/.local/share/friTap/plugins/`.

### 2. Create the plugin file

Save the following as `myflow.py` inside that directory. The loader instantiates
a class named **`Plugin`** from each `.py` file, so the class **must** be called
`Plugin`.

```python title="~/.local/share/friTap/plugins/myflow.py"
from friTap.plugins.base import FriTapPlugin
from friTap.events import FlowEvent, EventBus


class Plugin(FriTapPlugin):
    @property
    def name(self) -> str:
        return "myflow"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Prints each completed HTTP flow"

    def on_load(self, session) -> None:
        # Subscribe at PLUGIN_PRIORITY so plugins run before built-in handlers.
        session.lifecycle_bus.subscribe(
            FlowEvent,
            self._on_flow,
            priority=EventBus.PLUGIN_PRIORITY,
        )

    def _on_flow(self, event: FlowEvent) -> None:
        if event.flow_event_type == "completed":
            flow = event.flow
            if flow.request:
                print(f"{flow.request.method} {flow.request.url}")
```

### 3. Run friTap

That is it — friTap discovers, loads, and activates the plugin automatically.
On startup you will see a log line like `Loaded plugin: myflow v1.0.0`, and each
completed flow prints its method and URL.

!!! note "What `name` and `version` are for"
    Both are abstract properties on `FriTapPlugin` and **must** be implemented.
    `name` is the unique key in the plugin registry (a duplicate name overwrites
    the earlier plugin); `version` is logged at load time. `description` is
    optional and defaults to an empty string.

---

## `FriTapPlugin` vs `ScriptPlugin`

Choose the base class by *where your code needs to run*.

| | `FriTapPlugin` | `ScriptPlugin` |
|---|---|---|
| Runs in | Python host process | Target process (injected Frida JS) |
| Primary entry point | `on_load(session)` | `get_script_source(context)` |
| Sees | events, flows, parsers, sinks | native memory, function hooks |
| Lifecycle hooks | `on_load`, `on_event`, `on_unload` | adds `on_instrument`, `on_script_message`, `on_detach_process` |
| Backend-aware | no | yes (`supported_backends`, load order) |
| Use it to | post-process captured data, add parsers, integrate with other tools | hook additional functions, dump keys from other libraries, modify behavior |

`ScriptPlugin` **is a** `FriTapPlugin` (it subclasses it), so a script plugin
can also subscribe to host events in its `on_load`. The split is two-phase by
design:

- **Phase 1 — `on_load(session)`**: called when the plugin is loaded. No backend
  is attached yet, so subscribe to the event bus here.
- **Phase 2 — `on_instrument(context)`**: called once the target process is
  attached. This is where a `ScriptPlugin` injects its script.

### `FriTapPlugin` lifecycle methods

```python
def on_load(self, session) -> None: ...    # subscribe to events here
def on_event(self, event) -> None: ...      # catch-all for every event
def on_unload(self, session) -> None: ...   # release resources here
```

### Event cancellation

A host plugin can take over display of a buffer and suppress friTap's default
console output by cancelling the event:

```python
from friTap.events import DatalogEvent, EventBus

def on_load(self, session) -> None:
    session.lifecycle_bus.subscribe(
        DatalogEvent, self._handle, priority=EventBus.PLUGIN_PRIORITY,
    )

def _handle(self, event: DatalogEvent) -> None:
    print(event.data.decode("utf-8", errors="replace"))
    event.cancel()  # suppress default hexdump
```

!!! warning "Cancellation is advisory"
    Cancelling an event suppresses **console** display only. File-based
    handlers (PCAP, keylog, JSON) always record the data regardless.

---

## Lifecycle & load phases

`ScriptPlugin` adds a load *order* relative to friTap's own main agent script.
The order is declared by the `load_order` property, which returns a
`ScriptLoadOrder` enum value:

```python
from friTap.plugins.script_plugin import ScriptLoadOrder

ScriptLoadOrder.BEFORE_MAIN   # value "before" — injected before friTap's agent
ScriptLoadOrder.AFTER_MAIN    # value "after"  — injected after  (the default)
```

When friTap instruments the process, the `PluginLoader` sorts script plugins so
that **`BEFORE_MAIN` plugins run first**, then `AFTER_MAIN`. Injection happens in
`PluginLoader.instrument_all(context, order=...)`, which iterates the sorted
plugins and calls each plugin's `on_instrument(context)`. A failure in one
plugin is logged but does not block the others.

The default `on_instrument` implementation:

1. checks backend compatibility (`is_compatible_with(context.backend_name)`),
2. calls `get_script_source(context)` (an empty string skips injection),
3. creates and loads the script via the backend,
4. wires up message routing to `on_script_message`.

!!! info "Backend compatibility"
    Override `supported_backends` to restrict a plugin to specific backends
    (e.g. `return ["frida"]`). An empty list (the default) means *all* backends.
    Incompatible plugins are skipped with a warning rather than erroring.

---

## Discovery paths

`PluginLoader.discover()` finds plugins from three sources:

**1. The platform-native plugin directory** (auto-created on first run, via
`platformdirs.user_data_dir("friTap")`):

| OS | Path |
|---|---|
| Linux | `~/.local/share/friTap/plugins/` |
| macOS | `~/Library/Application Support/friTap/plugins/` |
| Windows | `C:\Users\<user>\AppData\Local\friTap\plugins\` |

**2. The legacy directory** `~/.fritap/plugins/` — used only if it exists **and**
the native directory does not (backwards compatibility).

**3. Python entry points** in the group `fritap.plugins` — the path for plugins
shipped as installable packages.

### File plugins must expose a `Plugin` class

For directory-based plugins, every `*.py` file whose name does **not** start
with `_` is imported, and the loader looks for a class literally named
`Plugin`. It is instantiated and, if it is a `FriTapPlugin` instance,
activated:

```python
class Plugin(FriTapPlugin):   # the name must be exactly "Plugin"
    ...
```

### Packaged plugins via entry points

Ship a plugin as a `pip` package by declaring an entry point. The entry-point
*value* is the plugin **class** (the loader calls `ep.load()` then instantiates
it):

```toml title="pyproject.toml"
[project.entry-points."fritap.plugins"]
myplugin = "my_package.plugin:MyPlugin"
```

Here `MyPlugin` is a `FriTapPlugin` (or `ScriptPlugin`) subclass — note that
entry-point plugins are *not* required to be named `Plugin`, unlike file
plugins.

---

## Registering a parser from a plugin

A host plugin can add a custom protocol parser so friTap recognizes additional
protocols (gRPC, MQTT, a proprietary binary protocol, …). Call
`session.register_parser()` from `on_load`:

```python
from friTap.plugins.base import FriTapPlugin
from friTap.parsers.base import BaseParser, ParseResult


class MqttParser(BaseParser):
    PROTOCOL = "mqtt"

    def can_parse(self, data: bytes) -> bool:
        return len(data) >= 2 and (data[0] >> 4) in range(1, 15)

    def feed(self, data: bytes, direction: str,
             stream_id: int | None = None) -> list[ParseResult]:
        ...   # return parsed results

    def flush(self) -> list[ParseResult]:
        return []


class Plugin(FriTapPlugin):
    name = "mqtt"
    version = "1.0.0"

    def on_load(self, session) -> None:
        session.register_parser(MqttParser, priority=75)
```

`register_parser(parser_cls, priority=50)` inserts the parser into the detection
registry; `can_parse()` is tried in **descending priority** during protocol
detection (higher number = tried first).

!!! note "Parser contract"
    `BaseParser` requires three methods — `feed()`, `flush()`, and
    `can_parse()` — plus a `PROTOCOL` class attribute. The
    [Adding Features](adding-features.md#add-a-protocol-parser-python) guide
    walks through writing a full parser, including `ParseResult` and how
    parsers slot into flow detection.

---

## Custom Frida script via `-c` / `--custom_script`

You do not need a full plugin to inject one-off instrumentation. Pass a Frida
JavaScript file on the command line:

```bash
fritap -c myhooks.js -k keys.log -m com.example.app
```

Internally, friTap wraps this script as a **`LegacyCustomScriptPlugin`** — a
`ScriptPlugin` with `load_order = BEFORE_MAIN`, so your script is injected
**before** friTap's own agent (matching the original `--custom_script`
behavior). It supports only the `frida` backend.

!!! info "Help text"
    The `-c` help reads: *"Path to a custom hook script that will be executed
    prior to applying the friTap hooks."*

### Sending messages back to the host

The custom-script wrapper reproduces friTap's original message handling:

- A message with `type == "error"` is pretty-printed and friTap terminates
  itself (`SIGTERM`).
- A payload dict containing a `"custom"` key is logged at info level.

So from your injected script you can surface data like this:

```javascript title="myhooks.js"
// logged by friTap as: "custom hook: <your value>"
send({ custom: "hooked SSL_write, len=" + len });
```

For richer Frida-side development — building the agent, the message protocol,
and a standalone keylog example — see
[Standalone Agent Usage](../advanced/standalone-agent.md).

### Bidirectional messaging (experimental)

!!! warning "Experimental"
    `ScriptPlugin.post_to_script(msg_type, payload, script_index=0)` lets the
    host send a message *to* an injected script. This API is experimental and
    its message envelope may change.

---

## Decryptor seam (extension point)

friTap's protocol-layer stack can decrypt nested protocols (turning a parent
layer's ciphertext into a child layer's plaintext) through the
**`LayerDecryptor`** abstraction in
[`friTap/flow/decryptors/`](https://github.com/fkie-cad/friTap/tree/main/friTap/flow/decryptors).

```python
from friTap.flow.decryptors import (
    LayerDecryptor,
    DecryptorRegistry,
    get_default_decryptor_registry,
)


class MyDecryptor(LayerDecryptor):
    name = "my-decryptor"

    def can_handle(self, parent_layer, flow) -> bool:
        ...   # True if this decryptor handles parent_layer's payload

    def feed(self, data: bytes, direction: str) -> bytes:
        ...   # return decrypted plaintext for "read"/"write"


get_default_decryptor_registry().register(MyDecryptor, priority=75)
```

`DecryptorRegistry.resolve(parent_layer, flow)` returns the highest-priority
decryptor whose `can_handle()` accepts the layer; a misbehaving decryptor is
isolated (logged and skipped). There is **no fallback** — an unhandled layer
resolves to `None`.

!!! note "Currently an empty seam"
    The default registry returned by `get_default_decryptor_registry()` is
    **intentionally empty**. It is a live extension point with no built-in
    decryptors yet — this is the documented path for adding nested-protocol
    decryption.

---

## Experimental: TUI columns & tabs

!!! warning "Experimental"
    The TUI provider hooks below are experimental; their protocols and
    registration signatures may change.

A host plugin can add columns to the flow-list table and tabs to the flow-detail
view by implementing the `ColumnProvider` / `TabProvider` protocols (defined in
`friTap/plugins/base.py`) and registering them via `session.register_column()`
and `session.register_tab()`:

```python
class LatencyColumn:                 # implements ColumnProvider
    name = "Latency"
    key = "latency"
    width = 8

    def value(self, flow) -> str:
        return f"{flow.duration_ms:.0f}ms"

    def style(self, flow) -> str:
        return ""


class Plugin(FriTapPlugin):
    name = "latency-col"
    version = "1.0.0"

    def on_load(self, session) -> None:
        session.register_column(LatencyColumn())
```

`ColumnProvider.value()` is called on **every** flow update — keep it cheap
(cache derived values, avoid I/O). See the
[TUI guide](../getting-started/tui.md) for the interactive interface itself.

---

## See also

- [Adding Features](adding-features.md) — parsers, TLS libraries, new protocol families
- [Architecture](architecture.md) — host/agent split, the event bus, pipeline & sinks
- [Python API](../api/python.md) — embedding friTap and the stable public surface
- [Standalone Agent Usage](../advanced/standalone-agent.md) — building and using the Frida agent directly
