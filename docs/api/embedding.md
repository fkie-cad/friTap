# Embedding the .tap Viewer

friTap's interactive `.tap` viewer can be used from another project. There are three ways to do it:

| Mode | What you do | Use it when |
|------|-------------|-------------|
| **A. Launch** | Call `open_tap(path)` from your own CLI | You want a viewer window and nothing else |
| **B. Mount** | Push `TapViewerScreen` into your own Textual app | You already have a Textual app |
| **C. Extend** | Ship a package that adds tabs, columns, decoders and filter fields | You want the viewer to understand your data |

All names live in the `friTap.ui` facade. It is lazy: `import friTap.ui` loads neither Textual nor Frida nor any capture code. Textual is imported only when you first touch a viewer name (`open_tap`, `TapViewerApp`, `TapViewerScreen`, `install_theme`, `theme_variable_defaults`). The extension, analyzer and decoder names never load Textual.

Note: `from friTap.ui import *` imports the Textual-backed names too (for example `TapViewerScreen`), so it needs Textual. Extension packages that must work without Textual should import from `friTap.ui.extensions`.

!!! note "Install"
    The viewer needs `textual>=0.86.0`. It is already part of the base install (`requirements.txt`), so `pip install fritap` is enough. `pip install fritap[tui]` is a no-op alias that only documents intent (the `tui` extra is empty in `setup.py`). `open_tap` raises `ImportError` with an install hint if Textual is missing.

---

## Mode A: launch from a host CLI

```python
from friTap.ui import open_tap

open_tap("capture.tap", title="My Tool", sub_title="capture.tap", theme="fritap-dark")
```

`open_tap(path, *, title=None, sub_title=None, theme=None, output_dir=None)` blocks until the viewer is closed.

| Parameter | Meaning |
|-----------|---------|
| `path` | The `.tap` file to open. |
| `title` | Header title. Default `"friTap"`. |
| `sub_title` | Header sub-title. Default: the file name. |
| `theme` | A registered Textual theme name. Default `"fritap-dark"`. |
| `output_dir` | Directory offered by the "save .tap" dialog (`w`). |

**Exceptions.** `FileNotFoundError` if `path` does not exist. `ImportError` if Textual is not installed. `open_tap` never calls `sys.exit`, never touches the root logger and never saves preferences.

**`TapViewerApp(tap_path, *, title, sub_title, theme, output_dir)`** is the app that `open_tap` runs. It shows one `TapViewerScreen` and exits when the viewer posts `Closed` (the `q` key). Use it directly if you want to call `app.run()` yourself.

**Logging.** While the viewer runs, the console handlers of friTap's own loggers (`friTap` and `friTap.*`) are muted, so log lines do not corrupt the terminal screen. They are restored when `open_tap` returns. Your own root-logger handlers are not touched. Because friTap logs are muted, extension load failures are not visible on the console: read them with [`extension_load_errors()`](#mode-c-extension-package).

See `example/tap_viewer_launch.py` for a complete script.

---

## Mode B: mount the viewer in your Textual app

```python
from textual.app import App
from friTap.ui import TapViewerScreen

class HostApp(App):
    def on_mount(self) -> None:
        self.push_screen(TapViewerScreen("capture.tap"))

    def on_tap_viewer_screen_closed(self, message: TapViewerScreen.Closed) -> None:
        self.notify(f"Viewer closed: {message.tap_path}")
```

`TapViewerScreen(tap_path, *, title=None, sub_title=None, output_dir=None, source=None, name=None, id=None, classes=None)`

| Parameter | Meaning |
|-----------|---------|
| `tap_path` | The `.tap` file. With `source` it only names the file in the banner. |
| `title`, `sub_title` | Screen header text. |
| `output_dir` | Directory offered by the "save .tap" dialog. |
| `source` | Optional, already loaded `TapSource` (below). |
| `name`, `id`, `classes` | Passed to Textual's `Screen`. |

The constructor calls `load_extensions(offline_decryptors=False)`: it loads UI extensions only. Offline decryptors are discovered lazily on the first decrypt. Extension filter fields therefore exist before the viewer reads its own `.tap`.

### Your own data source

`source` must implement `friTap.ui.TapSource` (a provisional protocol in `friTap/flow/replay.py`). `ReplayController` is the reference implementation. The members are exactly what the viewer calls:

- `header` (property)
- `flow_count` (property)
- `get_summaries() -> list[FlowSummary]`
- `get_flow(flow_id) -> Optional[Flow]`
- `get_flows() -> list[Flow]`
- `store_reparse(flow_id, request, response, clear_trailing=False)`
- `read_all_findings() -> list`
- `read_request_contexts() -> list`

With `source`, the host has already read the tap and filter attributes are computed at read time. Extension filter fields only get values if you called `load_extensions()` **before** loading the source.

The source must already be **loaded** (for a `ReplayController`, call `load()` first). The viewer reads `flow_count` and `get_summaries()` on mount and never loads it. The viewer **never closes** a source you pass in, not on unmount and not when a pcap decrypt swaps in a new `.tap`. You own its lifetime. Without `source`, the viewer opens `tap_path` itself and closes that controller when done.

### Key bindings

| Key | Action |
|-----|--------|
| `escape`, `backspace` | One step back, or close the viewer at the top level |
| `q` | Close the viewer |
| `/` | Focus the filter bar |
| `shift+escape`, `ctrl+l` | Clear the filter |
| `shift+f` | Toggle the findings view |
| `c`, `p`, `1` | Findings quick filters: credentials, PII, critical |
| `a` | Analyzer panel |
| `w` | Save `.tap` |
| `o` | Open a pcap |
| `R` | Report |

The screen binds no `r`, `t` or `?`, so your app can use them.

### Closing: the `Closed` message

`q`, or `escape` at the top level, posts `TapViewerScreen.Closed` to the app exactly once. The message carries `viewer` (the screen) and `tap_path`. Handle it with `on_tap_viewer_screen_closed`. After posting, the viewer dismisses itself only if it is the active screen and the screen stack holds more than one screen. If the viewer is the only screen (for example a Textual `MODES` base screen), only `Closed` is posted and your app decides what to do. If a modal is on top, a close request is ignored.

### `go_back()`

`viewer.go_back() -> bool` performs one back step: it leaves an open nested view (finding detail, flow detail, findings list), then closes the analyzer panel, then clears an active filter. It returns `False` at the top level and does not close the viewer. A host escape handler can call it first and close or pop the screen itself when it returns `False`.

### Theme and CSS isolation

- `install_theme(app)` adds friTap's CSS variables (`$fritap-*`) to your app. It is idempotent. The viewer calls it for you in `compose`, so you only call it yourself if you use friTap widgets elsewhere.
- Your values win. Variables you already define are never overridden.
- The viewer's CSS is scoped to an inner container (`DEFAULT_CSS`). `fritap.tcss` is not loaded into your app and no global styles are added.

### Escape and priority bindings

A Textual binding with `priority=True` on your `App` runs before the viewer sees the key. If your app binds `escape` that way and always acts on it, it swallows Escape inside the viewer's modals. Either act only while the viewer is not on top, or let the viewer go first:

```python
from textual.app import App
from textual.binding import Binding
from friTap.ui import TapViewerScreen

class HostApp(App):
    BINDINGS = [Binding("escape", "host_escape", "Back", priority=True)]

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        if action == "host_escape" and isinstance(self.screen, TapViewerScreen):
            return False  # binding is skipped; the viewer handles Escape itself
        return True
```

If you do want to handle it yourself, call `self.screen.go_back()` and only close or pop when it returns `False`.

See `example/tap_viewer_host_app.py` for a complete app.

---

## Mode C: extension package

An extension is a normal Python package that registers extras for the viewer. friTap finds it through the entry-point group `fritap.ui_extensions`:

```toml
# pyproject.toml
[project.entry-points."fritap.ui_extensions"]
my-ext = "my_pkg.fritap_ext:register"
```

The target is a **zero-argument callable**. It calls the `register_*` functions:

```python
# my_pkg/fritap_ext.py
from friTap.ui import (
    DetailTabSpec, FlowColumnSpec, BodyDecoderSpec, LayerFieldSpec,
    register_detail_tab, register_flow_column,
    register_body_decoder, register_filter_field,
)

def register() -> None:
    register_flow_column(FlowColumnSpec(
        key="sni_len", label="SNI len", width=7,
        value=lambda row: str(len(row.tls_sni))))
    register_detail_tab(DetailTabSpec(
        id="my-tab", label="My Tab",
        render=lambda flow: f"{len(flow.chunks)} chunks"))
    register_body_decoder(BodyDecoderSpec(
        name="upper", label="Upper-case",
        decode=lambda body, headers: [body.decode("utf-8", "replace").upper()]))
    register_filter_field(LayerFieldSpec(
        field="myproto.op", layers=("myproto",), path="op",
        value_type="str", description="My protocol operation"))
```

### Spec types and callbacks

| Spec | Fields | Callback contract |
|------|--------|-------------------|
| `DetailTabSpec` | `id`, `label`, `render` | `render(flow)` returns a renderable, a `str` (shown literally), or `None` (hides the tab). It receives the full `Flow`. |
| `FlowColumnSpec` | `key`, `label`, `width`, `value` | `value(summary_row)` returns the cell text. `width` is an `int`; `0` means auto. It receives a `friTap.flow.models.FlowSummary` (for example `total_bytes`, not `total_size`). |
| `BodyDecoderSpec` | `name`, `label`, `decode` | `decode(body: bytes, headers: dict)` returns `list[str]`, one line each. Listed in the body-processing modal; the label is shown literally. A name that collides with a built-in decoder, a decompression option id or `reset` is skipped with a warning; registering an existing extension name replaces that decoder. Lines are shown literally (never parsed as markup), capped at 5000 lines (`_EXTENSION_DECODER_MAX_LINES`). |
| `LayerFieldSpec` | `field`, `layers`, `path`, `value_type`, `description`, `zero_is_missing` | Not a callback. Declares a display-filter field `<proto>.<field>` read from the named layer dicts. Listed in the filter help. |

`LayerFieldSpec` comes from `friTap.filter.layer_fields` and is re-exported by `friTap.ui`. `value_type` is `"str"`, `"int"`, `"float"` or `"bool"` (`SUPPORTED_VALUE_TYPES`). `layers` must be a tuple or list of names, not a bare `str`.

A callback that raises does not crash the viewer: a failing `render` hides its tab, a failing column `value` shows an empty cell, and a failing `decode` shows an error line. A non-`str` renderable from `render` that raises while it is drawn also shows an error line. The error is logged.

### Validation

Specs are validated when you register them. A wrong spec type, a non-string or blank `id`/`key`/`name`, a non-callable callback, or a non-`int` or negative `width` raises `TypeError` or `ValueError`, and the registry stays unchanged. `register_filter_field` rejects a field name that is a built-in static filter field, a protocol predicate name (`known_protocol_names()`) or starts with `protocol.` (such names would never take effect). It also rejects an unsupported `value_type`, a non-`str` `description`, `layers` given as a `str`, and an empty `path` (only union specs may omit it).

Registering the same `id` / `key` / `name` / `field` again **replaces** the earlier spec. It never raises.

### Loading: `load_extensions()`

`load_extensions(force=False, *, offline_decryptors=True)` runs every `fritap.ui_extensions` entry point once. It is idempotent; `force=True` re-runs it (safe, because registration replaces by key). Offline-decryptor discovery is cached, so repeated default calls do not re-scan; `force=True` re-scans. `TapViewerScreen` and `fritap -r` (`MainScreen`) call it for you with `offline_decryptors=False`, so they load UI extensions only. Library code never discovers extensions on import.

With the default `offline_decryptors=True` it also discovers external offline decryptors (the `fritap.offline_decryptors` entry points and the drop-in directory). The viewer does not need that call: it discovers them lazily on the first decrypt, as before. A later call with the default still runs the discovery. The two steps have separate switches:

| Environment variable | Effect |
|----------------------|--------|
| `FRITAP_DISABLE_UI_EXTENSIONS=1` | Skip the `fritap.ui_extensions` entry points |
| `FRITAP_DISABLE_OFFLINE_DECRYPTOR_DISCOVERY=1` | Skip offline-decryptor discovery |

A failing entry point is logged and skipped; the others still load. `extension_load_errors()` returns `ExtensionLoadError(source, error)` records for failing entry points (including ones that raise `SystemExit`), for a failure of the offline discovery step itself (source `offline-decryptors`) and for each failing offline-decryptor source, prefixed `offline-decryptor:` (`offline-decryptor:dir:<file>` for a drop-in file that fails to import, `offline-decryptor:entrypoint:<name>` for an entry point that fails to load or register). They are logged as well. Offline-decryptor failures are read live from the last discovery scan, wherever it ran, so they include scans triggered by the viewer's first decrypt (after a screen's `offline_decryptors=False` call). The UI records are replaced whenever the UI step re-runs. Use it when friTap's loggers are muted (mode A):

```python
from friTap.ui import load_extensions, extension_load_errors

load_extensions()
for err in extension_load_errors():
    print(err.source, err.error)
```

### Analyzers and app-cipher decoders

These two registries are stable and live outside the viewer-extension registry:

- `register_analyzer(name, factory)` adds an analyzer (a `BaseAnalyzer` factory) selectable in the CLI and the analyzer panel. List them with `available_analyzers()`. A name that collides with a built-in is ignored with a warning (the built-in wins).
- `register_app_cipher_decoder(decoder)` adds an `AppCipherDecoder`: an object with `matches(host, path, query, body) -> bool` and `decode(host, path, query, body) -> DecodedView | None`. `DecodedView` holds `title`, `text`, `ok`, `reason` and `notes`. A decoder's identity is its `name` or `id` attribute, else its class qualname; registering the same identity again replaces it in place. A `decode()` that returns the wrong type, or a `matches()` that raises, is skipped and logged once.

### Limits

- **Filter fields must be registered before a `.tap` is read.** Filter attributes are extracted at read time. Entry points run in the viewer constructor, so this works there. If you register fields yourself, or pass a `source` you loaded yourself (mode B), call `load_extensions()` or register the fields before you open the file.
- **No new message transports.** `MESSAGE_TRANSPORTS` is frozen at import (`friTap/flow/layer_pipeline.py`).
- **Renderers run on the UI thread.** `render` runs when a flow is shown and when its data changes, and a column `value` runs for every visible row. Keep both fast.

See `example/fritap_ui_extension_demo/` for a complete installable package.

---

## Stability

| Tier | Names |
|------|-------|
| **Stable** (SemVer) | `open_tap`, `TapViewerApp`, `TapViewerScreen` (with `Closed` and `go_back`), `install_theme`, `register_analyzer`, `available_analyzers`, `register_app_cipher_decoder`, `AppCipherDecoder`, `DecodedView`, `ReplayController`, `BaseAnalyzer`, `Finding`, `Severity` |
| **Provisional** | Everything in `friTap.ui.PROVISIONAL`: `TapSource`, the four spec dataclasses, the `register_*` and `get_*` extension functions, `load_extensions`, `extension_load_errors`, `ExtensionLoadError`, `UI_EXTENSION_ENTRY_POINT_GROUP`, `iter_replay_rows`, `theme_variable_defaults`. May change in a MINOR release. |

```python
from friTap.ui import PROVISIONAL
print(sorted(PROVISIONAL))
```

The policy is in `RELEASING.md` ("Public API surface"). `friTap.tui.*` is internal: import from `friTap.ui` instead.

!!! warning "Two `FlowSummary` classes"
    `friTap.flow.tap_format.FlowSummary` is the mutable record read from the `.tap` file. It is the public `friTap.FlowSummary`, and what `TapSource.get_summaries()` returns. `friTap.flow.models.FlowSummary` is a frozen, slotted row object with filter attributes, built by `FlowSummary.from_tap_summary(...)`. **`FlowColumnSpec.value` receives the `friTap.flow.models` row**, and `DetailTabSpec.render` receives a `friTap.flow.models.Flow`. Read fields from the callback argument and do not rely on `isinstance` checks against the root `friTap.FlowSummary`.
