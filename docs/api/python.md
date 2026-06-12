# Python API

friTap ships a stable, SemVer-guaranteed Python API for driving captures, consuming live events, and working with `.tap` files offline. The public surface is everything exported from the `friTap` package `__all__` (59 symbols); removing or breaking any of them requires a friTap MAJOR bump (see `RELEASING.md`).

This page leads with the **modern API**:

- the [`FriTap` builder](#quick-start-fritap-builder) for configuring and starting captures,
- the [`EventBus`](#events-eventbus) and typed events for consuming data programmatically,
- [configuration dataclasses](#configuration-dataclasses),
- working with [flows](#working-with-flows), [offline conversion](#offline-conversion), [reading `.tap`](#reading-tap-files), [traffic analysis](#traffic-analysis), and [protobuf utilities](#protobuf-utilities).

The legacy `SSL_Logger` class is documented last, in a [deprecated section](#legacy-ssl_logger-deprecated).

!!! note "CI-runnable vs. live-device examples"
    Examples in this page are labelled either **live / device** (they attach to or
    spawn a real process and cannot run in CI) or **offline / CI-runnable** (they
    operate on `.tap` files or in-memory objects and run anywhere friTap imports).

---

## Quick start (FriTap builder)

!!! warning "Live / device example"
    `FriTap(...).start()` attaches to or spawns a real target through Frida. This
    cannot run in CI — it needs a device and the target app/process.

```python
from friTap import FriTap

session = (
    FriTap("com.example.app")
    .mobile()                  # target a USB device
    .keylog("keys.log")        # write an SSLKEYLOGFILE
    .pcap("cap.pcapng")        # write decrypted traffic (pcapng → embedded DSB)
    .start()                   # returns a FriTapSession
)

session.wait()   # block until the target exits; or call session.stop()
```

With callbacks (also **live / device**):

```python
from friTap import FriTap

session = (
    FriTap("com.example.app")
    .mobile("device-id")
    .pcap("capture.pcap")
    .on_keylog(lambda e: print(e.key_data))
    .on_data(lambda e: print(f"{e.src_addr}:{e.src_port} -> {e.dst_addr}:{e.dst_port}"))
    .start()
)
```

`build_config()` is the **offline-safe** half of the builder — it returns a
[`FriTapConfig`](#configuration-dataclasses) without touching a device, which is
useful for tests and for inspecting/serializing configuration:

```python
from friTap import FriTap

config = FriTap("com.example.app").mobile().keylog("keys.log").build_config()
print(config.target, config.output.keylog)   # offline / CI-runnable
```

### `FriTapSession`

`start()` returns a `FriTapSession` handle:

| Member | Kind | Description |
| --- | --- | --- |
| `event_bus` | property → `EventBus` | The session's [event bus](#events-eventbus); subscribe for live events. |
| `is_running` | property → `bool` | Whether the capture is still active. |
| `stop()` | method | Gracefully stop the capture session. |
| `wait()` | method | Block until the session ends (e.g. the process exits). |

---

## Builder reference

Every method below returns `self`, so calls chain. Names are verbatim from
`friTap.api.FriTap`. The builder is hand-documented (chained APIs render poorly
under autodoc).

### Device & target

| Method | Description |
| --- | --- |
| `mobile(device_id=None)` | Target a mobile device — USB if `device_id` is omitted, otherwise the given Frida device ID. |
| `host(address)` | Target a remote Frida device (`host:port`). |
| `spawn(enable=True)` | Spawn the target instead of attaching. |
| `spawn_gating(enable=True, all_processes=False)` | Enable spawn gating for multi-process apps. `all_processes=True` catches every spawn. |
| `child_gating(enable=True)` | Enable child-process gating. |
| `timeout(seconds)` | Set a timeout before resuming the suspended target. |

### Output

| Method | Description |
| --- | --- |
| `pcap(path)` | Write decrypted traffic to a PCAP file. The extension is authoritative — `.pcap` writes classic libpcap, `.pcapng` writes pcapng (with embedded DSB when keys are extracted). |
| `pcapng(path)` | Write self-decrypting PCAPNG. Equivalent to `pcap()` with a `.pcapng` extension; the file extension still wins. |
| `keylog(path)` | Write key material in Wireshark-loadable form for the active protocol (NSS `SSLKEYLOGFILE` for TLS). With `--protocol all/auto`, the path is split per protocol as `<stem>.<proto><ext>`. |
| `json_output(path)` | Write session metadata as JSON. |
| `verbose(enable=True)` | Enable verbose console output. |
| `live(enable=True)` | Stream to Wireshark via a named pipe. |
| `full_capture(enable=True)` | Capture the full network stream, not just decrypted payload. |

### Hooking

| Method | Description |
| --- | --- |
| `patterns(path)` | Use pattern-based (symbol-less) hooking from a JSON file. |
| `offsets(path)` | Use offset-based hooking from a JSON file. |
| `experimental(enable=True)` | Enable experimental features. |
| `anti_root(enable=True)` | Enable anti-root-detection hooks (Android). |
| `payload_modification(enable=True)` | Enable payload-modification capability. |
| `force_scan(name)` | Force-scan a module that Cronet-split-topology suppression would otherwise skip. Accepts a literal name, a stem prefix (`name*`) or a regex (`re:...`). May be called multiple times. |

### Protocol & backend

| Method | Description |
| --- | --- |
| `protocol(proto)` | Set the target protocol: `tls`, `ipsec`, `ssh`, `auto` (and other registered values). Default `tls`. |
| `backend(backend)` | Set the instrumentation backend: `frida` (default), `gdb`, `lldb`, `ebpf`. |

!!! warning "Experimental backends"
    Only `frida` is fully supported. `gdb`/`lldb`/`ebpf` are experimental/future;
    [`FriTapConfig`](#configuration-dataclasses) rejects a protocol/backend combination
    that is not fully supported.

### Debug & misc

| Method | Description |
| --- | --- |
| `debug(enable=True)` | Enable debug mode with Chrome Inspector (also turns on debug output). |
| `debug_output(enable=True)` | Enable debug output only (no inspector). |
| `custom_script(path)` | Load a custom Frida script before friTap's hooks. |
| `add_script_plugin(plugin)` | Register a `ScriptPlugin` to load when the session starts. |
| `environment(path)` | Provide an environment-variables JSON for spawn. |
| `proxy(address)` | Redirect connections to a `host:port` proxy and bypass cert pinning (requires `fritap-proxy`). |

### Callbacks

Each registers a callback fired on the session's [event bus](#events-eventbus).

| Method | Event delivered |
| --- | --- |
| `on_keylog(callback)` | [`KeylogEvent`](#keylogevent) |
| `on_data(callback)` | [`DatalogEvent`](#datalogevent) |
| `on_library_detected(callback)` | [`LibraryDetectedEvent`](#librarydetectedevent) |
| `on_session(callback)` | [`SessionEvent`](#sessionevent) |
| `on_flow(callback)` | [`FlowEvent`](#flowevent) — wires up a `FlowCollector` automatically. |

### Terminal methods

| Method | Description |
| --- | --- |
| `build_config()` | Build a `FriTapConfig` from the current builder state. **Offline-safe** — does not touch a device. |
| `start()` | Build the config, create the capture, wire up the event bus, and start. Returns a `FriTapSession`. **Live / device.** |

---

## Events & EventBus

friTap dispatches typed events through a thread-safe publish-subscribe
`EventBus`. Output handlers, the TUI, plugins, and your own callbacks all
subscribe to event classes.

::: friTap.events.EventBus
    options:
      show_root_heading: true
      members:
        - subscribe
        - unsubscribe
        - emit
        - clear

The bus also exposes the class constant `PLUGIN_PRIORITY = 100`; plugins should
pass `priority=EventBus.PLUGIN_PRIORITY` to `subscribe()` so they run before the
built-in output handlers.

A standalone bus can be created, subscribed to, and emitted into without any
device — useful for testing handlers:

```python
from friTap import EventBus, KeylogEvent

bus = EventBus()
bus.subscribe(KeylogEvent, lambda e: print("key:", e.key_data))
bus.emit(KeylogEvent(key_data="CLIENT_RANDOM abc def"))   # offline / CI-runnable
# -> key: CLIENT_RANDOM abc def
```

### Event base class

All events subclass `FriTapEvent`, which provides:

| Field / member | Type | Description |
| --- | --- | --- |
| `timestamp` | `float` | Creation time (`time.time()`). |
| `protocol` | `str` | Protocol context (default `"tls"`). |
| `cancel()` | method | Advisory cancellation (DOM `preventDefault` style). |
| `cancelled` | property → `bool` | Whether `cancel()` was called. |

### KeylogEvent

Emitted when key material is extracted (`on_keylog`).

| Field | Type | Description |
| --- | --- | --- |
| `key_data` | `str` | Pre-formatted keylog line (e.g. `CLIENT_RANDOM <hex> <hex>`). |
| `payload` | `dict \| None` | Structured payload for protocols that need it (e.g. SSH KEX shared secret). |

### DatalogEvent

Emitted when decrypted application data is captured (`on_data`).

| Field | Type | Description |
| --- | --- | --- |
| `data` | `bytes` | The decrypted payload. |
| `function` | `str` | The hooked function that produced it. |
| `direction` | `str` | `"read"` or `"write"`. |
| `src_addr` / `src_port` | `str` / `int` | Source endpoint. |
| `dst_addr` / `dst_port` | `str` / `int` | Destination endpoint. |
| `ss_family` | `str` | Socket family (e.g. `"AF_INET"`). |
| `ssl_session_id` | `str` | TLS session identifier. |
| `client_random` | `str` | TLS client random. |
| `transport` | `str` | `"tcp"` or `"udp"` (QUIC is `udp`). |
| `http3_headers` | `list \| None` | Decoded HTTP/3 headers `[[name, value], ...]` (app-api QUIC mode). |
| `stream_id` | `int \| None` | QUIC stream id. |
| `quic_scid` / `quic_dcid` | `str` | QUIC source / destination connection IDs. |
| `quic_stream_type` | `str` | QUIC stream type. |

### LibraryDetectedEvent

Emitted when a TLS/SSL library is detected (`on_library_detected`).

| Field | Type | Description |
| --- | --- | --- |
| `library` | `str` | Logical library name (e.g. `"openssl"`). |
| `module` | `str` | The loaded module/file name. |
| `path` | `str` | Full module path in the target. |

### SessionEvent

Emitted on TLS/QUIC session lifecycle changes (`on_session`).

| Field | Type | Description |
| --- | --- | --- |
| `session_id` | `str` | Session identifier. |
| `event_type` | `str` | One of `SESSION_STARTED`/`SESSION_RESUMED`/`SESSION_ENDED`/`SESSION_DESTROYED` (the string constants `"started"`, `"resumed"`, `"ended"`, `"destroyed"`). |
| `cipher_suite` | `str` | Negotiated cipher suite. |
| `cipher` | property → `str` | Read-only alias for `cipher_suite`. |
| `protocol_version` | `str` | TLS version (e.g. `"TLS 1.3"`). |
| `server_name` | `str` | SNI server name. |
| `alpn` | `str` | Negotiated ALPN (`"h2"`, `"http/1.1"`, …). |
| `quic_version` | `str` | QUIC transport version (QUIC only). |
| `client_random`, `connection_id`, `src_addr`, `src_port`, `dst_addr`, `dst_port` | | Additional session/endpoint metadata. |

### FlowEvent

Emitted when a flow is created, updated, or completed (`on_flow`).

| Field | Type | Description |
| --- | --- | --- |
| `flow` | [`Flow`](#working-with-flows) | The flow object. |
| `flow_event_type` | `str` | `"created"`, `"updated"`, or `"completed"`. |

### Other events

These are part of the public surface and are emitted by the agent/output
pipeline; subscribe to them the same way:

- **`ConsoleEvent`** (`message`, `level`) — console log lines from the agent.
- **`ErrorEvent`** (`error`, `description`, `stack`, `file`, `line`, `severity`) — agent/hooking errors; `severity` is `"info"`/`"warning"`/`"error"`/`"fatal"`.
- **`SocketTraceEvent`** (`src_addr`, `src_port`, `dst_addr`, `dst_port`, `ss_family`) — traced socket info.
- **`DetachEvent`** (`reason`) — emitted when the target process detaches.

---

## Configuration dataclasses

`FriTap.build_config()` returns a `FriTapConfig`. You can also construct it
directly and pass it to the lower-level `CoreController` / `SSL_Logger`.

::: friTap.config.FriTapConfig
    options:
      show_root_heading: true
      members: false

::: friTap.config.DeviceConfig
    options:
      show_root_heading: true
      members: false

::: friTap.config.OutputConfig
    options:
      show_root_heading: true
      members: false

::: friTap.config.HookingConfig
    options:
      show_root_heading: true
      members: false

`HookingConfig` exposes the encapsulated-protocol toggle `ohttp_enabled`
(OHTTP is on by default within `--protocol tls`) and the QUIC knobs
`quic_capture_mode`, `quic_only`, and `quic_egress_headers_layer`.

### Migrating from legacy parameters

`FriTapConfig.from_legacy_params(...)` bridges the old flat `SSL_Logger`
keyword arguments (`app`, `pcap_name`, `keylog`, `mobile`, `patterns`, …) into
the structured dataclasses, so existing code can move incrementally:

```python
from friTap import FriTapConfig

config = FriTapConfig.from_legacy_params(
    app="com.example.app",
    pcap_name="capture.pcap",
    keylog="keys.log",
    mobile=True,
)
print(config.target, config.device.mobile, config.output.pcap)   # offline / CI-runnable
```

---

## Working with flows

A `Flow` is friTap's reconstructed picture of one connection: endpoints, timing,
parsed request/response, a protocol **layer stack**, and any attached findings.
Flows are produced live (via `on_flow`) and read back from `.tap` files (see
[Reading `.tap`](#reading-tap-files)).

::: friTap.flow.models.Flow
    options:
      show_root_heading: true
      members:
        - to_dict
        - layer
        - request_body
        - response_body
        - reconstruct_body

### Serializing a flow

`Flow.to_dict(include_bodies=False)` returns a JSON-safe view: identity,
transport/timing, parsed request/response, layer names, tags/notes and findings.
Raw chunk bytes are never included; request/response bodies are included
(hex-encoded) only when `include_bodies=True`.

```python
flow_dict = flow.to_dict()                  # bodies omitted
flow_dict = flow.to_dict(include_bodies=True)  # bodies hex-encoded
```

### Layer access

Each flow carries a stack of protocol layers. Access them two ways:

- **Attribute access** — `flow.tls`, `flow.quic`, `flow.ssh` lazily materialize a
  typed layer if that protocol is registered (raises `AttributeError` for an
  unregistered name). Typed layers expose fields such as `flow.tls.sni` and
  `flow.tls.alpn`.
- **`flow.layer(name)`** — a non-mutating lookup returning the existing layer or
  `None`. Use this in serialization paths so reading never grows the stack:
  `flow.layer("http2")`, then inspect `.parsed` / `.data`.

```python
sni = flow.tls.sni                  # typed accessor
http2 = flow.layer("http2")         # None if absent
if http2 is not None:
    parsed = http2.parsed
```

### Why `pr.body` may be empty

Bodies are **not** accumulated in the parser's `ParseResult` anymore — to keep
`.tap` files small, identical/large bodies are reconstructed on demand from the
flow's raw chunks. So a `ParseResult` (`flow.request` / `flow.response`) can have
an empty `.body` even when data was captured. To get the bytes, reconstruct from
the flow:

```python
req = flow.request_body        # bytes, reconstructed + cached
resp = flow.response_body
# equivalently: flow.reconstruct_body("write") / flow.reconstruct_body("read")
```

### FlowSummary

`FlowSummary` is the lightweight index entry used when listing flows without
reading their full bodies (returned by `read_flow_summaries()` /
`get_summaries()`).

::: friTap.flow.models.FlowSummary
    options:
      show_root_heading: true
      members: false

---

## Offline conversion

Reconstruct a `.tap` file from an existing packet capture plus its key material —
no device, no live capture.

!!! warning "Requires Wireshark / tshark ≥ 4.x"
    `pcap_to_tap()` (and the `--from-pcap` CLI) shell out to `tshark` for
    dissection. If `tshark` is not on `PATH`, set `tshark_path=` (or the
    `$FRITAP_TSHARK` environment variable). The example below is **offline** but
    needs `tshark` installed.

```python
from friTap import pcap_to_tap

result = pcap_to_tap(
    "chrome.pcap",
    keylog_path="chromekeys.log",   # SSLKEYLOGFILE; raises NoDecryptionKeysError if given but unusable
    tap_path="out.tap",
    run_scan=True,                  # also run analyzers and embed findings
)
print(result.to_dict())
```

!!! note "Import path"
    `pcap_to_tap` is importable from the package root (`from friTap import pcap_to_tap`),
    but **not** from `friTap.offline` — re-exporting it there would shadow the
    `friTap.offline.pcap_to_tap` *module*. The no-manifest core is
    `friTap.convert_pcap_to_tap(...)`.

`pcap_to_tap()` reads a manifest sidecar `<pcap>.fritap.json` (keys
`keylog`/`tls_ports`/`quic_ports`) when `use_manifest=True`; explicit arguments
win over the manifest, which wins over defaults. It returns a `ConvertResult`:

::: friTap.offline.pcap_to_tap.ConvertResult
    options:
      show_root_heading: true
      members:
        - to_dict

Key fields: `tap_path`, `flow_count`, `decrypted_packet_count`, `stream_count`,
`dropped_packet_count`, `dropped_stream_count`, `findings_count`, and
`encrypted_streams_skipped` (streams that could not be decrypted and were
tallied rather than emitted).

!!! note "Caveats"
    Keyless 1-RTT-only QUIC captures are undetectable without keys. Encrypted
    streams that cannot be decrypted are skipped and counted in
    `encrypted_streams_skipped`. SSH banners and HTTP/2 control frames become
    synthetic, metadata-only flows. `NoDecryptionKeysError` is raised when
    `keylog_path` is given but no usable keys (and no embedded DSB) are found.

---

## Reading `.tap` files

friTap captures persist as a binary `.tap` file (see the
`.tap` binary format). Two readers are provided.

### TapReader

`TapReader` is the low-level streaming reader.

::: friTap.flow.tap_reader.TapReader
    options:
      show_root_heading: true
      members:
        - open
        - read_flow_summaries
        - read_flow
        - read_all_flows
        - close

```python
from friTap import TapReader

reader = TapReader("capture_20260507_153933.tap")   # offline / CI-runnable
meta = reader.open()
for summary in reader.read_flow_summaries():
    print(summary.flow_id, summary.host, summary.status_code)
reader.close()
```

### ReplayController

`ReplayController` is the higher-level facade used by the TUI replay view. It
adds an LRU cache (128 flows), a context-manager interface, and convenience
properties. It implements `IFlowSource` (`get_flows()` / `get_flow(id)`).

::: friTap.flow.replay.ReplayController
    options:
      show_root_heading: true
      members:
        - load
        - get_summaries
        - get_flows
        - get_flow
        - close

```python
from friTap import ReplayController

with ReplayController("capture_20260507_153933.tap") as rc:   # offline / CI-runnable
    meta = rc.load()
    print("flows:", rc.flow_count)
    for summary in rc.get_summaries():
        print(summary.flow_id, summary.protocol, summary.host)
    flow = rc.get_flow(rc.get_summaries()[0].flow_id)
    print(flow.to_dict())
```

---

## Traffic analysis

friTap can run its analyzers (`credentials`, `ioc`, `privacy`, `protobuf`, plus
custom ones) over a captured `.tap` file — passive analysis, no network activity.
Use `analyze_tap_report()` for programmatic access; it performs no I/O beyond
reading the `.tap` and never calls `sys.exit`.

::: friTap.commands.analyze.analyze_tap_report
    options:
      show_root_heading: true

::: friTap.commands.analyze.AnalyzeReport
    options:
      show_root_heading: true
      members:
        - gate_tripped
        - exit_code

```python
from friTap import analyze_tap_report

report = analyze_tap_report(
    "capture_20260507_153933.tap",   # offline / CI-runnable
    scanners="credentials,ioc",      # None or "all" → built-ins (which analyzers RUN)
    min_severity="info",
    report_format="table",
    # report-side filters (additive, keyword-only; all default to no-op):
    min_confidence=0.0,              # drop findings below this confidence (0.0–1.0)
    source=None,                     # comma-separated source names to SHOW (e.g. "credentials,privacy")
    category=None,                   # "secret,pii,network,protocol" to SHOW
    show_pii=False,                  # reveal PII/secret values instead of redacting
)

for finding in report.findings:
    print(finding.severity.name, finding.category, finding.title, finding.flow_id)

print(report.rendered)               # the rendered table/json/csv/md
raise SystemExit(report.exit_code)   # 2 if any finding ≥ medium, else 0 (CI gate)
```

`min_confidence`, `source`, `category`, and `show_pii` are **additive,
keyword-only** parameters — older calls that omit them keep working unchanged.
`scanners` chooses which analyzers *run*; `source`/`category` filter which of the
resulting findings are *shown*.

### Findings & severity

Each `Finding` has: `severity` (a `Severity` enum), `title`, `description`,
`source`, `flow_id`, `confidence` (default `1.0`), `timestamp`, and the dicts
`evidence` and `metadata`. `Severity` is `CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`INFO`
(rank 0 is most severe).

Every finding now carries a **category** in `metadata["category"]`, surfaced as the
`Finding.category` property: `secret` (credentials), `pii` (privacy), `network`
(IOC), or `protocol` (protobuf). PII findings additionally carry
`metadata["compliance"]` (e.g. `GDPR`, `CCPA`, `PCI-DSS`, `HIPAA`).

### Filtering findings

`FindingFilter` (exported from the top-level `friTap` package) is the reusable
filter behind the CLI's `--source`/`--category`/`--min-confidence` flags. Apply it
to any iterable of `Finding` objects:

```python
from friTap import FindingFilter

flt = FindingFilter(
    min_severity="info",
    min_confidence=0.8,
    sources={"credentials", "privacy"},
    categories={"secret", "pii"},
)
kept = [f for f in report.findings if flt.matches(f)]
```

!!! note "PrivacyAnalyzer import path"
    The built-in analyzer classes are available under `friTap.analysis.*` — the
    `privacy` analyzer is `from friTap.analysis.privacy import PrivacyAnalyzer`
    (**not** re-exported from the top-level `friTap` package). Select it by name via
    `scanners="privacy"` rather than importing it directly.

### CI gate

`AnalyzeReport.gate_tripped` is `True` when any finding is at or above the gate
severity (`medium`), and `exit_code` returns `2` in that case (else `0`) —
mirroring the `fritap analyze` CLI exit code. Use it to fail a pipeline when a
capture contains sensitive findings.

### Discovery helpers

- `list_analyzers()` → built-in analyzer names.
- `list_report_formats()` → available report formats (`json`, `csv`, `md`, `table`).

Custom analyzers can be loaded via the CLI `--analyzer-path module:Class`
(the `module:Class` form skips the `is_fritap_analyzer` marker requirement).

---

## Protobuf utilities

Schema-less protobuf wire decoding with zero external dependencies — handy for
inspecting captured gRPC/protobuf bodies.

::: friTap.parsers.protobuf.decode_raw
    options:
      show_root_heading: true

::: friTap.parsers.protobuf.format_message
    options:
      show_root_heading: true

```python
from friTap import decode_raw, format_message

msg = decode_raw(b"\x08\x96\x01")   # offline / CI-runnable
print(format_message(msg))
# 1: 150
```

`decode_raw(data, max_depth=16)` returns a `ProtobufMessage` (a tree of
`ProtobufField` objects); `format_message(msg, indent=0)` renders it as
human-readable text. `ProtobufProcessor` provides higher-level, schema-aware
processing.

---

## Legacy `SSL_Logger` (deprecated)

!!! warning "Deprecated — will be removed in friTap 3.0"
    `SSL_Logger` is retained only for backward compatibility. New code should use
    the [`FriTap` builder](#quick-start-fritap-builder) (or pass a
    [`FriTapConfig`](#configuration-dataclasses) — build one from old kwargs with
    [`FriTapConfig.from_legacy_params(...)`](#migrating-from-legacy-parameters)).

Minimal legacy usage (**live / device**):

```python
from friTap import SSL_Logger
import time

logger = SSL_Logger(
    app="firefox",
    pcap_name="traffic.pcap",
    keylog="keys.log",
    verbose=True,
)
logger.install_signal_handler()
logger.start_fritap_session()

while logger.running:
    time.sleep(1)
```

To migrate, replace the flat constructor with the builder:

```python
from friTap import FriTap

session = FriTap("firefox").pcap("traffic.pcap").keylog("keys.log").verbose().start()
```

## Next steps

- **[CLI reference](cli.md)** — every command-line flag and subcommand.
- **[Examples](../examples/index.md)** — practical end-to-end workflows.
