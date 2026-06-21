# Interactive TUI & Replay

friTap ships with an interactive terminal user interface (TUI) built on
[Textual](https://textual.textualize.io/). It gives you a guided, menu-driven
way to start captures, watch decrypted flows arrive in real time, filter them
with Wireshark-style expressions, inspect individual request/response bodies,
and replay previously saved `.tap` files — all without memorising CLI flags.

!!! info "When to use the TUI vs. the CLI"
    The TUI is the friendliest entry point for exploratory work and for reading
    back captures. Everything it does maps onto the command line documented in
    [CLI Reference](../api/cli.md), so once you know which mode and protocol you
    want, scripting the equivalent `fritap` invocation is straightforward.

## Launching the TUI

There are three ways to start it:

```bash
# 1. No arguments -> launches the interactive capture wizard
fritap

# 2. Replay a saved capture (-r / --replay)
fritap -r capture.tap

# 3. Shorthand: a single trailing .tap path is treated as replay
fritap capture.tap
```

When invoked with no arguments, friTap opens the TUI directly into the capture
wizard. When given a `.tap` file (via `-r`/`--replay` or as the sole argument),
it opens in **replay mode** and loads the stored flows.

!!! note "Requires Textual"
    The TUI needs the `textual` package (`textual>=0.80.0`). In current friTap
    releases Textual is a normal runtime dependency, so a standard
    `pip install fritap` already includes it. If your environment is missing it,
    friTap prints a hint to install it:

    ```bash
    pip install fritap[tui]      # extras form shown by friTap's error message
    pip install textual>=0.80.0  # or install Textual directly
    ```

    If Textual cannot be imported, friTap logs an error and (when launched with
    no arguments) falls back to the command-line interface.

!!! note "Protocol picker includes MTProto"
    In the capture wizard the protocol picker (also reachable with `p`) now lists
    **MTProto — Telegram** alongside TLS/SSL, IPSec, and SSH. Selecting it warns in
    the activity log (and a modal) when the crypto backend is **not** present (e.g.
    on a lean install) — live key capture still works without it, but offline
    decryption needs the backend, which ships in friTap's base install (no extra
    needed). See [Telegram (MTProto)](../protocols/telegram.md).

## Layout

The TUI uses a single split-pane screen:

- **Left panel** — a `StatusBar` (current device, mode, protocol, capture
  state) above the interactive `MenuPanel` listing the actions and their keys.
- **Right panel** — the working area. In **console view** it shows the live
  activity log; pressing `f` switches it to the **flow view** (a sortable flow
  list). Selecting a flow opens its **detail view** with tabbed
  request/response/protocol panes.

Press `f` to toggle between the console and flow views. The flow list takes
over the full width while active so you have room to read the table.

## The five capture modes

Press the number keys `1`–`5` to pick a capture mode. Each one opens a small
modal pre-filling sensible defaults:

| Key | Mode name (internal) | What it does | Default outputs |
|-----|----------------------|--------------|-----------------|
| `1` | Full Capture (`full`) | Keylog **and** decrypted PCAP | `keys.log`, `capture.pcapng` |
| `2` | Keys Only (`keys`) | TLS/QUIC key extraction only | `keys.log` |
| `3` | Plaintext PCAP (`plaintext`) | Decrypted traffic as a plaintext PCAP | `plaintext.pcapng` |
| `4` | Live Wireshark (`wireshark`) | Stream decrypted traffic straight into Wireshark | live |
| `5` | Live PCAPNG, auto-decrypt (`live_pcapng`) | Live PCAPNG feed with automatic decryption | live |

!!! warning "Modes 4 & 5 are experimental and Unix-only"
    The two live-Wireshark modes are **experimental** and intended for
    Unix-like systems (Linux/macOS). Mode 5's automatic decryption requires
    **Wireshark ≥ 4.0**. There is **no hard OS guard** in the code, so on an
    unsupported platform they will simply not behave correctly rather than
    refuse to start — treat this as a platform caveat.

!!! note "Live capture needs a device"
    Modes 1–5 all attach to a running process. You must have a target device
    (or local process) selected and a reachable `frida-server` before starting.
    Use `d` to choose a device, then `a` (attach) or `s` (spawn) to pick the
    target.

## Keybinding reference

These are the actual bindings registered by the app and its screens. Keys are
context-sensitive — some apply only in the flow list or detail view.

### Global (main app)

| Key | Action |
|-----|--------|
| `q` | Quit |
| `d` | Select device |
| `a` | Attach to a running process |
| `s` | Spawn a process |
| `1` | Capture mode 1 — Full Capture |
| `2` | Capture mode 2 — Keys Only |
| `3` | Capture mode 3 — Plaintext PCAP |
| `4` | Capture mode 4 — Live Wireshark (experimental) |
| `5` | Capture mode 5 — Live PCAPNG (experimental) |
| `Enter` | Start / stop capture |
| `Esc` | Stop / close / go back |
| `c` | Clear console |
| `i` | Install frida-server |
| `v` | Toggle verbose |
| `e` | Toggle experimental |
| `p` | Select protocol |
| `t` | Toggle theme (dark/light) |
| `?` | Show help |
| `y` | Copy log |
| `w` | Save `.tap` |

### Main screen (flow view)

| Key | Action |
|-----|--------|
| `f` | Toggle console / flow view |
| `a` | Toggle the Analyzer Panel (run analyzers over the loaded flows) |
| `Shift+F` | Toggle the Findings Viewer (analyzer findings) |
| `/` | Open the filter dialog |
| `Shift+Esc` | Clear the active filter |

### Analyzer Panel

Press `a` to open the **Analyzer Panel** — a docked pane above the flow list (the
flow list stays visible). Use it to run analyzers over the currently loaded flows
without leaving the TUI, which is what populates the Findings Viewer for a raw
`.tap` that has no stored findings yet.

1. Select which analyzers to run from the multi-select list (built-ins plus any
   discovered external analyzers — see [Traffic analysis](../advanced/traffic-analysis.md)).
   Optionally type a one-off `module:Class` plugin path.
2. Press `r` (or **Run**) — analysis runs in the background with a live progress
   line; the UI stays responsive.
3. The panel switches to a **summary dashboard** with selectable chips grouped by
   severity, analyzer, and category, plus a **View all** chip. Each chip's count
   matches exactly what it filters to (a severity chip shows that severity bucket
   only, not a floor). Selecting a chip drops into the Findings Viewer pre-filtered,
   where `Enter` jumps to the flow that produced a finding.

| Key | Action |
|-----|--------|
| `a` | Toggle the Analyzer Panel |
| `r` | Run the selected analyzers |
| `x` | Clear results / reset the panel |
| `Esc` | Close the panel |

Re-running replaces the previous results (counts always match the current
selection). Press `w` to save a `.tap` that now embeds the computed findings, so
re-opening it shows them directly in the Findings Viewer.

!!! note "`a` is context-aware"
    In a live capture session `a` keeps its capture meaning (attach to a process).
    The Analyzer Panel opens only when flows are loaded (replay, or a capture that
    has produced flows).

### Findings Viewer

Press `Shift+F` to toggle the **Findings Viewer** — a table of the analyzer
findings for the current capture (columns: **Severity**, **Source**, **Category**,
**Conf**, **Title**, **Flow**), with severity-colored rows. On a wide terminal an
extra **Preview** column is shown with a short snippet of each finding's matched
value. Pressing `Enter` on a row opens the [analyzer finding detail](#analyzer-finding-detail)
for that finding.

| Key | Action |
|-----|--------|
| `Shift+F` | Toggle the Findings Viewer on/off |
| `Enter` | Open the selected finding (analyzer finding detail) |
| `c` | Quick filter: credentials only |
| `p` | Quick filter: PII only |
| `1` | Quick filter: critical only |
| `/` | Open the filter dialog |
| `Shift+Esc` | Clear the active filter |
| `Esc` | Step back: a filtered (category) view clears to all findings; all findings backs out to the flow list |
| `w` | Save a `.tap` embedding the current findings |

`Esc` walks back up the navigation hierarchy one level at a time:

```
all findings ──Enter on chip/quick-filter──► category (filtered) ──Enter──► finding detail
     ▲                                              ▲                              │
     └──────────────── Esc ─────────────────────────┴────────────── Esc ──────────┘
```

!!! warning "PII is redacted in the viewer"
    PII and secret values are **redacted by default** in the Findings Viewer, just
    as in the report and sidecar. There is no in-TUI reveal toggle; use
    `fritap analyze <file>.tap --show-pii` (or `--scan-show-pii` during capture) to
    see raw values in a report.

### Analyzer finding detail

Pressing `Enter` on a finding opens a **finding-centric** detail view (distinct
from the flow-centric [flow detail view](#flow-detail-view)). It leads with the
finding — the matched value, evidence (location/header/field), and the
surrounding request context, with the matched value highlighted in the request
headers.

| Key | Action |
|-----|--------|
| `b` | Toggle base64 decoding of candidate values (e.g. decode an HTTP `Authorization: Basic …` header to `user:pass`) |
| `d` | Switch to the regular (flow-centric) flow detail view for the same flow |
| `Esc` | Back to the findings list (the category filter you came from is preserved) |

When you switch to the full flow detail with `d`, pressing `Esc` there returns you
to the analyzer finding detail (not the flow list), so the back-stack stays
consistent.

### Flow detail view

| Key | Action |
|-----|--------|
| `Esc` | Back to the flow list |
| `p` | Parse / reprocess the body (open body-processing) |
| `r` | Reset body processing |
| `s` | Save the body to a file |
| `h` | Toggle raw hex view |
| `n` | Next segment |
| `N` | Previous segment |
| `x` | Open the data explorer |

## Flow filtering

Press `/` to open the filter dialog. friTap uses **Wireshark-style display
filter** syntax. The input field validates as you type (leniently, with a short
debounce) and strictly when you press `Enter`.

### Available fields

| Field | Type | Meaning |
|-------|------|---------|
| `ip.src` / `ip.dst` | str | Source / destination address |
| `ip.addr` | str | Either endpoint (matches src **or** dst) |
| `tcp.srcport` / `tcp.dstport` | int | Source / destination port |
| `tcp.port` | int | Either port |
| `http.request` | bool | Flow has a request |
| `http.request.method` | str | HTTP method (GET, POST, …) |
| `http.request.uri` | str | Request URL |
| `http.host` | str | Request host |
| `http.response` | bool | Flow has a response |
| `http.response.code` | int | HTTP status code |
| `http.content_type` | str | Response (or request) content type |
| `http.content_length` | int | Response body size |
| `http` / `http2` / `http3` | bool | Protocol family predicates |
| `frame.protocol` | str | Detected protocol label |
| `flow.state` | str | Flow state |
| `flow.duration` | float | Flow duration (seconds) |
| `flow.size` | int | Total bytes in the flow |
| `flow.has_request` / `flow.has_response` | bool | Presence predicates |
| `tls` | bool | Flow carried a TLS session |
| `tls.session_id` | str | TLS session id |
| `ohttp.present` | bool | Oblivious HTTP inner request/response present |
| `ssh` | bool | Flow is SSH |
| `ipsec` | bool | Flow is IPsec |

### Example expressions

```text
http.response.code >= 400
http.request.method == "POST" and http.host == "api.example.com"
ip.addr == 10.0.0.5
tcp.port == 443 and tls
flow.size > 100000
ohttp.present
```

### Toggle presets

The filter dialog also offers one-click toggle buttons that combine into the
filter with `and`:

| Toggle | Expression applied |
|--------|--------------------|
| HTTP | `frame.protocol != "unknown"` |
| Errors | `http.response.code >= 400` |
| OHTTP | `ohttp.present` |
| IPSec | `frame.protocol == "ipsec"` |
| SSH | `frame.protocol == "ssh"` |

Press `Shift+Esc` from the flow view to clear the text filter and all toggles
at once. Inside the dialog, `Apply` confirms, `Clear` resets, `F1`/`?` opens
filter help, and `Esc` cancels.

## Flow detail view

From the flow list, press **`Enter`** on a row to open its detail view. The
detail pane is organised into tabs — **Request**, **Response**, **Detail**, and
any protocol-specific tabs the flow exposes. The most relevant tab is selected
automatically.

Within the detail view:

- `p` opens body processing so you can (re)parse the selected body — useful for
  applying a parser/decompression that wasn't applied at capture time.
- `r` resets that processing back to the raw body.
- `h` toggles a raw hex dump of the body.
- `n` / `N` step through multi-segment bodies.
- `x` opens the data explorer for deeper inspection.
- `s` saves the currently shown body to a file in the working directory.
- `Esc` returns to the flow list.

## Exporting with `w`

Press **`w`** at any time to export the current flows to a `.tap` file via the
`SaveTapModal`. This works both during a **live capture** and in **replay
mode** (so you can re-export a loaded capture, e.g. after reparsing flows). If
there are no flows yet, friTap shows a warning instead of opening the dialog.

The resulting `.tap` file can be reopened with `fritap -r <file>.tap`, analysed
with `fritap analyze`, or read programmatically — see
[Reading `.tap` files](../api/python.md) and
[Offline PCAP → .tap conversion](../advanced/offline-pcap-to-tap.md).

## Replay workflow

Replay mode (`fritap -r capture.tap` or `fritap capture.tap`) is backed by the
presentation-agnostic [`ReplayController`](../api/python.md), which other tools
can reuse outside the TUI. The flow is:

1. **Load** — the controller opens the `.tap` file and reads lightweight flow
   **summaries** first, so even large captures populate the list quickly.
2. **Browse** — the flow list is built from those summaries. Filtering works
   exactly as in live mode.
3. **On-demand detail** — selecting a flow calls `get_flow(flow_id)`, which
   reads the full flow from disk and caches it (LRU). Heavy body data is only
   loaded when you actually open a flow.
4. **Auto-reparse** — when a stored flow is opened, friTap re-parses it if it
   looks like it was produced by older code, specifically:
    - **legacy / unknown-protocol** flows from older `.tap` files,
    - **HTTP/2 "ghost" flows** (a protocol was detected but no request was
      recorded because old code skipped SETTINGS-only control frames), and
    - **WebSocket `TEXT` flows** (old code missed `permessage-deflate`
      decompression).

   Reparse results are stored on the controller so they survive cache eviction,
   and pressing `w` re-exports the improved flows.

## A short beginner walkthrough

This end-to-end example captures Chrome traffic, filters for errors, exports the
result, and replays it.

!!! note "Live steps need a device"
    Steps 1–4 attach to a real process, so you need a target device with a
    reachable `frida-server`.

1. **Launch the wizard:**

    ```bash
    fritap
    ```

2. **Pick a target and start a full capture.** Press `d` to select your device,
   `a`/`s` to choose Chrome (attach or spawn), then `1` for **Full Capture** and
   `Enter` to start. Browse a bit so traffic flows in.

3. **Switch to the flow view and filter for errors.** Press `f` to show the flow
   list, then `/` to open the filter and enter:

    ```text
    http.response.code >= 400
    ```

    (or click the **Errors** toggle), then `Enter` to apply. Only failing
    requests remain.

4. **Export the capture.** Press `w`, confirm the filename in the save dialog,
   and stop the capture with `Esc`/`Enter`. Quit with `q`.

5. **Replay it later:**

    ```bash
    fritap -r capture.tap
    ```

    The flows reload from the summary index, and opening any of them pulls the
    full body on demand (auto-reparsing legacy/HTTP2/WebSocket flows as needed).

## See also

- [CLI Reference](../api/cli.md) — the command-line flags the TUI drives.
- [Offline PCAP → .tap conversion](../advanced/offline-pcap-to-tap.md) — build a
  `.tap` from an existing PCAP for replay.
- [Python API — `ReplayController`](../api/python.md) — consume `.tap` files
  programmatically from your own tools.
