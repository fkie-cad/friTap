# Standalone Agent Usage

This guide explains how to use friTap's `fritap_agent.js` JavaScript agent directly with Frida, without the friTap Python wrapper. This is useful for custom integrations, research, or when you need more control over the instrumentation process.

## Overview

friTap consists of two main components:

1. **Python Host (`SSL_Logger`)** - Manages Frida sessions, handles output, generates PCAP files
2. **JavaScript Agent (`fritap_agent.js`)** - Performs the actual SSL/TLS hooking inside the target process

friTap ships **two** compiled agent bundles, both built with `frida-compile`
(see `package.json`):

- **`friTap/fritap_agent.js`** — the main TLS-hooking agent, built from
  `agent/fritap_agent.ts` (`npm run build`). The legacy and modern code paths
  live in this one file and are toggled internally through the `use_modern`
  configuration field rather than in separate agent files.
- **`friTap/fritap_memscan.js`** — the heap **memory-scan** agent, built from
  `agent/memory_scan_agent.ts` (`npm run build:memscan`). It recovers TLS
  secrets by scanning the target's heap instead of hooking the TLS library, and
  is injected independently of `fritap_agent.js` (see the
  [`-ms`/`--memory-scan` CLI flag](../api/cli.md#-ms-memory-scan-patternjson)).
  This standalone-usage guide otherwise describes the main agent.

You can use the agent standalone if you:

- Need custom message handling
- Want to integrate friTap into existing Frida scripts
- Are building custom security tools
- Need more control over the instrumentation flow

## Agent Location

The two compiled JavaScript agents are located at:

```
friTap/fritap_agent.js     # main TLS-hooking agent (npm run build)
friTap/fritap_memscan.js   # heap memory-scan agent (npm run build:memscan)
```

For `fritap_agent.js`, both the modern (Frida 17+) and legacy (Frida <17) hook
paths are bundled into that one file; the active path is selected at runtime via
the `use_modern` config field. `fritap_memscan.js` is a separate, independently
injected bundle built from `agent/memory_scan_agent.ts`.

## Critical: Initialization Protocol

The friTap agent uses a **blocking initialization protocol**. When loaded, it sends several configuration requests and **waits for responses**. If your script doesn't respond to these messages, the agent will hang and Frida will time out.

### Required Initialization Messages

Modern friTap agents consolidate all per-feature handshakes into a single
`config_batch` message. The agent sends these messages (in order) and blocks
waiting for each response:

| Message | Expected Response Type | Purpose |
|---------|----------------------|---------|
| `"config_batch"` | `{"type": "config_batch", "payload": <dict of up to 23 fields>}` | Single consolidated handshake carrying every configuration value (see [field reference](#config_batch-field-reference) below) |
| `"anti"` | `{"type": "antiroot", "payload": <bool>}` | Enable anti-root bypass (Android); sent once after `config_batch` |

Note the deliberate asymmetry: the request `"anti"` is answered on the
`"antiroot"` channel, while `config_batch` is answered on its own name.

!!! warning "`anti` must be the last handshake"
    `"anti"` is the **terminal** request. The agent resumes its top-level once
    the `antiroot` reply lands, and that is what unblocks `script.load()`. Reply
    to `config_batch` first; if you answer `anti` before the agent has its
    configuration, the agent proceeds unconfigured — and if you never answer it,
    `script.load()` blocks forever.

!!! info "Canonical message protocol"
    For the full agent ↔ host message protocol — every outgoing `contentType`
    the agent emits, plus the build/compile pipeline — see the
    [Architecture reference](../development/architecture.md).

### Reply on the script that asked

Post the reply to the **script that sent the request**, not to a single global
"current script" reference.

This is invisible with one script and fatal with two. Under child gating or spawn
gating friTap creates additional scripts, and `instrument()` overwrites the host's
current-script reference. A reply for the *parent's* in-flight handshake would
then be posted to a freshly created *child* script, leaving the parent blocked in
`recv().wait()` forever. friTap's own responder therefore takes the asking script
as a parameter (`SSL_Logger._answer_startup_handshake(payload, script)`) and posts
back on it.

For the same reason, `config_batch` and `anti` must be answered
**unconditionally** — once per asking script, not once per session. An earlier
one-shot gate in friTap meant every script after the first hung, because the
terminal `anti` reply cleared the gate for everyone. The batch payload is
rebuilt per request (it is pure with respect to the session), so answering it
repeatedly is safe.

### Deprecated per-feature handshakes

Older agent builds asked for each feature separately. The **agent no longer sends
these**, but friTap's host **still answers them** as a compatibility fallback
(`friTap/legacy/message_handler.py`), so an old bundle paired with a current host
still starts. Treat them as a deprecated host-side fallback — not as removed.

| Legacy request | Reply channel | Value |
| --- | --- | --- |
| `experimental` | `experimental` | bool |
| `defaultFD` | `defaultFD` | bool |
| `socket_tracing` | `socket_tracing` | bool or path |
| `pattern_hooking` | `pattern_hooking` | JSON string or `None` |
| `offset_hooking` | `offset_hooking` | JSON string or `None` |
| `install_lsass_hook` | `install_lsass_hook` | bool |
| `protocol_select` | `protocol_select` | protocol name |
| `library_scan` | `library_scan` | scan results or `None` |
| `use_modern` | `use_modern` | bool |

Unlike `anti`, every legacy reply channel is named identically to its request.
When porting an integration written against these, collapse them into a single
`config_batch` reply.

### Minimal Message Handler

Here's a message handler that responds to all initialization messages. Every
`config_batch` key is optional — the agent applies its own default with `??` for
anything you omit — but the full list is spelled out here so you can see what is
available:

```python
def on_message(message, data):
    if message["type"] != "send":
        return
    payload = message.get("payload", {})

    # Single consolidated handshake: agent sends "config_batch" once per script
    # and blocks until we reply. Every key is optional; defaults apply.
    if payload == "config_batch":
        script.post({"type": "config_batch", "payload": {
            "offsets":                   None,    # JSON string or None
            "patterns":                  None,    # JSON string or None
            "socket_tracing":            False,
            "defaultFD":                 False,
            "pcap_enabled":              False,
            "keylog_enabled":            False,   # set True to also extract TLS keys
            "experimental":              False,
            "protocol_select":           "tls",   # any registered protocol, or "all"/"auto"
            "install_lsass_hook":        False,   # Windows only
            "use_modern":                False,   # experimental modern path
            "library_scan":              None,
            "library_scan_enabled":      False,
            "ohttp_enabled":             True,
            "quic_capture_mode":         "stream",  # "stream" | "app-api"
            "quic_only":                 False,
            "quic_egress_headers_layer": "auto",
            "debug_output":              False,
            "no_loader_hook":            False,   # Android: skip android_dlopen_ext trampoline
            "spawned":                   False,   # True if you spawned the target
            "stealth_loader":            False,   # EXPERIMENTAL hardware-breakpoint loader watch
            "pairip_safe":               False,   # minimal symbol-only BoringSSL keylog
            "probe":                     False,   # dry run: report platform, install nothing
            "extensions":                {},      # generic feature-config passthrough
        }})
        return

    # Anti-root probe is the last handshake message (separate from config_batch).
    if payload == "anti":
        script.post({"type": "antiroot", "payload": False})
        return

    # ... handle agent telemetry (console, keylog, datalog, etc.) ...
```

## Switching between Legacy and Modern paths

friTap ships two agent code paths today:

- **Legacy** (default, `use_modern: false`) — the original platform-specific
  hook tree under `agent/legacy/`. Battle-tested across all supported
  libraries and protocols.
- **Modern** (experimental, `use_modern: true`) — the refactored
  definition-based path under `agent/tls/`, `agent/quic/`, etc. Not required
  by any protocol selector (every protocol, including `ssh` and `ipsec`, also
  installs on the legacy path); it enables improved Cronet /
  BoringSSL `SSL_CTX_set_keylog_callback` hooks for Chrome. Has known
  regressions on iOS/macOS Cronet, Windows LSASS, and IPsec.

Toggle by setting `use_modern: true` in your `config_batch` reply.

## config_batch field reference

There are **23** fields. friTap's own host builds all of them in
`friTap/legacy/ssl_logger_core.py::_build_config_batch()`.

!!! note "No field is mandatory"
    The agent reads every key with a `??` default, so a partial dict is valid —
    omitting a field selects its default rather than breaking the handshake. Send
    only what you need to change. (Earlier revisions of this page claimed the
    reply "must include every field"; that was wrong in both directions, since
    the list it gave was also incomplete.)

| Field | Type | Default | Purpose |
|---|---|---|---|
| `offsets` | JSON string or `None` | `None` | Custom hook offsets (advanced) |
| `patterns` | JSON string or `None` | `None` | Custom byte-pattern definitions |
| `socket_tracing` | bool | `False` | Log socket address metadata for captured TLS sessions |
| `defaultFD` | bool | `False` | Fall back to file-descriptor extraction when SSL_get_fd is unavailable |
| `pcap_enabled` | bool | `False` | Required `True` if you process pcap-format datalogs. Set `False` if you do your own raw packet capture and only want keys (mirrors friTap's own `-f`/full-capture mode) |
| `keylog_enabled` | bool | `True` | Set `False` to skip key extraction entirely. When `False`, the agent installs **no** key-extraction hooks (callback / symbol / pattern-scan) for any library on any platform, and emits no key material of any protocol — TLS/QUIC `keylog`, SSH `ssh_key`/`ssh_keylog`, and IPSec `ipsec_child_sa_keys`/`ipsec_ike_keys` are all gated by this one flag. Useful when you only want decrypted plaintext. Default `True` preserves prior behaviour for handlers that omit the field |
| `experimental` | bool | `False` | Enable experimental hooking strategies |
| `protocol_select` | protocol name \| `"all"` \| `"auto"` | `"tls"` | Which protocol's hooks to install. **Not a three-value enum** — it accepts every *registered* protocol name (e.g. `tls`, `ssh`, `ipsec`, `mtproto`, `signal`, `telegram`, …) plus `all` and `auto`; the set grows with the protocol registry, so run `fritap --help` for the current list. Note: `ipsec` is matched by the agent's hook registrations, but the friTap CLI/TUI cannot select it yet (its Python handler is not registered) — from the CLI, IPsec hooks install only via `all`/`auto`. Every protocol works with `use_modern` `false` or `true` |
| `install_lsass_hook` | bool | `False` | Hook LSASS (Windows only) |
| `use_modern` | bool | `False` | Opt into the experimental modern agent path |
| `library_scan` | object or `None` | `None` | Library-scan configuration |
| `library_scan_enabled` | bool | `False` | Enable the tlsLibHunter library scan |
| `ohttp_enabled` | bool | `True` | Enable OHTTP (NSS HPKE) keylog hooks within the TLS family |
| `quic_capture_mode` | `"stream"` \| `"app-api"` | `"stream"` | QUIC/HTTP-3 capture strategy: `stream` taps the QUIC stream layer; `app-api` taps app-decoded headers |
| `quic_only` | bool | `False` | Restrict hooking to the QUIC path only (skips classic TLS hooks for a leaner, lower-risk attach) |
| `quic_egress_headers_layer` | `"auto"` or layer name | `"auto"` | Forces the HTTP/3 egress-headers chain layer; `"auto"` keeps the winner-takes-all fallback |
| `debug_output` | bool | `False` | Mirrors the `-do`/`--debug-output` CLI flag; gates expensive debug-only symbol enumeration in the agent (without it, every attach would walk the full Cronet/libmonochrome dynsym) |
| `no_loader_hook` | bool | `False` | **Android.** Skip the inline `android_dlopen_ext` loader trampoline — the PairIP / anti-tamper `SIGSEGV` avoidance path ([friTap#64](https://github.com/fkie-cad/friTap/issues/64)). Only already-loaded or explicitly offset-selected libraries get hooked. Host source: `-nlh/--no-loader-hook` |
| `spawned` | bool | `False` | Whether the target was **spawned** rather than attached. Lets the agent auto-skip the loader hook only in spawn mode (where it trips PairIP's startup scan) while keeping it for attach. Host source: the spawn flag, not a config option |
| `stealth_loader` | bool | `False` | **EXPERIMENTAL.** Watch the loader with a hardware breakpoint (CPU debug registers) instead of patching the linker. Host source: `--experimental-stealth-loader` |
| `pairip_safe` | bool | `False` | Minimal, scan-free **symbol-only keylog** on BoringSSL libraries; skips the loader hook, pattern scan, Java hooks and OHTTP. Host source: `--pairip-safe` |
| `probe` | bool | `False` | **New in agent ABI 2.** Dry run: the agent sends its `platform_report` and **returns before installing any hooks**. Host source: `--probe`. See [rpc.exports and probe acknowledgement](#probe-acknowledgement) |
| `extensions` | object | `{}` | Generic, protocol-agnostic **feature-config passthrough**. Keys are opt-in feature names, never protocol literals — e.g. `{"scan_region": "libfoo.so"}` drives the memory-scan engine (`agent/shared/scan/`). Empty unless a feature was requested, so the default wire shape is unchanged |

### Probe acknowledgement

When `probe: true`, the agent sends — *before* installing anything — a
`platform_report` message and then stops:

```json
{
  "contentType": "platform_report",
  "platform": "android/arm64",
  "target": "com.example.app",
  "probe": true,
  "abi": 2
}
```

An integrator implementing probe support must treat the **`probe` field of
`platform_report`** as the acknowledgement. friTap does exactly that: if no
report arrives within 3 s, or the report's `probe` is falsey, it concludes the
bundle predates probe mode and exits with code `2` rather than reporting a
diagnostic it cannot trust. The `platform_report` is sent in **every** run, not
just probe runs, so it is also a cheap way to learn the agent's platform branch
and ABI.

## rpc.exports

The agent declares a small RPC surface at the top of `agent/fritap_agent.ts`,
deliberately before initialization, so it survives an init failure and remains
callable on a half-started agent.

| Export (JS) | Python call | Returns | Purpose |
| --- | --- | --- | --- |
| `agentAbiVersion()` | `script.exports_sync.agent_abi_version()` | `int` | The bundle's compile-time `AGENT_ABI_VERSION`. Use it to detect a stale bundle at runtime |
| `gracefulDetach()` | `script.exports_sync.graceful_detach()` | — | Marks the agent as shutting down, stops `blink`, then `Interceptor.detachAll()` |

!!! info "Frida 17 naming convention"
    JS declares **camelCase** (`rpc.exports.gracefulDetach`); Python calls
    **snake_case** (`script.exports_sync.graceful_detach()`). Frida performs the
    conversion. Getting this backwards yields a missing-export error, not a
    warning.

**Call `graceful_detach` on teardown.** It removes the hooks from inside the
agent, cheaply and in one pass. An integrator that skips it falls back to
`script.unload()` alone, which on a target with many hot hooks can block for
seconds while the JS message loop drains — friTap bounds that fallback at 5 s and
then deliberately skips `session.detach()` rather than race a busy session.

```python
try:
    script.exports_sync.graceful_detach()
except Exception:
    pass          # agent may already be gone
script.unload()
process.detach()
```

## Agent ABI version

`AGENT_ABI_VERSION` versions the **entire JS ↔ Python boundary**: the
`config_batch` field set, the `ContentType` values the agent emits, and the
`rpc.exports` surface. It is **currently `2`**.

- Host side: `friTap/constants.py:AGENT_ABI_VERSION`
- Agent side: `agent/shared/generated_constants.ts` (generated — do not hand-edit)
- Readable at runtime via `agentAbiVersion()` and in the `platform_report`'s `abi`

friTap checks it twice: statically, by grepping the bundle for the constant before
loading, and over RPC after loading. Either mismatch produces a warning naming
**both** versions and telling you to rebuild with `./dev/compile_agent.sh`.

!!! warning "Third-party bundles must declare the same ABI"
    A package that contributes an agent bundle through the `fritap.agent_bundle`
    entry-point group must expose `AGENT_ABI_VERSION` equal to the host's. If it
    differs, friTap **skips that entry point with a warning** and falls back to
    the shipped agent — your bundle silently does not get used. The
    `FRITAP_AGENT_BUNDLE` environment variable is *not* ABI-filtered and always
    wins, so it is the escape hatch for local experiments.

    Bump procedure: see `RELEASING.md`.

## Message Types from Agent

After initialization, the agent sends these message types:

### Console Messages (`contentType: "console"`)

Status and informational messages from the agent.

```python
if content_type == "console":
    msg = payload.get("console", "")
    print(f"[*] {msg}")
```

### Debug Messages (`contentType: "console_dev"`)

Development/debug messages (only when debug mode is enabled).

```python
if content_type == "console_dev":
    msg = payload.get("console_dev", "")
    print(f"[DEBUG] {msg}")
```

### Captured Data (`contentType: "datalog"`)

Decrypted SSL/TLS payload data. The `data` parameter contains the binary payload.

```python
import struct
import socket

def get_addr_string(socket_addr, ss_family):
    """Convert socket address to string."""
    if ss_family == "AF_INET":
        return socket.inet_ntop(socket.AF_INET, struct.pack(">I", socket_addr))
    else:  # AF_INET6
        raw_addr = bytes.fromhex(socket_addr)
        return socket.inet_ntop(socket.AF_INET6, struct.pack(">16s", raw_addr))

# In message handler:
if content_type == "datalog" and data:
    src_addr = get_addr_string(payload["src_addr"], payload["ss_family"])
    dst_addr = get_addr_string(payload["dst_addr"], payload["ss_family"])
    func_name = payload.get("function", "unknown")  # SSL_read, SSL_write, etc.
    src_port = payload.get("src_port", 0)
    dst_port = payload.get("dst_port", 0)
    ssl_session = payload.get("ssl_session_id", "N/A")

    print(f"[{func_name}] {src_addr}:{src_port} --> {dst_addr}:{dst_port}")
    print(f"  Data: {len(data)} bytes")
    print(f"  Hex: {data[:50].hex()}")
```

### Key Material (`contentType: "keylog"`)

TLS key material in NSS SSLKEYLOGFILE format (compatible with Wireshark).

> This contentType only fires when `keylog_enabled: true` was sent in
> `config_batch` (see the [field reference](#config_batch-field-reference)).
> The same gate governs **all** key material, not just TLS/QUIC `keylog`: the
> SSH `ssh_key` / `ssh_keylog` and IPSec `ipsec_child_sa_keys` /
> `ipsec_ike_keys` content types are routed through the same choke point, so
> integrators that consume those must set `keylog_enabled: true`.
> Plaintext-only integrations should set `keylog_enabled: false` so the agent
> skips key-extraction hooks entirely instead of relying on the host to
> discard incoming events.

```python
if content_type == "keylog":
    keylog = payload.get("keylog", "")
    if keylog:
        print(f"[KEYLOG] {keylog}")
        # Write to file for Wireshark
        with open("keys.log", "a") as f:
            f.write(keylog + "\n")
```

## Complete Example Script

See the full working example at `example/chrome_ssl_intercept.py` in the friTap repository.

Here's a simplified version:

```python
#!/usr/bin/env python3
"""Standalone friTap agent usage example."""

import frida
import sys
import os
import signal

# Path to the friTap agent
AGENT_PATH = "path/to/friTap/fritap_agent.js"

script = None

def on_message(message, data):
    """Handle messages from the friTap agent."""
    global script

    if message["type"] == "error":
        print(f"[ERROR] {message}")
        return

    if message["type"] == "send":
        payload = message.get("payload", {})

        # Consolidated initialization handshake (see "Minimal Message Handler"
        # above for the full field reference). Any field omitted here — e.g.
        # probe, pairip_safe, no_loader_hook — falls back to the agent default.
        if payload == "config_batch":
            script.post({"type": "config_batch", "payload": {
                "offsets":                   None,
                "patterns":                  None,
                "socket_tracing":            False,
                "defaultFD":                 False,
                "pcap_enabled":              False,
                "keylog_enabled":            False,
                "experimental":              False,
                "protocol_select":           "tls",
                "install_lsass_hook":        False,
                "use_modern":                False,
                "library_scan":              None,
                "library_scan_enabled":      False,
                "ohttp_enabled":             True,
                "quic_capture_mode":         "stream",
                "quic_only":                 False,
                "quic_egress_headers_layer": "auto",
                "debug_output":              False,
            }})
            return

        if payload == "anti":
            script.post({"type": "antiroot", "payload": False})
            return

        # Handle regular messages
        if not isinstance(payload, dict):
            return

        content_type = payload.get("contentType")

        if content_type == "console":
            print(f"[*] {payload.get('console', '')}")

        elif content_type == "keylog":
            print(f"[KEY] {payload.get('keylog', '')}")

        elif content_type == "datalog" and data:
            print(f"[DATA] {payload.get('function', 'unknown')}: {len(data)} bytes")


def main():
    global script

    target = sys.argv[1] if len(sys.argv) > 1 else "com.android.chrome"

    # Connect to device
    device = frida.get_usb_device()
    print(f"[*] Connected to {device.name}")

    # Attach to target
    print(f"[*] Attaching to {target}...")
    process = device.attach(target)

    # Load the agent
    with open(AGENT_PATH, 'r') as f:
        agent_code = f.read()

    script = process.create_script(agent_code, runtime="qjs")
    script.on("message", on_message)
    script.load()

    print("[*] Agent loaded! Press Ctrl+C to stop.")

    # Handle Ctrl+C
    def cleanup(sig, frame):
        script.unload()
        process.detach()
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)

    # Keep running
    sys.stdin.read()


if __name__ == "__main__":
    main()
```

## Configuration Options

### Enabling Features via Initialization

All feature toggles live inside the single `config_batch` reply — flip any
field from its default to enable the corresponding behaviour. Because every key
is optional, a reply can carry **only** the fields you are changing. The example
below enables pattern-based hooking with custom byte patterns, socket
tracing, and the default-FD fallback in one shot:

```python
import json

if payload == "config_batch":
    patterns = {
        "modules": {
            "libsignal_jni.so": {
                "android": {
                    "arm64": {
                        "Dump-Keys": {
                            "primary": "FF 43 02 D1 FD 7B 05 A9...",
                            "fallback": "FF 83 01 D1 FD 7B 03 A9..."
                        }
                    }
                }
            }
        }
    }
    # Only the fields that differ from the agent's defaults.
    script.post({"type": "config_batch", "payload": {
        "patterns":       json.dumps(patterns),
        "socket_tracing": True,
        "defaultFD":      True,
        "keylog_enabled": True,
    }})
    return

# The anti-root probe remains a separate handshake, and must be last.
if payload == "anti":
    script.post({"type": "antiroot", "payload": True})
    return
```

### Custom Function Offsets

For libraries without symbols, provide custom offsets via the `offsets` field
of `config_batch` (it expects a JSON-encoded string). Each function maps to an
object with an `address` and an `absolute` flag (the `IAddress` interface):
`absolute: true` means a runtime virtual address, `absolute: false` an offset from
the module base.

```python
import json

if payload == "config_batch":
    offsets = {
        "openssl": {
            "SSL_read":  {"address": "0x1234", "absolute": True},
            "SSL_write": {"address": "0x5678", "absolute": True}
        }
    }
    script.post({"type": "config_batch", "payload": {
        "offsets":        json.dumps(offsets),
        "keylog_enabled": True,
    }})
    return
```

## Desktop Usage

The same approach works for desktop applications:

```python
# Linux/macOS
device = frida.get_local_device()
process = device.attach("firefox")

# Windows
device = frida.get_local_device()
process = device.attach("chrome.exe")
```

## Spawning Applications

To spawn an application instead of attaching:

```python
# Spawn the application
pid = device.spawn("com.example.app")
process = device.attach(pid)

# Load agent...

# Resume the process
device.resume(pid)
```

## Troubleshooting

### Agent Hangs on Load

**Cause:** Missing initialization message responses.

**Solution:** Ensure your message handler responds to BOTH initialization
messages — `config_batch` (with a dict; a **partial** dict is fine, every key has
a default) and `anti` (with `{"type": "antiroot", "payload": <bool>}`), and that
it answers **both, unconditionally, on the script that asked**. Three failure
modes look identical from the outside:

1. **`anti` never answered** — the agent's top-level never resumes, so
   `script.load()` blocks forever. `anti` is terminal; it must be answered.
2. **Reply posted to the wrong script** — with child/spawn gating, replying on a
   cached "current script" reference sends the parent's answer to a child script.
   The parent stays in `recv().wait()`. See
   [Reply on the script that asked](#reply-on-the-script-that-asked).
3. **A one-shot handshake gate** — if you stop answering after the first script,
   every subsequent script hangs.

If you are porting code from an older agent build that listened for individual
handshakes (`offset_hooking`, `pattern_hooking`, `socket_tracing`, `defaultFD`,
`experimental`, `install_lsass_hook`, `protocol_select`, `library_scan`,
`use_modern`), collapse them into a single `config_batch` reply — current agents
no longer send them (friTap's host still *answers* them for old bundles; see
[Deprecated per-feature handshakes](#deprecated-per-feature-handshakes)).

### Hooks Installed but the Target Dies

Send `probe: true` in `config_batch`. The agent then reports its platform and
returns **before installing any hooks**, which separates "the agent cannot load
here" from "one of the hooks is fatal". Verify the reply is honored by checking
that the `platform_report` you receive has `probe: true` — a bundle older than
agent ABI 2 ignores the field and instruments the target as usual. This is exactly
what `fritap --probe` does; see the
[CLI reference](../api/cli.md#-probe).

### Stale Bundle / Unrecognised Handshake

**Cause:** The `.js` bundle you loaded was built from different TypeScript than the
host you are pairing it with. `friTap/fritap_agent.js` is **pre-compiled** —
nothing rebuilds it at run time.

**Solution:** Rebuild with `./dev/compile_agent.sh` and compare
`agentAbiVersion()` against `friTap/constants.py:AGENT_ABI_VERSION`. See
[Agent ABI version](#agent-abi-version) and the
[rebuild rule](../troubleshooting/common-issues.md#i-edited-agentts-and-nothing-changed-the-rebuild-rule).

### No Data Captured

**Cause:** Application uses an unsupported TLS library or custom implementation.

**Solution:**
1. Use `--list-libraries` with full friTap to identify loaded TLS libraries
2. Enable `debug_output` to see what the agent detects
3. Use pattern-based hooking for stripped libraries

### Permission Denied

**Cause:** Frida-server not running as root, or SELinux blocking.

**Solution:**
```bash
# Run frida-server as root
adb shell su -c "/data/local/tmp/frida-server &"

# Check SELinux status
adb shell getenforce
```

## Next Steps

- **Pattern Generation**: Learn about [BoringSecretHunter](patterns.md#automating-with-boringsecrethunter) for generating patterns
- **CLI Reference**: See [CLI options](../api/cli.md) for full friTap capabilities
- **Python API**: Use [Python API](../api/python.md) for programmatic control with built-in PCAP generation
