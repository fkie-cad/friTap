# Standalone Agent Usage

This guide explains how to use friTap's `fritap_agent.js` JavaScript agent directly with Frida, without the friTap Python wrapper. This is useful for custom integrations, research, or when you need more control over the instrumentation process.

## Overview

friTap consists of two main components:

1. **Python Host (`SSL_Logger`)** - Manages Frida sessions, handles output, generates PCAP files
2. **JavaScript Agent (`fritap_agent.js`)** - Performs the actual SSL/TLS hooking inside the target process

You can use the agent standalone if you:

- Need custom message handling
- Want to integrate friTap into existing Frida scripts
- Are building custom security tools
- Need more control over the instrumentation flow

## Agent Location

The compiled JavaScript agent is located at:

```
friTap/friTap/fritap_agent.js        # Modern agent (Frida 17+)
friTap/friTap/_ssl_log_legacy.js # Legacy agent (Frida <17)
```

## Critical: Initialization Protocol

The friTap agent uses a **blocking initialization protocol**. When loaded, it sends several configuration requests and **waits for responses**. If your script doesn't respond to these messages, the agent will hang and Frida will time out.

### Required Initialization Messages

Modern friTap agents consolidate all per-feature handshakes into a single
`config_batch` message. The agent sends these messages (in order) and blocks
waiting for each response:

| Message | Expected Response Type | Purpose |
|---------|----------------------|---------|
| `"config_batch"` | `{"type": "config_batch", "payload": <dict with 13 fields>}` | Single consolidated handshake carrying every configuration value (see [field reference](#config_batch-field-reference) below) |
| `"anti"` | `{"type": "antiroot", "payload": <bool>}` | Enable anti-root bypass (Android); sent once after `config_batch` |

> **Note:** Older agent builds shipped individual per-feature handshakes
> (`offset_hooking`, `pattern_hooking`, `socket_tracing`, `defaultFD`,
> `experimental`, `install_lsass_hook`). These have been removed in favor of the
> single `config_batch` round-trip — keep this in mind when porting integrations
> written against older docs.

### Minimal Message Handler

Here's the minimal message handler that responds to all initialization messages:

```python
def on_message(message, data):
    if message["type"] != "send":
        return
    payload = message.get("payload", {})

    # Single consolidated handshake: agent sends "config_batch" once and
    # blocks until we reply with a dict containing every config value.
    if payload == "config_batch":
        script.post({"type": "config_batch", "payload": {
            "offsets":              None,    # JSON string or None
            "patterns":             None,    # JSON string or None
            "socket_tracing":       False,
            "defaultFD":            False,
            "pcap_enabled":         False,
            "keylog_enabled":       False,   # set True to also extract TLS keys
            "experimental":         False,
            "protocol_select":      "tls",   # "tls" | "ssh" | "ipsec"
            "install_lsass_hook":   False,   # Windows only
            "use_modern":           False,   # experimental modern path
            "library_scan":         None,
            "library_scan_enabled": False,
            "ohttp_enabled":        True,
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
  definition-based path under `agent/tls/`, `agent/quic/`, etc. Required for
  the `ssh` and `ipsec` protocol selectors, and enables improved Cronet /
  BoringSSL `SSL_CTX_set_keylog_callback` hooks for Chrome. Has known
  regressions on iOS/macOS Cronet, Windows LSASS, and IPsec.

Toggle by setting `use_modern: true` in your `config_batch` reply.

## config_batch field reference

The dict sent in reply to `config_batch` must include every field below. Values
not relevant to your run can be left at their defaults.

| Field | Type | Default | Purpose |
|---|---|---|---|
| `offsets` | JSON string or `None` | `None` | Custom hook offsets (advanced) |
| `patterns` | JSON string or `None` | `None` | Custom byte-pattern definitions |
| `socket_tracing` | bool | `False` | Log socket address metadata for captured TLS sessions |
| `defaultFD` | bool | `False` | Fall back to file-descriptor extraction when SSL_get_fd is unavailable |
| `pcap_enabled` | bool | `False` | Required `True` if you process pcap-format datalogs. Set `False` if you do your own raw packet capture and only want keys (mirrors friTap's own `-f`/full-capture mode) |
| `keylog_enabled` | bool | `True` | Set `False` to skip key extraction entirely. When `False`, the agent installs **no** key-extraction hooks (callback / symbol / pattern-scan) for any library on any platform, and emits no key material of any protocol — TLS/QUIC `keylog`, SSH `ssh_key`/`ssh_keylog`, and IPSec `ipsec_child_sa_keys`/`ipsec_ike_keys` are all gated by this one flag. Useful when you only want decrypted plaintext. Default `True` preserves prior behaviour for handlers that omit the field |
| `experimental` | bool | `False` | Enable experimental hooking strategies |
| `protocol_select` | `"tls"` \| `"ssh"` \| `"ipsec"` | `"tls"` | Which protocol's hooks to install. `ssh`/`ipsec` require `use_modern: true` |
| `install_lsass_hook` | bool | `False` | Hook LSASS (Windows only) |
| `use_modern` | bool | `False` | Opt into the experimental modern agent path |
| `library_scan` | object or `None` | `None` | Library-scan configuration |
| `library_scan_enabled` | bool | `False` | Enable the lsLibHunter library scan |
| `ohttp_enabled` | bool | `True` | Enable OHTTP keylog hooks |

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
        # above for the full field reference).
        if payload == "config_batch":
            script.post({"type": "config_batch", "payload": {
                "offsets":              None,
                "patterns":             None,
                "socket_tracing":       False,
                "defaultFD":            False,
                "pcap_enabled":         False,
                "keylog_enabled":       False,
                "experimental":         False,
                "protocol_select":      "tls",
                "install_lsass_hook":   False,
                "use_modern":           False,
                "library_scan":         None,
                "library_scan_enabled": False,
                "ohttp_enabled":        True,
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
field from its default to enable the corresponding behaviour. The example
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
    script.post({"type": "config_batch", "payload": {
        "offsets":              None,
        "patterns":             json.dumps(patterns),
        "socket_tracing":       True,
        "defaultFD":            True,
        "pcap_enabled":         False,
        "keylog_enabled":       False,
        "experimental":         False,
        "protocol_select":      "tls",
        "install_lsass_hook":   False,
        "use_modern":           False,
        "library_scan":         None,
        "library_scan_enabled": False,
        "ohttp_enabled":        True,
    }})
    return

# The anti-root probe remains a separate handshake.
if payload == "anti":
    script.post({"type": "antiroot", "payload": True})
    return
```

### Custom Function Offsets

For libraries without symbols, provide custom offsets via the `offsets` field
of `config_batch` (it expects a JSON-encoded string):

```python
import json

if payload == "config_batch":
    offsets = {
        "libcustom.so": {
            "SSL_read": "0x1234",
            "SSL_write": "0x5678"
        }
    }
    script.post({"type": "config_batch", "payload": {
        "offsets":              json.dumps(offsets),
        "patterns":             None,
        "socket_tracing":       False,
        "defaultFD":            False,
        "pcap_enabled":         False,
        "keylog_enabled":       False,
        "experimental":         False,
        "protocol_select":      "tls",
        "install_lsass_hook":   False,
        "use_modern":           False,
        "library_scan":         None,
        "library_scan_enabled": False,
        "ohttp_enabled":        True,
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
messages — `config_batch` (with a dict containing all 13 fields) and `anti`
(with `{"type": "antiroot", "payload": <bool>}`). If you are porting code
from an older agent build that listened for individual handshakes
(`offset_hooking`, `pattern_hooking`, `socket_tracing`, `defaultFD`,
`experimental`, `install_lsass_hook`), collapse them into a single
`config_batch` reply instead — those per-message handshakes are deprecated and
no longer sent by the agent.

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

- **Pattern Generation**: Learn about [BoringSecretHunter](patterns.md#automated-pattern-generation-with-boringsecrethunter) for generating patterns
- **CLI Reference**: See [CLI options](../api/cli.md) for full friTap capabilities
- **Python API**: Use [Python API](../api/python.md) for programmatic control with built-in PCAP generation
