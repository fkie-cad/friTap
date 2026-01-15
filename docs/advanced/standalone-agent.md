# Standalone Agent Usage

This guide explains how to use friTap's `_ssl_log.js` JavaScript agent directly with Frida, without the friTap Python wrapper. This is useful for custom integrations, research, or when you need more control over the instrumentation process.

## Overview

friTap consists of two main components:

1. **Python Host (`SSL_Logger`)** - Manages Frida sessions, handles output, generates PCAP files
2. **JavaScript Agent (`_ssl_log.js`)** - Performs the actual SSL/TLS hooking inside the target process

You can use the agent standalone if you:

- Need custom message handling
- Want to integrate friTap into existing Frida scripts
- Are building custom security tools
- Need more control over the instrumentation flow

## Agent Location

The compiled JavaScript agent is located at:

```
friTap/friTap/_ssl_log.js        # Modern agent (Frida 17+)
friTap/friTap/_ssl_log_legacy.js # Legacy agent (Frida <17)
```

## Critical: Initialization Protocol

The friTap agent uses a **blocking initialization protocol**. When loaded, it sends several configuration requests and **waits for responses**. If your script doesn't respond to these messages, the agent will hang and Frida will time out.

### Required Initialization Messages

The agent sends these messages (in order) and blocks waiting for each response:

| Message | Expected Response Type | Purpose |
|---------|----------------------|---------|
| `"offset_hooking"` | `{"type": "offset_hooking", "payload": <JSON or null>}` | Custom function offsets |
| `"pattern_hooking"` | `{"type": "pattern_hooking", "payload": <JSON or null>}` | Byte patterns for hooking |
| `"socket_tracing"` | `{"type": "socket_tracing", "payload": <bool>}` | Enable socket tracing |
| `"defaultFD"` | `{"type": "defaultFD", "payload": <bool>}` | Use default file descriptors |
| `"experimental"` | `{"type": "experimental", "payload": <bool>}` | Enable experimental features |
| `"anti"` | `{"type": "antiroot", "payload": <bool>}` | Enable anti-root bypass (Android) |
| `"install_lsass_hook"` | `{"type": "install_lsass_hook", "payload": <bool>}` | Hook LSASS (Windows) |

### Minimal Message Handler

Here's the minimal message handler that responds to all initialization messages:

```python
def on_message(message, data):
    """Handle messages from the friTap agent."""
    global script

    if message["type"] == "error":
        print(f"[ERROR] {message.get('description', message)}")
        return

    if message["type"] == "send":
        payload = message.get("payload", {})

        # CRITICAL: Respond to initialization messages
        # The agent BLOCKS waiting for these responses!

        if payload == "offset_hooking":
            script.post({"type": "offset_hooking", "payload": None})
            return

        if payload == "pattern_hooking":
            script.post({"type": "pattern_hooking", "payload": None})
            return

        if payload == "socket_tracing":
            script.post({"type": "socket_tracing", "payload": False})
            return

        if payload == "defaultFD":
            script.post({"type": "defaultFD", "payload": False})
            return

        if payload == "experimental":
            script.post({"type": "experimental", "payload": False})
            return

        if payload == "anti":
            script.post({"type": "antiroot", "payload": False})
            return

        if payload == "install_lsass_hook":
            script.post({"type": "install_lsass_hook", "payload": False})
            return

        # Handle regular messages (see below)
        # ...
```

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
AGENT_PATH = "path/to/friTap/_ssl_log.js"

script = None

def on_message(message, data):
    """Handle messages from the friTap agent."""
    global script

    if message["type"] == "error":
        print(f"[ERROR] {message}")
        return

    if message["type"] == "send":
        payload = message.get("payload", {})

        # Respond to initialization messages
        init_responses = {
            "offset_hooking": {"type": "offset_hooking", "payload": None},
            "pattern_hooking": {"type": "pattern_hooking", "payload": None},
            "socket_tracing": {"type": "socket_tracing", "payload": False},
            "defaultFD": {"type": "defaultFD", "payload": False},
            "experimental": {"type": "experimental", "payload": False},
            "anti": {"type": "antiroot", "payload": False},
            "install_lsass_hook": {"type": "install_lsass_hook", "payload": False},
        }

        if payload in init_responses:
            script.post(init_responses[payload])
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

To enable specific features, modify the initialization responses:

```python
# Enable pattern-based hooking with custom patterns
if payload == "pattern_hooking":
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
    script.post({"type": "pattern_hooking", "payload": patterns})
    return

# Enable socket tracing
if payload == "socket_tracing":
    script.post({"type": "socket_tracing", "payload": True})
    return

# Enable anti-root bypass (Android)
if payload == "anti":
    script.post({"type": "antiroot", "payload": True})
    return

# Enable default FD fallback
if payload == "defaultFD":
    script.post({"type": "defaultFD", "payload": True})
    return
```

### Custom Function Offsets

For libraries without symbols, provide custom offsets:

```python
if payload == "offset_hooking":
    offsets = {
        "libcustom.so": {
            "SSL_read": "0x1234",
            "SSL_write": "0x5678"
        }
    }
    script.post({"type": "offset_hooking", "payload": offsets})
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

**Solution:** Ensure your message handler responds to ALL initialization messages (`offset_hooking`, `pattern_hooking`, `socket_tracing`, `defaultFD`, `experimental`, `anti`, `install_lsass_hook`).

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

- **Pattern Generation**: Learn about [BoringSecretHunter](patterns.md#boringsecrethunter) for generating patterns
- **CLI Reference**: See [CLI options](../api/cli.md) for full friTap capabilities
- **Python API**: Use [Python API](../api/python.md) for programmatic control with built-in PCAP generation
