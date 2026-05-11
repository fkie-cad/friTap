# friTap Plugin Examples

Example plugins demonstrating the three plugin tiers.

## Examples

| File | Base Class | What It Demonstrates |
|------|-----------|---------------------|
| `stats_plugin.py` | `FriTapPlugin` | Event counting via EventBus subscriptions (no Frida scripts) |
| `module_logger_plugin.py` | `ScriptPlugin` | Custom Frida JS injection, bidirectional messaging, `ScriptLoadOrder` |
| `custom_aes.py` | `CustomProtocolPlugin` | Minimal key + data capture with `hook_key_on_enter`, `hook_read`, `hook_write` |
| `srtp.py` | `CustomProtocolPlugin` | Real-world SRTP key/data extraction from libsrtp |
| `wireguard.py` | `CustomProtocolPlugin` | Advanced features: multiple library patterns, platform targeting, base64 encoding, struct offsets, `hook_key_on_leave`, `format_template`, `wireshark_preference` |

## Quick Start

1. Copy a `.py` file to your platform's plugin directory:

   ```bash
   # Find your plugin directory:
   python -c "from friTap.plugins.loader import PLUGIN_DIR; print(PLUGIN_DIR)"

   # Copy the plugin:
   cp stats_plugin.py "$(python -c 'from friTap.plugins.loader import PLUGIN_DIR; print(PLUGIN_DIR)')"
   ```

2. Run friTap normally — the plugin loads automatically:

   ```bash
   fritap -m com.example.app -keylog keys.log
   ```

## Plugin Class Naming

For file-based discovery (the platform plugin directory), your plugin file **must** define a class named `Plugin` that inherits from a `FriTapPlugin` subclass. The `module_logger_plugin.py` example intentionally uses a different class name (`ModuleLoggerPlugin`) to show a plugin that requires programmatic registration instead of auto-discovery.

## Full Documentation

See the [Plugin System documentation](../../../docs/api/plugins.md) for the complete reference.
