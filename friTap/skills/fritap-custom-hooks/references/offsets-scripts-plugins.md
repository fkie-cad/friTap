# Offsets, custom scripts, plugins and the standalone agent

Source: `USAGE.md` ("Providing custom offsets/addresses", "Using friTap with a
custom Frida scripts"), `offsets_example.json`, `docs/development/plugins.md`,
`docs/advanced/standalone-agent.md`.

## Custom offsets (`--offsets`)

`--offsets` takes a JSON file or a JSON string. friTap overrides only the
functions listed; it still auto-detects all others.

```json
{
  "openssl": {
    "SSL_read":  { "address": "0x15b4", "absolute": false },
    "SSL_write": { "address": "0x144c", "absolute": false }
  },
  "sockets": {
    "getpeername": { "address": "0x572115b4", "absolute": true },
    "getsockname": { "address": "0x5721163",  "absolute": true },
    "ntohs":       { "address": "0x572116f2", "absolute": true },
    "ntohl":       { "address": "0x572116c2", "absolute": true }
  }
}
```

- `address`: hex string.
- `absolute: false`: offset from the SSL/socket library base address.
- `absolute: true`: runtime virtual address. If friTap cannot find the
  library base, every address is treated as absolute.
- Library keys used in `offsets_example.json`: `openssl`, `wolfssl`,
  `gnutls`, `mbedtls`, `nss`, `sspi`, `sockets`. It is valid JSON and loads
  as-is, but its addresses are examples: replace them with offsets from your
  library build.
- Offsets skip scanning: friTap hooks the computed address directly. They
  are only valid for the exact library build they were taken from.
- With `--pairip-safe`, `libunity.so` is opt-in via `--offsets`.

```bash
fritap -m --offsets offsets.json -k keys.log com.example.app
fritap --offsets '{"openssl": {"SSL_read": {"address": "0x15b4", "absolute": false}}}' -k keys.log target_app
```

## Custom Frida script (`-c` / `--custom_script`)

friTap wraps the script as `LegacyCustomScriptPlugin` (a `ScriptPlugin` with
`load_order = BEFORE_MAIN`), so it runs before friTap's own hooks. Frida
backend only.

```bash
fritap -m -k keys.log -do -c ./custom.js -v com.example.app
```

```javascript
// custom.js: report TLS-looking exports of every loaded module
Process.enumerateModules().forEach(module => {
    module.enumerateExports().forEach(exp => {
        const name = exp.name.toLowerCase();
        if (name.includes("ssl") || name.includes("tls")) {
            send({ custom: `Found export: ${exp.name} in ${module.name} at ${exp.address}` });
        }
    });
});
```

Message handling:

- A payload dict with a `custom` key is logged by friTap.
- A `type == "error"` message during load (top-level code, or about a second
  after `script.load()` returns) terminates friTap.
- Later errors (deferred callbacks) are logged (identical ones at most once a
  minute) and the run continues.

The script is not exposed through the agent API (`start_capture`).

## friTap plugins

| | `FriTapPlugin` | `ScriptPlugin` |
|---|---|---|
| Runs in | Python host | target process (injected Frida JS) |
| Entry point | `on_load(session)` | `get_script_source(context)` |
| Use for | post-processing, parsers, sinks | extra hooks, keys from other libraries |

- File plugins: a `.py` file (name not starting with `_`) with a class named
  exactly `Plugin`, in the plugin directory. Print it with
  `python -c "from friTap.plugins.loader import _get_plugin_dir; print(_get_plugin_dir())"`
  (Linux `~/.local/share/friTap/plugins/`, macOS
  `~/Library/Application Support/friTap/plugins/`, Windows
  `C:\Users\<user>\AppData\Local\friTap\plugins\`; legacy
  `~/.fritap/plugins/` only if the native directory does not exist).
- Packaged plugins: entry-point group `fritap.plugins`, value = plugin class.
- `name` and `version` are required; a duplicate `name` replaces the earlier
  plugin. Startup logs `Loaded plugin: <name> v<version>`.
- `ScriptPlugin.load_order`: `ScriptLoadOrder.BEFORE_MAIN` or `AFTER_MAIN`
  (default). Restrict backends with `supported_backends`.
- Host plugins can add parsers with `session.register_parser(cls, priority)`.
- Cancelling an event only suppresses console output; pcap, keylog and JSON
  handlers still record the data.
- `ScriptPlugin.post_to_script(...)` and TUI column/tab providers are
  experimental. The `LayerDecryptor` registry is an empty extension point for
  nested-protocol decryption.

## Standalone agent (`friTap/fritap_agent.js`)

Load the compiled agent from your own Frida host (Python `frida` bindings,
`runtime="qjs"`). It blocks in startup until the host answers:

1. `"config_batch"` -> post `{"type": "config_batch", "payload": {...}}`. Every
   field is optional (23 fields; defaults apply). Relevant here:
   `patterns` and `offsets` (JSON **strings**, e.g. `json.dumps(patterns)`),
   `keylog_enabled: true`, `use_modern`, `library_scan_enabled`,
   `debug_output`, `protocol_select`, `probe`.
2. `"anti"` -> post `{"type": "antiroot", "payload": <bool>}`. This must be
   answered last; without it `script.load()` never returns.

Reply on the script that asked, and answer both messages for every script
(child/spawn gating creates more scripts). Keys arrive as
`contentType: "keylog"` messages (only with `keylog_enabled: true`),
plaintext as `datalog`. On teardown call
`script.exports_sync.graceful_detach()` before `script.unload()`.

The bundle is a build artifact of `agent/*.ts`; its `AGENT_ABI_VERSION`
(currently 2) must match the host. Rebuild with `./dev/compile_agent.sh` after
editing the TypeScript. `FRITAP_AGENT_BUNDLE` points friTap itself at another
bundle (not ABI-filtered). Full example: `example/chrome_ssl_intercept.py`.
