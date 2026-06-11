# Adding Features to friTap

This guide shows how to extend friTap with new capabilities. Each section is a
single, end-to-end worked example so you can follow one task from start to
finish:

1. [Add a TLS library (modern `HookDefinition` path)](#add-a-tls-library-modern-hookdefinition-path)
2. [Legacy class-based path (deprecated)](#legacy-class-based-path-deprecated)
3. [Add a protocol parser (Python)](#add-a-protocol-parser-python)
4. [Add a plugin / custom Frida script](#add-a-plugin-custom-frida-script)
5. [Adding a brand-new protocol family](#adding-a-brand-new-protocol-family)

friTap is split into two halves: a **TypeScript Frida agent** (`agent/`, compiled
to `friTap/fritap_agent.js`) that does the in-process hooking, and a **Python
host** (`friTap/`) that orchestrates the agent and post-processes the captured
data. TLS/SSH/QUIC library support lives in the agent; parsers, plugins, and
analyzers live in Python.

!!! info "Research first"
    Before hooking a new native library, study it. Locate the read/write and
    key-derivation functions, confirm their argument order, and decide whether
    you can resolve them by exported symbol or need byte patterns:

    ```bash
    # Exported symbols (preferred resolution path)
    readelf -s libnewssl.so | grep FUNC
    objdump -T libnewssl.so | grep -E "ssl|tls|read|write"

    # Stripped? Generate byte patterns with BoringSecretHunter, or reverse with
    # Ghidra/radare2 and capture the function prologue. See advanced/patterns.md.
    ```

---

## Add a TLS library (modern `HookDefinition` path)

The modern agent is **data-driven**: instead of writing a hand-rolled hooking
class, you describe the library declaratively as a `HookDefinition`, and a
generic executor installs the Frida interceptors for you. This is the path you
should take for new libraries.

!!! warning "The modern path is opt-in (EXPERIMENTAL)"
    For TLS libraries the modern executors are selected only when the user
    passes `--modern` (`use_modern`); the **default is the legacy path**
    (`friTap/friTap.py`, `default=False`). SSH and IPsec auto-enable modern.
    Known modern-path regressions (`_MODERN_REGRESSIONS`) cover iOS/macOS Cronet,
    Windows LSASS, and IPsec. Register your library on **both** the modern and
    legacy `hookFn`s (as the existing entries do) so it works regardless of the
    flag, and treat the modern path as experimental until verified on a device.

We will add a fictional `libnewssl` whose API mirrors OpenSSL. The reference
implementation to copy from is `agent/tls/definitions/openssl.ts`.

### Step 1 — Write the definition factory

Create `agent/tls/definitions/newssl.ts` exporting a factory that returns a
`HookDefinition`. The full interface is in `agent/core/hook_definition.ts`
(`HookDefinition`); the fields below are the minimal real-shaped set.

```typescript
// agent/tls/definitions/newssl.ts
import { HookDefinition, ResolvedFunctions } from "../../core/hook_definition.js";
import { readHexFromPointer } from "../decoders/hex_utils.js";
import { STANDARD_SOCKET_SYMBOLS } from "./shared_constants.js";
import { createLifecycleHook } from "./shared_factories.js";

// fdDecoder: turn the library's SSL context into a socket file descriptor so
// friTap can attribute traffic to the right connection.
export function newSslFdDecoder(ssl: NativePointer, fns: ResolvedFunctions): number {
    if (!fns["NewSSL_get_fd"]) return -1;
    return fns["NewSSL_get_fd"](ssl) as number;
}

export function newSslSessionIdDecoder(ssl: NativePointer, fns: ResolvedFunctions): string {
    if (!fns["NewSSL_get_session_id"]) return "";
    const idPtr = fns["NewSSL_get_session_id"](ssl) as NativePointer;
    return idPtr.isNull() ? "" : readHexFromPointer(idPtr, 32);
}

export function createNewSslDefinition(): HookDefinition {
    const def: HookDefinition = {
        libraryId: "newssl",
        offsetKey: "newssl",                 // key used to look up --offsets / patterns
        functions: {
            // Symbols resolved in the target library...
            librarySymbols: [
                "NewSSL_read",
                "NewSSL_write",
                "NewSSL_get_fd",
                "NewSSL_get_session_id",
                "NewSSL_set_keylog_callback",
            ],
            // ...and in the socket library (libc on Linux, etc.)
            socketSymbols: STANDARD_SOCKET_SYMBOLS,
        },
        // NativeFunction wrappers the executor will build for you, so your
        // decoders can call them directly (see newSslFdDecoder above).
        nativeFunctions: [
            { symbol: "NewSSL_get_fd", retType: "int", argTypes: ["pointer"] },
            { symbol: "NewSSL_get_session_id", retType: "pointer", argTypes: ["pointer"] },
            { symbol: "NewSSL_set_keylog_callback", retType: "void", argTypes: ["pointer", "pointer"] },
        ],
        fdDecoder: newSslFdDecoder,
        sessionIdDecoder: newSslSessionIdDecoder,
        // Plaintext capture: which args carry the SSL ctx / buffer / length, and
        // where the byte count comes from (return value for read, arg for write).
        readHook: {
            symbol: "NewSSL_read",
            args: { sslCtxArgIndex: 0, bufferArgIndex: 1, bytesTransferred: "retval" },
            functionLabel: "NewSSL_read",
        },
        writeHook: {
            symbol: "NewSSL_write",
            args: { sslCtxArgIndex: 0, bufferArgIndex: 1, lengthArgIndex: 2, bytesTransferred: "arg" },
            functionLabel: "NewSSL_write",
        },
        // Key extraction. Use kind: "callback_on_ssl_new" / "callback_on_init" /
        // "manual_on_connect" / "custom" / "none". A custom installer gives you
        // full control (see createBoringSSLKeylogApproach in openssl.ts).
        keylog: { kind: "none" },
    };

    // Lifecycle hook so sessions are torn down cleanly when the ctx is freed.
    def.extraHooks = [
        createLifecycleHook("NewSSL_free", newSslFdDecoder, newSslSessionIdDecoder),
    ];

    return def;
}
```

!!! tip "BoringSSL-family libraries"
    If your library is a BoringSSL fork, set `libraryType: "boringssl"` on the
    definition. The loader then routes keylog extraction through the three-tier
    chain in `agent/shared/boringssl_hook_chain.ts` (callback →
    `bssl::ssl_log_secret` symbol → `pattern.json` byte scan) automatically.

### Step 2 — Add a platform executor

The executor is the thin glue that hands your definition to the generic loader.
Create one per platform, e.g. `agent/tls/platforms/linux/newssl_linux.ts`,
following `agent/tls/platforms/linux/gnutls_linux.ts`:

```typescript
// agent/tls/platforms/linux/newssl_linux.ts
import { socket_library } from "../../../platforms/linux.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createNewSslDefinition } from "../../definitions/newssl.js";

export function newssl_execute_modern(moduleName: string, is_base_hook: boolean) {
    executeFromDefinition(
        createNewSslDefinition(),
        moduleName,
        socket_library,
        is_base_hook,          // isBaseHook
        enable_default_fd,     // enable_default_fd
    );
}
```

`executeFromDefinition(def, moduleName, socketLibrary, isBaseHook, enableDefaultFd)`
(`agent/core/loader.ts`) resolves the symbols (exports → offsets → user
`--patterns`), wraps the `nativeFunctions`, installs your read/write hooks,
dispatches the keylog approach, and runs any `extraHooks`.

### Step 3 — Register the library

Wire the executor into the platform agent — for Linux that is
`agent/platforms/linux.ts`, inside the `hookRegistry.registerAll([...])` block
(around the existing TLS entries, ~`:104-132`):

```typescript
// agent/platforms/linux.ts — add to the registerAll([...]) array
{
    platform: plattform_name,
    pattern: /.*libnewssl\.so/,                 // module-name regex
    hookFn: (use_modern ? newssl_execute_modern : newssl_execute),
    library: "NewSSL",                          // shown in logs
    libraryType: "newssl",                      // tlsLibHunter scan key
    protocol: "tls",
},
```

Each registration is a `HookRegistration` (`agent/shared/registry.ts`):
`platform`, `pattern`, `hookFn`, and `library` are required; `protocol`
(defaults to `"tls"`) and `priority` (defaults to `100`) are optional, as are
`libraryType`, `pathFilter`, and `excludePattern`. Use `register(...)` for a
single hook or `registerAll([...])` for several. Add the matching entry to
`windows.ts` / `macos.ts` / `android.ts` if you support those platforms.

The agent entry point is `agent/fritap_agent.ts`; the platform agents are loaded
from there.

### Step 4 — Build

```bash
npm run build
# runs: frida-compile agent/fritap_agent.ts -o friTap/fritap_agent.js
```

Then test on a device against a known-good target:

```bash
fritap --modern -k newssl_keys.log ./newssl_test_app
grep CLIENT_RANDOM newssl_keys.log     # confirm key extraction fired
```

---

## Legacy class-based path (deprecated)

Before the data-driven refactor, each library was a hand-written class with its
own `install()` / pattern-scan logic. Those implementations still ship and are
selected when `use_modern` is **false** (the current default for TLS). They live
under `agent/legacy/tls/...` — for example
`agent/legacy/tls/platforms/linux/openssl_boringssl_linux.ts` exports
`boring_execute`, which `agent/platforms/linux.ts` selects via
`(use_modern ? boring_execute_modern : boring_execute)`.

!!! note
    Do not author new libraries against the legacy classes. Write a
    `HookDefinition` (above) and register it on both the modern and legacy
    `hookFn` slots so it works whether or not the user passes `--modern`.

---

## Add a protocol parser (Python)

Parsers turn captured plaintext byte streams into structured `ParseResult`
records (method/URL/headers/body) so flows can be analyzed and replayed. They
run in the **Python host**, not the agent, and are registered at runtime.

Subclass `BaseParser` (`friTap/parsers/base.py`) and implement the three
abstract methods plus the `PROTOCOL` class attribute:

```python
# my_grpc_parser.py
from friTap.parsers.base import BaseParser, ParseResult


class GrpcParser(BaseParser):
    PROTOCOL = "grpc"

    def can_parse(self, data: bytes) -> bool:
        """Cheap sniff: return True if this looks like our protocol."""
        return data[:1] in (b"\x00", b"\x01")  # gRPC length-prefixed frame flag

    def feed(self, data: bytes, direction: str,
             stream_id: int | None = None) -> list[ParseResult]:
        """Consume bytes; return any completed messages.

        `direction` is "in"/"out"; `stream_id` is set for multiplexed
        transports (HTTP/3) and may be ignored otherwise.
        """
        results: list[ParseResult] = []
        # ...accumulate and decode frames...
        return results

    def flush(self) -> list[ParseResult]:
        """Emit anything still buffered when the flow ends."""
        return []
```

Register the class with the registry (`friTap/parsers/registry.py`). Higher
priority is tried first; the first parser whose `can_parse()` returns `True`
wins, and `HexdumpParser` is the guaranteed fallback:

```python
from friTap.parsers.registry import get_default_registry

get_default_registry().register(GrpcParser, priority=75)
```

The built-in parsers, in descending priority, are **HTTP/1** (100), **HTTP/2**
(90), **WebSocket** (85), **HTTP/3** (80), and **Hexdump** (0, fallback). Because
registration is a plain runtime call, the cleanest way to ship a parser is from
a plugin's `on_load` hook via `session.register_parser(GrpcParser, priority=75)`
(see the next section).

---

## Add a plugin / custom Frida script

Plugins extend the Python host without modifying friTap itself — they subscribe
to the `EventBus`, register parsers/columns/tabs, or inject extra Frida scripts.
There are two base classes:

- **`FriTapPlugin`** (`friTap/plugins/base.py`) — the general plugin. Override
  `name`, `version`, and `on_load(session)`; subscribe to events
  (`DatalogEvent`, `FlowEvent`, …) or call `session.register_parser(...)` there.
- **`ScriptPlugin`** (`friTap/plugins/script_plugin.py`) — for plugins that
  inject their own Frida script. It adds a two-phase lifecycle and a
  `load_order` of either `ScriptLoadOrder.BEFORE_MAIN` or `AFTER_MAIN`
  (default), controlling whether your script loads before or after friTap's main
  agent.

The `-c` / `--custom_script` CLI flag is itself implemented as a plugin:
`LegacyCustomScriptPlugin` (`friTap/plugins/legacy_custom_script.py`) wraps the
supplied script file as a `ScriptPlugin` with `load_order = BEFORE_MAIN`, so a
user-provided script runs before the main hooks install.

!!! tip "Decryptor seam"
    To decrypt a nested protocol layer (e.g. an inner tunnel) rather than parse
    plaintext, implement `LayerDecryptor` and register it with the (intentionally
    empty) `DecryptorRegistry` from `friTap/flow/decryptors/`
    (`get_default_decryptor_registry()`). This is a live extension point.

For full plugin lifecycle, discovery paths, and worked examples, see the
plugin guide at `docs/development/plugins.md`.

---

## Adding a brand-new protocol family

TLS, SSH, QUIC (under the TLS family), and IPsec are the protocols friTap
understands. The set of **protocol families** is a static map in
`agent/protocols/registry.ts`:

```typescript
const _protocols: { [name: string]: Protocol } = {
    tls: new TLSProtocol(),
    ipsec: new IPSecProtocol(),
    ssh: new SSHProtocol(),
};
```

`getProtocol(name)` resolves a `--protocol` value against this map and returns
`undefined` for anything unknown. Adding a genuinely new family (e.g. `signal`,
`smb3`) therefore requires two changes:

1. Implement the `Protocol` interface in a new file under `agent/protocols/`
   (the contract is in `agent/protocols/base.ts`: `detect`,
   `getLibraryPatterns`, `getRequiredFunctions`, `getKeyLabels`,
   `formatKeylog`).
2. Add the instance to the `_protocols` map in `agent/protocols/registry.ts` and
   register your library hooks for it (the per-library `HookRegistration.protocol`
   field carries the family name).

Most new work is adding a **library** under an existing family (the first
section), not a new family — reach for this only when the cryptographic protocol
itself is new.

!!! warning "IPsec key extraction is EXPERIMENTAL"
    The IPsec family currently ships as a **detection-only stub**
    (`agent/ipsec/definitions/strongswan.ts`). The `derive_ike_keys` /
    `ikev2_derive_child_sa_keys` hooks exist but are partial and do not yet
    extract usable key material. Detection works; key extraction does not.

---

## Next steps

- `docs/development/plugins.md` — full plugin system: lifecycle, discovery, custom scripts, decryptors.
- [advanced/patterns.md](../advanced/patterns.md) — byte-pattern resolution for stripped libraries (`--patterns` / `--offsets`).
- `docs/development/architecture.md` — agent build, the `config_batch` message protocol, and end-to-end data flow.
