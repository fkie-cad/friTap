# Contributing guidelines

## Adding a new SSL/TLS library

friTap's TLS-hooking code lives under `agent/tls/`, organised in three layers:

- **`agent/tls/libs/<library>.ts`** — the platform-agnostic implementation
  of the library's hook (typed signatures, key/secret extraction logic,
  read/write hooks). For BoringSSL/OpenSSL this is
  [`agent/tls/libs/openssl_boringssl.ts`](https://github.com/fkie-cad/friTap/blob/main/agent/tls/libs/openssl_boringssl.ts).
- **`agent/tls/platforms/<os>/<library>_<os>.ts`** — per-OS bindings that
  resolve module names, symbols, or pattern offsets and invoke the
  generic implementation above. The full grid (Android, iOS, Linux,
  macOS, Windows) lives under
  [`agent/tls/platforms/`](https://github.com/fkie-cad/friTap/tree/main/agent/tls/platforms).
- **`agent/platforms/<os>.ts`** — the platform orchestrator. Each new
  library exports an `_execute_modern` (definition-based) and/or
  `_execute` (legacy class-based) function which is imported and called
  here. Example:
  [`agent/platforms/android.ts`](https://github.com/fkie-cad/friTap/blob/main/agent/platforms/android.ts).

So adding a new library `foo` for Android looks like:

1. Implement the generic hook in `agent/tls/libs/foo.ts`.
2. Add the Android bindings in `agent/tls/platforms/android/foo_android.ts`,
   exporting `foo_execute_modern()` (or `foo_execute()` for the legacy
   class-based pattern).
3. Import and invoke `foo_execute_modern` from
   `agent/platforms/android.ts` in the appropriate hook-registration
   path.
4. Repeat steps 2–3 for any other operating systems your library
   targets. Per-OS files live in `agent/tls/platforms/{linux,macos,ios,windows}/`.

The "modern" definition-based pattern (`*_execute_modern`) is the
preferred shape for new libraries; older libraries still use the legacy
class-based pattern under `agent/legacy/tls/platforms/<os>/`. Look at any
existing `*_execute_modern` for a canonical structure — `boring_execute_modern`
in `openssl_boringssl_android.ts` is a good reference.

For protocols other than TLS:

- **SSH** (`agent/ssh/`) and **IPsec** (`agent/ipsec/`) follow the same
  three-layer shape (`libs/` + `platforms/<os>/` + a top-level platform
  orchestrator).
- **QUIC** (`agent/quic/`) and **OHTTP** (`agent/ohttp/`) use a variant
  organisation: `definitions/` (per-implementation hook definitions, e.g.
  `quiche.ts`, `neqo.ts`, `bhttp.ts`, `nss_hpke.ts`) plus
  `platforms/<os>/`. There is no `libs/` directory in these trees.

When adding support for a new protocol, please prefer the standard protocol
layout used by TLS, SSH, and IPsec unless there is a strong reason to do
otherwise. In practice, this means adding a dedicated `agent/<protocol>/`
directory with implementation-specific logic under `libs/`, platform-specific
logic under `platforms/<os>/`, and a top-level platform orchestrator that wires
the protocol into friTap.

When in doubt, look at how the existing implementation closest to your target
is wired into `agent/platforms/<os>.ts`. If you are unsure which structure fits
best for a new protocol, please open an issue first so we can discuss the
expected layout before you start implementing it.

## Adding a protocol layer

The agent-side hooks above capture bytes; the **flow-side protocol layer model**
(`friTap/flow/`) is how those bytes and their metadata surface to consumers as
`flow.<protocol>.{field, data, parsed}`. To expose a new protocol there:

1. Pick a layer class. For a metadata-bearing transport/encryption protocol,
   subclass `ProtocolLayer` (in `friTap/flow/layers.py`) and add its typed
   metadata fields, following `TlsLayer` / `QuicLayer` / `SshLayer`. For a plain
   application protocol, reuse the generic `AppLayer` instead of writing a new
   class.
2. Register it by adding a `ProtocolDescriptor` in
   `friTap/flow/layer_registry.py`:

   ```python
   register(ProtocolDescriptor("foo", FooLayer, data_source="chunks"))
   ```

   `data_source` declares where the layer's `.data` comes from:
   - `"chunks"` — a zero-copy view over the flow's decrypted bytes (transport
     and application layers).
   - `"owned"` — bytes the layer holds itself (inner protocols decrypted out of
     a carrier).
   - `"none"` — metadata-only, no payload bytes.

Two rules to keep in mind:

- **Metadata extraction belongs in the offline pipeline**, never the live agent.
  TLS/QUIC/SSH handshake metadata is recovered by tshark in
  `friTap/offline/tshark.py` and stamped onto the flow during offline
  reconstruction. The live agent emits connection identity and lifecycle only.
- **Nested-protocol plaintext** goes through the optional `decryptor` seam
  (`friTap/flow/decryptors/`): a decryptor peels a plaintext inner protocol out
  of an encrypted carrier and feeds it to an `"owned"`-data inner layer. The
  registry is empty today; this is the extension point for protocols like
  Signal or MTProto carried inside TLS.

## Ground truth

For each new library we want to build a ground-truth executable so that
we can verify the hook works against a known-correct binary. Ground-truth
sources live alongside their library implementation. If you're adding
a library without a ground truth, flag it in your PR — we will work with
you to add one before merging.

## Background

- [friTap blog post](https://lolcads.github.io/posts/2022/08/fritap/#program-flow)
  on the program flow.
- The [Debugging friTap wiki page](https://github.com/fkie-cad/friTap/wiki/Debugging-friTap)
  explains the debug feature, which is what we recommend while developing
  a new library hook.

## Frida bridges (frida 17+)

Starting with **Frida version 17 and above**, language-specific bridges
must be installed manually. friTap requires:

- [`frida-java-bridge`](https://github.com/frida/frida-java-bridge) –
  for interacting with Java-based apps on Android.
- [`frida-objc-bridge`](https://github.com/frida/frida-objc-bridge) –
  for interacting with Objective-C code on iOS/macOS.

Install both using Frida's package manager:

```bash
frida-pm install frida-objc-bridge frida-java-bridge
```

For local maintainers building the agent, `npm ci` against the checked-in
`package-lock.json` installs the bridges via the npm dependency tree
automatically. See [`RELEASING.md`](./RELEASING.md) for the full agent-rebuild flow.
