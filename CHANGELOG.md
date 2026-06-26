# Changelog

All notable changes to friTap will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [2.2.2]

### Added
  - **`--pairip-safe` (Android).** Minimal, scan-free capture mode for Google
    PairIP-protected apps. Hooks only a curated TLS-library allowlist
    (`agent/shared/pairip_safe_libs.ts`) resolved without any `Memory.scan`
    (exports → `.symtab` → offsets), and disables the loader hook, Java/ART hooks,
    the WebView/Cronet pattern scan and OHTTP — the broad footprint that trips
    PairIP's integrity check and `SIGSEGV`s the app. Keys persist via "blink"
    (hooks toggled so `.text` stays pristine between scans). Works with attach and
    spawn (`-s`). Captures the System WebView (Chromium) login by offset-hooking
    `bssl::ssl_log_secret`; `dev/find_ssl_log_secret_offset.py` derives the
    (target-specific) offset from a stripped `.so`. Unity's `libunity.so` MbedTLS
    hook is opt-in via `--offsets` (inline `.text` on an app-bundled lib carries a
    PairIP-detection risk). Full guide: `docs/advanced/pairip-safe.md`.
    (fkie-cad/friTap#64)
  - **`--no-loader-hook` / `-nlh` (Android).** Skips the inline `android_dlopen_ext`
    loader trampoline. Only already-loaded / explicitly-selected (`--offsets`) TLS
    libraries are then hooked. Intended for apps protected by Google PairIP and other
    anti-tamper runtimes, where the loader hook is detected during the spawn-time
    integrity scan and the app self-terminates with SIGSEGV (fkie-cad/friTap#64).


### Fixed
  - **`--no-loader-hook` now also gates the OHTTP loader hook.** `installOhttpHooks`
    installed its own `android_dlopen_ext` trampoline, so `--no-loader-hook` did not
    actually prevent the PairIP SIGSEGV — the linker was still patched. All three
    Android loader-hook sites (OHTTP, loader+patterns, library-scan) now honour a
    single skip decision (fkie-cad/friTap#64).
  - **Clean exit when the target crashes.** After a `process-terminated` detach, the
    teardown could wedge on a Frida callback thread and friTap hung until the user
    pressed Ctrl+C. The main thread now owns the final exit once all data is flushed.

### Changed
  - **Crash attribution for anti-tamper self-destructs.** The agent now emits
    crash breadcrumbs at install time (`install-tls-hooks: <lib>`, `pattern-scan:
    <lib>`), and on a `process-terminated` death in spawn mode friTap prints an
    explicit diagnosis: the inline TLS-library hooks (not just the loader hook)
    are present during the startup integrity scan, so spawn capture is unreliable
    on PairIP-protected apps even with `--no-loader-hook` — use attach mode. A
    late-loading `libpairipcore.so` is now also re-scanned for after instrument so
    the red banner appears even when it loads after the initial gate (friTap#64).
  - **Readable, de-duplicated anti-tamper banner.** The detection/skip notice is now
    rendered once as a single blank-line-padded, red (on a TTY) banner on the host
    side, instead of several interleaved `[*] [!] …` / `[-] [!!!] …` lines emitted
    from multiple agent code paths. The agent emits only the structured signal; the
    Python side owns presentation.
  - **Anti-tamper auto-protection (Android).** When friTap detects a known
    anti-tamper library (e.g. Google PairIP / `libpairipcore.so`) **in spawn mode**,
    it now automatically skips the `android_dlopen_ext` loader hook instead of
    installing it and crashing the target. friTap prints an unmissable banner
    explaining that spawn-mode capture is not possible and that the app should be
    started and then **attached** to (without `-s`). Already-loaded TLS libraries are
    still hooked. Attach mode and non-protected apps are unaffected. Applies to both
    the default (legacy) and `--modern` hooking paths.
  - The detection is now surfaced as a structured `anti_tamper_detected` event
    (`AntiTamperDetectedEvent`) on the Python event bus / API, in addition to the
    console banner — previously the agent's signal was dropped.

## [2.2.0]

### Added
  - **Offline `pcap → .tap` decryption** — `fritap --from-pcap … --keylog
    <tls> --telegram-keylog <telegram> --tap …` strips TLS and natively decrypts the
     layer into MTProto transport decryptor
  - **Generic memory-region key-scan engine** (`--scan-keys-region
    <module|base,size|heap>`). A new protocol-agnostic scanner (`agent/shared/scan/`)
    walks a CLI-selected memory region — a module name, an explicit `0xADDR,SIZE`
    range, or `heap` (all writable ranges) — runs content heuristics inside hardened
    guard rails (chunked, shutdown-aware), and emits the **top-ranked anonymous
    candidates** to the keylog (requires `-k`). Each candidate is reveal-free (score
    / signals / region / offset / length / bytes — no protocol identity, no decrypted
    content): the agent tags them `classifier="scan_candidate"` and
    `friTap/output/scan_candidate_formatter.py` renders them. The engine names no
    protocol and runs standalone; an optional binding can narrow the region and add
    its own classifier through the `scan_extension` provider seam without touching the
    engine. Useful for locating key material in stripped/obfuscated builds where no
    library-specific hook exists.
  - **TUI** — a "Signal" entry now appears in the protocol picker.
  - **Restored Signal chat-TLS key capture for modern libsignal** (>= 7.52 / 8.x)
    via a new `ssl_log_secret` pattern.

## [2.1.0] - 2026-06-13

### Added
- **Telegram / MTProto support (Android).** A new `--protocol mtproto` selects a
  Telegram key/decryption path that mirrors the TLS/SSH protocol modules:
  - **MTProto 2.0 crypto core** — SHA256 KDF + AES-256-IGE + msg_key verification,
    with an optional `tgcrypto` fast path.
  - **Offline `pcap → .tap` decryptor** — because tshark cannot decrypt MTProto,
    friTap ships its own (TCP reassembly → AES-CTR transport de-obfuscation →
    AES-IGE), wired into `fritap --from-pcap … --mtproto-keylog …`.
  - **Canonical keylog format** (`MTPROTO_AUTH_KEY <dc_id> <auth_key_id> <auth_key>
    <key_type>`) shared by the live writer and the offline reader.
  - **`MtprotoLayer`** that round-trips through the `.tap`, plus pluggable **parser
    discovery** (drop-in dir + `fritap.parsers` entry points) so a user's Telegram
    TL parser plugs in with no core edits.
  - **Optional dependency** — offline decryption needs the `cryptography` backend
    (it does the transport AES-CTR de-obfuscation *and* the AES-IGE records),
    shipped as the `friTap[mtproto]` extra. `tgcrypto` is an optional AES-IGE
    speed-up only (it cannot do the transport CTR) and is available via the
    `friTap[mtproto-fast]` extra. When the backend is missing, the CLI (live
    `--protocol mtproto` and offline `--mtproto-keylog`) and the TUI protocol
    picker print an actionable install hint instead of failing obscurely.
  - **Phase-0 experiment scripts** (`research/mtproto_phase0/`) to derive the
    on-device hook offsets/byte-patterns that the bundled agent module needs.
  See `docs/protocols/telegram.md`. (End-to-end secret chats and non-Android
  platforms are future work.)
- **Analyzer finding-detail view in the replay TUI.** Pressing `Enter` on a row
  in the Findings Viewer now opens a finding-centric detail view (distinct from
  the flow-centric flow detail): it leads with the matched value and evidence,
  highlights the match in the request headers, and offers a one-key **base64
  decode** (`b`) for values like HTTP `Authorization: Basic …`. Press `d` to
  switch to the regular flow detail, and `Esc` to walk back up the navigation
  hierarchy (finding → category findings → all findings → flow list). The
  Findings Viewer also gains an optional **Preview** column (matched-value
  snippet, shown on wide terminals). New widget
  `friTap/tui/widgets/analyzer_finding_detail.py`.
- **Interactive Analyzer Panel in the replay TUI** (key `a`). Opening a `.tap`
  with `fritap -r <file>.tap` now exposes a docked panel above the flow list to
  run analyzers over the loaded flows from inside the TUI — previously the
  Findings Viewer (`Shift+F`) could only *show* findings already stored in the
  `.tap`. Multi-select the analyzers (built-ins plus auto-discovered externals)
  or type a one-off `module:Class` path, press `r` to run (background worker,
  live progress, UI stays responsive), then a summary **dashboard** of selectable
  chips (by severity, analyzer, category, plus *View all*) drops into the Findings
  Viewer pre-filtered. `x` clears, `Esc` closes. `a` is context-aware — it still
  means *attach* during a live capture that has no flows. Findings computed in the
  session are written into the `.tap` on save (`w`). New widget
  `friTap/tui/widgets/analyzer_panel.py`.
- **Zero-config analyzer discovery** (`friTap/analysis/discovery.py`) — a custom
  analyzer is now available across the Python API, the CLI (`--scan` and the
  `analyze` subcommand) and the TUI without re-passing `--analyzer-path`.
  Discovery scans three sources: a drop-in directory
  (`~/.local/share/friTap/analyzers/` on Linux,
  `~/Library/Application Support/friTap/analyzers/` on macOS,
  `C:\Users\<user>\AppData\Local\friTap\analyzers\` on Windows), the
  `fritap.analyzers` setuptools entry-point group, and a new optional
  `FriTapPlugin.register_analyzers()` hook. Discovery is lazy + cached and feeds
  the analyzer registry. **Security:** discovered code executes when analyzers are
  first listed/resolved (same trust model as the plugin directory); set
  `FRITAP_DISABLE_ANALYZER_DISCOVERY=1` to disable ambient discovery (explicit
  `--analyzer-path` still works). Embedders also get public
  `friTap.analysis.registry.register_analyzer(name, factory)` (programmatic
  registration) and `refresh_discovered()` (force a re-scan).
- **`--list-analyzers`** (top-level and `fritap analyze --list-analyzers`) — prints
  every available analyzer (built-ins plus discovered externals, with their source)
  and exits; needs no target. New public `list_analyzers_detailed()` (alongside
  `list_analyzers()`) returns `AnalyzerInfo(name, source, description)` records.
- **`--analyzer-path <module[:Class]>` for the live `--scan`** (repeatable;
  previously only the offline `analyze` subcommand accepted it). Plumbed through
  `OutputConfig.scan_analyzer_path` → `from_legacy_params` → `_setup_live_scan`.
- **Python-API scan builder** on `friTap.FriTap`: `.scan([spec])`,
  `.analyzer_path(path)` (repeatable), `.scan_report(fmt)`, `.scan_min_severity(sev)`,
  `.scan_show_pii(enable)` — fluent setters mirroring the `--scan*` CLI flags.
- **`FindingFilter.severities`** — an exact-severity-bucket criterion (a frozenset,
  symmetric with `sources`/`categories`), complementing the existing `min_severity`
  floor. The TUI severity chips use it so a chip's count matches its filtered result.
- **Google QUICHE Phase-2 egress-headers chain** in
  `agent/quic/definitions/google_quiche.ts`. The HTTP/3 request-header
  capture path is now a winner-takes-all fallback chain:
  `QuicSpdyStream::WriteHeaders` (quiche-internal, preferred) →
  `net::QuicChromiumClientStream::WriteHeaders` (chrome shim, fallback) →
  `quic::QuicSpdySession::WriteHeadersOnHeadersStream` (gQUIC, last resort).
  Only the highest-priority layer that resolves is attached, so the Python
  `FlowCollector` never sees duplicate header chunks for the same request.
  When the user runs in `--quic-capture-mode app-api`, each attach prints a
  one-line summary `[*] Google QUICHE egress headers chain in <module>:
  active layer = <layer>` so the active layer is obvious at a glance.
  Chrome-shim `args[0]` is the `QuicChromiumClientStream*` wrapper, not the
  inner `QuicSpdyStream*`; a new `unwrapChromiumClientStream` helper
  recovers the inner pointer (cached after first probe) so the chrome-shim
  surrogate streamId still correlates with the response-side
  `OnHeadersDecoded`. See `docs/protocols/quic.md` and
  `SEEING_THROUGH_CHROME_HTTP3.md`.
- Runtime-verified `arm64` patterns for the two chain-fallback labels
  (`QuicChromiumClientStream_WriteHeaders`,
  `QuicSpdySession_WriteHeadersOnHeadersStream`) shipped in
  `friTap/patterns/default_patterns.json` so the chain works out of the box
  on stripped Chrome 148 / libmonochrome and Cronet 148 / libcronet without
  requiring `--patterns <user.json>`. User-supplied patterns continue to
  override defaults via `PatternLoader.deep_merge` (leaf-list replace).
- `--quic-egress-headers-layer
  {auto,quiche-internal,chrome-shim,session-level}` CLI flag (default
  `auto`). Non-`auto` values FORCE a specific layer of the egress chain;
  the other two layers are skipped even when their patterns resolve. Use
  this to validate chain behaviour on builds where the primary layer would
  otherwise always win (e.g. exercise the chrome-shim unwrap path on
  libmainlinecronet.141). Plumbed end-to-end through `config.py`,
  `friTap.py`, `ssl_logger_core.py` `config_batch`, and `fritap_agent.ts`.
  Only effective in `--quic-capture-mode app-api`.
- `debug_output` config-batch field — mirrors the existing `-do` /
  `--debugoutput` CLI flag into the agent so JS code paths can cheaply
  skip expensive diagnostic work (e.g. full dynsym walks on Cronet /
  libmonochrome) when the user did not ask for debug output. Standalone
  agent integrators: add the field to your `config_batch` reply — defaults
  to `False`.
- Debug-mode candidate enumeration for the three chain labels: when `-do`
  is set, `resolveQuicheSymbols` dumps every export-table, dynsym, and
  byte-pattern candidate it considered for each chain label plus which one
  was picked, with a `WARNING` line on labels whose pattern matched more
  than one site (the blog's "uniqueness failure" hazard). Skipped silently
  when `-do` is off.
- `unwrapChromiumClientStream` hardening — outer try/catch so a wild
  dereference during offset probing cannot crash the host or affect other
  hooks, plus a module-validation step that rejects offsets whose alleged
  inner stream's `vtable[0]` does not land in the wrapper's own module or
  a Cronet-family module (`libcronet*`, `libmainlinecronet*`,
  `libmonochrome*`). Per-probe diagnostics emitted only when `-do` is set.
- `keylog_enabled` `config_batch` field — gates key extraction symmetrically
  with the existing `pcap_enabled` flag. When `friTap.py` is invoked with
  `-p <pcap>` but no `-k <keylog>`, the Python host sets `keylog_enabled=False`
  and the agent installs **no** key-extraction hooks. Standalone-agent
  integrators: add the field to your `config_batch` reply — defaults to `True`
  for backward compatibility (see `docs/advanced/standalone-agent.md`).
- The gate now applies to **every protocol, platform and library**, not just the
  modern BoringSSL path:
  - A single install-time gate in the modern loader skips the entire keylog
    install (callback / symbol / pattern-scan) for all data-driven libraries;
    every legacy TLS library installer (`openssl/boringssl`, `gnutls`, `gotls`,
    `wolfssl`, `nss`, `rustls`, `s2ntls`, `flutter`, `monobtls`, `cronet`) and
    the QUIC quiche keylog pipe/config hooks are gated the same way — saving CPU
    and pattern-scan budget on long-running plaintext-only captures.
  - New `sendKeyMaterial()` choke point in the agent gates protocol key material
    that is emitted outside the `keylog` content type. **Fixes a leak**: IPSec
    (strongSwan) `ipsec_child_sa_keys` / `ipsec_ike_keys` were previously emitted
    even in plaintext-only mode; SSH `ssh_key` / `ssh_keylog` now route through
    the same single gate.
- **HTTP/3 body plaintext capture for Google QUICHE / Cronet**
  (`agent/quic/definitions/google_quiche.ts`): hooks `OnDataFramePayload`
  (inbound) and `WriteOrBufferBody` (outbound) so request/response bodies reach
  the pcap in `--quic-capture-mode app-api`. QUIC records now carry real
  endpoints via a new `resolveQuicMessage` helper instead of `0.0.0.0:0`.
- **`--modern` flag** opts into the refactored agent (three-tier BoringSSL
  keylog chain, improved Cronet hooks); the stable **legacy path stays the
  default**, with a startup warning listing known modern-mode regressions.
- **OpenSSH (SSH) interception** (modern mode): key-extraction and plaintext
  packet hooks. `--protocol ssh` auto-enables `--modern` and child-gating for
  `sshd`; `--protocol` also gains `all` / `auto`.
- **`--force-scan <module>`** (repeatable; `re:`/prefix match, or
  `FRITAP_FORCE_SCAN`) forces the BoringSSL pattern scan onto a Cronet
  APEX-split module friTap would otherwise treat as already covered.
- **QUIC capture-mode step in the TUI** capture wizard (`stream` vs
  experimental `app-api`).
- **Per-flow protocol layer stack** — each flow is now an ordered, linear stack
  of typed protocol layers (outermost transport → innermost application), each
  exposing `flow.<protocol>.{field, data, parsed}` (e.g. `flow.tls.sni`,
  `flow.layer("http2").parsed`) plus `flow.layers` for positional access. The
  stack is registry-driven (`ProtocolDescriptor`), with an empty `decryptor`
  seam reserved for future nested protocols (Signal/MTProto inside TLS).
- **`.tap` schema v3** — flows now serialize an ordered `meta["layers"]`.
  Transport and application layers add no bytes (they record chunk-views plus a
  parsed-field tag); only owned inner-layer bytes are serialized, exactly once.
  Backward compatible: v1/v2 `.tap` files still open, with their layer stacks
  rebuilt from the legacy flow fields.
- **Offline handshake-metadata producer** — the offline pcap→tap pipeline now
  extracts TLS (SNI/cipher/version/ALPN) and SSH (banners plus KEXINIT
  kex/cipher/mac) handshake metadata via tshark and stamps it onto `flow.tls` /
  `flow.ssh`. SSH and IPsec surface as synthetic metadata-only flows.

### Changed
- Plaintext-only pcaps (`-p` without `-k`) no longer embed Decryption Secrets
  Blocks (DSBs) in the resulting pcap-ng, because key extraction now runs only
  when explicitly requested. Pass `-k <keylog>` to restore the prior behaviour
  of self-decrypting pcaps.
- Full-capture mode (`-f`) now sets `pcap_enabled=False`, so only key-extraction
  hooks are installed in-agent — the raw packets come from the external
  tcpdump/scapy capture, and the previously-installed in-agent plaintext hooks
  (whose output was discarded anyway) no longer run.
- **Pattern-based hook install is now asynchronous and detach-safe** —
  `PatternStrategy` uses non-blocking `Memory.scan`, so `gracefulDetach` is
  serviced mid-scan and huge stripped modules (e.g. Chrome's ~193 MB
  `libmonochrome_64.so`) no longer stall teardown.
- **BoringSSL embedded in Android native libraries hooks more reliably** via a
  shared `bssl::ssl_log_secret` symbol fallback for every boringssl-tagged lib
  (libssl/Conscrypt, Cronet, Flutter, Mono-BTLS) when pattern-scan and the
  keylog-callback interception both fail to resolve.
- **Plaintext pcap hooks no longer fire during key-only captures** across legacy
  and modern paths — a runtime `pcap_enabled` gate short-circuits the
  `SSL_read` / `SSL_write` executors.
- **New 3-segment SemVer scheme with a strict frida-major pin** (`compat.yml`
  as source of truth + CI version-guard); legacy frida 15/16/17 installs via
  per-major constraints files / `dev/install_legacy.py`.
- **Flow-mode TUI**: backend errors are categorized and rendered as rich
  diagnostics, plus per-session debug-log files and assorted polish.
- **Handshake metadata is now offline-only** — the live agent / `MessageRouter`
  no longer carries TLS handshake metadata (cipher/version/SNI/ALPN); the live
  path emits connection identity and lifecycle only. This metadata is produced
  solely by the offline `pcap + keys → .tap` pipeline.

### Fixed
- **The dashboard "View all" chip no longer costs an extra `Esc` press.** It
  applies an empty (no-op) `FindingFilter`, which previously registered as an
  active filter, so the first `Esc` cleared a filter that filtered nothing
  before the second `Esc` returned to the flow list. `FindingFilter.is_active()`
  now distinguishes a real filter from "show all", so a single `Esc` steps back.
- **`--list-analyzers` no longer lists a built-in twice** when a discovered
  external analyzer shares a built-in's name (the built-in wins the collision,
  matching the registry's shadow rule).
- **Findings Viewer no longer crashes on findings whose data contains Rich
  markup.** A matched value / title / source containing a stray `[` or `[/]`
  (plausible in captured HTML/JSON payloads, and reachable via the new Preview
  column) previously raised `MarkupError` and aborted the table render; every
  user-derived cell is now escaped (only the severity cell is intentional markup).
- **TUI analyzer runs no longer cancel an active capture, and a superseded run
  can't clobber newer results.** The analyzer worker runs in its own worker group
  (so `exclusive` no longer cancels the live-capture session / server-check
  workers) and carries a monotonic run token; a re-run or *Clear* mid-run
  invalidates the prior run's late completion (thread workers cannot be
  force-killed, so the token plus a cancellation check are both required).
- **Saving a `.tap` after an in-TUI analyzer run no longer drops the file's
  originally stored findings.** Export now merges the `.tap`'s existing findings
  with the session's results (de-duplicated) rather than writing only the
  replace-per-run display cache.
- **A discovered analyzer with an invalid (`None`/empty) `name` no longer crashes
  analyzer enumeration** (`--list-analyzers`, the TUI panel) — it is logged and
  skipped.
- **Analyzer discovery is now thread-safe** — the discovery cache and registry are
  guarded by locks and the "discovery complete" flag is published only after the
  registry is fully populated, so a concurrent (e.g. TUI worker-thread) resolution
  can no longer observe a partial, built-ins-only set.
- Opening the Analyzer Panel from the Findings Viewer now returns to the flow view
  first instead of stacking the panel over the findings list.
- Analyzer dashboard chips use index-based widget ids, so an analyzer or category
  name containing a space or `.` no longer breaks the dashboard.
- **Auto-loaded `default_patterns.json` no longer suppresses shipped hardcoded
  patterns** — a throw-safe `hasUsablePatternsFor()` gate requires a real,
  non-empty pattern for the current platform/arch before taking the JSON path,
  otherwise the built-in default is used.
- **Missing-architecture patterns no longer abort sibling hooks** —
  `get_CPU_specific_pattern()` returns `null` instead of throwing, and the
  pattern hookers skip cleanly on empty input rather than scanning with an
  empty pattern.
- **Parser and LLDB-backend stability** — hardened parsers against malformed
  input and reworked the LLDB return-site dispatch to mirror GDB's synchronous
  `finish`.
- **TapWriter persistence gap** — flows that completed via a Content-Length
  response (in `_attach_response` during `on_data`) previously emitted only an
  `UPDATED` event and were never written or analyzed. They now emit exactly one
  `COMPLETED` and are persisted to the `.tap`.

## [2.0.0] - 2026-05-09

### Breaking
- Adopted clean 3-segment SemVer (`MAJOR.MINOR.PATCH`); the 4-segment
  `MAJOR.MINOR.PATCH.MICRO` scheme is retired.
- Tightened pin to `frida>=17.0.0,<18.0.0` and
  `frida-tools>=12.0.0,<13.0.0`. `pip install fritap` will now refuse to
  install against frida 18 instead of crashing at runtime.
- Removed the unreachable legacy frida-16 agent (`fritap_agent_legacy.js`).
  Users on frida 16 should pin `fritap>=1.3.3.4,<=1.4.3.0`.
- Runtime warning when `frida.__version__` major doesn't match the supported
  value (set `FRITAP_STRICT_FRIDA=1` to make it fatal).

### Why this is 2.0.0
Past patch-level releases silently raised the required frida major (see the
"Frida compatibility" table in `README.md`). This release acknowledges the
boundary explicitly with one major bump and adds a CI version-guard
(`dev/check_compat.py`) so the next time frida bumps a major, friTap *must*
bump its major in the same PR. Closes [#63](https://github.com/fkie-cad/friTap/issues/63).

### Frida compatibility (historical)

| friTap range          | frida required | frida-tools required |
|-----------------------|----------------|----------------------|
| ≤ 1.3.3.3             | ≥ 15           | ≥ 10                 |
| 1.3.3.4 – 1.4.3.0     | ≥ 16           | ≥ 11                 |
| 1.4.3.1 – 1.6.3.2     | ≥ 17           | ≥ 12                 |
| **2.0.0+**            | 17.x           | 12.x                 |

### Added

#### Architecture
- **EventBus** (`friTap/events.py`): Publish-subscribe event system replacing monolithic message handler, with typed events (KeylogEvent, DatalogEvent, ConsoleEvent, ErrorEvent, SessionEvent, etc.)
- **Output Handlers** (`friTap/output/`): Modular output system with handlers for keylog, JSON, JSONL, PCAP, PCAPNG, console, and live Wireshark
- **Backend Abstraction** (`friTap/backends/`): Abstract backend interface decoupling core logic from Frida, with concrete FridaBackend implementation
- **Backend Exception Hierarchy**: 7 backend-agnostic exception types (BackendNotRunningError, BackendInvalidArgumentError, etc.) mapping to frida exception types
- **Config Dataclasses** (`friTap/config.py`): Typed configuration with FriTapConfig, DeviceConfig, OutputConfig, HookingConfig
- **Builder API** (`friTap/api.py`): Fluent builder pattern for programmatic friTap usage
- **Server Manager** (`friTap/server_manager/`): Cross-platform frida-server download, deployment, and lifecycle management
- **TUI** (`friTap/tui/`): Terminal user interface with device selection, process browser, and capture controls
- **Plugin System** (`friTap/plugins/`): Extensible plugin architecture for custom integrations

#### Agent (TypeScript)
- **HookingPipeline** (`agent/shared/hooking_pipeline.ts`): Accumulation model with SymbolStrategy, PatternStrategy, and MemoryScanStrategy
- **HookRegistry** (`agent/shared/registry.ts`): Centralized platform hook registration management
- **Pattern System**: Default patterns auto-loaded from `friTap/patterns/default_patterns.json` with user pattern deep-merge support

#### Security
- **Download Hash Verification**: SHA256 verification of frida-server downloads before decompression
- **Pattern Validation**: Hex pattern format and structure validation for user-provided pattern files

#### Error Handling
- **EventBus Failure Tracking**: Per-handler failure counting with auto-unsubscribe after 10 failures
- **ErrorEvent Emission**: Automatic ErrorEvent emission when handlers fail (with recursion guard)
- **Output Handler I/O Protection**: Try-except wrapping around file I/O in keylog, JSON, PCAPNG, and PCAP handlers

#### Testing
- Comprehensive test suite with 145 tests (104 unit, 20 integration, 21 agent compilation)
- Tests for EventBus, output handlers, backend exceptions, config, patterns, PCAP, and API
- CI pipeline with automated test execution

#### Documentation
- Getting started guide, API reference, development guides
- Pattern system documentation
- Contributing guidelines

### Changed
- Migrated all `import frida` usage from core modules (ssl_logger.py, friTap.py, android.py, fritap_utility.py, TUI) to backend abstraction layer
- Exception handling in ssl_logger.py and friTap.py now uses backend-agnostic exception types
- Legacy code preserved in `friTap/legacy/` behind `_handlers_active` guard

### Fixed
- Re-enabled `pytest tests/unit -q` in CI (was commented out). Unit suite is now green: 104 passed, 0 failed.
- Test suite cleanup (F1 follow-up to this release): removed `tests/unit/test_pcap.py` (26 tests probing a phantom packet-construction API that never existed on the current `PCAP` class) and pruned ~22 tests in `tests/unit/test_ssl_logger.py` that probed private methods (`_get_device`, `_attach_to_process`, `_setup_logging`, `_format_log_message`, ...) which were never part of `SSL_Logger`'s public surface. Replaced with shape and behavior tests against actual current methods. No coverage was lost.
- Re-exported `frida` and `logging` symbols in `friTap/ssl_logger.py` so tests can patch `friTap.ssl_logger.{frida,logging}` via the documented entry-point path.
- EventBus test logging propagation fixed for pytest caplog compatibility.

---

> **Historical releases (pre-2.0.0).** The summaries below are
> distilled from each tagged release's commit history into a narrative
> per version. They are not authoritative — for forensic detail, run
> `git log v<prev>..v<this>` against the corresponding tags. The
> 4-segment `MAJOR.MINOR.PATCH.MICRO` scheme used through this period
> silently absorbed several frida-major bumps (issue #63); cross-reference
> the [Frida compatibility table](https://github.com/fkie-cad/friTap#frida-compatibility)
> when reading.

## [1.5.x — 1.6.3.2] - dates unknown (untagged on git)

These minor versions were published to PyPI but never tagged in git;
the boundary between 1.5.x and 1.6.x is unrecoverable without PyPI
metadata. The headline content is the start of the architectural
migration to **CoreController + EventBus + Backend abstraction +
Output handlers/Sinks**, all kept backward-compatible behind the
`_handlers_active` guard. The TUI and the plugin system originated
here, as did support for the friTap `.tap` file format and its flow
view. Plus continued Cronet pattern improvements and stability fixes
for the new pcap writer.

## [1.4.1.9] - 2026-02-25

Windows OpenSSL key extraction (`SSL_write_ex` / `SSL_read_ex`); more
robust Conscrypt hooking on Android; experimental Wine support; goTLS
datalog message fixes (buffer as second argument); startup-handling
deadlock fix; spawn-gating and child-gating improvements.

## [1.4.1.1] - 2025-12-29

Android interface refactor; tcpdump invocation hardened (cached
`is_tcpdump_available`, escape-quoting fixes, multi-PID termination);
libsignal hooking fix on certain devices; assorted property/syntax
slips corrected.

## [1.4.0.3] - 2025-09-23

Pattern-based scanning improved for `onReturn` hooks; better TLS key
extraction for Signal on Android; Cronet/Conscrypt hook improvements;
logging refactor to reduce duplicate callback invocations.

## [1.3.8.9] - 2025-07-29

OpenSSL `ssl_log_secret()` improvements on Linux; pattern for OpenSSL
on x86-64; new `-t` / `--timeout` flag wired through to `SSL_Logger`.

## [1.3.8.0] - 2025-07-24

Cronet hook fix for newer libcronet versions on Android; documentation
fixes (jailbreaking guidance).

## [1.3.7.7] - 2025-07-21

YangSSL support (a metaRTC fork mixing mbedtls and OpenSSL); LSASS hook
moved to a background thread; `--no-lsass` flag fixed on Windows.

## [1.3.6.1] - 2025-07-09

**Experimental GoTLS support** on Android and Linux (pattern-based,
may crash); OpenSSL/BoringSSL key extraction improved on Android.

## [1.3.5.3] - 2025-07-07

**Python SSL library hooking** on Windows and Linux; per-session JSON
output (`-j` / `--json`); `ssl_library_infos` feature; first version of
the MkDocs documentation; MacOS/iOS detection fix.

## [1.3.4.1] - 2025-07-01

**Migration to frida 17.** This is the silent breaking change behind
issue #63 — users on frida 15/16 stopped receiving updates without
warning. Also: pattern-based hooking with secondary fallback patterns;
GitHub Actions PyPI publishing; Android package-name detection.

## [1.3.2.2] - 2025-04-16

BoringSSL identification by the `SSL_CTX_set_keylog_callback` export
(in addition to symbol matching); graceful handling when expected
symbols are missing in certain Android shared objects.

## [1.3.2.0] - 2025-04-13

**Rustls support on Linux**, both TLS 1.3 and 1.2 via pattern-based
hooking; custom Rustls patterns via JSON file; user-set keylog
callbacks preserved (not overwritten) for OpenSSL/BoringSSL/s2n.

## [1.3.1.0] - 2025-03-19

**Initial Rustls support** on Linux (rustls-ffi) and Android (TLS 1.3
only, ARM64); Quiche library support; respect target-set callbacks.

## [1.3.0.1] - 2025-02-16

**NSS** TLS keylog (CLIENT_RANDOM) and plaintext extraction working;
BoringSSL `ssl_log_secrets()` hook improvements; byte-pattern hooking
with symbol fallback as the primary discovery mechanism.

## [1.2.8.8] - 2025-02-07

Cronet patterns improved for x64 and ARM64; Conscrypt improvements on
Android; NSS TLS keylog hooks enabled.

## [1.2.8.5] - 2025-01-28

Cronet pattern fix; Unbound `SSL_Logger` fix; full-capture multi-USB-device fix.

## [1.2.8.0] - 2025-01-17

MacOS-vs-iOS detection fixes; BoringSSL hooking improvements on MacOS.

## [1.2.6.8] - 2025-01-13

Optional device-id with `-m`; tcpdump multi-PID termination handled;
`psutil` declared as a dependency.

## [1.2.6.4] - 2024-12-16

PCAP fixes for full packet capture.

## [1.2.6.0] - 2024-12-09

Argument-parsing bug fixes; full-capture fixes for Android.

## [1.2.4.3] - 2024-12-02

GitHub Pages documentation setup; module-mode now supports a
user-supplied custom message handler.

## [1.2.4.0] - 2024-11-20

Custom frida script injection (`--custom_script`).

## [1.2.3.6] - 2024-11-16

Cronet pattern updated for the latest version; friTap can now be run
as a package or as a job from AndroidFridaManager.

## [1.2.3.0] - 2024-10-30

**s2n-tls support** on Linux and Android (read/write hooks, key
callback installation, TLS session ID extraction); BoringSSL secret
logging in the Android Mono runtime; s2n PCAP source/destination fix.

## [1.2.2.8] - 2024-10-08

**First Flutter support** on Android and older iOS; pattern-based
hooking error handling improved.

## [1.2.2.0] - 2024-10-02

**Pattern-based hooking via byte patterns** (foundation for many later
releases); first **Cronet** support; QUIC traffic tracking with
BoringSSL on Android; iOS 15 BoringSSL update; module-mode (use friTap
from other Python projects); offset-feature fixes; new build system.

## [1.1.0.6] - 2024-03-06

Re-tag of 1.1.0.5 (no code changes between v1.1.0.5 and v1.1.0.6 — same
"add feature for default socket informations" tag message; effectively a
packaging hotfix). Listed for completeness; the substantive change is
1.1.0.5 below.

## [1.1.0.5] - 2024-03-06

Default socket-info feature; iOS 16/17 BoringSSL update; full-capture
spawn-mode bug fix.

## [1.1.0] - 2023-06-28

OpenSSL **payload modification** hook; matrixSSL ground truth
executables; Conscrypt fixes for Android 13+; basic anti-root hooks.

## [1.0.9] - 2022-12-15

SSPI improvements for Windows; `--version` flag; legacy-support fixes.

## [1.0.8] - 2022-11-21

Custom offsets for SSPI; experimental Ncrypt key extraction;
BoringSSL fix for older Android versions.

## [1.0.7.1] - 2022-10-21

Detaching bug fix.

## [1.0.7] - 2022-10-21

Compatibility with frida < 16 via a legacy script (this is the
mechanism the v2.0.0 cleanup retired); iOS/macOS hooking fixes;
library-load wait so hooks register on dynamically-loaded SSL modules.

## [1.0.6] - 2022-10-10

**Modular architecture refactor**; pip support; debug mode; updated to
frida 16.0.1; Windows function-detection regex updates; first
isolated/independent agent compilation.

## [1.0.3] - 2022-03-08

Remote-frida-device connections; **first version of full packet
capture** (scapy-based; Linux/Windows/MacOS).

## [1.0.1] - 2022-02-23

Alternatives for `SSL_set_keylog_callback`; **WolfSSL master-key
extraction**; new logo; Visual Studio version fix.

## [1.0.0] - 2022-02-11

**Initial public release.** SSL/TLS interception and key extraction
supporting OpenSSL, BoringSSL, NSS, GnuTLS, WolfSSL, MatrixSSL,
BouncyCastle/SpongyCastle, and Conscrypt across Linux, Windows,
Android, iOS, and macOS. PCAP output, payload-manipulation hooks,
child-process tracing, spawn gating, IPv6 support, custom socket
factory, and named-pipe live view via Wireshark.
