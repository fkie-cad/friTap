# Changelog

All notable changes to friTap will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
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

### Changed
- Plaintext-only pcaps (`-p` without `-k`) no longer embed Decryption Secrets
  Blocks (DSBs) in the resulting pcap-ng, because key extraction now runs only
  when explicitly requested. Pass `-k <keylog>` to restore the prior behaviour
  of self-decrypting pcaps.
- Full-capture mode (`-f`) now sets `pcap_enabled=False`, so only key-extraction
  hooks are installed in-agent — the raw packets come from the external
  tcpdump/scapy capture, and the previously-installed in-agent plaintext hooks
  (whose output was discarded anyway) no longer run.

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
