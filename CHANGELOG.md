# Changelog

All notable changes to friTap will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [2.6.7] - 2026-11-13

### Security
  - `-j file.json` / `-j file.jsonl` no longer write raw TLS key material by default.
  - Keylog records in JSON are redacted to their label and public client_random unless `-k` or `--json-keys` is given.
  - `-j -` and the file outputs now share one key-redaction policy.

### Added
  - P3: the `chromium-internal` attribution bucket is now filled from a new `chromium_internal_hosts` signature list (exact or `*.suffix` hosts, unioned with `FRITAP_SDK_SIGNATURES` overlays, kept by `dev/update_sdk_signatures.py`); it applies only to unattributed flows on Chromium-family transports and is dropped when an originator claim arrives.
  - `.tap` record type `REC_REQUEST_CONTEXT` (`0x05`, additive): per-request Java contexts (URL, method, frames, timing, status, originator claim, matched flow ids), stored even when they match no flow, bounded on write and read, capped at 20 000 per file; `TapWriter.write_request_context()`, `TapReader.iter_request_contexts()`, header flag `FLAG_HAS_REQUEST_CONTEXTS` (`0x0004`). Older readers skip the record.
  - Host support for a new opt-in `request_context` agent message (Java request context: Cronet / GMS Cronet / HttpEngine / WebView URL, method, status and Java frames per request lifecycle point), emitted only with `--attribute-sdk`: schema + generated TS type, router (escaped; URL capped at 2048 chars, at most 32 frames), `RequestContextEvent`, and a buffered `FlowCollector.on_request_context`. The agent hooks and the flow join are the two entries below.
  - Java request-context host join (`--attribute-sdk`, P3): new `friTap/flow/request_context_join.py` folds `request_context` events per `req_id` (redirect chain, WebView owner map; bounded to 4096 live contexts, TTL 120 s after `end` / 300 s idle) and matches a flow by a GURL-like normalized request key (method + canonical URL) and HOST receive time (context start <= flow first request + 2 s, within 60 s): exact single candidate (or same-SDK duplicates) -> `java-request`/high, different SDKs picked by ordinal -> `java-request`/medium, a WebView `loadUrl`/`postUrl` navigation (the `webview_load`) -> `java-request`/high, any other WebView request (subresource or in-page main-frame navigation) via its owning load -> `context`/medium (no owner -> no claim), request keys compare the first 1024 canonical URL characters, host+time only -> no claim. `request_attribution()` in `friTap/flow/attribution.py` builds the claim (`context` capped at `medium`); precedence is under Changed. Per-request originators mark a connection `mixed`; finished contexts are written as `REC_REQUEST_CONTEXT` records (with `matched_flow_ids`, the claim, `bucket:"cache"` for cached unmatched requests) by `--tap` and the TUI live save.
  - Java request context hooks (Android, `--attribute-sdk` with plaintext `-p`, not with `-f`, `--pairip-safe` or `--quic-only`; new `agent/shared/java_request_context.ts`): the agent records the Java stack where a request is built and emits `request_context` events for its lifecycle (`start`, `redirect`, `response`, `end`, `webview_load`, `webview_request`). Hooked: `org.chromium.net.impl.CronetUrlRequest` in app-embedded Cronet, in the GMS Cronet Dynamite loader (found from the delegate passed to `CronetEngine.Builder`'s constructor) and in the platform HttpEngine copy (boot loader); `WebView.loadUrl`/`postUrl`/`loadDataWithBaseURL`; `WebViewClient.shouldInterceptRequest` (the base class, plus app overrides of clients set through `setWebViewClient` after the hooks are in). The full URL, including the query string, is sent (capped at 2048 characters and escaped on the host). Every Java hook is reverted by the detach teardown before `Interceptor.detachAll`. Docs: `docs/platforms/android.md#per-request-sdk-attribution-java-request-context`.
  - Android arm64: TCP TLS plaintext (`-p`) from the stripped BoringSSL in app-embedded Cronet (`libcronet.<ver>.so`) and GMS Dynamite Cronet, through a new supplementary row "BoringSSL plaintext (Cronet)". Builds that export `SSL_read`/`SSL_write` stay with the export-based hooks (`exportsSslRecordApi`), so records are not emitted twice. The `ssl_lib.cc` anchor locator (`boringssl_plaintext_locator.ts`) and the QUICHE frame locator (`quiche_frame_locator.ts`) now fall back to landing-pad function bounds (the nearest `PACIASP` / `bti c`, `withLandingPadFallback` in `agent/shared/eh_frame.ts`) where `.eh_frame_hdr` has no FDE for the address. A new supplementary row "Google QUICHE (HttpEngine)" covers `libhttpengine.so`. Device verification of the Cronet/HttpEngine plaintext is still pending.
  - Agent Skills (`friTap/skills/`): ready-to-use `SKILL.md` workflows for AI agents — `fritap-capture`, `fritap-leak-proof`, `fritap-privacy-audit`, `fritap-security-audit`, `fritap-android`, `fritap-decrypt`, `fritap-memory-scan`, `fritap-telegram`, `fritap-wine-schannel`, `fritap-custom-hooks` — each with `references/` pages, packaged with friTap. A unit-test lint (`tests/unit/skills/`) checks their CLI flags and agent tool names against the real parsers and tool registry. Docs: `docs/agents/skills.md`.
  - `fritap skills list|show <name>|install [names] [--target DIR] [--force]` lists, prints and installs the skills (default target `./.claude/skills`; `--target` for any agent that reads `SKILL.md`).
  - `fritap mcp` exposes one MCP prompt per skill, with optional `target` and `device` arguments.
  - Claude Code plugin and marketplace (`.claude-plugin/plugin.json`, `marketplace.json`): `/plugin marketplace add fkie-cad/friTap`, then `/plugin install fritap@fritap` installs the skills and an MCP server running `fritap mcp --root ${CLAUDE_PROJECT_DIR}` (live capture off by default).
  - IPsec/strongSwan IKEv2 + ESP key extraction now works on stock, stripped `charon` (Debian/Ubuntu): friTap locates the non-exported `derive_ike_keys` and the kernel-netlink `add_sa` by their DBG format-string anchors (no symbols, no per-version byte patterns) and extracts IKE SA keys (SPIi/SPIr, SK_ei/er/ai/ar) and ESP CHILD_SA keys (SPI, enc/auth keys) with a register-/ABI-correct layout. `--protocol ipsec` is now accepted.
  - `-k <path>` with IPsec writes Wireshark decryption tables next to the keylog: `ikev2_decryption_table` (IKEv2) and `esp_sa` (ESP), matching strongSwan's own `save-keys` plugin format, so a captured IKE_SA + CHILD_SA exchange decrypts in Wireshark/tshark (verified end-to-end for AES-CBC-256/HMAC-SHA2-256-128 and AES-GCM-128). For AEAD (GCM/CCM) ESP the `esp_sa` integrity column is `NULL`, which current Wireshark requires to decrypt.
  - The two IPsec agent messages gained structured fields (additive, `fritap.*` schema versions unchanged): `ipsec_ike_keys` now carries `ike_version`, `spi_i`, `spi_r`, `enc_alg`, `enc_key_len_bits`, `int_alg`; the new `ipsec_esp_keys` carries `spi`, `src`, `dst`, `family`, `enc_alg`, `int_alg`, `enc_key`, `int_key`.
  - `--json-keys` (Python API: `.json_keys()`) writes raw key material into the JSON output without `-k`.
  - `--json-keys` turns on agent key extraction like `-k`, without writing a keylog file.
  - `--no-follow-exec` (Python API: `.follow_exec(False)`) stops friTap from following instrumented processes across `exec()` and skips the child gating that needs (~40-50 ms per fork).
  - `--enable_child_gating` follows every instrumented child across `exec()` and instruments its children in turn, so `git clone https://...` (`git-remote-https`) and `subprocess` -> `curl` chains are captured; an exec'd image Frida holds without reporting it (macOS, Python `subprocess` with `close_fds=True`, ~25 s late) is detected and taken over.
  - Agent API (`friTap.agent_api`): one registry of 16 tools (discover, capture, read, export) with JSON-Schema parameters, a shared error document and token-budgeted, size-capped results.
  - `find_values` agent tool: offline canary known-value search — trace operator-supplied values (email, advertising id, Android id, IMEI, GPS fix, IP, free string) through decoded traffic, expanding each into its obvious obfuscations (URL/base64/hex encodings, md5/sha1/sha256) and reporting each hit's `transform`, `confidence`, `direction` and `where`. The matched span is withheld unless `show_values` (gated by `--allow-values`); short/low-entropy canaries are flagged under `warnings`. The `kind` parameter now also accepts the PII-detector aliases `advertising_id`/`idfa`/`gaid`/`adid`/`idfv` (normalized to `aaid`) and `geo`/`geolocation`/`location` (normalized to `gps`).
  - `diff` agent tool: semantic capture/phase diff — the HTTP endpoints that appeared, disappeared or changed (status codes, content types, request volume) between two captures, or between two phase windows of one capture (`phases.jsonl` sidecar), as budget-aware JSON or Markdown. Host groups carry offline destination attribution.
  - Offline destination attribution (`friTap.analysis.attribution`): maps a captured host to its owning entity, tracker category and first-/third-party verdict using a bundled friTap-curated tracker seed (`trackers.json`), optionally superseded by a local full Tracker Radar map (`trackers_full.json`, CC BY-NC-SA 4.0, never shipped), and a bundled Public Suffix List snapshot (no network, no I/O at import time). `get_digest` gains opt-in `attribute` / `first_party` params that annotate each host row with trusted `owner`/`category`/`party`; omitted, the digest is byte-identical to before.
  - `dev/update_tracker_radar.py` writes the local-only full attribution map `trackers_full.json` (gitignored, never published or packaged) from an upstream Tracker Radar checkout; the resolver prefers it over the shipped seed when present.
  - SDK/caller attribution (opt-in `--attribute-sdk`): the agent captures a per-connection `caller_stack` backtrace (Java + native frames) at the first TLS plaintext read/write, resolved on the host to the owning SDK (bundled signature table, `friTap.analysis.attribution.sdk`) and joined to the flow on the connection 5-tuple (stable before the TLS session id exists). Wired into both the legacy and `--modern` agent trees. Resolves fd-less BIO stacks (Android Conscrypt `SSLEngine`, curl connection filters, `SSL_get_fd` == -1) by reusing friTap's socket-fd recovery. Persisted into the `.tap` as an additive per-flow `sdk` dict; `get_digest` lifts it onto the host and endpoint rows, and `diff` onto the endpoint rows, as a trusted top-level `sdks` list of `{sdk, vendor, category}` (never under `untrusted`). Off by default; without it flows carry no `sdk`, `caller_stack` or originator (TLS/QUIC flows still get the `attribution.transport` described below).
  - Transport-security checks: a `tls_hygiene` analyzer flags deprecated TLS/SSL versions, weak cipher suites and cleartext transport (problems only, so a well-configured flow stays silent), feeding the digest's existing `focus=security`. The version/cipher checks read handshake metadata, which friTap records for offline `--from-pcap` captures.
  - OWASP MASVS mapping (`friTap.analysis.masvs`): `get_digest` and `list_findings` gain an opt-in `masvs` flag that tags each finding with the MASVS v2.1 controls it maps to (e.g. `MASVS-NETWORK-1`, `MASVS-CRYPTO-1`, `MASVS-AUTH-1`, `MASVS-PRIVACY-1/2`); omitted, the output is byte-identical to before. The same `--masvs` flag is on the human commands `fritap report` (digest) and `fritap analyze` (adds a MASVS column/field to the table, CSV, Markdown and JSON reporters). The TUI exposes it too: the finding-detail panel shows a finding's MASVS controls, and `R` opens a scrollable Report view (the digest with MASVS and a cyclable all/security/privacy focus) for the current capture or replay — a live capture is digested from its in-memory flows (no save needed) via the new `scan_flows` seam. Docs: a security audit playbook (`docs/agents/security-audit.md`).
  - `first_party` (on `get_digest` and `diff`) now accepts the string `"auto"` to infer the app's own first-party set instead of supplying one: the most-contacted non-tracker registrable domain (eTLD+1) plus any other non-tracker domain seen at least half as often. `get_digest` infers from the digested hosts; `diff` infers from the union of both sides' hosts so party labels stay comparable across A/B (`friTap.analysis.attribution.infer_first_party`). An explicit list and the absent/empty case are unchanged.
  - `fritap q <tool>` runs any agent tool from the shell and prints JSON (`--list`, `--help-json`).
  - `fritap mcp` serves the tools over MCP (stdio, or streamable HTTP with `--http`); install with `pip install 'fritap[mcp]'`.
  - `fritap serve` serves the tools as a local REST API with `/openapi.json` (no extra dependencies); `GET /healthz` is an unauthenticated liveness probe returning only `{"status": "ok"}`.
  - Server options `--root`, `--allow-capture`, `--allow-target`, `--allow-secrets`, `--max-response-bytes`, `--host`, `--port`, `--token` (`FRITAP_API_TOKEN`); live capture is off unless `--allow-capture`, and a non-loopback bind requires a token.
  - Live capture sessions for agents: `start_capture`, `capture_status`, `mark_phase`, `stop_capture`, `list_sessions`.
  - Committed OpenAPI 3.1 document and per-tool JSON Schemas in `docs/api/schemas/`, plus JSON Schemas for `fritap.events/1` and `fritap.digest/2`; a unit test fails when they drift from the code.
  - Docs: "Using friTap from AI agents" (`docs/api/agent.md`), a privacy audit playbook, `AGENTS.md` and `llms.txt`.
  - `capture_status` reports `ended_by` (`target_exited`, `duration`, `stopped`, `error`) so a normal target exit (exit code 3) is not mistaken for a failure; `mark_phase` adds `t_rel` (seconds since capture start) next to the epoch `t`.
  - `fritap q` accepts its q-level options (`--root`, `--allow-secrets`, `--compact`, `--max-response-bytes`) before the tool name, and a mistyped tool name (`get_digets`, `list_flows`) now gets an `unknown_tool` JSON error with a did-you-mean hint instead of falling through to capture mode.
  - Display-filter errors suggest the operator for typos (`contians` -> `contains`, `=` -> `==`); surfaced as the `bad_filter` hint of the agent API.
  - Server option `--allow-values` (`fritap mcp` / `fritap serve`): `show_values: true` is refused with `forbidden` unless the server was started with it; `fritap q` and the Python API keep allowing it (`ToolContext.allow_values`).
  - `--pcap-format {auto,pcap,pcapng}` sets the `-p` container for plaintext and `-f` captures; `auto` (default) keeps choosing by extension (`.pcapng` -> pcapng, else pcap).
  - `capture_status` reports `protocols_in_use`, `idle_hooks` and a per-protocol `status` (`active`, `idle`, `no_library_seen`, `failed`), plus an `other_events` counter.
  - macOS: GnuTLS (Homebrew `libgnutls.30.dylib`) is now hooked for keys and plaintext, in legacy and `--modern` mode.
  - Chrome/Chromium/Cronet HTTP/3 (Google QUICHE): request line, status and all header fields are captured from the raw STREAM frames (QPACK incl. dynamic table) for connections seen from their start; late-joined connections fall back to bodies only.
  - QUIC data records carry their real connection 4-tuple and stream id (Google QUICHE, when its layout is learned), an explicit `direction`, the producing `library` and a `quic_payload` kind (`stream` raw HTTP/3 bytes | `body` de-framed DATA).
  - Android Chromium monoliths (Monochrome, Chrome, WebView): TCP TLS plaintext from the statically linked, stripped BoringSSL `SSL_read`/`SSL_write` (located via `ssl_lib.cc` anchors); keys still come from the Cronet hooks.
  - Go TLS on macOS and Windows (legacy and `--modern`): keys from `writeKeyLog` (symbols, or the byte patterns for `-ldflags="-s -w"` builds) and, with `-p -ed`, plaintext; Go images are found by their build-info blob, so any executable name and c-shared libraries work.
  - Linux: Go binaries under any name (and c-shared `.so`) are detected by content too; the `*.go1.x` / `*.go.so` name rows stay.
  - Linux: programs that statically link rustls are detected by content (the `rustls-0.2x` crate-path string panic metadata keeps in `.rodata`, surviving `strip`), so a plain Rust binary under any name (e.g. `myapp`) is hooked for keys — not just modules named `*rustls*`. The name row stays; verified on rustls 0.22.4 and 0.23.x, TLS 1.2 + 1.3, legacy and `--modern`.
  - Android: stripped rustls `.so`s are hooked with the shared static-rustls byte-pattern table (arm64 + x64 — the same patterns Linux uses) in both the legacy and `--modern` paths, falling back to the built-in Android patterns for the other versions/architectures.
  - Legacy (default) Go TLS plaintext on every platform: `-p` with `-ed` now captures Go records without `--modern` (same `writeRecordLocked` / `(*Conn).Read` probes).
  - SSH (OpenSSH): the stripped `ssh` that Debian (12, 13) and Ubuntu (22.04, 24.04) ship is hooked, arm64 and x86-64, in legacy and `--modern` mode. The locator also resolves their `sshd`/`sshd-session`, but that path has not been run-tested. friTap finds the functions it does not export by the log strings they use (their own name and messages). The shared locator, `agent/shared/string_anchor_functions.ts`, works for any stripped ELF.
  - Agent API `start_capture`: boolean `anti_root` (Android only) passes `--anti_root` (`-ar`) to the capture.
  - Agent API `diff`: phase mode accepts `session_id` instead of `tap`, and tap mode accepts `session_a`/`session_b` instead of `tap_a`/`tap_b` (any mix); a side taken from a session is labelled with its session id.
  - Agent API phases: every phase entry (`mark_phase`, `capture_status`, `stop_capture`, `phases.jsonl`) carries an ISO-8601 `at` next to the epoch `t`, and `get_flow` adds the flow's `phase` when a `phases.jsonl` sidecar sits next to the tap (omitted otherwise, so output without phases is byte-identical).
  - Wine GDB route: `--patterns` now reaches the GDB key extractor. A flat GDB-format file is passed through; a friTap v2 file is translated (x64 GnuTLS/OpenSSL/LibreSSL entries; `??` wildcards and unknown ids are skipped with a warning) into a temporary flat file removed when the session ends (`agent_gdb/wine/pattern_translate.py`).
  - Live TLS flows carry the connection's ClientHello random as `tls.client_random` when the agent reports it (empty otherwise; flows of the connection seen before the agent knew it are backfilled). It is persisted in the `.tap` layer stack only when set, so flows without it are byte-identical to before. Records of one connection that first lack the client_random and later carry it now stay one flow stack with one HTTP/2 parser, instead of splitting into a `net:` and a `cr:` connection. A different client_random on the same 4-tuple still starts a new connection (port reuse). The additive `caller_stack` message (`--attribute-sdk`) and `CallerStackEvent` gain optional `client_random`, `tid`, `thread_name`, `pid` and `transport_module` fields.
  - Socket-less TLS connections (Chromium/Cronet memory BIOs and similar) whose records carry a TLS client_random now get their own stable synthetic TCP tuple derived from `blake2s(client_random)` (client `198.18.x.y:49152-65535`, server `198.19.x.y:443`, RFC 2544 range) instead of being dropped or merged onto the shared `-ed` tuple `127.0.0.1:1234<->127.0.0.1:2345`. The tuple is pinned per connection, so one TLS connection is one TCP stream in the `-p` pcap and the live sinks. At stop the `-p` pcap (classic or pcapng) is rewritten atomically to a connection's real tuple when one was learned and does not collide with another stream; the outcome is recorded under the additive `synthetic_endpoints` key of `<pcap>.fritap.json`. JSON/JSONL data records and `.tap` flows carry an additive `endpoints_synthetic` flag (`.tap` flows are upgraded to real endpoints live); digests, HAR and IOC output skip synthetic addresses. Records without a client_random (Go TLS, Windows SSPI/Schannel) keep the old behavior. Docs: `docs/api/cli.md`.
  - SDK/caller attribution (`--attribute-sdk`): every caller stack now reaches the host, not only those matching a known SDK. The `CallerStackEvent` gains an `untrusted` dict (up to 16 native `{module, symbol}` and 16 Java frames, `thread_name`, `transport_module`; escaped, 120 characters each) and its `sdk` is `null` when nothing matched. Flows store a compact per-connection `caller_stack` (8 frames per kind, 80 characters per string), written to the `.tap` meta only when set; `sdk` stays reserved for signature matches. The collector joins a stack by the TLS client_random first, then the 4-tuple, then a real session id; a stack that arrives before its flow waits up to 120 s (at most 1024 waiting stacks). Docs: `docs/api/agent.md`.
  - Transport vs originator attribution: flows gain an additive `attribution` block in the `.tap` meta. `transport {module, kind}` is set on every TLS/QUIC flow (kinds `chrome`, `webview`, `cronet`, `gms-cronet`, `httpengine`, `flutter`, `libsignal`, `electron`, `cef`, `other`; `libmonochrome`/`libchrome` are `chrome` when the target package or process is Chrome, else `webview`; `libcronet` loaded from a GMS path is `gms-cronet`). With `--attribute-sdk` it also carries `originator {sdk, vendor, category}`, `confidence` (`high`/`medium`/`low`) and `source`: a directly joined stack is `native-stack` (`high` only on transports whose stacks are captured on the caller's own thread, currently `libsignal`; `medium` otherwise, including Chromium-family transports whose stacks come from the shared network thread, `other`, and overlay kinds); flows that inherit the connection's originator (later HTTP/2 and HTTP/3 streams, siblings) are `connection-fallback`, always `low`, never `high`. `mixed: true` marks a connection with more than one originator. The Java request context (above) adds the sources `java-request` and `context`; `bucket` is `cache` on cached request-context records and `chromium-internal` for Chromium's own background traffic. The digest's host rows gain `transports` (sorted kinds). Docs: `docs/api/agent.md#transport-vs-originator`.
  - `sdk_signatures.json` gains `category: "transport"` entries and an optional `transport_kind` key (schema still `fritap.sdk_signatures/1`; `entry_count` 33 -> 45); `dev/update_sdk_signatures.py` keeps `transport_kind`. `FRITAP_SDK_SIGNATURES=path[:path]` (`os.pathsep`-separated) layers overlay signature files over the shipped table; a bad file is warned about and skipped (the attribution fixture uses `FRITAP_SDK_SIGNATURES=dev/fixtures/attribution_app/sdk_signatures_fixture.json`).
  - `dev/attribution_metrics.py`: new `tk%` (transport kind correct) and `cs%` (has caller stack) columns, `by_source`/`by_transport_kind`/`buckets` counts, and `fallback_high`; a `fallback_high` above 0 makes the exit code 1. With request-context records in the `.tap` it also reports `%hi_ok` / `%hi_wr` (high-confidence right / wrong SDK), `ctx%` (ground-truth requests with a context record) and `ctx_ok%` (record names the right SDK); a `wrong_high` above 0 also makes the exit code 1.

### Changed
  - Behaviour change: `libmonochrome`/`libchrome` transports in Chromium-based browsers (Brave, Edge, Samsung Internet, Vivaldi, Opera, Kiwi, Yandex) now resolve to kind `chrome` instead of `webview`; the browser list is data-driven (`chromium_browser_packages` in `sdk_signatures.json`, extendable via `FRITAP_SDK_SIGNATURES` overlays).
  - Behaviour change (`--attribute-sdk`): transport modules (`libcronet`, `libflutter.so`, `libmonochrome`, `libwebviewchromium`, ...) are deny-listed from originator classification, so a native stack showing only `libcronet` or `libflutter.so` no longer reports "Cronet" or "Flutter" as the SDK. `classify_package` (Java/ObjC prefixes) is unchanged.
  - Behaviour change (`--attribute-sdk`): a strictly stronger originator claim now replaces a weaker one on a flow (`claim_rank()` in `friTap/flow/attribution.py`): confidence first (`high` > `medium` > `low`), then the source (`java-request` > `context` > `native-stack` > `connection-fallback`). An equal or weaker claim never replaces the current one.
  - Digest `sdks` now come from `attribution.originator`, falling back to the flow's `sdk`.
  - Behaviour change: attach mode follows the target across `exec()` too (child gating on the attached process; its fork children are resumed at once); `--no-follow-exec` turns it off.
  - Behaviour change: add `--json-keys` (or `-k`) to get the old JSON output with `key_data`.
  - `-j file.json` / `-j file.jsonl` on their own now capture plaintext `data` events (previously only `-j -`, `-p` or `--tap` turned the plaintext hooks on).
  - Agent API: `list_endpoints` and `list_findings` return 20 rows by default (was 50); pass `limit` for more.
  - Agent API: the per-call keylog confirmation of `export` is `confirm_secrets` (renamed from `allow_secrets`, the server-policy name); a keylog export needs both keys, e.g. `fritap q export --format keylog --out k.log --allow-secrets --confirm-secrets`.
  - Agent API: the `patterns` capture option is a file path only (inside `--root`); inline JSON is rejected like `--patterns` itself does. `offsets` still accepts a path or inline JSON.
  - Agent ABI 3 (`AGENT_ABI_VERSION`): every agent message carries a concrete record `protocol` and a hook executor may report that it installed nothing; rebuild custom bundles (`python dev/generate_agent_types.py`, `./dev/compile_agent.sh`).
  - `dev/compile_agent.sh` builds the slim Wine bundle in a private staging directory instead of temporarily swapping the tracked `tsconfig.json`.
  - Internal: the flow collector keeps a connection's SDK, caller stack and mixed flag in one per-connection attribution record instead of three parallel maps (no behaviour change).
  - Behaviour change: an explicit pcap format now wins over the `-p` extension; `FriTap.pcapng("a.pcap")` writes pcapng (with a warning) instead of classic pcap.
  - Behaviour change: `-f --tap X.tap` no longer leaves `X.tap` empty. At the end of the capture friTap builds it from the finished full-capture pcap, keylog and manifest with the offline `--from-pcap` pipeline, writing atomically; on failure it logs the reason and the manual `fritap --from-pcap ... --tap ...` command. The live `.tap` writer is no longer created (or the file truncated) at start under `-f`.

### Fixed
  - Process-wide libc listeners (socket fd tracker, unwanted-fd eviction, Google QUICHE UDP peer observer) now share one CModule observer (`agent/shared/native_socket_observer.ts`) whose callbacks never enter JS, so Frida-internal I/O on app threads can no longer deadlock against the JS lock. If CModule is unavailable, friTap warns and falls back to the JS listeners. The QUICHE observer now records a UDP peer only after a successful `connect()`.
  - `libhttpengine.so` (Android 14+ mainline HttpEngine) no longer falls back to key-only mode with "Error: missing argument ... Only key extraction will be available for libhttpengine.so". The module has no `SSL_get_fd` / `SSL_SESSION_get_id`; both are now optional (`agent/shared/optional_ssl_fd_session.ts`). Without `SSL_get_fd` records take the deferred, SSL-scoped fd recovery, and without `SSL_SESSION_get_id` the session id is empty. Legacy and `--modern`.
  - `--attribute-sdk`: a late caller stack joining an already-finalized connection no longer leaks per-connection state in the flow collector.
  - `--attribute-sdk`: when a connection id is reused (idle reset or session end then reuse), a caller stack joined by tuple, session id or client_random now only attributes flows of the lifetime it joined; flows of an earlier lifetime no longer pick up the newer SDK or the `mixed` flag (and vice versa).
  - Attaching by numeric PID now resolves the process's package/name once after attach (frida `enumerate_processes(pids=[pid], scope="metadata")`), so the transport classifier can tell Chrome from WebView for `libmonochrome`; flows captured earlier are re-classified. Overlay `transport_kind` values that are not slugs are warned about and ignored.
  - Agent `devlog_info`/`devlog_warn`/`devlog_error` messages (`console_info`/`console_warn`/`console_error`) were silently dropped; they now reach `--debug-log` and `-d`/`-do` as debug-level lines prefixed `[agent <level> <file>:<line> <func>]`. Agent developer logs (these, `console_debug` and `console_dev`) no longer leak into `-j -` / `-j file.jsonl` without `-d`/`-do`, nor into the TUI activity log; `ConsoleEvent` gains an additive `origin` field (`"agent_dev"`).
  - `docs/api/schemas/fritap.digest-2.schema.json` rejected valid digests built with `masvs: true` (finding rows' `masvs` list, `params.masvs`) or with attribution (`params.attribute`/`first_party`, host rows' `owner`/`category`/`party`), and any digest with an SDK (`--attribute-sdk`) failed strict validation. The schema now declares these optional fields, including `sdks` and `transports` on host and endpoint rows; the `fritap.digest/2` version is unchanged.
  - Grouped finding rows (`list_findings` rows, digest `findings.top`) no longer hide which flows they cover: each row gains an additive `refs` list (distinct flow refs, first-seen order, capped at 10, plus `refs_more` when cut). `ref` still names the first flow; `fritap.findings/1` and `fritap.digest/2` are unchanged. The Markdown digest lists all refs of a row.
  - `fritap mcp`: Claude clients (Claude Code, the friTap plugin, Claude Desktop) silently dropped the seven tools that take `tap` *or* `session_id` (`get_digest`, `list_protocols`, `list_endpoints`, `list_findings`, `get_flow`, `find_values`, `export`), because the Anthropic API rejects a top-level `oneOf` in a tool's input schema. The MCP tool definitions now omit top-level `oneOf`/`anyOf`/`allOf` and state the group in the description ("Give exactly one of: tap, session_id."); the registry still enforces it on every call. `docs/api/schemas/` and the REST/OpenAPI surface are unchanged.
  - Agent API `first_party` (`get_digest`, `diff`): a string other than `"auto"` (`fritap q get_digest --first-party myapp.com`, or an MCP/REST client sending `"myapp.com"`) was split into single characters. It is now a comma-separated domain list (`--first-party a.com,b.com`), normalized in `friTap.analysis.attribution.normalize_first_party`; the schema documents the string form and the validator now enforces property-level `anyOf`, so non-string/non-list values are `bad_param`.
  - `fritap q find_values --values` always failed with `bad_param` (the flag produced strings, the schema wanted objects). `values` items now also accept the `KIND=VALUE` / bare `VALUE` shorthand (kind `free`, labelled `<kind>-<n>`), and arrays of objects on the `fritap q` CLI take one item per repeated flag (no comma splitting; a `{...}` argument is one JSON object). `--json` / `--params-file` are unchanged.
  - Agent API `diff`: a `phase_a`/`phase_b` label missing from the phases file silently produced an empty window (every endpoint reported as added/removed); it is now `bad_param` listing the known labels with a did-you-mean hint. A phases file without valid markers is `not_found`.
  - Agent API `mark_phase`: whitespace-only labels and marking a session that already ended are `bad_param`; the `label` parameter documents the lower-case, hyphenated convention that `diff` matches exactly.
  - `fritap analyze --help` and `fritap report --help` printed the capture help; they now print their own.
  - `--patterns`: invalid hex in a legacy-format pattern file was only debug-logged and still sent to the agent, replacing the library's built-in pattern; it is now dropped with a warning. The bundled `pattern.json` example (placeholder hex) is now a valid modern-format example, and the `--patterns` help no longer claims inline JSON is accepted.
  - `offsets_example.json` was not valid JSON, so the agent silently ignored it; it is now a valid example of the shape the agent reads, and an `--offsets` file that is not valid JSON logs a warning.
  - Help and docs: the `-ms` help said the memory scanner shares the `-k` keylog (it writes `<stem>.memscan<ext>` beside it); the `-l` help and docs named `/tmp/sharkfin` (the pipe is `<tempdir>/fritap_sharkfin.pcapng`, not supported on Windows); `docs/api/cli.md` listed a stale `--protocol` set and claimed `ipsec` is rejected; `--repair-keylog` was documented as writing `.repaired.keylog` (it writes `.relabeled.keylog`); the Telegram docs presented live MTProto plaintext as working (only key extraction is implemented); Windows docs listed Edge/Firefox as Schannel; several Android/USAGE/patterns examples used invalid flags (`-f` without `-p`, `-spawn`, `--force-scan` without a module, `-p <package>`); Wine docs contradicted themselves on `ptrace_scope`.
  - Runtime package data hidden by broad `.gitignore` rules (the attribution datasets, `friTap/plugins/shared_utility/*.js` and the TL schema `SOURCE.txt`) was missing from fresh checkouts, the public mirror and wheels; it is now tracked and listed in `package_data` / `MANIFEST.in`.
  - Agent debug messages (`devlog_debug`, e.g. `[ssl-identity]` lines) now reach `--debug-log`; they were dropped by the host before.
  - Plaintext-only captures (`-p` without `-k`) of stripped BoringSSL (WebView, Chrome, `libhttpengine` with `--modern`) now carry `client_random` on their flows: the ssl_st layout decoded from the target's own code is used at once (per-read plausibility checks still apply), and modules outside the Chromium plaintext path get a one-time layout lookup on arm64. That lookup now starts when the plaintext hooks are installed rather than on the first record, so early flows are covered too, and it no longer fails on `libhttpengine`, where a SIMD instruction (`movi v0.2d, #0`) was mistaken for a write to the `ssl` register. With `--attribute-sdk`, a held `caller_stack` now falls back to its 5-tuple join instead of being held forever.
  - CI `agent-build-check` now uses Node 22. Node 20 does not expand the `agent/**/*.test.ts` glob passed to `node --test`, so `npm run test:agent` failed with "Could not find". `package.json` now declares `engines.node >=22`.
  - SSH (OpenSSH): `ssh` no longer dies right after start under friTap; offset probes called the target's `sshbuf_len()` on non-buffers, which OpenSSH answers with `raise(SIGSEGV)`. Buffers are now read by struct with guarded reads.
  - SSH (OpenSSH): keys and packets from a spawned `ssh` are no longer lost; its `closefrom(3)` closed the agent's channel, so friTap now keeps the agent's descriptors open across `closefrom()` (Linux).
  - SSH (OpenSSH): cookies are read from `ssh->kex->my/peer` (KEXINIT bodies without a type byte) instead of a wrong `state->kex` walk, and `SHARED_SECRET` is written without the 4-byte length prefix, so Wireshark derives the right keys.
  - SSH plaintext PCAP: outgoing/incoming packets are matched by their real layout at the hook points and written as RFC 4253 frames (synthetic padding).
  - SSH (OpenSSH): the per-direction key fallback read from `struct newkeys` found nothing. `readCString(31)` read past the cipher name's NUL, and chacha20-poly1305's `iv_len` of 0 was rejected.
  - SSH (OpenSSH 8.x, e.g. Ubuntu 22.04): buffers were rejected because `struct sshbuf` still has `dont_free` before `refcount`. Both layouts are accepted now.
  - SSH (OpenSSH): the `closefrom()` guard no longer fails with "already replaced this function" when ssh's own `closefrom` is also the global lookup result.
  - arm64 string-xref scans (BoringSSL tier 4, QUICHE STREAM-frame locator, SSH anchors) found nothing on Frida <= 17.15 (the release for Python 3.10). Those Frida versions reject a match pattern that starts with a wildcard byte.
  - A gated child friTap does not instrument stays tracked until its resume returns, so a teardown racing that resume still resumes it.
  - `SSL_read_ex` records (e.g. CPython) were labelled as writes; read/write direction now comes from one shared list of hook names.
  - A TLS 1.3 connection no longer splits into a request flow and a response flow in legacy mode when only the responses carry a session id.
  - Records are never labelled with protocol `auto` or `all` (the `--protocol` hook selection): the router uses the hook's own protocol tag, falling back to the message type's protocol, so e.g. SSH and Signal records under `--protocol auto` are labelled `ssh` / `signal`.
  - Agent API: capture option files (`protocol_options.offsets` / `patterns`) are resolved inside the `--root` sandbox like every other path.
  - pcap vs pcapng is decided in one place: `-p out.bin` with pcapng requested no longer gets a classic pcap header and a pcapng header in the same file, and `-f` finalization, its DSB key injection and the Windows LSASS helper now use the same format.
  - `capture_status` under automatic protocol detection no longer makes speculative hooks look like protocol use: e.g. the RC4 hooks on libssl/libcrypto now show as `idle` and outside `protocols_in_use`.
  - wolfSSL, GnuTLS, NSS and legacy Android Cronet write records carry only the bytes the call actually wrote: partial writes and `WANT_WRITE`/`EAGAIN` retries no longer duplicate plaintext.
  - GnuTLS: a record buffered by `GNUTLS_E_AGAIN`/`GNUTLS_E_INTERRUPTED` and flushed by a `NULL`/0 retry is now captured (once).
  - Go TLS plaintext hooks (not yet installed by default) read their arguments from Go's register ABI instead of the C argument slots.
  - Modern Cronet (`--modern`) `SSL_write` records carry only the bytes the call wrote, like the legacy Cronet hook.
  - Go TLS on arm64: keys are logged again; the secret was read from the client random's capacity register (X5/X6 instead of X6/X7).
  - Go TLS on arm64: `writeKeyLog` and `writeRecordLocked` hooks no longer fail with "unable to intercept function"; they fall back to the instruction after Go's stack check.
  - Go TLS: symbols that are not dynamic exports (the usual case) are found again via the debug-symbol and export fallbacks, and a found `writeKeyLog` no longer aborts the legacy Go hooker.
  - Go TLS, stripped binaries (legacy and `--modern`): keys are logged from the byte-pattern match of `writeKeyLog`, read from Go's registers like the symbol path (they were read from the C argument slots). New x64/arm64 patterns match Go 1.18-1.26, and `--modern` now runs the pattern fallback instead of skipping key extraction.
  - `--modern` Go TLS plaintext: no return hooks on Go functions (goroutines can move between threads); writes come from `writeRecordLocked` and reads from the copy inside `(*Conn).Read`, with Go register arguments on x64 and arm64. Records still need `--enable_default_fd`.
  - Go TLS on 32-bit x86 and ARM (`GOARCH=386`/`arm`): `writeKeyLog` keys are read from Go's stack arguments (these targets have no register ABI). Plaintext hooks stay off on these targets.
  - Go TLS on legacy Linux and Android: without `-k`, no key hooks are installed for stripped binaries (the pattern path ignored the setting), and the symbol fallback now hooks BoringSSL's `ssl_log_secret` with C arguments, not Go argument slots.
  - Go TLS on arm64: a hooked Go function no longer overruns the goroutine stack (crashes with "unexpected return pc" / SIGBUS, mostly with `-p`); its stack check is widened so Go grows the stack before the hook runs.
  - "found & will be hooked" console lines name the protocol (e.g. `(tls)`, `(rc4)`), and a library is reported only for protocols whose hooks were installed: without `-k` the RC4 key hooks install nothing, so rc4 no longer appears as an idle protocol.
  - Flows are stamped with the library detected for their own protocol: under `--protocol auto` an RC4/SSH library announcement no longer relabels TLS/QUIC flows (QUIC falls back to the TLS-family library).
  - `-f` with a pcapng (or BPF-filtered pcap) output no longer leaves the `_<name>` staging capture next to the output; it is kept only when it could not be converted, and its path is logged.
  - The full-capture hint matches the output format: a pcapng says the keys are embedded and Wireshark decrypts it directly; a pcap points at the `-k` keylog file.
  - `-k keys.log -f -p out.pcap` no longer ends with "no keylog file was written; use -k <keylog>" when the keylog holds keys. The hint read a keylog handle captured before the lazily opened file existed; it now uses `PCAP.written_keylog_path()`, the same existing-and-non-empty rule the capture manifest uses.
  - TCP-TLS flows are labelled with the library that actually produced them: plaintext records now carry their hooked module, so WebView (`libwebviewchromium.so`) HTTP/2 flows are no longer labelled with a Cronet module just because Cronet was detected last. Applies to both agent trees and the OpenSSL/BoringSSL, Chromium, GnuTLS, NSS, wolfSSL, mbedTLS, s2n, MatrixSSL and Cronet hooks.

## [2.6.1] - 2026-11-02

### Security
  - Require `brotli>=1.2.1` and skip `br` bodies on vulnerable versions (CVE-2026-111497).
  - `FRITAP_ALLOW_UNPATCHED_BROTLI=1` re-enables `br` for distro builds with a backported fix.
  - tshark runs now disable HTTP and WebSocket body decompression.
  - New `--isolate-decoders` runs brotli, zstd, zlib and QPACK decoding in a sandboxed worker.
  - frida-server downloads are checked against GitHub's SHA-256 digest and fail closed.
  - Keylog merges and repairs copy only valid keylog lines.
  - Agent keylog lines containing control characters are dropped.
  - Agent text is escaped before it reaches the terminal.
  - Agent address fields are validated before use in capture filters.
  - Debug blob dumps go to a capped, dedicated directory.

### Fixed
  - HTTP/2 bodies are no longer lost when DATA frames span TLS records.
  - The first HTTP/2 response on a connection is no longer replaced by SETTINGS.
  - QUIC responses are no longer attributed to another server's flow.
  - Android spawn retries when the app is killed during a slow attach.
  - A slow device is no longer reported as unrooted.
  - friTap no longer hangs when the target process dies.
  - Device tcpdump is stopped on every exit path, and only friTap's own instance.
  - `session.json` is written crash-safe and is never left empty.
  - Non-fatal agent script errors no longer terminate friTap.
  - Plain target kills are no longer blamed on instrumented hooks.
  - Exceptions in the agent's deferred Java hooks are now caught.
  - A zero-length HTTP/1 chunk no longer hangs the parser.
  - HTTP/1 parsing resumes after protocol errors and `Connection: close`.
  - A non-UTF-8 HTTP/2 header no longer blinds the connection.
  - Markup in captured headers can no longer crash or blank the TUI.
  - One failing analyzer no longer aborts `--analyze`.
  - Records over 64 KiB are split instead of dropped from `-p` pcaps.
  - Device capture files are now unique per run.

### Changed
  - QPACK header blocks are size-checked before decoding.
  - HTTP/2 header blocks, streams and frames are capped.
  - HTTP/3 DATA frames are counted instead of buffered.
  - WebSocket deflate output is capped per message and per connection.
  - Automatic body decompression is capped at 16 MiB.
  - MTProto parsing has work and inflate budgets.
  - Analyzer scans and findings per flow are capped.
  - Markdown and CSV reports escape captured text.
  - `.tap`, pcap, pcapng and minidump readers validate length fields.
  - tshark runs have a size-scaled timeout (`FRITAP_TSHARK_TIMEOUT`).
  - Mid-stream TLS recovery has a trial budget.
  - Collector connections, queues and buffers are bounded.
  - Parsers recover up to three times before being disabled.
  - BHTTP now parses indeterminate-length messages with bounds checks.
  - Truncated gzip streams are flagged with a note.
  - Offline commands start faster by loading pydantic lazily.

## [2.5.8] - 2026-10-25

### Added
  - **Full packet capture (`-p <file> -f`) on the Wine GDB path.** The whole-host
    capture now runs alongside the GDB key extractor and is finalized both on
    Ctrl-C and when the Wine app exits on its own (previously a natural exit left
    only the `_<name>` temp file). With a `.pcapng` target the keys extracted by
    gdb are embedded as a Decryption Secrets Block, so `fritap -r cap.pcapng` /
    Wireshark decrypt it directly.
  - **`sudo` + Wine spawn launches Wine as the invoking user.** When friTap runs
    as root via `sudo` (needed for `-f`), spawn mode starts Wine with
    `SUDO_UID`/`SUDO_GID` and that user's `HOME`, so the user's `~/.wine` prefix
    works. The sniffer, the `/proc` scan, the `SIGSTOP`/`SIGCONT` freeze/resume
    and teardown stay root.
  - **gdb runs as the invoking user under `sudo` when possible (least
    privilege).** gdb parses untrusted target memory and runs Python scripts, so
    on the Wine GDB path friTap now drops it to the `sudo` user when
    `kernel.yama.ptrace_scope=0` (or Yama is absent), the target belongs to that
    user (always in spawn mode, checked in attach mode), the user can read
    friTap's gdb script directory, and the user can write the keylog (a missing
    keylog is created owned by the user; an existing root-owned one blocks the
    drop). Otherwise gdb stays root and friTap logs `Keeping gdb as root:
    <reason>`; on success it logs `Running gdb as <user> (uid N); ...`. friTap
    never changes `ptrace_scope` itself.

### Fixed
  - **Wine launch command without `-s`.** `fritap -k keys.log wine app.exe` runs
    in attach mode; friTap now also matches the running app by its exe path /
    basename (a Wine process's cmdline never contains `wine app.exe`) and, if
    nothing is running, prints a hint to add `-s` instead of only "Could not
    determine a PID to attach to".
  - **WINEPREFIX ownership pre-flight check** on the GDB Wine spawn path: friTap
    aborts with a clear message when the prefix is owned by a different user than
    the one Wine will run as (Wine would refuse it and exit silently).
  - The "Plaintext/pcap capture is not supported for Wine" notice no longer fires
    for full capture (`-f`), and now points to `-p <file> -f` for plaintext-only
    requests.
  - Broken attach examples: the Wine detach hint and `docs/platforms/wine.md`
    used `-p "$(pgrep …)"`, but `-p` is `--pcap`; attach targets are positional.
  - `docs/platforms/wine.md`: "Basic Usage" showed the stale `sudo fritap
    --experimental -k keys.log wine app.exe` (no `-s`), fixed invalid `sudo
    WINEPREFIX=… -E` ordering and a `sudo -E` example that hit the prefix trap,
    and updated the deployment models to the GDB default.

## [Unreleased] — 2.3.0

### Added
  - **Automatic GDB-based TLS key extraction for Wine targets on Linux.** When a
    Wine target is detected on a Linux host, friTap now routes key extraction
    through the standalone GDB extractor (`agent_gdb/wine`) instead of injecting
    Frida (gdb and Frida both need `ptrace`, so they cannot share the process).
    No `--experimental` flag is needed. Works for both spawn (`fritap -s -k
    keys.log wine app.exe`) and attach (`fritap -k keys.log $(pgrep -f app.exe)`).
    This path extracts **key material only**; if plaintext/pcap capture is
    requested, friTap prints a notice that it is not currently supported for Wine
    and continues with key extraction. The extractor now resolves the real Wine
    ELF loader automatically (handling the symlinked `wine` wrapper and the newer
    *wow64* `wine64` layout with no `wine-preloader`), works on gdb builds without
    `gdb.events.executable_changed` (falls back to `new_objfile`), ships fallback
    loader signatures for the wow64 layout, and is now packaged into installed
    wheels. See `docs/platforms/wine.md`. The extractor also gained a fallback
    GnuTLS signature + handler (`GnuTLSNssKeylogFuncUnixBP`) for builds that
    **inline** `_gnutls_call_keylog_func` (e.g. Ubuntu gnutls 3.8.x): it hooks the
    registered NSS keylog callback, which gnutls invokes for every secret of every
    handshake (the `SSLKEYLOGFILE` check is internal), so keys are captured
    passively — verified to byte-match gnutls's own `SSLKEYLOGFILE` output. Also
    made the extractor work on gdb < 13 (replaced `gdb.events.executable_changed`
    with `new_objfile`, `Breakpoint.locations` with a tracked hook set, and made
    `set exception-verbose` optional), skip unreadable Wine memory regions during
    scanning, and use all-stop for attach so capture keeps running. For spawn
    (`fritap -s wine app.exe`), friTap launches Wine normally and **attaches**
    (gdb-spawning Wine deadlocks its cold boot on the wow64 layout); this needs
    `kernel.yama.ptrace_scope=0`. Verified end to end on Ubuntu Wine 9.0 (wow64) +
    gnutls 3.8.9 + gdb 10.2: real `CLIENT_RANDOM` keys captured from a live Windows
    WinHTTP (Schannel→gnutls) app, byte-matching gnutls's own `SSLKEYLOGFILE`.
  - **`--wine auto|on|off` and direct `.exe` targets.** A Windows binary given
    directly on Linux (`fritap -s app.exe`) is now auto-detected as a Wine target
    (by PE `MZ` magic, or the `.exe` name when the file can't be read) and `wine`
    is prepended automatically. `--wine` controls this: `auto` (default) detects,
    `on` forces the GDB Wine route, `off` disables it. An explicit `--backend
    frida` keeps the Frida path for Wine targets (so the experimental Wine agent
    stays reachable); `--wine on` overrides that.
  - **RC4 as a first-class protocol (`--protocol rc4`).** RC4 is independent of
    TLS: run it standalone (`--protocol rc4`) or nested inside TLS
    (`--protocol tls,rc4`, i.e. plaintext → RC4 → TLS). RC4 **keys** are hooked
    on every platform (OpenSSL/LibreSSL/BoringSSL `RC4_set_key`, Nettle
    `nettle_arcfour_set_key`, mbedTLS `mbedtls_arc4_setup`; Windows CNG
    `BCryptGenerateSymmetricKey` and legacy CryptoAPI `CryptEncrypt`/`CALG_RC4`)
    and can also be recovered heap-side with `-ms --protocol rc4` (S-box scan +
    candidate-key trial-decrypt). Offline decryption via `--from-pcap
    --rc4-keylog`, auto-detecting standalone (raw TCP) vs nested (strip TLS via
    tshark, then peel RC4).
  - **Multi-protocol selection.** `--protocol` now accepts a set, e.g.
    `--protocol tls,rc4` or `--protocol tls --protocol rc4`. Each protocol's
    hooks install only when it is explicitly selected (no implication);
    `ssh`/`ipsec`/`mtproto` remain exclusive. `--protocol tls` alone is
    unchanged.
  - **Schannel read-only heap scan (Windows).** Memory-scan engine selection is
    now driven by the `--protocol` set and platform, resolved from the central
    `memory_scan_patterns.json`. On Windows, `-ms` additionally attaches a
    **read-only** scan to `lsass.exe` for Schannel TLS 1.2/1.3 secrets and the
    session cache (skipped with `-nl`). Verified on Windows 11 **arm64** (build
    26200); **x64** ships uncalibrated with a calibration tool under
    `dev/schannel_calibrate/`. Unpaired lsass secrets are written to
    `<stem>.schannel.unpaired` and correlated to client-randoms offline with
    `--from-pcap --schannel-unpaired`, emitting a normal NSS keylog.
  - **Targeted memory scan.** `-ms <engine>` (`-ms schannel`, `-ms rc4`,
    `-ms boringssl`) scans only that engine regardless of `--protocol`.
  - **`--probe` (dry run).** Loads the agent, reports which platform branch it
    selected, and stops **before installing any hooks** — for diagnosing targets
    that die during instrumentation (fkie-cad/friTap#65). If the loaded bundle
    does not acknowledge probe mode, friTap exits non-zero and says so rather
    than silently doing a normal instrumented run.
  - **`--script-load-timeout` (default 20 s, `0` disables).** Bounds the agent's
    `script.load()`, which previously could hang forever waiting for a startup
    handshake. Automatically tripled when a pattern or memory-region scan is
    requested, since those legitimately take longer.
  - **iOS crash reporting.** Crash reports are pulled via `idevicecrashreport`
    and decoded (`0x8badf00d` watchdog, jetsam, `EXC_BAD_ACCESS`,
    `0xdead10cc`, codesigning), mirroring the existing Android tombstone/logcat
    enrichment. Crash reporting is now also registered in **attach** mode.
  - **`dev/macos_verify/`** — device-free end-to-end verification of the Apple
    capture path on macOS, usable as a stand-in for a jailbroken iOS device.
  - **Schannel sidecar `group` column.** `.schannel.unpaired` takes an optional
    5th column `group=<id>`; `--schannel-unpaired` uses it to place a group's
    leftover TLS 1.3 secret as `EXPORTER_SECRET` by elimination. The memscan agent
    emits it (per-connection id) for TLS 1.3 secrets when the `tls13_secret.group`
    tier is enabled; sidecars without the column parse as before.
  - **Static RE corroboration of the Schannel TLS 1.3 `group` rule.**
    `ncryptsslp.dll` (Win11 **arm64**, build 26200) was reverse-engineered,
    proving a connection's three app-secret containers are **separate heap
    allocations** from distinct `TlsDeriveSecret` calls with no enclosing struct —
    so the positional offsets are deterministic heap layout, not structural,
    corroborating the earlier "no parent pointer" finding. Write-up in
    `dev/windows_re/verify_kit/STATIC_RE_FINDINGS.md`.
  - **Schannel memory-scan: fail-safe per-cipher-suite group offset.**
    `tls13_secret.group.by_cipher` + `cipher_at` in `patterns.json`; the agent
    reads the suite id at `anchor+0x08` and falls back to the SHA384-measured
    default, emitting **no group** rather than a wrong one for unknown suites.
    `tls13_secret.size_at` stays `-1`: the RE confirms there is no clean
    scanner-usable length field in the `ncryptsslp` descriptor.
  - **`quic.library` display-filter field / `QuicLayer.library`** for live QUIC flows.
  - **New environment variables:** `FRITAP_PCAP_PARSER=scapy` (old pcap parser),
    `FRITAP_SCHANNEL_ORACLE=0` (all Schannel trials via tshark),
    `FRITAP_NO_TSHARK_VERSION_CACHE=1` (no on-disk `tshark --version` cache) and
    `FRITAP_PCAP_CACHE_MAX_MB` (shared-parse limit, default 256, `0` disables).

### Changed
  - **Agent ABI 1 → 2** (`probe` config field + the `platform_report` content
    type). The bundle's ABI is now also checked **statically, before load**, so
    a stale `friTap/fritap_agent.js` is reported before it touches the target.
    An ABI-mismatched agent bundle contributed via the `fritap.agent_bundle`
    entry point is now reported with a **warning** instead of being skipped
    silently.
  - **Offline conversion reads the capture fewer times.** Keyed `--from-pcap` reads
    TLS, QUIC and SSH from one `tshark -T ek` pass instead of five, Signal reuses the
    TLS pass's plaintext (and now honours its heuristic/decode-as settings), and the
    raw-TCP decryptors share one parse. `.tap` output is unchanged.
  - **Fast pcap parser** for MTProto, standalone RC4 and mid-stream TLS (~14–23×
    faster); rare packets still fall back to scapy, and `FRITAP_PCAP_PARSER=scapy`
    restores the old parser.
  - **Connection ids are protocol-scoped for non-TLS protocols**
    (`net:<protocol>:<4-tuple>`), so flow ids of MTProto, QUIC, RC4 and Signal
    captures re-converted with `--from-pcap` change, and offline RC4/Signal flows no
    longer carry a synthetic `ssl_session_id`. Existing `.tap` files are unaffected.
  - **`ConvertResult.per_protocol`** is the canonical home for per-protocol counters;
    the flat `mtproto_*` keys are deprecated aliases (still in `to_dict()`).
  - **Offline-decryptor plugins get `resync_search_depth` only via the new
    `OfflineDecryptorEntry.resync_param`**; `**kwargs` emitters no longer receive
    `obf_max_blocks`. `mtproto_keylog=` still works as a `<protocol>_keylog` keyword.
  - **BREAKING: `Flow.decode_request_protobuf()` / `decode_response_protobuf()`
    return a `ProtobufView`** (or `None`) instead of a list of `ProtobufMessage`
    trees, and honour `schema_path`, a new `message_type`, `grpc-encoding` and gRPC
    framing. Call `decode_raw()` on the body for the old tree; no shim.
    `ProtobufProcessor` also loads `.proto` sources.
  - **The `tls` display filter no longer matches Telegram Secret-Chat flows**;
    `tls.session_id` is empty for non-TLS flows, and live non-TLS flows no longer
    get a stray TLS layer.
  - **Smaller offline speedups:** mid-stream TLS binding tries small sequence numbers
    first (~2.1 s → 0.02 s on Signal), non-TCP packets skip scapy, MTProto OBF
    recovery reuses its probe index (~−27% CPU), keyless conversion skips the QUIC
    pass on UDP-free captures, and `tshark --version` is cached per binary.
  - **`--from-pcap` progress names the protocol** being decrypted, and the "no TLS
    keylog needed" note no longer dismisses QUIC.
  - **Schannel correlation decides most trials in Python** (TLS 1.2 AES-GCM,
    ChaCha20-Poly1305, AES-CBC; TLS 1.3 incl. KeyUpdates), cutting tshark spawns of
    `--schannel-unpaired` / `--repair-keylog` from 15–29 to ~1.
  - **pytest configuration moved to `pyproject.toml`.** `tests/pytest.ini` was
    silently ignored; markers (`--strict-markers`), the timeout and warning filters
    now actually apply.

### Removed
  - **Private back-compat aliases on `friTap.offline.pcap_to_tap`:** 28 unused
    MTProto helper re-exports, `_TELEGRAM_TRANSPORTS`, and the remaining aliases
    (pipeline_api helpers, `canonical_keylog_path`, `record_tls_span`, 20 MTProto
    helpers, `_attach_rc4_in_tls_layers`, `DEFAULT_OBF_MAX_BLOCKS`) together with
    the lazy `__getattr__` shim. Import them from their real modules.
  - **The legacy multi-pass tshark path:** the separate-pass helpers in
    `pcap_to_tap`, `pipeline_api` and `offline.tshark` (e.g. `extract_tls_metadata`,
    `emit_tls_streams_singlepass`). Use `run_tls_combined_pass` / `TlsSinglePass`;
    `build_tls_command` and `build_quic_command` remain.
  - **Dead TLS internals** `cipher_suite_from_serverhello` and `confirm_secret`.

### Fixed
  - **Offline pcap parsing:** Ethernet padding no longer becomes phantom stream bytes,
    and BSD loopback (DLT_NULL) IPv6 is decoded on every platform.
  - **Offline tshark handling:** a non-UTF-8 byte on stderr no longer hangs the
    conversion, tshark is terminated when the consumer stops early, and a capture
    truncated in its last packet converts its readable part with a warning.
  - **Offline: SSH client/server banners are no longer swapped** when the server
    sends first.
  - **Offline: manifest keylog paths resolve against the manifest's directory**, and
    the Python API honours the manifest's per-protocol `keylogs` map.
  - **Offline exit codes:** metadata-only conversions (e.g. SSH) exit 0 instead of 4;
    a missing `--<proto>-keylog`, `--schannel-unpaired` or `--tls-midstream-secrets`
    file exits 5 instead of being skipped (the Python API warns).
  - **Schannel: `EXPORTER_SECRET` placement by elimination works on real captures**
    and is group-scoped; unplaced secrets are logged with a count.
  - **Schannel oracle:** TLS 1.3 secrets roll once per KeyUpdate; oracle errors and
    authenticated non-`Finished` TLS 1.2 records defer to tshark instead of
    rejecting a valid master.
  - **Schannel: `--repair-keylog` offers `???` lines for relabelling**, and
    `--keylog` + `--schannel-unpaired` no longer emits duplicate flows.
  - **TUI: Telegram Secret-Chat flows show a "Secret chat:" line** instead of
    "SSL Session: telegram_e2e:<fingerprint>".
  - **Agent build:** a signature mismatch in `agent/ms_agent/engines/schannel/index.ts`
    is fixed (`emitSchannelUnpaired`'s `group` param is now optional) so the committed
    `friTap/fritap_memscan.js` bundle rebuilds cleanly under CI `agent-build-check`.
  - **CI:** `agent-build-check` fetches the frida native binding (`npm rebuild frida`
    after `npm ci --ignore-scripts`), the DLT_NULL loopback IPv6 test is
    host-independent (failed on Linux), and the tree is ruff-clean again.
  - **TUI no longer reports a dead frida-server as "running"** — frida 17
    answers `enumerate_processes()`/`query_system_parameters()` over ADB even
    with no frida-server (`access: 'jailed'`), so every check passed while
    `attach()` failed with "unable to connect to remote frida-server: closed".
    The status bar, wizard and error context now require `access == 'full'`,
    and the wizard and capture pre-flight start frida-server automatically via
    AndroidFridaManager. Requires **AndroidFridaManager >= 2.0.6** (readiness
    probe, detached server launch that survives `adb kill-server`).
  - **Cap frida below 17.16.0 on Python 3.10** — it imports `typing.NotRequired`
    (3.11+) while still declaring `Requires-Python: >=3.7`.
  - **Pinned ruff and declared the lint rule set in `pyproject.toml`** — ruff 0.16
    expanded its default rules from 59 to 413.
  - **The Apple BoringSSL keylog offset is now derived from the target's own binary**
    rather than looked up in a version ladder whose open `> 1979.1` catch-all pinned
    every release from the iOS-17 era onward to a single frozen offset, which
    corrupted a neighbouring `SSL_CTX` field and killed the target
    (fkie-cad/friTap#65).
  - **Spawn mode no longer kills the target before any hook is installed** — friTap
    messaged `NSProcessInfo` inside a suspended spawn, which is fatal on Apple
    platforms, and now uses `sysctl` instead (fkie-cad/friTap#65).
  - **macOS: genuine OpenSSL outside `/usr/lib` is hooked at all.** A versioned
    `libssl.<n>.dylib` from Homebrew, pyenv, MacPorts or conda matched **no**
    registry entry — the LibreSSL entry required `/usr/lib`, the "Python OpenSSL"
    entry required `python` in the path (a Homebrew path has no such component),
    and the generic entry excluded the versioned name by name. friTap attached,
    installed nothing and logged nothing. The three `libssl*.dylib` entries are
    now a strict partition and versioned names route to the genuine-OpenSSL
    executor rather than the Apple BoringSSL one.
  - **macOS: a vendored `usr/lib` sysroot is no longer mistaken for the system
    one.** The LibreSSL entry's path filter was the plain substring `/usr/lib/`,
    so `.../MyApp.app/Contents/Frameworks/usr/lib/libssl.3.dylib` was routed to
    the priority-150 system-LibreSSL hook. It is now anchored.
  - **`libssl.1.1.dylib` is no longer hooked twice.** The generic entry's
    `excludePattern` was `/^libssl\.\d+\.dylib$/`, which cannot match `1.1`, so
    Homebrew `openssl@1.1` and Python 3.9-era framework builds matched both the
    Python and generic entries — and since the loader invokes every match, both
    executors installed, the second writing an Apple BoringSSL struct offset into
    a genuine OpenSSL `SSL_CTX`. The same class of overlap is fixed on Linux
    (`libssl.so.3` under a python path) and Windows (`C:\Python312\DLLs\libssl-3.dll`).
  - **iOS: `libssl`/LibreSSL are registered.** `ios.ts` had no entry for either,
    so iOS's own shared-cache LibreSSL and any app-bundled OpenSSL went entirely
    unhooked. Routing is unit-tested; the executors themselves are not yet
    validated on a device.
  - **`-ll` / `--extract-libraries` exit instead of starting a capture.** Both
    promise "will not start the logging process", but printed their result and
    then fell through into a full capture session that blocked in
    `wait_for_completion()` until the user hit Ctrl+C. The early-exit helper had
    been hoisted into a nested function, so its `return` returned from the helper
    rather than from `cli()`. Both now exit `0` on success and `2` when the
    inspection fails — previously a failed inspection also exited `0`, because the
    error was reported in the return value and never inspected.
  - **The startup handshake is answered per script.** Only the first script in a
    session used to be answered, so every additional one (`--enable_child_gating`,
    `--enable_spawn_gating`) blocked forever in `script.load()`.
  - **Gated child/spawn instrumentation no longer runs on Frida's event thread**
    or on the message-queue consumer thread, and the gated process is now
    resumed in a `finally` — a failed instrumentation used to leave it suspended
    until the platform watchdog killed it (reported as the app's own crash).
  - **A spawned target is resumed when instrumentation fails**, instead of being
    left suspended, with an explicit warning that it is running uninstrumented.
  - **Frida error diagnostics no longer claim `server_reachable=False`** for
    errors raised from script-first backend calls, where the first argument is a
    script rather than a device.
  - **A module without `SSL_CTX_set_keylog_callback` is reported, not silently
    unhooked.** The setter was constructed above the null guard meant to catch it,
    so the guard was dead and the throw was swallowed — no hooks, no message.
    macOS, iOS, Linux, Windows.
  - **`--spawn` no longer splits an executable path on spaces** for programmatic
    configs, and no longer warns about ordinary Android package names.
  - **A device-ID session no longer probes the host filesystem** for a remote path.
  - **Registry exclusions log once**, not once per `dlopen` of a denylisted module.

### Testing
  - `stubRanges()` agent stub: the default reported every address as mapped, so the
    symbol-table `isReadable` guard would have passed even if deleted.
  - Docs guard test against reintroducing the `EPIPE` claim or an unredirected pipe.
  - One shared log-capture helper replaces three copies.
  - Architecture layering guard: new rule **R12** (no private imports from inside an
    offline protocol package), R8 allowlists for the new offline modules,
    `friTap.filter` in the generic core, and an R8c guard for the cycle edges.
  - New `slow` pytest marker: slow tests run only with `FRITAP_SLOW_TESTS=1` or `-m slow`.

## [2.2.4]

### Added
  - **`--pairip-safe` in the TUI (Android).** The Ready-to-Capture screen now offers a
    `PairIP Safe` toggle (key `p`), shown only for Android devices, so the PairIP
    workaround can be enabled from the wizard without dropping to the CLI
    (fkie-cad/friTap#64).
  - **Improved Wine TLS hooking.** Pattern-based keylog hook for Wine targets in the
    Frida agent, improving capture reliability for Windows binaries run under Wine.

### Fixed
  - **Spawn targets with spaces.** A quoted spawn command (e.g.
    `wine "/path/Program Files/app.exe"`) is now tokenized shell-style into argv on
    both the CLI and TUI, so spaced and Windows-style paths survive to
    `device.spawn()`. Also fixes Wine launch-command parsing.

## [2.2.3]

### Added
  - **dev/find_ssl_log_secret_offset.py helper script** locate `bssl::ssl_log_secret` in a 
    stripped BoringSSL/Chromium shared object, for friTap's `--pairip-safe` offset hook as an alternative to BoringSecretHunter (BSH)

### Fixed
  - **Linter fixes** Fixing linter issues in `dev/find_ssl_log_secret_offset.py`
  - **updating our documentation** Updated the text on `pairip-safe.md` 


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
