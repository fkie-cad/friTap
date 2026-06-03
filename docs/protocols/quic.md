# QUIC / HTTP/3 capture

friTap captures plaintext QUIC and HTTP/3 the same way it captures TLS —
hooks above the encryption boundary inside the target process, so no
network MITM, no certificate pinning bypass, no system VPN. The packets
land in the same PCAPNG file Wireshark already understands.

QUIC is **the youngest protocol stack in friTap** (TLS support is ~5
years older). Treat this page as the live status of which QUIC libraries
work, and how to opt into the application-API capture mode that surfaces
decoded HTTP/3 headers.

## Library support matrix

| Library | Status | Module name(s) | Notes |
|---|---|---|---|
| **Google QUICHE** (Chrome / Cronet C++) | ✓ supported | `libmonochrome_64.so`, `libcronet.<ver>.so`, `libmainlinecronet.<ver>.so` | The reference target — every chain-fallback hook described below applies here. |
| **Cloudflare quiche** (Rust) | ✓ supported | `libquiche.so` | Symbols exported; pattern fallback rarely needed. |
| **Mozilla Neqo** (Firefox HTTP/3) | ✓ supported | `libxul.so`, `firefox` binary | Wraps NSS for TLS — combine with the NSS hooks for a full keylog. |
| **Microsoft MsQuic** | planned | `msquic.dll`, `libmsquic.so` | Referenced in datalog types and Python constants; no `agent/quic/definitions/` file yet. Track at issue tracker. |
| LiteSpeed lsquic | absent | `liblsquic.so` | Not started. |
| nghttp3 / ngtcp2 | absent | `libngtcp2.so`, `libnghttp3.so` | Not started. |
| picoquic | absent | `libpicoquic.so` | Not started. |
| quicly (Fastly) | absent | `libquicly.so` | Not started. |
| aioquic (Python) | absent | n/a (CPython) | Not started. |

Want a library not on the list? Open an issue and attach (a) the
process you're trying to capture and (b) the path/name of the loaded
`.so`/`.dll` on disk.

## Quick start (Google QUICHE on Android)

```bash
# Android, attaching to an app already running. -m enables mobile,
# -s spawns fresh, -k captures the TLS-1.3 keys Wireshark needs to
# decrypt a *paired* tcpdump-collected ciphertext capture.
fritap -m -s com.google.android.youtube \
    -p youtube.pcap \
    -k keys.log \
    --quic-capture-mode app-api
```

Two outputs land in the working directory:

| File | What's in it |
|---|---|
| `youtube.pcap` | Plaintext HTTP/3 stream-level body bytes (request / response), wrapped as synthetic UDP/443 frames. Open in Wireshark; with `--quic-capture-mode app-api` (below) you also see decoded request/response header blocks as JSON-shaped sideband entries. |
| `keys.log` | TLS-1.3 secrets compatible with Wireshark's `SSLKEYLOGFILE` — RFC 9001 §5 derives QUIC packet-protection keys from the TLS traffic secrets via HKDF, so a single keylog decrypts both the TLS handshake AND the QUIC payload in any *ciphertext* capture you take separately. |

## Capture modes — `--quic-capture-mode`

```text
--quic-capture-mode stream    # (default) lower-boundary stream hooks
--quic-capture-mode app-api   # Boundary-4 decoded HTTP/3 headers + bodies
```

- **`stream`** hooks `QuicStream::Readv`, `QuicStreamSequencer::Readv`,
  `QuicStreamSequencer::OnStreamFrame` — the raw post-decrypt cleartext
  ring buffer. You get bytes; HTTP/3 framing, QPACK headers, and stream
  multiplexing are not parsed.
- **`app-api`** hooks the application-API boundary —
  `QuicSpdyStream::HttpDecoderVisitor::OnDataFramePayload`,
  `QuicSpdyStream::WriteOrBufferBody`,
  `QuicSpdyStream::OnHeadersDecoded`,
  `QuicSpdyStream::WriteHeaders` — so you get clean de-framed body bytes
  AND already-decoded `(name, value)` header pairs (no QPACK to parse).

App-api mode is the one most people actually want. Use stream mode when
you're debugging the lower layers or capturing a non-HTTP-over-QUIC
protocol.

## Hooking stripped Chrome / Cronet — the chain-fallback design

Chrome / Cronet ships stripped: `nm` returns nothing useful,
`Module.findExportByName(...)` returns `null`. friTap resolves QUIC
function addresses through a four-strategy chain inside
`agent/quic/definitions/google_quiche.ts`:

1. **Export table** — `mod.findExportByName(mangled)`. Works only on
   unstripped builds (rare for release Chrome / Cronet).
2. **Symbol table** — `mod.enumerateSymbols()` over `.dynsym`. Works on
   Mainline Cronet APEX (`libmainlinecronet.<ver>.so`) which imports the
   QUICHE symbols even though they're not exported.
3. **Byte-pattern scan** — `Memory.scanSync` with patterns from
   `quic_patterns.json` + `friTap/patterns/default_patterns.json`. This
   is the workhorse on stripped libcronet / libmonochrome.
4. **Static offsets** — manual `--offsets` overrides.

For `WriteHeaders` specifically the chain extends one level further:

```text
            QuicSpdyStream::WriteHeaders                 (quiche-internal — primary)
                              │
            chain-fallback ▼  (when quiche-internal misses, e.g. inlined out)
            net::QuicChromiumClientStream::WriteHeaders  (chrome shim)
                              │
            chain-fallback ▼  (when chrome shim also misses)
            quic::QuicSpdySession::WriteHeadersOnHeadersStream  (gQUIC session-level)
```

**Winner-takes-all topology.** When more than one layer resolves, only
the highest-priority one is attached — the others stay silent. This
prevents duplicate headers in the Python flow collector
(`FlowCollector.on_data` does NOT dedup datalog events).

Each attach prints one summary line:

```
[*] Google QUICHE egress headers chain in libmainlinecronet.141.0.7340.3.so: active layer = quiche-internal (QuicSpdyStream::WriteHeaders)
```

### Forcing a chain layer — `--quic-egress-headers-layer`

```text
--quic-egress-headers-layer auto             # (default) chain logic
--quic-egress-headers-layer quiche-internal  # only quiche-internal
--quic-egress-headers-layer chrome-shim      # only chrome shim
--quic-egress-headers-layer session-level    # only session-level gQUIC
```

Use a non-`auto` value to validate the lower tiers on builds where the
primary layer would otherwise always win. Example: test the chrome-shim
unwrap path on libmainlinecronet.141 (where `QuicSpdyStream::WriteHeaders`
normally wins via the symbol table):

```bash
fritap -m -s com.android.vending \
    -p out.pcap -k keys.log \
    --quic-capture-mode app-api \
    --quic-egress-headers-layer chrome-shim
```

If the forced layer doesn't resolve on the target build, the summary
line says `active layer = NONE` and friTap prints which layers WOULD
have resolved under `auto`. The flag is for testing; for normal captures
leave it at `auto`.

### Debugging chain resolution — `-do`

`-do` / `--debugoutput` is propagated to the agent. When set, the chain
resolver dumps every candidate it considered for each chain label:

```
[chain-debug] label=QuicSpdyStream_WriteHeaders (QuicSpdyStream::WriteHeaders) picked=0x6faa1c38e4 exports=<none> symtab_hits=1 pattern_hits=1
[chain-debug]    symtab: 0x6faa1c38e4 _ZN4quic14QuicSpdyStream12WriteHeadersEN6quiche...
[chain-debug]    pattern: 0x6faa1c3908
[chain-debug] label=QuicChromiumClientStream_WriteHeaders (...) picked=<unresolved> exports=<none> symtab_hits=0 pattern_hits=1
[chain-debug]    pattern: 0x6faa1ee9a4
[chain-debug] label=QuicSpdySession_WriteHeadersOnHeadersStream (...) picked=<unresolved> exports=<none> symtab_hits=1 pattern_hits=1
[chain-debug]    symtab: 0x6faa1c1234 _ZN4quic15QuicSpdySession27WriteHeadersOnHeadersStream...
[chain-debug]    pattern: 0x6faa1c1234
```

If `pattern_hits > 1` you'll see a `WARNING` line about uniqueness — the
pattern is matching multiple sites, which is exactly the failure mode
the blog post calls out (a byte signature uniquely matches but doesn't
uniquely *identify*). Re-anchor the pattern.

The dynsym walk is expensive on huge binaries (libmonochrome ~193 MB),
so this enumeration is skipped silently when `-do` is off.

## Where the addresses come from — BoringSecretHunter

Patterns for stripped builds are derived once per Chrome release by
**BoringSecretHunter** (BSH), a Ghidra-based static analysis tool that
emits friTap-compatible JSON:

```bash
# Pull the binary from the device (NOT cat-through-shell — adb shell
# is not 8-bit clean and will corrupt the .so).
adb pull /data/app/.../lib/arm64/libcronet.148.0.7778.167.so /tmp/

# Run BSH and write a JSON friTap can ingest with --patterns directly.
bsh analyze --find-quiche -o /tmp/bsh.json /tmp/libcronet.148.0.7778.167.so

# Inspect what BSH found:
python3 -c "import json; d=json.load(open('/tmp/bsh.json')); \
  print(sorted(d.get('quiche_patterns',{}).get('google_quiche',{}).get('arm64',{}).keys()))"

# Then feed it to friTap:
fritap -m -s com.app.target \
    -p out.pcap -k keys.log \
    --quic-capture-mode app-api \
    --patterns /tmp/bsh.json
```

The technique BSH uses — string anchors (`CHECK` macro file paths, UMA
histogram names, `AssertNotOpen("writing headers")` debug labels) plus
call-graph chaining from already-identified neighbours — is documented
in the blog post `SEEING_THROUGH_CHROME_HTTP3.md` at the repo root, and
in BSH's own `docs/QUICHE_Detection.md`.

## Stream correlation

Every QUIC datalog event carries a `streamId` derived from
`streamObj.toUInt32()` — the low 32 bits of the underlying
`QuicSpdyStream*` pointer. `WriteHeaders` (request side) and
`OnHeadersDecoded` (response side) on the same stream see the same
pointer, so Python's `FlowCollector.on_data` → `conn.map_qsid` collapses
the request and response into one flow.

For the **chrome-shim layer**, `args[0]` is the
`QuicChromiumClientStream*` wrapper, not the inner `QuicSpdyStream*`.
The unwrap helper (`unwrapChromiumClientStream` in `google_quiche.ts`)
probes a small set of candidate struct offsets, validates each with
vtable + r-x + module checks, and caches the winning offset so the hot
path is O(1). Without the unwrap, the chrome-shim's streamId would be
in a different namespace and would NOT correlate with response headers.

The **session-level layer** does not have a per-stream `this`. It uses
the explicit `QuicStreamId` argument from `w1` as the surrogate — which
lives in yet another namespace, so request/response **do not pair** when
this layer wins. This is acceptable because the session-level hook is
the last-resort tier that only fires when both higher layers have
already missed; it's defense-in-depth, not a primary path.

## Limitations

- **`stream` mode shows ciphertext-shaped bytes only.** No header parsing,
  no stream multiplexing. Use `app-api` mode for anything resembling
  request/response semantics.
- **`app-api` mode is Google QUICHE only.** Cloudflare quiche and Mozilla
  Neqo do not have the same `QuicSpdyStream::WriteHeaders` shape; their
  app-api hooks are separate work.
- **Session-level fallback rarely fires on modern HTTP/3.** IETF HTTP/3
  bypasses `QuicSpdySession::WriteHeadersOnHeadersStream` via
  `QuicSpdyStream::WriteHeadersImpl`'s `UsesHttp3()` branch. The hook is
  installed for defense-in-depth on builds where everything above it
  failed; in production captures of Chrome 148+ traffic it stays silent.
- **Stripped builds need patterns.** `default_patterns.json` ships
  runtime-verified arm64 patterns for the two chain-fallback labels
  (`QuicChromiumClientStream_WriteHeaders`,
  `QuicSpdySession_WriteHeadersOnHeadersStream`); patterns for
  `QuicSpdyStream::WriteHeaders` and `OnHeadersDecoded` on a *specific*
  Chrome release still come from the user's `--patterns <file>` or from
  running BSH against that release.
- **Attach-time crash on `DebugSymbol.findFunctionsNamed`.** A prior
  resolution strategy SIGSEGV'd Cronet during attach. The current agent
  avoids it; if you write a new friTap-style agent against stripped
  Cronet, do not enumerate debug symbols — use byte patterns instead.
