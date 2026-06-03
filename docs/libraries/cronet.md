# Cronet & Mainline Cronet on Android

Cronet is Chromium's networking stack — the same code that powers Chrome and any app embedding it. On modern Android the picture is split across multiple binaries, and friTap hooks them differently depending on where TLS key material lives versus where HTTP/3 stream plaintext can be intercepted. This page explains the split so you know what to expect in friTap's output.

## The three Cronet realities on Android

1. **Embedded / Play Services Cronet (Android 12 and earlier).** Every app carries its own `libcronet*.so` (and statically linked BoringSSL inside it). No system module is involved.
2. **Chrome / WebView (all Android versions).** The Chromium engine ships as `libmonochrome_64.so` (or `libchrome.so` on older builds). BoringSSL **and** QUICHE are statically linked into the same binary.
3. **Mainline Cronet (Android 14+).** Cronet ships as a system module inside the Connectivity APEX (`com.android.tethering`). It is exposed to apps via the `android.net.http.HttpEngine` Java API. The binaries live in `/apex/com.android.tethering/lib64/`:
   - `libmainlinecronet.<version>.so` — the Cronet runtime, containing **QUICHE** (HTTP/3 / QUIC transport).
   - `stable_cronet_libssl.so` — a dedicated BoringSSL build that ships inside the APEX. Renamed (vs. the system `libssl.so`) so the dynamic linker can't collide it with Conscrypt's BoringSSL inside the same process. This is where the TLS 1.3 handshake, traffic-secret derivation, and `ssl_log_secret` live.
   - `libmainlinecronet` **imports** the `SSL_*` symbols from `stable_cronet_libssl.so`. It does not contain `ssl_log_secret` of its own — pattern-scanning it for the BoringSSL keylog prologue is futile by construction.

## Which binary produces what

| Binary                                  | TLS keylog material | HTTP/3 plaintext streams | friTap hook strategy                        |
|----------------------------------------|---------------------|--------------------------|---------------------------------------------|
| `stable_cronet_libssl.so` (APEX)       | ✓ (via `SSL_CTX_set_keylog_callback`) | ✗ | BoringSSL keylog callback hook              |
| `libmainlinecronet.<ver>.so` (APEX)    | ✗ (only imports BoringSSL ABI)         | ✓ (QUICHE in-process) | QuicSpdyStream symbol hook (plaintext pcap) |
| `libmonochrome_64.so` (Chrome bundle)  | ✓ (statically linked BoringSSL)        | ✓ (statically linked QUICHE) | BoringSSL keylog + QuicSpdyStream hook  |
| `libcronet.<ver>.so` (per-app embedded)| ✓ | ✓ | BoringSSL keylog + QuicSpdyStream hook       |

Wireshark decrypts QUIC packets using the same `SSLKEYLOGFILE` secrets that work for TLS-over-TCP — RFC 9001 §5 has Wireshark itself derive QUIC packet-protection keys from the TLS traffic secrets via HKDF. So a single hook on `stable_cronet_libssl.so`'s keylog callback is sufficient to get Wireshark-decryptable QUIC for Mainline Cronet apps. The `QuicSpdyStream` hooks are independent and only fire when you opt into plaintext pcap.

## What you'll see in friTap output

For an app using Mainline Cronet on Android 14+, you'll typically see something like:

```text
[*] stable_cronet_libssl.so found & will be hooked on Android!
[*] stable_cronet_libssl.so: keylog hooks installed via callback (SSL_CTX_set_keylog_callback)
[*] libmainlinecronet.<ver>.so: BoringSSL appears to live in sibling 'stable_cronet_libssl.so'; skipping redundant scan
```

That sibling-coverage message is friTap telling you it intentionally did **not** pattern-scan `libmainlinecronet` for `ssl_log_secret` — that function isn't there, and `stable_cronet_libssl.so` is carrying the BoringSSL surface. This is the correct behavior; nothing is missing.

If you also passed plaintext pcap (`-do`), you'll additionally see:

```text
[*] Google QUICHE detected in libmainlinecronet.<ver>.so, installing QUIC stream hooks...
[*] Hooked QuicSpdyStream::Readv for plaintext capture
[*] Hooked QuicSpdyStream::WriteOrBufferBody for plaintext capture
```

For Chrome itself, the QUICHE hooks fire on `libmonochrome_64.so` rather than the APEX library — Chrome carries its own embedded Chromium stack and doesn't actually route page-load traffic through Mainline Cronet (even though the APEX may be loaded into the process).

## Force-scanning the higher-level runtime

The sibling-coverage suppression is purely a runtime optimization. If for some reason you need to pattern-scan `libmainlinecronet` anyway (e.g., a hypothetical build that statically links BoringSSL into it), pass `--force-scan libmainlinecronet*`. friTap will then ignore the sibling and run the full pattern cascade.

## Detection on other Android versions

- **Android ≤13**: no Mainline Cronet APEX exists; ignore everything on this page outside of the embedded / Play Services Cronet row and the Chrome/Monochrome row.
- **Android 14+**: GMS-certified devices ship the APEX. AOSP-only builds may or may not.

friTap detects the topology at runtime by inspecting loaded modules, so you don't have to pass anything special.

## Related pages

- [BoringSSL Support](boringssl.md)
- [Android Platform Guide](../platforms/android.md)
- [Pattern-Based Hooking](../advanced/patterns.md)
