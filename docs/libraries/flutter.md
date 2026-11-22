# Flutter

Flutter apps link BoringSSL statically into `libflutter.so`. Dart's `dart:io`
`HttpClient` (and packages built on it, such as `package:http` on mobile) runs its
TLS through that copy, not through the platform TLS stack, so Java/Conscrypt hooks
see none of it. friTap handles `libflutter.so` with two rows.

## Keys

The "Flutter BoringSSL" row hooks BoringSSL's internal `ssl_log_secret` by byte
pattern (built-in patterns, or your own via `--patterns`). The secret is read with
the length BoringSSL passes to `ssl_log_secret`, so SHA-384 suites (48-byte TLS 1.3
secrets) and the TLS 1.2 master secret (48 bytes) are logged in full. Earlier
versions cut every secret to 32 bytes, which made those keylog lines useless.

If the built-in patterns do not match your `libflutter.so`, generate an
`ssl_log_secret` pattern with
[BoringSecretHunter](boringssl.md#boringsecrethunter). It does not locate
`SSL_read`/`SSL_write`; for plaintext see below.

## Plaintext (arm64)

With `-p`, the supplementary row "BoringSSL plaintext (Flutter)" locates
`SSL_read`/`SSL_write` inside `libflutter.so` with the resolver described in
[Plaintext from statically linked BoringSSL](boringssl.md#plaintext-from-statically-linked-boringssl)
(exports, `--offsets`, learned cache, `ssl_lib.cc` anchor locator) and hooks them.

- Dart's TLS does not do socket I/O inside `SSL_read`/`SSL_write`, so the
  records carry fd `-1`.
- They carry the connection's `client_random`, which is how they are joined to the
  TLS connection and its keys.

Android example:

```bash
# Attach to a running app (PID)
fritap -m -p flutter.pcap -k keys.log --tap flutter.tap 12345

# Spawn the app
fritap -m -s -p flutter.pcap -k keys.log --tap flutter.tap com.example.flutter_app
```

## Limitations

- **Non-arm64 (arm, x86, x86_64): keys only.** The anchor locator is arm64-only.
  Plaintext still works there if you find `SSL_read`/`SSL_write` by hand and
  pass them for `libflutter.so` via `--offsets` (see
  [BoringSecretHunter](boringssl.md#boringsecrethunter) for the steps).
- Traffic that does not go through `dart:io` (for example a plugin using
  OkHttp or Cronet) is captured by those libraries' own rows, not by the Flutter
  rows.

## Related pages

- [BoringSSL Support](boringssl.md)
- [Android Platform Guide](../platforms/android.md)
- [Pattern-Based Hooking](../advanced/patterns.md)
