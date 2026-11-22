# example_flutter

A new Flutter project.

## Getting Started

This project is a starting point for a Flutter application.

A few resources to get you started if this is your first Flutter project:

- [Lab: Write your first Flutter app](https://flutter.dev/docs/get-started/codelab)
- [Cookbook: Useful Flutter samples](https://flutter.dev/docs/cookbook)

For help getting started with Flutter, view our
[online documentation](https://flutter.dev/docs), which offers tutorials,
samples, guidance on mobile development, and a full API reference.

## Local SHA-384 server

To get ground truth for 48-byte (SHA-384) TLS 1.3 secrets, point the app at
`tools/https_sha384.py`, a small Python HTTPS server that only offers TLS 1.3
`TLS_AES_256_GCM_SHA384` and answers `200` with `Connection: close` and the body
`ok <path> cipher=<cipher>`. The request is only added when
`FRITAP_LOCAL_TLS_URL` is defined at build time; the self-signed cert is
accepted only for `127.0.0.1`/`localhost`.

Do not use `openssl s_server -www`: it deadlocks with dart:io `HttpClient`
(s_server sends close_notify and waits, HttpClient waits for the TCP close).

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -days 30 -subj /CN=127.0.0.1 -keyout key.pem -out cert.pem
python3 tools/https_sha384.py --cert cert.pem --key key.pem --port 8443 \
  --keylog server_keylog.txt
adb -s <serial> reverse tcp:8443 tcp:8443
flutter build apk --release \
  --dart-define=FRITAP_LOCAL_TLS_URL=https://127.0.0.1:8443/
```

Quick check from the host: `curl -k 'https://127.0.0.1:8443/?n=1'` should print
`cipher=TLS_AES_256_GCM_SHA384`. The server's `--keylog` is the reference to
compare friTap's keylog against.

The extra request logs as usual
(`FRITAP_GT method=GET url=https://127.0.0.1:8443/?n=<N> status=200 ...`).
Its keylog secrets (CLIENT_/SERVER_HANDSHAKE_TRAFFIC_SECRET,
CLIENT_/SERVER_TRAFFIC_SECRET_0) must be 96 hex chars (48 bytes). 64 hex chars
mean a SHA-256 suite was negotiated.
