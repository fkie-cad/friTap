// friTap ground-truth app: HTTPS via dart:io HttpClient, which uses the
// BoringSSL statically linked into libflutter.so (no platform networking).
//
// Requests run on launch, on every app resume, and on the "Run requests"
// button. Each request logs one line to logcat (tag "flutter"):
//   FRITAP_GT method=<M> url=<URL> status=<code|ERR> nonce=<N> run=<R> [error=<msg>]
// Each run starts with "FRITAP_GT run_start run=<R> trigger=<T>" and ends with
// "FRITAP_GT run_end run=<R>".
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:flutter/material.dart';

void main() => runApp(const FritapHttpsApp());

class GroundTruthRequest {
  const GroundTruthRequest(this.method, this.urlFor, {this.bodyFor});
  final String method;
  final String Function(String nonce) urlFor;
  final String Function(String nonce)? bodyFor;
}

// Optional local TLS server (tools/https_sha384.py via adb reverse) that
// forces TLS_AES_256_GCM_SHA384. Empty unless passed via --dart-define.
const String localTlsUrl = String.fromEnvironment('FRITAP_LOCAL_TLS_URL');

String withNonceQuery(String url, String nonce) =>
    '$url${url.contains('?') ? '&' : '?'}n=$nonce';

final List<GroundTruthRequest> groundTruthRequests = [
  GroundTruthRequest('GET', (n) => 'https://www.google.com/?q=fritap-$n'),
  GroundTruthRequest('GET', (n) => 'https://httpbingo.org/get?n=$n'),
  GroundTruthRequest('POST', (n) => 'https://httpbingo.org/post',
      bodyFor: (n) => jsonEncode({'fritap_nonce': n, 'msg': 'hello-fritap'})),
  // www.apple.com selects TLS_AES_256_GCM_SHA384 even when the client
  // prefers AES_128_GCM (server-preference ordering).
  GroundTruthRequest('GET', (n) => 'https://www.apple.com/robots.txt?n=$n'),
  if (localTlsUrl.isNotEmpty) GroundTruthRequest('GET', (n) => withNonceQuery(localTlsUrl, n)),
];

// The local server uses a self-signed cert; only loopback hosts are exempted,
// and only when the define is set. All other hosts keep normal verification.
bool acceptLocalSelfSignedCert(X509Certificate cert, String host, int port) =>
    localTlsUrl.isNotEmpty && (host == '127.0.0.1' || host == 'localhost');

String newNonce() {
  final rnd = Random.secure();
  return List.generate(8, (_) => rnd.nextInt(256).toRadixString(16).padLeft(2, '0')).join();
}

void logGroundTruth(String line) => print('FRITAP_GT $line');

Future<String> performRequest(HttpClient client, GroundTruthRequest req, int run) async {
  final nonce = newNonce();
  final url = req.urlFor(nonce);
  try {
    final request = await client.openUrl(req.method, Uri.parse(url));
    final body = req.bodyFor?.call(nonce);
    if (body != null) {
      request.headers.contentType = ContentType.json;
      request.write(body);
    }
    final response = await request.close();
    await response.drain<void>();
    logGroundTruth('method=${req.method} url=$url status=${response.statusCode} nonce=$nonce run=$run');
    return '${req.method} ${response.statusCode} $url';
  } catch (e) {
    final msg = e.toString().replaceAll('\n', ' ');
    logGroundTruth('method=${req.method} url=$url status=ERR nonce=$nonce run=$run error=$msg');
    return '${req.method} ERR $url';
  }
}

class FritapHttpsApp extends StatelessWidget {
  const FritapHttpsApp({super.key});

  @override
  Widget build(BuildContext context) =>
      const MaterialApp(title: 'friTap HTTPS', home: RequestScreen());
}

class RequestScreen extends StatefulWidget {
  const RequestScreen({super.key});

  @override
  State<RequestScreen> createState() => _RequestScreenState();
}

class _RequestScreenState extends State<RequestScreen> with WidgetsBindingObserver {
  int _run = 0;
  bool _busy = false;
  List<String> _results = const [];

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _runRequests('launch');
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) _runRequests('resume');
  }

  Future<void> _runRequests(String trigger) async {
    if (_busy) return;
    final run = ++_run;
    setState(() => _busy = true);
    logGroundTruth('run_start run=$run trigger=$trigger');
    final client = HttpClient()
      ..connectionTimeout = const Duration(seconds: 15)
      ..badCertificateCallback = acceptLocalSelfSignedCert;
    final results = <String>[];
    for (final req in groundTruthRequests) {
      results.add(await performRequest(client, req, run));
    }
    client.close(force: true);
    logGroundTruth('run_end run=$run');
    if (mounted) setState(() { _busy = false; _results = results; });
  }

  @override
  Widget build(BuildContext context) => Scaffold(
        appBar: AppBar(title: Text('friTap HTTPS (run $_run)')),
        body: ListView(children: [for (final r in _results) ListTile(title: Text(r))]),
        floatingActionButton: FloatingActionButton.extended(
          onPressed: _busy ? null : () => _runRequests('button'),
          label: Text(_busy ? 'Running...' : 'Run requests'),
        ),
      );
}
