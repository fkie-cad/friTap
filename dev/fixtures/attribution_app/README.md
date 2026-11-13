# friTap attribution fixture app

Ground-truth Android app for measuring how well friTap attributes TLS/QUIC traffic
from statically-linked BoringSSL (Cronet / HttpEngine / WebView) to the originating SDK.

Two fake SDKs, `com.fritap.sdkalpha.AlphaSdk` and `com.fritap.sdkbeta.BetaSdk`, hit the
**same hosts** through the same Chromium-based transports, so connections are pooled and
coalesced. Every engine build and every request start (`UrlRequest.start()`,
`WebView.loadUrl()`) happens inside a method of the SDK class, so the SDK package is on the
Java stack when the transport is entered.
`com.fritap.attributionfixture.common` holds only the scenario driver and the logging code.

| transport         | engine                                                            | owner           |
|-------------------|-------------------------------------------------------------------|-----------------|
| `cronet-embedded` | `org.chromium.net:cronet-embedded:143.7445.0`, provider `App-Packaged-Cronet-Provider` | one per SDK |
| `cronet-shared`   | same provider, a single engine built by the app's common code     | shared by both SDKs (forces H2 coalescing) |
| `gms-cronet`      | `play-services-cronet:18.1.1`, provider `Google-Play-Services-Cronet-Provider` | one per SDK |
| `httpengine`      | platform `android.net.http.HttpEngine` (API 34+)                  | one per SDK     |
| `webview`         | system WebView, one offscreen (never attached) WebView per SDK    | one per SDK     |

All Cronet/HttpEngine engines use `enableHttp2(true)`, `enableQuic(true)` and
`addQuicHint("cloudflare-quic.com", 443, 443)`. The engine/provider actually used is logged
under the logcat tag `FritapFixture`.

Per round and SDK, the requests are sequential with about 300 ms spacing. Each Cronet and
HttpEngine transport issues one request to the H2 host and one to the H3 host, and the
WebView issues one load:

- H2: `https://httpbingo.org/anything/<sdk>/<transport>/<run>/<n>`
- H3: `https://cloudflare-quic.com/fritap/<sdk>/<transport>/<run>/<n>` (404 is expected)
- WebView: `https://httpbingo.org/anything/<sdk>/webview/<run>/<n>`

`<run>` is the epoch seconds at the start of the run. `<n>` is a per-SDK, per-run sequence
number, so every path is unique. Both SDKs run each round at the same time, on the threads
`alpha-worker` and `beta-worker`. A run has 9 requests per SDK per round, so the default of
3 rounds makes 54 requests.

## Build

Gradle 9.4.1 (system, `/opt/homebrew/bin/gradle`) + AGP 9.1.1 + JDK 21. The JDK is pinned in
`gradle.properties` (`org.gradle.java.home`) because Gradle's default JDK 27 is too new.
`local.properties` (gitignored) holds `sdk.dir`:

```sh
cd dev/fixtures/attribution_app
echo "sdk.dir=$HOME/Library/Android/sdk" > local.properties   # once
gradle assembleDebug                                          # -> app/build/outputs/apk/debug/app-debug.apk
```

The APK is arm64-v8a only. minSdk is 30 and target/compileSdk is 36.

## Install and run

```sh
SERIAL=emulator-5556
adb -s $SERIAL install -r app/build/outputs/apk/debug/app-debug.apk

# run once on launch (optional --ei rounds N, default 3)
adb -s $SERIAL shell am start -n com.fritap.attributionfixture/.MainActivity --ez autorun true

# repeat without restarting the app (attach capture tools first, then trigger):
adb -s $SERIAL shell am broadcast -a com.fritap.attributionfixture.RUN \
    -n com.fritap.attributionfixture/.RunReceiver --ei rounds 3
```

The broadcast needs the explicit component (`-n`), because Android does not deliver implicit
broadcasts to manifest receivers. If the app process is not running, the broadcast cold-starts
it. Runs that are triggered while another run is in progress are queued, so runs never overlap.
A run takes about 1–2 minutes. The first run in a fresh process is slower because the
WebView/GMS provider must initialise.

## Ground truth

```sh
adb -s $SERIAL logcat -c                                   # before triggering a run
adb -s $SERIAL logcat -d -s FRITAP_GT:I -v raw | grep '^{' > gt.jsonl
```

Even with `-v raw`, logcat prints a `--------- beginning of main` divider line. The
`grep '^{'` removes it, so `gt.jsonl` contains only JSON lines.

Each line is one event:

```json
{"v":1,"event":"start","run":R,"sdk":"alpha","transport":"cronet-embedded","req_id":"alpha-cronet-embedded-R-1","url":"...","method":"GET","t_ms":...,"thread":"alpha-worker"}
```

- `done` adds `"status":<int>,"protocol":"h2|h3|http/1.1|","cached":<bool>`
- `fail` adds `"error":"..."` (this includes `timeout after N ms`)
- `skip` adds `"reason":"..."` (for example, the GMS provider is unavailable)

For WebView requests, `start` is logged on the `main` thread at `loadUrl`. `done` is logged
from `onPageFinished`, with `protocol: ""` and `status: 0` unless an HTTP error reported a
status.

`sdk_signatures_fixture.json` maps the two SDK packages. It uses the
`friTap/analysis/attribution/data/sdk_signatures.json` schema, so it can be layered over
the bundled table with
`FRITAP_SDK_SIGNATURES=dev/fixtures/attribution_app/sdk_signatures_fixture.json`
(or `SdkResolver(extra_paths=[...])`, `friTap/analysis/attribution/sdk.py`).

## Measure attribution (P3)

Capture a run with plaintext, the Java request context and a `.tap`, with the fixture
signatures layered in, then collect the ground truth:

```sh
export FRITAP_SDK_SIGNATURES=dev/fixtures/attribution_app/sdk_signatures_fixture.json
adb -s $SERIAL logcat -c
fritap -m -k keys.log -p out.pcap --attribute-sdk --tap out.tap com.fritap.attributionfixture
# in a second shell: trigger a run (broadcast above), wait for it to finish, stop friTap
adb -s $SERIAL logcat -d -s FRITAP_GT:I -v raw | grep '^{' > gt.jsonl

env/bin/python dev/attribution_metrics.py --tap out.tap --gt gt.jsonl --keylog keys.log \
    --sdk-map FritapAlpha=alpha --sdk-map FritapBeta=beta [--run <id>] [--json report.json]
```

`--sdk-map NAME=sdk` maps an attributed SDK name to the ground-truth `sdk` value; `--run`
restricts the report to one ground-truth run. The script prints a table per transport, per
SDK and overall. Besides the earlier columns (`tk%` transport kind correct, `cs%` has a
caller stack, ...) it reports:

| column    | meaning |
|-----------|---------|
| `%hi_ok`  | seen requests whose flow is attributed at `high` confidence to the right SDK |
| `%hi_wr`  | seen requests whose flow is attributed at `high` confidence to the **wrong** SDK |
| `ctx%`    | ground-truth requests with a request-context record for the same normalized URL |
| `ctx_ok%` | ground-truth requests whose request-context record names the right SDK |

`ctx%` and `ctx_ok%` are empty when the `.tap` holds no request-context records (no
`--attribute-sdk`, or no `-p`). The extras below the table include `wrong_high` and
`fallback_high`.

Exit status: `0` for a clean report (also when nothing matched), `2` when an input cannot
be read, and `1` when `wrong_high` (high confidence, wrong SDK) or `fallback_high` (a
`connection-fallback` claim at `high` confidence) is above 0.
