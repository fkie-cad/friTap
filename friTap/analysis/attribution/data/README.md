# Attribution datasets

Bundled, **offline** data used by `friTap.analysis.attribution` to map a
captured host to its owning entity, a tracker category, and a first-/third-party
verdict. The files are read lazily at runtime; nothing here is fetched over the
network at import or call time. The PSL snapshot and the optional local-only
`trackers_full.json` are regenerated with
[`dev/update_tracker_radar.py`](../../../../dev/update_tracker_radar.py).

## `trackers.json`

Curated `domain -> {owner, category}` map, shipped with friTap.

- **Provenance:** a **curated seed** (`"kind": "seed"`), authored and
  hand-maintained by the friTap project. It contains **no** DuckDuckGo
  Tracker Radar data.
- **Category slugs:** `advertising`, `analytics`, `social`, `tag_manager`,
  `cdn`, `crash_reporting`, `other` (the same set the full map uses).
- **License:** GPL-3.0-only, like friTap itself.

### Seed vs. full

`trackers.json` is the **curated seed** that ships with friTap: a
hand-maintained set covering the major tracking/advertising/analytics
entities. It gives useful coverage without bundling any third-party tracker
list.

`trackers_full.json` is the optional **full distillation** (`"kind": "full"`)
of the [DuckDuckGo Tracker Radar](https://github.com/duckduckgo/tracker-radar)
`domains/` tree:

- **Generated locally** with `python dev/update_tracker_radar.py` (pin the
  upstream revision with `--ref`). For each domain file it keeps only the
  owner display name (`owner.displayName`, falling back to `owner.name`) and
  one normalised category slug, chosen from the file's `categories` array by
  the fixed priority in `CATEGORY_PRIORITY`, so the output is deterministic.
- **License:** Tracker Radar data is licensed
  [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/), and
  so is this distillation (it credits DuckDuckGo Tracker Radar in its
  `source`/`source_url`/`license` keys).
- **Local-only:** the file is gitignored and is **never** committed,
  published or packaged (it is not in `package_data` or `MANIFEST.in`).
- **Precedence:** when the file is present, the resolver loads it instead of
  the seed (`friTap.analysis.attribution.resolver.default_trackers_path`); an
  explicit `TrackerResolver(trackers_path=...)` always wins. Seed and full
  files share one format.

## `sdk_signatures.json`

Distilled `prefix -> {sdk, vendor, category}` table used by
`friTap.analysis.attribution.sdk` to map a captured **call stack** (Java/ObjC
class or package names, and native module names) to the SDK that emitted the
request. Read lazily at runtime; fully offline at import and call time.

- **Provenance:** a **curated seed** (`"kind": "seed"`), hand-maintained by the
  friTap project. It covers the major Android SDKs across advertising,
  analytics, attribution, crash reporting, push, networking and
  cross-platform frameworks (Facebook SDK, Firebase/Crashlytics, Google Mobile
  Ads, AppsFlyer, Adjust, Branch, Amplitude, Segment, Sentry, Bugsnag, Flurry,
  Unity/Unity Ads, AppLovin, ironSource, Vungle, Chartboost, OneSignal,
  Airship, Braze, Mixpanel, OkHttp/Retrofit, Flutter, React Native, Cronet,
  ...). The seed itself is friTap-authored and bundles **no** third-party data.
- **Category slugs:** `advertising`, `analytics`, `social`, `attribution`,
  `crash_reporting`, `push`, `payment`, `maps`, `networking`, `framework`,
  `transport`, `other`.
- **Matching:** longest dotted-prefix wins and matching is on a dot boundary,
  so `com.google.firebase.crashlytics.*` resolves to Crashlytics rather than
  the broader Firebase entry, and `com.facebookx` never matches `com.facebook`.
- **Transport entries (`transport_kind`):** an entry may carry an optional
  `transport_kind`. It marks a module that *carries* traffic (the transport)
  rather than one that *causes* it (the originator). The dedicated transport
  entries use `category: "transport"` (libmonochrome, libchrome,
  libwebviewchromium, libmainlinecronet, libhttpengine, stable_cronet_libssl,
  libsignal_jni, Google Chrome Framework, chrome.dll, Electron Framework,
  Chromium Embedded Framework, libcef); the pre-existing `libcronet`
  (`cronet`) and `libflutter.so` (`flutter`) entries keep their original
  `sdk`/`vendor`/`category` and only gain `transport_kind`.
  - **Deny-list:** `classify_frames` never returns a native module whose entry
    has a `transport_kind` as the originator; it skips it and keeps scanning.
    Java/ObjC frame matching is unaffected.
  - **`classify_transport(module, path, process_name, package_name)`** returns
    `{"module": <basename>, "kind": <kind>}`. It matches the module
    **basename** case-insensitively: a key matches as a prefix followed by end,
    `.`, `_` or `-` (so `libmonochrome_64.so` and `libcronet.143.7445.0.so`
    match); keys ending in `.so`/`.dll` must match exactly. Longest key wins.
  - **`chrome-or-webview`** (libmonochrome, libchrome) is a sentinel: it
    resolves to `chrome` when the package or process name (any `:suffix`
    stripped, case-insensitive) is listed in the top-level
    `chromium_browser_packages` array, and to `webview` otherwise. Kind
    `chrome` means "a Chromium-based browser's own network stack", not only
    Google Chrome: the list covers Chrome (`com.android.chrome`,
    `com.google.android.apps.chrome`, `org.chromium.chrome`, Frida's friendly
    name `chrome`, `com.chrome.*` for beta/dev/canary), Brave, Microsoft Edge
    (`com.microsoft.emmx`, `com.microsoft.emmx.*`), Samsung Internet, Vivaldi,
    Opera, Kiwi and Yandex. Each item is an exact name or a `prefix*` pattern
    (a single trailing `*`; `com.chrome.*` does not match `com.chrome`
    itself). Browsers that render through the system WebView (DuckDuckGo) or
    are not Chromium (Opera Mini) stay off the list. The array is optional:
    without it the resolver falls back to the Chrome-only default
    (`DEFAULT_CHROMIUM_BROWSER_PACKAGES`); `dev/update_sdk_signatures.py`
    keeps it, sorted and deduplicated.
  - **GMS Cronet:** kind `cronet` resolves to `gms-cronet` when the module path
    contains `com.google.android.gms` or `/dynamite` (case-insensitive).
- **`chromium_internal_hosts`** (top-level list, optional): hosts of
  Chromium/WebView/Cronet's own background services. Each item is an exact
  host (`update.googleapis.com`) or a `*.suffix` pattern (`*.gvt1.com` matches
  `x.gvt1.com`, not `gvt1.com`); matching ignores case, port and a trailing
  dot. An unattributed flow on a Chromium-family transport whose Host /
  `:authority` (else TLS SNI) matches gets `attribution.bucket =
  "chromium-internal"`; a later originator claim drops that bucket. Invalid
  items are warned about and dropped; a missing key means an empty list.
  `dev/update_sdk_signatures.py` keeps the list sorted and deduplicated.
  Bundled entries and why each is internal:
  - `safebrowsing.googleapis.com`: Safe Browsing list updates and lookups.
  - `update.googleapis.com`: component updater (Omaha).
  - `*.gvt1.com`: component/update download CDN (`redirector.gvt1.com`, `edgedl.me.gvt1.com`).
  - `optimizationguide-pa.googleapis.com`: Optimization Guide hints and models.
  - `clientservices.googleapis.com`: Finch variations seed.
  - `content-autofill.googleapis.com`: Autofill server queries.
  - `dns.google`: Secure DNS (DoH) auto-upgrade.
  - `clients2.google.com`: extension/CRX updates and crash uploads.
  - `clients4.google.com`: Chrome sync and background services.

  Deliberately excluded because apps call them directly: `www.gstatic.com`,
  `accounts.google.com`, `android.clients.google.com`.
- **Overlays (`FRITAP_SDK_SIGNATURES`):** extra signature files in the same
  format can be layered over the bundled table. Set
  `FRITAP_SDK_SIGNATURES=path[:path]` (`os.pathsep`-separated; empty parts are
  ignored) for the module-level resolver, or pass
  `SdkResolver(extra_paths=[...])`. Overlay entries win per key; an overlay's
  `chromium_browser_packages` and `chromium_internal_hosts` are **unioned**
  with the bundled lists (an overlay may carry only those arrays, no `entries`). A missing or invalid overlay file,
  or an invalid browser pattern, is logged as a warning and skipped, never
  fatal.
- **Optional enrichment (Exodus Privacy):** the canonical package -> tracker
  signature source is [Exodus Privacy](https://reports.exodus-privacy.eu.org/)
  (`https://reports.exodus-privacy.eu.org/api/trackers`; each tracker carries a
  `code_signature` / `network_signature`). Exodus data is licensed under the
  **GNU AGPL** and is therefore **NEVER bundled** here. The optional updater
  [`dev/update_sdk_signatures.py`](../../../../dev/update_sdk_signatures.py)
  can fetch and merge it **only** when the operator explicitly opts in with
  `--merge-exodus`; that is the sole place in this feature that touches the
  network, and the fetched data stays on the operator's machine unless they
  choose to commit the regenerated file (which then becomes `"kind": "merged"`).

## `public_suffix_list.dat`

Verbatim snapshot of the Mozilla Public Suffix List, used to compute the
registrable domain (eTLD+1) offline.

- **Provenance:** <https://publicsuffix.org/list/public_suffix_list.dat>
  (the only URL upstream supports pulling from). The snapshot's `// VERSION:`
  and `// COMMIT:` header lines record exactly which revision is bundled.
- **License:** Mozilla Public License, v. 2.0 (MPL-2.0), as stated at the top
  of the file itself.
