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
  `other`.
- **Matching:** longest dotted-prefix wins and matching is on a dot boundary,
  so `com.google.firebase.crashlytics.*` resolves to Crashlytics rather than
  the broader Firebase entry, and `com.facebookx` never matches `com.facebook`.
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
