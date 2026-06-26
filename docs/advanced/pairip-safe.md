# PairIP-Protected Apps (`--pairip-safe`)

Google **PairIP** (`libpairipcore.so`) is a VM-based Play-Integrity / anti-tamper
runtime shipped with many Google Play apps (and some large titles such as
Blizzard's *Warcraft Rumble*). It runs a **periodic in-process code-integrity
check** and **self-terminates the app with a `SIGSEGV`** the moment it finds an
inline hook in a library it protects. friTap's normal hooking footprint trips
that check, so the default capture path crashes the target.

`--pairip-safe` is a minimal, **scan-free** Android capture mode designed to
survive PairIP long enough to extract TLS keys.

!!! warning "This is not a PairIP bypass"
    `--pairip-safe` does not defeat or neutralize PairIP. It simply avoids the
    operations PairIP looks for. Capture is best-effort and depends on *where*
    the app's TLS lives (see [Limitations](#limitations)).

---

## The PairIP mental model

Understanding three facts explains everything `--pairip-safe` does:

1. **The kill is an in-process `SIGSEGV`, not a syscall/`ptrace` trick.** PairIP
   checksums loaded code and, on a mismatch, raises `SIGSEGV` from inside the
   app's own threads. You cannot defang it by hooking `kill`/`syscall`.

2. **What trips it is friTap's *broad footprint*, not the act of attaching.**
   Plain `frida -U -f <pkg>` (no script) does **not** crash a PairIP app,
   because it patches no code. The operations PairIP detects are:

   - the inline `android_dlopen_ext` **loader hook**,
   - any **`Memory.scan`** (byte-pattern) over a protected library,
   - **Java/ART** instrumentation,
   - the WebView/Cronet **pattern scan** and the OHTTP loader patch.

3. **In practice, only the app's *own* libraries appear to be in PairIP's
   checksum scope.** This is an observation, not a documented PairIP spec:
   inline hooks on system libraries under `/apex` and `/system` (e.g. Conscrypt's
   `libssl.so`, the mainline `libhttpengine.so`) have been **observed to
   survive**, while an inline hook on an **app-bundled** library (e.g.
   `libunity.so`, shipped inside the split APK) was **detected and the app was
   killed**. That observation is what makes some hooks safe and others risky
   (see [Unity](#unity-libunity-opt-in)).

When friTap detects PairIP it prints:

```
[!!!] ANTI-TAMPER PROTECTION DETECTED: Google PairIP (libpairipcore.so)
  VM-based Play-integrity / anti-tamper; checksums loaded code and self-terminates (SIGSEGV) when it detects an inline hook.
  -> friTap's inline hooks may be detected; the app may crash (SIGSEGV).
  See fkie-cad/friTap#64. There is no in-tool PairIP bypass.
```

---

## What `--pairip-safe` does

| Aspect | Default friTap | `--pairip-safe` |
| --- | --- | --- |
| TLS library selection | auto-detect + library scan | curated **allowlist** only |
| Symbol resolution | exports → symbols → **`Memory.scan`** | exports → symbols → **offsets** (never `Memory.scan`) |
| `android_dlopen_ext` loader hook | yes | **disabled** |
| Java / ART hooks (e.g. provider install) | yes | **disabled** |
| WebView/Cronet pattern scan, OHTTP patch | yes | **disabled** |
| Hook persistence | static | **"blink"** (see below) |

### The allowlist

`--pairip-safe` hooks only the libraries in a single curated list
(`agent/shared/pairip_safe_libs.ts`). Adding a library is one entry in that
array, which automatically extends the registry, the spawn watcher, and the
blink loop. Current entries:

| Library | Type | Resolution | Notes |
| --- | --- | --- | --- |
| `libssl.so` | BoringSSL/OpenSSL | symbol | Conscrypt; system `/apex` (safe) |
| `libhttpengine.so` | BoringSSL | symbol (`.symtab`) | mainline Cronet; system `/apex` (safe) |
| `libjavacrypto.so` | BoringSSL | symbol | Conscrypt JNI |
| `libconscrypt_*jni.so` | BoringSSL | symbol | Conscrypt |
| `libcommerce_http_client.so` | BoringSSL | symbol | app SDK (loads only when used) |
| `libwebviewchromium.so` | BoringSSL | **offset** | System WebView (Chromium); login WebView — see [WebView capture](#capturing-a-stripped-webview-chromium-login) |
| `libunity.so` | MbedTLS (UnityTLS) | **offset, opt-in** | app-bundled; see [Unity](#unity-libunity-opt-in) |

### Scan-free resolution

Under `--pairip-safe` every hook is resolved **without any `Memory.scan`** (the
byte-pattern tier is hard-disabled). For a BoringSSL library the keylog chain is:

1. **`SSL_CTX_set_keylog_callback`** — the public keylog API, resolved from
   exported symbols (`.dynsym`) and, if needed, the full symbol table
   (`.symtab`). The callback it installs is a **heap data field**, not a code
   patch — which is what lets blink work.
2. **`bssl::ssl_log_secret`** — a BoringSSL-internal function called on every
   handshake, used when the callback can't be installed (stripped builds). It is
   resolved in order: full symbol table (`.symtab`, ranked by mangled/exact/
   substring name) → debug symbols → exported symbols → and only as a **last
   resort** an **offset** supplied via `--offsets`.

Offsets are the last resort because they are **fragile across device / library
versions** (see [WebView capture](#capturing-a-stripped-webview-chromium-login)).
Exports and the `.symtab` scan are both scan-free and therefore PairIP-safe;
some `libhttpengine.so` builds, for example, keep `SSL_*` only in `.symtab`.

### Blink persistence

PairIP's integrity check runs *periodically*. Blink exploits the fact that the
keylog callback survives even after the inline `SSL_new` / `SSL_CTX_new` hooks
are detached:

- **Warmup** (~25 s): hooks stay attached ("BRIGHT") so the app's initial
  `SSL`/`SSL_CTX` objects are reliably tagged.
- then **toggle**: BRIGHT (~0.8 s, re-tag new contexts) / **DARK** (~12 s +
  jitter, `.text` pristine) so a random PairIP scan almost always lands in a
  DARK window.

!!! note "Blink shapes *when* you capture"
    Because hooks are detached most of the time after warmup, a **lone** new
    handshake usually lands in a DARK window and is missed. Capture is most
    reliable for handshakes that occur **during the warmup window**. See
    [Forcing traffic](#forcing-traffic-and-the-0-keys-case).

---

## How it works (internals)

The flag flows from the CLI (`friTap/friTap.py`) into `HookingConfig.pairip_safe`
(`friTap/config.py`), is delivered to the agent over the `config_batch`
handshake, and sets the agent global `pairip_safe` (`agent/fritap_agent.ts`).
From there it reshapes the Android hook install (`agent/platforms/android.ts`) in
five ways — these are **structural** decisions made once at install time, not
scattered per-hook runtime checks:

1. **Registry replacement, not filtering.** The hook registry is built solely
   from the allowlist via `buildPairipSafeRegistrations()` instead of the full
   Android hook set (`__androidHooks`). Every Cronet / WebView / QUIC / pattern
   entry is therefore never even a candidate — only `PAIRIP_SAFE_LIBS` is
   registered.
2. **Loader hook forced off.** `loaderHookSkipped` is forced `true`, so neither
   the inline `android_dlopen_ext` trampoline nor the experimental
   hardware-breakpoint "stealth loader" is installed — both would end up hooking
   late-loaded WebView/Cronet libs and trip PairIP. (`--experimental-stealth-loader`
   is disabled under `--pairip-safe`.)
3. **Phases skipped at registration time.** The install is split into yielded
   phases; under `--pairip-safe` only the `ssl-libs` phase is pushed. The `java`
   (ART), `ohttp+scan-results`, `loader+patterns`, and `library-scan` phases are
   gated out (`if (!pairip_safe) phases.push(...)`).
4. **No `Memory.scan`, ever.** Three guards make the byte-pattern tier
   unreachable: the modern BoringSSL keylog chain returns `"none"` before the
   pattern tier (`boringssl_hook_chain.ts`), the pipeline never registers the
   Pattern / MemoryScan strategies (`pipeline_utils.ts`), and the legacy boring
   path refuses to scan (`legacy/.../openssl_boringssl_android.ts`). An
   unresolved library degrades to "no hook" rather than scanning.
5. **Per-library resolution** then proceeds exports → `.symtab` → offsets
   (see [Scan-free resolution](#scan-free-resolution)).

### Catching late-loaded libraries (the watcher)

The `ssl-libs` phase only hooks libraries already resident when it runs (the
attach case). Libraries that load **later** — the spawn case (TLS libs load after
resume) and any late `dlopen` (e.g. the WebView when the login page renders) —
are handled by `installPairipSafeWatcher()` (`agent/shared/shared_functions.ts`),
which uses **no loader hook, no breakpoint, and no `Memory.scan`**:

- it first waits out PairIP's startup integrity window (`firstDelayMs` =
  **8 s for spawn, 1.5 s for attach**) and re-scans for already-resident targets;
- it then watches for new module loads via **`Process.attachModuleObserver`**
  (Frida 17.x — event-driven, no code patch), with a **`setInterval` poll
  (~1 s)** fallback when the observer API is unavailable;
- all hooking runs on the JS thread via `setTimeout(0)`, never synchronously
  inside a loader callback on the app thread (which could perturb PairIP
  mid-`dlopen`).

The watcher's membership test is the same `matchPairipSafeLib()` predicate that
built the registry, so registry, watcher, and blink loop always agree on the
target set — adding one `PAIRIP_SAFE_LIBS` entry extends all three.

### Persistence and teardown

Each installed BoringSSL keylog hook registers itself with the
[blink](#blink-persistence) loop (`registerBlinkTarget()`), which roots the
keylog `NativeCallback` permanently and toggles the inline `SSL_new` /
`SSL_CTX_new` hooks. On detach, `gracefulDetach` calls `stopBlink()` before
`Interceptor.detachAll()` so the toggling stops cleanly. (The Unity
`ssl_compute_master` scrape is an inline `.text` hook that does **not** blink —
see [Unity](#unity-libunity-opt-in).)

---

## Usage

```bash
# Attach (the proven path) — app already running:
fritap -m -k keys.log --pairip-safe -v <pid|package>

# Spawn — catches more of startup, but hooks are deferred (see below):
fritap -m -k keys.log --pairip-safe -v -s com.example.app
```

### Attach vs spawn

- **Attach** is the proven path. Hooks install within ~2 s of attach.
- **Spawn** (`-s`) defers hook installation **~8 s past resume** to let PairIP's
  startup integrity sweep finish before any hook lands. The trade-off: the app's
  **earliest** handshakes (which often complete in the first few seconds) are
  **missed**. Spawn does not magically produce keys — see below.

---

## Forcing traffic and the "0 keys" case

!!! tip "0 keys is usually *no catchable traffic*, not a broken hook"
    If a run captures 0 keys, the hooks almost certainly installed fine — the
    app just didn't perform a TLS handshake on a hooked library **during the
    capture window**. Verify with `adb shell` (as root):

    ```bash
    # the target's own :443 connections (replace <pid>)
    adb shell "su -c 'ss -tunp | grep :443 | grep pid=<pid>'"
    ```

    An app sitting on a cached-session main menu is frequently **network-idle**
    (zero of its own `:443` sockets); there is simply nothing to capture.

To capture, you need a **fresh handshake on a hooked library while hooks are
attached** (ideally during warmup). Options:

- **Drive the app**: log in, enter a screen that fetches data, start gameplay —
  whatever causes new TLS.
- **Toggle connectivity** to force reconnect handshakes — but only useful when
  the app has live connections it will re-establish:

  ```bash
  adb shell cmd connectivity airplane-mode enable
  adb shell cmd connectivity airplane-mode disable
  ```

  Do this **right after** the `keylog hooks installed` banner so reconnects land
  inside the warmup window.

---

## Capturing a stripped WebView / Chromium login

Many apps render their login (e.g. a Battle.net OAuth page) in an in-app WebView
backed by the **Android System WebView (Chromium)**. Its
`libwebviewchromium.so`:

- **loads lazily** — only when a WebView is first rendered, so it is absent from
  an early `Process.enumerateModules()` (you'll see only the
  `*_loader.so` / `*_plat_support.so` stubs);
- statically links BoringSSL and is **fully stripped** — no `SSL_*` symbols in
  `.dynsym` or `.symtab`, and Chromium installs no keylog callback.

Neither `enumerateExports`/`enumerateSymbols` nor (under `--pairip-safe`)
`Memory.scan` can reach it. The one scan-free hook point is the BoringSSL
internal **`bssl::ssl_log_secret(ssl, label, secret)`**, which is called on
every handshake — friTap reads its arguments on entry, so it works even though
no keylog callback is set. You supply its **offset** via `--offsets`.

### Finding the offset: `dev/find_ssl_log_secret_offset.py`

!!! danger "The offset is target-specific"
    A `ssl_log_secret` offset is valid **only** for the exact `.so` it was
    derived from — a given **WebView version + architecture** (or, for Unity, a
    given app's `libunity.so` build). System WebView updates roughly monthly,
    so the offset **will drift**. Re-derive it for *your* device/version; do not
    hard-code or copy an offset from another device.

The helper (`lief` + `capstone`, no symbols required) finds it by locating the
TLS keylog label strings, following the `ADRP`+`ADD`+`BL` call sites that pass
each label to `ssl_log_secret`, and **voting**: the `BL` target shared by the
most labels is the function. It validates the hit with a prologue check and
prints a ready-to-use `--offsets` JSON.

```bash
# 1. pull the device's exact System WebView .so
adb shell pm path com.google.android.webview          # -> base.apk path
adb pull <base.apk> /tmp/webview.apk
python3 - <<'PY'
import zipfile; zipfile.ZipFile('/tmp/webview.apk').extract('lib/arm64-v8a/libwebviewchromium.so','/tmp/wv')
PY

# 2. derive the offset (or pass --apk /tmp/webview.apk to do extraction for you)
python3 dev/find_ssl_log_secret_offset.py /tmp/wv/lib/arm64-v8a/libwebviewchromium.so
```

Example output (Pixel 7, System WebView **149.0.7827.91**, arm64 — *your offset
will differ*):

```
[*] load bias: 0x0
[*] labels found: CLIENT_RANDOM@0x2a775d, CLIENT_HANDSHAKE_TRAFFIC_SECRET@0x296740, ...
[*] candidate BL targets (votes = distinct labels calling it):
      0x5adbb60  votes=4  (CLIENT_HANDSHAKE_TRAFFIC_SECRET, CLIENT_RANDOM, CLIENT_TRAFFIC_SECRET_0, SERVER_TRAFFIC_SECRET_0)
      0x3c6b0a0  votes=1  (SERVER_HANDSHAKE_TRAFFIC_SECRET)
================================================================
  ssl_log_secret @ vaddr 0x5adbb60  (votes=4: ...)
  runtime-relative offset: 0x5adbb60  (load bias 0x0)
  prologue valid: YES
      0x5adbb60: paciasp
      0x5adbb64: sub sp, sp, #0x80
      0x5adbb68: stp x29, x30, [sp, #0x40]
      ...
================================================================

--offsets argument:
  {"libwebviewchromium.so": {"ssl_log_secret": {"address": "0x5adbb60", "absolute": false}}}
```

### Capturing with the offset

```bash
fritap -m -k keys.log --pairip-safe -v \
  --offsets '{"libwebviewchromium.so":{"ssl_log_secret":{"address":"0x5adbb60","absolute":false}}}' \
  <pid|package>
```

The library loads lazily, so attach first, then **navigate to the login page**
(the page load itself is HTTPS — you do not need valid credentials to produce a
handshake). The spawn/late-load watcher installs the hook the moment
`libwebviewchromium.so` appears.

---

## Unity (libunity, opt-in)

Unity games carry a statically-linked **MbedTLS** (UnityTLS) inside
`libunity.so`, used by native `UnityWebRequest` traffic. It is stripped (no
`ssl_compute_master`/`mbedtls_*`/`unitytls_*` symbols), so friTap offset-hooks
`ssl_compute_master` and scrapes the master secret as a TLS 1.2 `CLIENT_RANDOM`
keylog line.

!!! warning "This hook is opt-in, by design"
    `libunity.so` is **app-bundled** (inside PairIP's checksum scope) and, unlike
    the BoringSSL keylog callback, the scrape is an **inline `.text` hook that
    does not blink** — a PairIP sweep can find it and `SIGSEGV` the app
    (observed death marker: `install-tls-hooks: libunity.so`). On at least one
    title (Warcraft Rumble) the hook was also measured as **never firing** (the
    app routes TLS through Conscrypt/Cronet/Chromium, not UnityTLS). So friTap
    does **not** auto-install it. To force it, pass its offset explicitly:

    ```bash
    fritap -m -k keys.log --pairip-safe -v \
      --offsets '{"libunity.so":{"ssl_compute_master":{"address":"0x...","absolute":false}}}' <pid>
    ```

    When skipped, friTap prints the known offset for the detected build as a
    copy-paste hint. The hook also logs a **fire-count** so you can confirm
    whether Unity's TLS is exercised at all before relying on it.

---

## Limitations

- **Best-effort, not a bypass.** A PairIP sweep can still coincide with an
  attached inline hook (especially the opt-in Unity hook, or during warmup).
- **Offsets are target-specific and fragile** — re-derive per device/version.
- **Coverage is limited to the allowlist.** TLS that flows through a library not
  in the list (or one whose offset you haven't supplied) is not captured.
- **Spawn misses the earliest handshakes** (deferred hooking); attach is proven.
- **Android only.**

## See also

- [CLI Reference](../api/cli.md) — `--pairip-safe`, `--offsets`, `-s/--spawn`
- [BoringSSL](../libraries/boringssl.md) — keylog chain & `ssl_log_secret`
- [Troubleshooting → PairIP](../troubleshooting/common-issues.md#anti-tamper-integrity-protected-apps-pairip)
- friTap issue [fkie-cad/friTap#64](https://github.com/fkie-cad/friTap/issues/64)
