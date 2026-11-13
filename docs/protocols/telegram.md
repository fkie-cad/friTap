# Telegram (MTProto)

friTap extracts Telegram's MTProto keys on Android and decrypts captured
Telegram traffic offline. Unlike TLS/QUIC, where friTap shells out to tshark,
**tshark cannot decrypt MTProto**, so friTap ships its own MTProto decryptor.

What works today is **key extraction plus offline decryption**:

1. **Live key hook**: friTap hooks tgnet's `Datacenter::getAuthKey` in the running
   app and writes `MTPROTO_AUTH_KEY` lines (plus `MTPROTO_E2E_KEY` lines with
   `--protocol telegram`) to the `-k` keylog.
2. **Memory scan**: `-ms mtproto` (alias `-ms telegram`) recovers
   `MTPROTO_AUTH_KEY`, `MTPROTO_E2E_KEY` and `MTPROTO_OBF_KEY` lines from the
   heap into a `<stem>.mtproto.keylog` sidecar.
3. **Offline decryption**: `fritap --from-pcap ... --mtproto-keylog` (or
   `--telegram-keylog`) decrypts a pcap recorded in the same session into a
   `.tap`.

!!! warning "Planned / future work: live MTProto plaintext"
    Live plaintext hooks (decrypted MTProto messages delivered straight from the
    agent into a `.tap`, without a keylog and a pcap) are **planned and not
    implemented yet**. The tgnet plaintext byte patterns in
    `agent/mtproto/definitions/tgnet.ts` (`decryptInbound` / `encryptOutbound`)
    are empty TODOs, and the symbol-only fallback does not resolve on stripped
    release builds. To read Telegram messages today, record a pcap together with
    the keys and decrypt it offline, as described below.

    The agent also contains experimental Java hooks (`SecretChatHelper`) that emit
    **secret-chat** text in plaintext (`-p`) mode. They are not device-validated
    and do not cover cloud chats; do not rely on them in place of the offline path.

Telegram has **two distinct encryption layers**, and friTap's keys and offline
decryptor cover both:

| Layer | What it protects | End-to-end? | Key line |
|-------|------------------|-------------|----------|
| **Cloud chats** | MTProto **transport** encryption between the client and Telegram's servers | **No**: Telegram holds the key and can read cloud chats | `MTPROTO_AUTH_KEY` |
| **Secret chats** | MTProto 2.0 **end-to-end** encryption between two devices (per-chat DH key) | **Yes**: device to device only | `MTPROTO_E2E_KEY` |

The umbrella **`--protocol telegram`** extracts keys for **both** layers in one
run; the lower-level **`--protocol mtproto`** extracts cloud transport keys only.

!!! warning "Cloud chats are not end-to-end"
    Cloud chats use MTProto **transport** encryption only: the messages are visible
    to Telegram's servers, and the `MTPROTO_AUTH_KEY` friTap extracts is the
    client-to-server transport key, **not** an end-to-end key. Only **secret chats**
    (`MTPROTO_E2E_KEY`) are end-to-end encrypted.

!!! warning "Authorized analysis only"
    friTap is a defensive security research tool (Fraunhofer FKIE). MTProto support
    requires key material extracted from a device **you are authorized to inspect**
    (your own device, a research/consented investigation). It performs no remote or
    over-the-network key recovery. Secret chats are end-to-end encrypted, so their
    keys exist only on the two participating devices; you must control (or have
    consent from) **both** parties. Auth keys grant full access to the Telegram
    account: treat every keylog as secret and delete it after the analysis.

## How it works

Telegram Android (`org.telegram.messenger`) uses the native **tgnet** library
(`libtmessages.*.so`), not TDLib. Requirements: a rooted **Android arm64** device
or emulator with a matching frida-server. The tgnet byte pattern and the
memory-scan profile exist for arm64 only (arm32 and x86_64 are TODO).
Device-validated on Telegram 12.8.1; other builds may need new patterns.

| Step | What you get | Notes |
|------|--------------|-------|
| **1. Live key hook** | `MTPROTO_AUTH_KEY` (+ `MTPROTO_E2E_KEY`) lines in the `-k` keylog | `Datacenter::getAuthKey` is a stripped local symbol; friTap finds it by an arm64 byte pattern (`friTap/patterns/default_mtproto.json`) |
| **2. Memory scan (optional)** | `MTPROTO_AUTH_KEY`, `MTPROTO_E2E_KEY`, `MTPROTO_OBF_KEY` in `<stem>.mtproto.keylog` | Hook-free heap scan; also recovers the obfuscated-transport CTR state of connections that were already open |
| **3. Offline decryption** | A `.tap` with decrypted MTProto messages | `--from-pcap` with `--mtproto-keylog` / `--telegram-keylog`; the keylog ties each record's `auth_key_id` to its `auth_key` |

!!! note "PFS / temporary keys"
    Telegram enables Perfect Forward Secrecy: transport traffic is encrypted with
    **ephemeral temporary auth keys**, not the permanent key stored in `tgnet.dat`.
    friTap therefore captures the key **at runtime** (the in-use temp key), so the
    keylog must be recorded **during** the same session as the pcap.

## Phase 0 (on-device setup)

The bundled MTProto agent module hooks `Datacenter::getAuthKey` inside
`libtmessages.*.so`. Its hook points are derived once, on-device, by the
**Phase-0 experiment scripts** at
[`research/mtproto_phase0/`](https://github.com/fkie-cad/friTap/tree/main/research/mtproto_phase0).
They are reverse-engineering aids; you only need them when porting the agent to a
new tgnet build, **not** for everyday captures:

* **Hook offsets / byte-patterns**: resolve the function offsets (or stable byte
  patterns for stripped builds) that the agent attaches to.
* **`auth_key` / `auth_key_id` extraction**: confirm where the runtime temp key
  and its 8-byte id live so the keylog lines verify against captured records.
* **Transport / framing checks**: validate de-obfuscation and abridged /
  intermediate framing against live traffic before wiring the offsets into the
  agent.

Each experiment resolves one input the agent needs; once the offsets are folded
into the shipped agent module, normal captures (below) require none of this. The
same scripts are the starting point for the planned plaintext hook patterns.

## Crypto backend

Offline decryption needs an AES backend, **`cryptography`**: it does both the
transport AES-CTR de-obfuscation and the AES-IGE record decryption. This ships in
friTap's base install, so `pip install friTap` covers it (no extra needed). For a
lean install you can pull it in directly:

```bash
pip install cryptography
```

`tgcrypto` is an **optional speed-up** that only accelerates AES-IGE; it cannot
replace `cryptography` (it can't do the transport CTR). It is installed
automatically with the base on platforms where a wheel exists, so no separate
step is needed.

If the backend is missing (e.g. on a lean install), the live/offline CLI and the
TUI protocol picker print an actionable install hint instead of failing obscurely.

## Usage

### 1. Live key extraction (getAuthKey hook)

Spawn (`-s`) so every connection is captured from its first byte. `-f` records
the real encrypted traffic and **requires `-p <file>`**; `-k <file>` receives the
key lines. The package name stays the positional target.

```bash
# Cloud + secret-chat keys into one combined keylog, plus the encrypted pcap
fritap -m -s --protocol telegram -f -p tg.pcapng -k tg.keys org.telegram.messenger

# Cloud transport keys only, stop after 3 minutes
fritap -m -s --protocol mtproto -f -p tg.pcapng -k tg.keys --duration 180 org.telegram.messenger
```

On success friTap logs
`[TGNET_Telegram] Hooked Datacenter::getAuthKey at ... (byte pattern)`. Open a
few chats and send messages while it runs; for secret chats send several messages
so their keys are in use.

With `--protocol telegram`:

* **Cloud chats**: the transport key comes from the native
  `Datacenter::getAuthKey` hook and is written as `MTPROTO_AUTH_KEY`
  (same as `--protocol mtproto`).
* **Secret chats**: the end-to-end key comes from Java
  (`SecretChatHelper` / `TLRPC$EncryptedChat.auth_key`) and is written as
  `MTPROTO_E2E_KEY`.

Both kinds of line go to **one combined keylog** (the `-k` file), so a single
keylog feeds the offline decryptor for cloud *and* secret chats.
`--protocol telegram` refuses to run without a capture intent (`-k`, `-p` or
`-f -p`).

### 2. Memory scan (`-ms mtproto` / `-ms telegram`)

The hook-free heap scanner works on an already-running app (attach, no `-s`). It
recovers cloud keys, secret-chat keys and, via **Tier E**, the live
obfuscated-transport CTR state (`MTPROTO_OBF_KEY`) of open connections, which lets
the offline decryptor recover streams that started before the capture.

```bash
# Keys only
fritap -m -ms mtproto org.telegram.messenger

# Keys + encrypted pcap (`-ms telegram` is an alias for `-ms mtproto`)
fritap -m -ms telegram -f -p tg.pcapng org.telegram.messenger

# Hook and memory scan together
fritap -m --protocol telegram -f -p tg.pcapng -k tg.keys -ms mtproto org.telegram.messenger

# Faster polling
fritap -m -ms mtproto --memory-scan-interval 1.0 -f -p tg.pcapng org.telegram.messenger
```

`-ms` takes an optional value, so put the target after the engine name. Keep
Telegram in the foreground and exchange messages during the scan: a connection
must be alive during a scan pass for its CTR state to be recovered.
`--ms-emit-unconfirmed` also writes MTProto candidates the SHA1 oracle could not
verify (harmless offline, more noise).

The scan writes a sidecar `<stem>.mtproto.keylog`. With `-k tg.keys` the stem is
`tg.memscan` (`tg.memscan.mtproto.keylog`); without `-k` it is
`<target>_memscan` in the current directory. Check counts without printing keys:

```bash
cut -d' ' -f1 tg.memscan.mtproto.keylog | sort | uniq -c
```

### 3. Offline decryption

`--mtproto-keylog` and `--telegram-keylog` both feed friTap's own decryptor and
decrypt **cloud chats and the secret-chat (E2E) messages carried inside them**
from one keylog, given `MTPROTO_AUTH_KEY` and `MTPROTO_E2E_KEY` lines. Pass the
hook keylog or the memory-scan sidecar:

```bash
fritap --from-pcap tg.pcapng --telegram-keylog tg.keys --tap tg.tap
fritap --from-pcap tg.pcapng --mtproto-keylog tg.memscan.mtproto.keylog --tap tg.tap

# Search further behind the live CTR counter for mid-stream recovery
fritap --from-pcap tg.pcapng --mtproto-keylog tg.memscan.mtproto.keylog \
    --resync-search-depth 16384 --tap tg.tap

fritap --analyze tg.tap            # passive analysis + findings report
```

`--resync-search-depth` (default 4096 blocks, about 64 KB, for MTProto) bounds how
far behind the live CTR counter mid-stream recovery searches; raise it when the
scan ran long after the traffic.

`--mtproto-keylog` / `--telegram-keylog` are deliberately separate from `--keylog`
(NSS/TLS, consumed by tshark): MTProto keys are consumed by friTap's own decryptor.
Both can be combined on one capture.

Read the offline summary counters: `mtproto messages` > 0, `recovered streams`
for mid-stream recovery, `degraded streams` / `undecryptable records` ideally 0.
See [Offline pcap to .tap](../advanced/offline-pcap-to-tap.md) for the counters.

!!! info "Device-validated (`org.telegram.messenger` 12.8.1, Android arm64)"
    Cloud-chat key extraction (across multiple datacenters), secret-chat E2E key
    extraction, and offline decryption of real captured cloud traffic are all
    device-validated.

## Keylog format

One canonical, comment-tolerant line format (the single source of truth lives in
`friTap/protocols/mtproto_keylog_spec.py`, imported by both the live writer and the
offline reader):

```
# friTap MTProto keylog v1 — format: MTPROTO_AUTH_KEY <dc_id> <auth_key_id_hex16> <auth_key_hex512> <key_type>
MTPROTO_AUTH_KEY 2 a1b2c3d4e5f60718 <512-hex chars> temp
MTPROTO_E2E_KEY <key_fingerprint_hex16> <shared_key_hex512> <chat_id> [<peer_user_id>]
MTPROTO_OBF_KEY <key_out_hex64> <iv_out_hex32> <key_in_hex64> <iv_in_hex32> <num_out> <num_in> <endpoint|->
```

* `auth_key_id` (8 bytes) is the join key present in every MTProto record header.
* `key_type` is `perm` or `temp` (PFS).
* `MTPROTO_E2E_KEY` is the per-secret-chat end-to-end key. The live hook writes it
  with `--protocol telegram`; the memory scan writes it too.
* `MTPROTO_OBF_KEY` is the live obfuscated-transport AES-256-CTR state of one
  connection. Only the memory scan (Tier E) writes it.

The offline reader consumes all three line types from one file.

## What lands in the `.tap`

A decrypted MTProto flow carries an `MtprotoLayer` whose owned bytes are the
**decrypted MTProto message payloads** (the TL-serialized bodies) per direction;
secret-chat messages appear as a `telegram_e2e` layer. friTap does **not** parse
the full Telegram TL schema; that is left to a parser you plug in (drop a
`BaseParser` subclass with `is_fritap_parser = True` into the friTap `parsers/`
data dir, or ship it via the `fritap.parsers` entry-points group).

## Scope & limitations

* **Supported:** key extraction for cloud chats (transport) and **secret chats
  (end-to-end)** via the live hook and the memory scan; offline cloud +
  secret-chat decryption via `--mtproto-keylog` / `--telegram-keylog`; obfuscated
  transport; abridged & intermediate framing.
* **Both secret-chat parties required:** secret chats are end-to-end, so their key
  exists only on the two participating devices; you must capture from a device that
  is one of the two parties.
* **E2E keys need the transport key:** secret-chat messages travel inside the
  cloud transport, so an E2E-only keylog yields no flows; `MTPROTO_AUTH_KEY` is
  required too.
* **Capture from connection start when you can:** de-obfuscation needs the first
  64 bytes of each stream. Spawning (`-s`), or force-stopping and relaunching
  before attaching, is the most reliable. When you attach to a running app, add
  `-ms mtproto` as the fallback: Tier E recovers the CTR state of connections that
  are alive during a scan pass (`MTPROTO_OBF_KEY`), so the offline decryptor can
  resume them mid-stream. Tier E offsets are build-specific (an RTTI walk finds
  the anchor on newer builds); if the scan logs
  `[Tier E] 0 live Connection objects matched the vtable anchor`, no connection
  was alive or the build needs recalibration.
* **Degrades gracefully (skipped + counted, never garbage):** streams whose
  obfuscation init was missed and no `MTPROTO_OBF_KEY` aligned (`degraded streams`),
  records whose `auth_key_id` matches no captured key (likely a perm/temp mismatch
  or a keylog from another session).
* **Future / not implemented:** live MTProto plaintext hooks (see the warning at
  the top), Fake-TLS / padded-intermediate transports, MTProto-over-QUIC, arm32 /
  x86_64 patterns, and non-Android platforms.
