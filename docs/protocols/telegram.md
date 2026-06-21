# Telegram (MTProto)

friTap can decrypt Telegram traffic on Android. Unlike TLS/QUIC — where friTap
shells out to tshark — **tshark cannot decrypt MTProto**, so friTap ships its own
MTProto decryptor.

Telegram has **two distinct encryption layers**, and friTap supports both:

| Layer | What it protects | End-to-end? | Key line |
|-------|------------------|-------------|----------|
| **Cloud chats** | MTProto **transport** encryption between the client and Telegram's servers | **No** — Telegram holds the key and can read cloud chats | `MTPROTO_AUTH_KEY` |
| **Secret chats** | MTProto 2.0 **end-to-end** encryption between two devices (per-chat DH key) | **Yes** — device↔device only | `MTPROTO_E2E_KEY` |

The umbrella **`--protocol telegram`** covers **both** layers in one run; the
lower-level **`--protocol mtproto`** captures cloud-chat transport only and remains
available for reuse. See [`--protocol telegram` (cloud + secret chats)](#protocol-telegram-cloud--secret-chats)
below.

!!! warning "Cloud chats are not end-to-end"
    Cloud chats use MTProto **transport** encryption only: the messages are visible
    to Telegram's servers, and the `MTPROTO_AUTH_KEY` friTap extracts is the
    client↔server transport key — **not** an end-to-end key. Only **secret chats**
    (`MTPROTO_E2E_KEY`) are end-to-end encrypted.

!!! warning "Authorized analysis only"
    friTap is a defensive security research tool (Fraunhofer FKIE). MTProto support
    requires key material extracted from a device **you are authorized to inspect**
    (your own device, a research/consented investigation). It performs no remote or
    over-the-network key recovery. Secret chats are end-to-end encrypted, so their
    keys exist only on the two participating devices — you must control (or have
    consent from) **both** parties.

## How it works

Telegram Android (`org.telegram.messenger`) uses the native **tgnet** library
(`libtmessages.tmessages.so`), not TDLib. There are two supported workflows:

| Phase | What you get | Notes |
|-------|--------------|-------|
| **A — live plaintext** | Decrypted MTProto messages captured straight into a `.tap` | Hooks the post-decrypt buffer in tgnet; robust, works regardless of key type |
| **B — keylog + offline** | An MTProto keylog + a `pcap → .tap` offline decryptor | Re-analyze captured pcaps; the keylog ties each record's `auth_key_id` to its `auth_key` |

!!! note "PFS / temporary keys"
    Telegram enables Perfect Forward Secrecy: transport traffic is encrypted with
    **ephemeral temporary auth keys**, not the permanent key stored in `tgnet.dat`.
    friTap therefore captures the key **at runtime** (the in-use temp key), so the
    keylog must be recorded **during** the same session as the pcap.

## Phase 0 (on-device setup)

The bundled MTProto agent module hooks the post-decrypt buffer and the in-use
temp `auth_key` inside `libtmessages.tmessages.so`. Those hook points are derived
once, on-device, by the **Phase-0 experiment scripts** at
[`research/mtproto_phase0/`](https://github.com/fkie-cad/friTap/tree/main/research/mtproto_phase0).
They are reverse-engineering aids — you only need them when porting the agent to a
new tgnet build, **not** for everyday captures:

* **Hook offsets / byte-patterns** — resolve the function offsets (or stable byte
  patterns for stripped builds) that the agent attaches to.
* **`auth_key` / `auth_key_id` extraction** — confirm where the runtime temp key
  and its 8-byte id live so the keylog lines verify against captured records.
* **Transport / framing checks** — validate de-obfuscation and abridged /
  intermediate framing against live traffic before wiring the offsets into the
  agent.

Each experiment resolves one input the agent needs; once the offsets are folded
into the shipped agent module, normal captures (below) require none of this.

## Crypto backend

Offline decryption needs an AES backend, **`cryptography`** — it does both the
transport AES-CTR de-obfuscation and the AES-IGE record decryption. This now
ships in friTap's base install, so `pip install friTap` covers it (no extra
needed). For a lean install you can pull it in directly:

```bash
pip install cryptography
```

`tgcrypto` is an **optional speed-up** that only accelerates AES-IGE — it cannot
replace `cryptography` (it can't do the transport CTR). It is installed
automatically with the base on platforms where a wheel exists, so no separate
step is needed.

If the backend is missing (e.g. on a lean install), the live/offline CLI and the
TUI protocol picker print an actionable install hint instead of failing obscurely.

## Usage

### Live capture (Phase A / B)

```bash
# Live: decrypted MTProto straight into a .tap
fritap -m --protocol mtproto org.telegram.messenger

# Live full capture: pcap + MTProto keylog together (for later offline re-analysis)
fritap -m --protocol mtproto -f -p tg.pcapng -k tg.keys org.telegram.messenger
```

### Offline decryption (Phase B)

```bash
fritap --from-pcap tg.pcapng --mtproto-keylog tg.keys --tap tg.tap
fritap analyze tg.tap            # run discovered analyzers/parsers over the result
```

`--mtproto-keylog` is deliberately separate from `--keylog` (NSS/TLS, consumed by
tshark): MTProto keys are consumed by friTap's own decryptor.

## `--protocol telegram` (cloud + secret chats)

`--protocol telegram` is the umbrella selector that captures **both** Telegram
encryption layers in one run:

* **Cloud chats** — the MTProto **transport** key is extracted live from the native
  `libtmessages.*.so` (`Datacenter::getAuthKey`) and emitted as `MTPROTO_AUTH_KEY`
  lines (same as `--protocol mtproto`).
* **Secret chats** — the MTProto 2.0 **end-to-end** key is extracted live from Java
  (`SecretChatHelper` / `TLRPC$EncryptedChat.auth_key`) and emitted as
  `MTPROTO_E2E_KEY` lines.

Both kinds of line are written to **one combined keylog file**, so a single `-k`
keylog feeds the offline decryptor for cloud *and* secret chats.

### Live capture intents (`-k` vs `-p`)

The live capture model mirrors Signal — the two intents are independent:

* **`-k` (keys for offline decrypt)** — extracts cloud `MTPROTO_AUTH_KEY` and secret
  `MTPROTO_E2E_KEY` lines into the combined keylog; pair with `-f`/`-p` to record a
  pcap for later offline decryption.
* **`-p` (live plaintext)** — captures decrypted **secret-chat** messages straight
  into the `.tap` via the secret-chat Java hooks.

```bash
# Live full capture: pcap + combined (cloud + secret) Telegram keylog
fritap -m --protocol telegram -f -p tg.pcapng -k tg.keys org.telegram.messenger

# Live secret-chat plaintext straight into a .tap (Java hooks)
fritap -m --protocol telegram -p org.telegram.messenger
```

!!! note "Cloud-chat live plaintext is future work"
    Live plaintext capture via `-p` currently covers **secret chats** (the Java
    hooks). For **cloud chats**, use the keylog → offline path (`-k` then
    `--telegram-keylog`); the native cloud-chat live-plaintext hook is not yet
    implemented.

### Offline decryption (cloud + secret chats)

Pass the combined keylog with **`--telegram-keylog`**. friTap decrypts both layers:
cloud chats via the existing MTProto transport decryptor, and secret chats via a new
**`telegram_e2e`** flow layer:

```bash
fritap --from-pcap tg.pcapng --telegram-keylog tg.keys --tap tg.tap
fritap analyze tg.tap            # run discovered analyzers/parsers over the result
```

Offline decryption needs the `cryptography` backend, which ships in friTap's base
install (no extra needed; on a lean install, `pip install cryptography`). The
optional `tgcrypto` accelerator for faster AES-IGE is pulled in automatically with
the base where a wheel exists. `--telegram-keylog` is the combined counterpart to
`--mtproto-keylog` (cloud transport only).

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
```

* `auth_key_id` (8 bytes) is the join key present in every MTProto record header.
* `key_type` is `perm` or `temp` (PFS).

A combined keylog written by `--protocol telegram` additionally carries
`MTPROTO_E2E_KEY` lines (the per-secret-chat end-to-end auth key) alongside the
cloud `MTPROTO_AUTH_KEY` lines, in the same file. The offline reader consumes both.

## What lands in the `.tap`

A decrypted MTProto flow carries an `MtprotoLayer` whose owned bytes are the
**decrypted MTProto message payloads** (the TL-serialized bodies) per direction.
friTap does **not** parse the Telegram TL schema — that is left to a parser you plug
in (drop a `BaseParser` subclass with `is_fritap_parser = True` into the friTap
`parsers/` data dir, or ship it via the `fritap.parsers` entry-points group).

## Scope & limitations

* **Supported:** cloud chats (transport) and **secret chats (end-to-end)** via
  `--protocol telegram`; obfuscated transport; abridged & intermediate framing.
  Live secret-chat plaintext via the Java hooks (`-p`); offline cloud + secret-chat
  decryption via `--telegram-keylog`.
* **Both secret-chat parties required:** secret chats are end-to-end, so their key
  exists only on the two participating devices — you must capture from a device that
  is one of the two parties.
* **Capture from connection start:** start the capture at the MTProto connection
  start (capture from app launch / reconnect) so the transport streams are not
  mid-flow — de-obfuscation needs the first 64 bytes of each stream.
* **Degrades gracefully (skipped + counted, never garbage):** captures started
  mid-stream, records whose `auth_key_id` matches no captured key (likely a
  perm/temp mismatch).
* **Future:** native **cloud-chat live-plaintext** hook (use the keylog → offline
  path for cloud chats today), Fake-TLS / padded-intermediate transports,
  MTProto-over-QUIC, and non-Android platforms.
