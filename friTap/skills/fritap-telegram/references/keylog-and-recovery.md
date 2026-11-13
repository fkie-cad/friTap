# MTProto keylog format, obfuscation and recovery

Reference for the `fritap-telegram` skill. Source of truth for the line
format: `friTap/protocols/mtproto_keylog_spec.py` (shared by the live writer
and the offline reader). Lines starting with `#` are comments. All three labels
can live in one file; each reader ignores the labels it does not handle.

## Key lines

```text
MTPROTO_AUTH_KEY <dc_id> <auth_key_id_hex16> <auth_key_hex512> <key_type>
MTPROTO_E2E_KEY <key_fingerprint_hex16> <shared_key_hex512> <chat_id> [<peer_user_id>]
MTPROTO_OBF_KEY <key_out_hex64> <iv_out_hex32> <key_in_hex64> <iv_in_hex32> <num_out> <num_in> <endpoint|->
```

| Label | Layer | Join key | Written by |
|-------|-------|----------|-----------|
| `MTPROTO_AUTH_KEY` | Cloud transport (256-byte key, `perm` or `temp`) | `auth_key_id` (8 bytes, in every record header) | getAuthKey hook (`-k`), memory scan Tiers A/B |
| `MTPROTO_E2E_KEY` | Secret chat (256-byte shared key) | key fingerprint (low 64 bits of SHA1(key)) | Java hooks (`--protocol telegram -k`), memory scan Tier C |
| `MTPROTO_OBF_KEY` | Obfuscated transport AES-256-CTR state, per direction | trial alignment (endpoint hint optional) | memory scan Tier E only |

`iv_out` / `iv_in` are the **live** CTR counter blocks at scan time (not the
original IV); `num_out` / `num_in` are the byte phase (0..15) inside the
current keystream block.

## Where the files land

- Hook path: the `-k` path itself. With several active protocols friTap splits
  the keylog per protocol (`<stem>.<proto><ext>`).
- Memory scan: its own keylog (`keys.memscan.log` next to `-k keys.log`, or
  `<sanitized-target>_memscan.keylog` without `-k`) plus the MTProto sidecar
  `<that stem>.mtproto.keylog`. In memory-scan-only mode the scanner owns the
  `-k` path.

## Memory-scan tiers (profile `tgnet-android-arm64-2026`)

From `friTap/memory_scanning/patterns.json`:

| Tier | Default | Purpose |
|------|---------|---------|
| A `bytearray_authkey` | on | Cheap anchor for candidate 256-byte key blobs; emits nothing itself |
| B `authkeyid_roundtrip` | on | Confirms keys via `sha1(key)[-8:]` plus a pointer back to the ByteArray |
| C `art_secretchat_key` | on | Secret-chat keys from the ART heap, same SHA1 oracle |
| D `entropy_sweep` | off | Expensive fallback if tgnet changes ByteArray |
| E `connection_ctr_state` | on | Live obfuscated-transport CTR state of open connections (`MTPROTO_OBF_KEY`) |

## Why streams degrade

Telegram's transport is obfuscated: each TCP stream starts with a 64-byte init
block from which both AES-CTR directions are derived. The offline decryptor
needs that block, or a recovered `MTPROTO_OBF_KEY`, before it can read any
record. Offline counters (printed per protocol by `fritap --from-pcap`):

| Counter | Meaning |
|---------|---------|
| `messages` | Decrypted MTProto messages |
| `recovered streams` | Mid-stream streams re-derived from `MTPROTO_OBF_KEY` |
| `partial streams` | Valid start, later gap; records before the gap decrypted |
| `undecryptable records` | Record's key id matched no key, or decryption failed (PFS temp/perm mismatch, keylog from another session) |
| `degraded streams` | Started mid-stream with MTProto evidence and no usable CTR state |
| `unrecovered degraded streams` | Recovery was tried, no `MTPROTO_OBF_KEY` aligned |
| `non-mtproto degraded streams` | Init-less streams without MTProto evidence (not counted above) |
| `short streams` | Start gap or too little client data; not a mid-stream problem |
| `unsupported-framing streams` | Padded-intermediate, full or Fake-TLS framing |

A secret-chat key without any transport key triggers an `E2E`-only warning:
E2E blobs ride inside the cloud transport, so nothing decrypts.

## Mid-stream recovery conditions

From `USAGE.md` and `docs/advanced/offline-pcap-to-tap.md`. Recovery with
`-ms` works when:

1. the connection is **alive during a scan pass** (keep Telegram in the
   foreground, exchange messages);
2. the pcap holds **recent traffic** on that stream: alignment searches about
   64 KB around the live counter by default (`--resync-search-depth`, in
   16-byte blocks, default 4096);
3. the same scan recovered the transport `MTPROTO_AUTH_KEY` (PFS temp key
   resident at scan time). For secret chats, send several messages first.

Spawn (`-s`) remains the way to catch connections that close before a scan.
