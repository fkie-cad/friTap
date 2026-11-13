# Memory-scan engines, profiles and output files

Source of truth: `friTap/memory_scanning/patterns.json` (profiles),
`friTap/memory_scanning/loader.py` (resolver), `friTap/memory_scanning/__init__.py`
(sidecar paths), `friTap/output/factory.py` (`memory_scan_keylog_path`).

## Engines and shipped profiles

Valid engine names: `boringssl`, `schannel`, `rc4`, `mtproto`
(`telegram` is an alias for `mtproto`). Any profile `id` below can also be
passed to `-ms` to run just that profile.

| Profile id | Engine | Protocol | Platforms | Scans | Notes |
| --- | --- | --- | --- | --- | --- |
| `boringssl-2025-inplacevector-u8len` | boringssl | tls | all | target | BoringSSL with `InplaceVector` uint8 length (about 2024-02 on): Chrome monochrome, Cronet, in-tree forks. Validated on Android/Chrome. |
| `rc4-memscan-generic` | rc4 | rc4 | all | target | S-box detection plus candidate-key trial decryption. No build-specific layout. |
| `schannel-win11-ncryptsslp` | schannel | tls | windows | `lsass.exe` (read-only, separate session) | arm64 verified on Windows 11 build 26200; x64 `calibrated: false`, empty needle candidates, so it emits nothing. |
| `tgnet-android-arm64-2026` | mtproto | mtproto | android | target | `libtmessages*.so`, calibrated for `libtmessages.49` / Telegram 12.10.x. Emits `MTPROTO_AUTH_KEY`, `MTPROTO_E2E_KEY`, `MTPROTO_OBF_KEY`. |

## How `-ms` resolves engines

1. No value: profiles whose `protocol` is in the expanded `--protocol` set
   (default `tls`) and whose `platforms` match the target OS.
2. A value that is an existing file: that file is merged over the shipped
   database by profile `id`, then step 1 applies.
3. A known engine name or alias: only that engine's profiles, regardless of
   `--protocol`.
4. A profile id: only that profile.
5. Anything else is an error that lists the valid engines.

Profiles are grouped by `scan_target`: `self` runs in the injected target,
`lsass` runs in a separate Frida session attached to `lsass.exe` (Windows only,
skipped with `-nl` / `--no-lsass`). If nothing matches, friTap logs
`memory-scan: no scan engine for protocol(s) ...` and skips the scan.

## Output files

The memory-scan keylog path:

| Command shape | Memory-scan keylog |
| --- | --- |
| `-ms` alone | `<sanitized-target>_memscan.keylog` in the current directory |
| `-ms -k keys.log` (plus other capture flags) | `keys.memscan.log` beside `keys.log` |
| memory-only mode (TUI "memory only") with `-k` | the `-k` path itself |

Sidecars next to it (`<stem>` = memory-scan keylog without extension):

| File | Content | Offline use |
| --- | --- | --- |
| `<stem>.schannel.unpaired` | `<kind> <secret_hex> <session_id\|-> <ssl_version> [group=<id>]`, kind `schannel_tls12_master` or `schannel_tls13_secret` | `--schannel-unpaired` |
| `<stem>.rc4.keylog` | `RC4_KEY <key_hex> <len> <source> <direction> <assoc>` (source `memscan-sbox` or `memscan-trial`) | `--rc4-keylog` |
| `<stem>.mtproto.keylog` | `MTPROTO_AUTH_KEY` / `MTPROTO_E2E_KEY` lines | `--mtproto-keylog` |
| `<stem>.tls_midstream.secrets.jsonl` | one JSON object per TLS 1.3 socket: both randoms plus the application traffic secrets | `--tls-midstream-secrets` |

Files are created lazily, so a missing sidecar means that engine found
nothing.

## Offline verification commands

```bash
fritap --from-pcap full.pcapng --keylog keys.memscan.log --tap out.tap
fritap --from-pcap win.pcapng --schannel-unpaired keys.memscan.schannel.unpaired --tap win.tap
fritap --from-pcap out.pcap --keylog keys.tls.log --rc4-keylog keys.rc4.log
fritap --from-pcap out.pcap --rc4-keylog keys.memscan.rc4.keylog
fritap --from-pcap out.pcap --tls-midstream-secrets keys.memscan.tls_midstream.secrets.jsonl --tap out.tap
fritap --from-pcap tg.pcap --mtproto-keylog keys.memscan.mtproto.keylog --tap tg.tap
fritap --from-pcap x.pcap --help
```

Offline RC4 key mining from a dump or a live Windows process (read-only, never
lsass) is also available: `--rc4-scan-dump`, `--rc4-scan-pid`,
`--rc4-scan-name`, used with `--from-pcap` (see `fritap --from-pcap x.pcap --help`).

## Custom profiles

A memory-scan profile describes where a secret is (struct layout, anchors,
validators); a `--patterns` file describes where a function is. They are not
interchangeable. Top-level keys: `schema`, `_meta`, `profiles[]`; per profile:
`id`, `description`, `match` (advisory), `scan_regions`, `constants`,
`struct_offsets`, `tiers`, `validators`, `keylog_labels`, plus `engine`,
`protocol`, `platforms`, `scan_target`. Full table:
`docs/advanced/patterns.md` (Memory-scan secret profiles).

```bash
fritap -ms my_profiles.json com.android.chrome
```
