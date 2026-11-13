# Wine GDB route: troubleshooting

Source: `docs/platforms/wine.md`. Start any diagnosis with verbose debug
output:

```bash
fritap -s -do -v -k keys.log wine /path/to/app.exe
```

| Symptom | Cause | Fix |
|---------|-------|-----|
| `wine: '/home/<you>/.wine' is not owned by you` or friTap aborts naming the prefix owner | Wine would run as a different uid than the prefix owner (root shell / `su`) | Run as your user, use `sudo` (Wine then runs as `SUDO_UID`), or `WINEPREFIX=/root/.wine` |
| `Keeping gdb as root: <reason>` | One drop check failed (`ptrace_scope` not `0`, foreign target, unreadable gdb scripts, root-owned keylog) | Fine for extraction; to drop, fix the named reason |
| gdb cannot attach as non-root | `ptrace_scope` is `1` or higher | `sudo sysctl -w kernel.yama.ptrace_scope=0` (with consent) or use `sudo` |
| Extractor fails at start | gdb lacks Python | Install a gdb where `gdb -batch -ex "python print(1)"` prints `1` |
| Hint to add `-s` | No `-s` means attach and no matching process runs | Add `-s`, or start the app first |
| friTap options swallow the target's flags | Target args start with `-` | Put the target after `--` |
| Notice that plaintext pcap / `--live` is unsupported | `-p` without `-f` on the GDB path | Use `-p cap.pcapng -f`, or the Frida agent (`--wine off --experimental`) |
| Empty keylog, app ran | No fresh handshake after attach, or the TLS build matches no shipped signature | Use `-s`, drive new connections; regenerate signatures (below) |
| Spawn misbehaves for one target | App-specific startup | Start it with `wine app.exe &`, then attach |

## Attach pattern

```bash
wine "/path/to/app.exe" &
fritap -k keys.log app.exe
fritap -k keys.log "$(pgrep -f app.exe | head -1)"
```

## Signatures for other builds

The extractor finds GnuTLS (`_gnutls_call_keylog_func`, or the registered NSS
keylog callback when that function is inlined, e.g. Ubuntu gnutls 3.8.x),
OpenSSL/BoringSSL `SSL_log_secret` and LibreSSL KDF functions
(`tls13_hkdf_expand_label_with_length`, `tls1_PRF`, with `client_random`
parsed from the ClientHello on `ws2_32!send`) by byte signatures. For a
different Wine or TLS build:

- Generate patterns with `agent_gdb/wine/utils/wine_hunter.py` (Ghidra /
  PyGhidra, see `agent_gdb/wine/utils/README.md`) and pass them with
  `fritap --patterns patterns.json` (or to the standalone extractor with
  `--patterns patterns.json`). friTap passes a flat GDB-format file through
  unchanged and translates a friTap v2 pattern file to it (`x64` entries
  without `??` wildcards only; see `agent_gdb/wine/pattern_translate.py`).
- Or add hex signatures to `DEFAULT_TLS_PATTERNS` / `DEFAULT_WINE_PATTERNS`
  in `agent_gdb/wine/gdb_script/gdb_wine_extract.py`.

Standalone extractor (outside friTap):

```bash
python agent_gdb/wine/wine_key_extract.py --spawn /path/to/app.exe -k keys.log -- <args>
python agent_gdb/wine/wine_key_extract.py --attach <pid> -k keys.log
```

## Frida Wine agent (experimental)

Only for plaintext pcaps, `--live`, payload modification or socket tracing.
Spawning with it often restarts Wine without hooks; prefer attach.

```bash
fritap --wine off --experimental -s -k keys.log --pcap plaintext.pcap wine /path/to/app.exe
```
