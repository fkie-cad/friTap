# GDB Wine Key Extraction

Extracts TLS key material from Windows programs running under Wine by hooking
known TLS logging functions via GDB.

## Usage

```sh
./wine_key_extract.py --spawn prog.exe -k output.log -- <program arguments>
./wine_key_extract.py --attach 6548 -k output.log
./wine_key_extract.py --spawn prog.exe -k output.log --patterns patterns.json -- <program arguments>
```

Options:

- `-a, --attach PID` — attach to a running wine process instead of spawning one
- `-s, --spawn EXECUTABLE` — Windows executable to spawn under `wine`
- `-k, --keylog LOCATION` — write extracted keys to this file (NSS keylog format)
- `-p, --patterns FILE` — additional/override function patterns, as produced by `utils/wine_hunter.py`
- `-v, --verbose` — enable verbose logging
- `-do, --debug-output` — enable debug logging
- `-g, --gdb` — don't suppress GDB's own stdout/stderr (for debugging the script itself)

## Patterns

Patterns for Wine can be generated using `utils/wine_key_extract.py`

This script currently only contains a limited number of patterns for hooking TLS keylog functions and may need to be extended or modified:
| Library             | Typical location                                              |
|------------------|-----------------------------------------------------------------|
| `GnuTLS (Linux)`           | used by wine for implementing schannel, hooking `_gnutls_call_keylog_func` |
| `GnuTLS (Windows)`       | hooking `_gnutls_call_keylog_func`                |
| `OpenSSL` | hooking `SSL_log_secret`         |
more patterns can be added by passing them via the `--patterns` or hard coding them in the dictionary `DEFAULT_TLS_PATTERNS`, depending on tls library more Breakpoint classes must be implemented, depending on the implementation of the TLS library.


## Requirements
- gdb
- wine
