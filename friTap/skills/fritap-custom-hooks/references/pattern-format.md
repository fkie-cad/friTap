# Byte-pattern JSON format (`--patterns`)

Source: `docs/advanced/patterns.md`, `USAGE.md` ("Hooking by Byte-Patterns"),
repo-root `pattern.json`, `friTap/patterns/default_patterns.json`,
`friTap/patterns/loader.py`.

## Two engines, two schemas

| Engine | Active when | Schema | Shape |
|--------|-------------|--------|-------|
| Legacy (`PatternBasedHooking`) | default | B | `modules -> module -> platform -> arch -> category -> {primary, fallback, second_fallback?}` |
| Modern (`PatternStrategy`) | `--modern` | A | `library -> os -> arch -> function -> [hex, ...]` |

The repo-root `pattern.json` is a valid Schema A example (entries copied from
the shipped defaults; `_`-prefixed keys such as `_comment` are ignored) and
validates without warnings; use it as a starting point for `--modern`.

The Cronet / Flutter / Android key-extraction hooks run on the legacy engine,
so most user files are Schema B. Both schemas may live in one file (Schema B
under the top-level `modules` key, Schema A under library keys).

Defaults load automatically. `--patterns <file>` (a path; inline JSON is not
accepted) is deep-merged on top: only the leaves you define override the defaults. A file
invalid for both schemas is ignored with a warning and the defaults run.

## Schema B (default engine)

```json
{
  "modules": {
    "libflutter.so": {
      "android": {
        "arm64": {
          "Dump-Keys": {
            "primary":  "FF 83 00 D1 FD 7B 01 A9 ?? ?? ?? ?? F4 4F 03 A9",
            "fallback": "FF 83 00 D1 FD 7B 01 A9 F4 4F 03 A9"
          }
        }
      }
    }
  }
}
```

- Module key: the loaded module name (`libflutter.so`, `libcronet.so`,
  `libssl.so`, ...).
- Platform key: `android`, `ios`, `linux`, `macos`, `windows`.
- The engine tries `primary`, then `fallback`, then `second_fallback`, and
  stops at the first match. Empty strings are placeholders (skipped; symbol
  hooking is used).

### Categories (Schema B function keys)

| Category | Purpose | Pairing |
|----------|---------|---------|
| `Dump-Keys` | Hooks the key-logging function (`ssl_log_secret` in BoringSSL); friTap parses the keys | alone |
| `Install-Key-Log-Callback` | Hooks the function that installs the keylog callback | needs `KeyLogCallback-Function` |
| `KeyLogCallback-Function` | Hooks the callback itself; keys arrive already formatted | needs `Install-Key-Log-Callback` |
| `SSL_Read` | Hooks the read function for plaintext | with `SSL_Write` |
| `SSL_Write` | Hooks the write function for plaintext | with `SSL_Read` |

## Schema A (`--modern`)

```json
{
  "openssl": {
    "android": {
      "x64": {
        "ssl_log_secret": [
          "55 48 89 E5 48 83 EC 20 48 89 7D F8",
          "55 41 57 41 56 41 54 53 48 83 EC 30 48 8B 47 68"
        ]
      }
    }
  }
}
```

The library key is matched against the module name first, then the library
type; `os` against the current platform; the arch key against `Process.arch`,
falling back to `default`. The list is the primary/fallback chain. The shipped
defaults also carry QUICHE HTTP/3 stream patterns under `google_quiche`.

## Common rules

- Arch keys: `x64`, `arm64`, `arm`, `x86`, `default`. `x86_64` / `armv7`
  never match and the patterns are silently skipped.
- Pattern string regex: `^([0-9A-Fa-f?]{2}\s)*[0-9A-Fa-f?]{2}$`.
  Space-separated 2-character tokens; `??` and nibble wildcards (`E?`) are
  allowed mid-pattern.
- Never start or end a pattern with `??`; Frida's scanner rejects fully
  wildcarded edges.
- Keys starting with `_` (`_meta`, `_docs`, `_comment`) are ignored by the
  validator.
- The scanner searches the module's r-x ranges (whole-module fallback). More
  than one hit: the first is hooked and a warning is logged. No hit: no error,
  the pipeline continues (visible only with `-do`).

## Generating a pattern

### BoringSecretHunter

[BoringSecretHunter](https://github.com/monkeywave/BoringSecretHunter) is a
Ghidra-based tool (run via Docker) that locates `ssl_log_secret()` in stripped
BoringSSL/rustls libraries:

```bash
git clone https://github.com/monkeywave/BoringSecretHunter.git
cd BoringSecretHunter
docker build -t boringsecrethunter .
mkdir -p binary results
cp /path/to/libtarget.so binary/
docker run --rm -v "$(pwd)/binary":/usr/local/src/binaries -v "$(pwd)/results":/host_output -e DEBUG_RUN=true boringsecrethunter
```

Copy the `Byte pattern for frida (friTap): ...` line unchanged into
`Dump-Keys.primary` (Schema B) or into a Schema A `ssl_log_secret` list. It is
a third-party tool: build it from the upstream repository.

### By hand

1. Find the function in a disassembler (for BoringSSL: `ssl_log_secret`,
   called during every handshake even with key logging disabled).
2. Copy the first ~32-48 bytes of its prologue.
3. Replace build-specific bytes (relative offsets, immediates) with `??`,
   keeping concrete bytes at both ends.
4. Put it into the schema for your engine.

## Validate before running

```bash
python -m json.tool patterns.json
python -c "import json, logging; from friTap.patterns.loader import PatternLoader; print(PatternLoader.validate(json.load(open('patterns.json')), logging.getLogger('t')))"
```

`True` means the loader accepts the file.

## Running

```bash
fritap -m --patterns patterns.json -k keys.log com.example.app
fritap -m -do -v --patterns patterns.json -k keys.log com.example.app
fritap -m --modern --patterns schema_a.json -k keys.log com.example.app
fritap -m --force-scan libmainlinecronet.141.0.7340.3.so --patterns patterns.json -k keys.log com.example.app
```

`--force-scan <module>` forces the BoringSSL pattern scan onto a module that
friTap thinks a sibling library already covers; it needs a module name (or a
`re:` regex / trailing `*`). `FRITAP_FORCE_SCAN` (comma-separated) does the
same from the environment.
