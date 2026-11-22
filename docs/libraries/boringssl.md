# BoringSSL Support

friTap provides comprehensive support for BoringSSL, Google's SSL/TLS implementation derived from OpenSSL. BoringSSL is commonly found in Chrome, Android applications, and is often statically linked into other libraries.

## Overview

BoringSSL is Google's fork of OpenSSL, designed for use in Google's various products. It's frequently encountered in:

- **Chrome browser** (desktop and mobile)
- **Android applications** using Cronet
- **Flutter applications** (statically linked)
- **Go applications** using crypto/tls
- **Various Google services** and products

## Supported Features

| Platform | Key Extraction | Traffic Capture | Notes |
|----------|---------------|-----------------|-------|
| Linux    | ✓ Full       | ✓ Full         | All versions |
| Windows  | ✓ Limited    | ✓ Full         | Read/Write hooks only |
| macOS    | ✓ Keys       | ✗ Not available | Apple's `/usr/lib/libboringssl.dylib`. Keys only — see [Apple BoringSSL](#apple-boringssl-macos-and-ios). |
| macOS (Chrome / Electron) | ✓ Keys | ✓ Partial | BoringSSL inside `Google Chrome Framework` / `Electron Framework`, arm64 only — see [Chrome and Electron](../platforms/macos.md#chrome-and-electron). |
| Android  | ✓ Full       | ✓ Full         | All Android versions |
| iOS      | ✓ Keys       | ✗ Not available | Same Apple BoringSSL as macOS. Keys only — see [Apple BoringSSL](#apple-boringssl-macos-and-ios). |

**Legend:**
- **Full**: Complete key extraction and traffic capture
- **Keys**: Key extraction only — no plaintext interception
- **Limited**: Partial functionality

## Detection Methods

friTap uses multiple methods to detect and hook BoringSSL:

### 1. Symbol-Based Detection

When symbols are available:

```bash
# Standard symbol-based hooking
fritap -k keys.log target_app
```

### 2. Pattern-Based Detection

For stripped or statically-linked BoringSSL:

```bash
# Use built-in patterns
fritap -k keys.log target_app

# Use custom patterns
fritap --patterns boringssl_patterns.json -k keys.log target_app
```

!!! note "Anti-tamper (PairIP) targets"
    When `Memory.scan` is unsafe (e.g. under [`--pairip-safe`](../advanced/pairip-safe.md)),
    friTap falls back to a scan-free hook on the internal
    `bssl::ssl_log_secret`. For a fully-stripped host with no symbols (such as
    the Android System WebView's `libwebviewchromium.so`), derive its offset with
    `dev/find_ssl_log_secret_offset.py` and pass it via `--offsets`. See
    [PairIP-Protected Apps](../advanced/pairip-safe.md#capturing-a-stripped-webview-chromium-login).

### 3. Module-Based Detection

BoringSSL is often found in these modules:
- `libssl.so` (traditional)
- `libboringssl.so` (standalone)
- `/usr/lib/libboringssl.dylib` (**Apple** — macOS and iOS; backs CFNetwork, URLSession and Network.framework)
- `libflutter.so` (Flutter apps)
- `libcronet.so` (Chrome/Android)
- `libhttpengine.so` (statically linked; `SSL_*` may live only in `.symtab`)
- `libcommerce_http_client.so` (Blizzard commerce SDK — curl + statically-linked BoringSSL; also covered by [`--pairip-safe`](../advanced/pairip-safe.md))

### Apple BoringSSL (macOS and iOS)

Apple ships its own BoringSSL as `/usr/lib/libboringssl.dylib`, and it is the TLS
stack underneath CFNetwork, URLSession and Network.framework. Two Apple-specific
properties shape what friTap can do there:

- **Keys only, no plaintext.** The socket file descriptor cannot be recovered from
  an `SSL_read`/`SSL_write` call on Apple platforms, so friTap installs no plaintext
  hooks for Apple BoringSSL. Use the extracted keylog with Wireshark.
- **The keylog callback is not exported.** Apple does not export
  `SSL_CTX_set_keylog_callback`. friTap instead hooks the exported
  `SSL_CTX_set_info_callback` and writes its keylog callback pointer **directly into
  the live `SSL_CTX` struct** at a byte offset, which it derives at run time by
  disassembling the non-exported setter (falling back to a per-OS-version table).

!!! warning "A wrong offset kills the target"
    Writing a function pointer at the wrong `SSL_CTX` offset corrupts an unrelated
    field and crashes the process — the symptom reported in
    [fkie-cad/friTap#65](https://github.com/fkie-cad/friTap/discussions/65). The
    offset table, which values are actually measured, and the
    `dev/derive_boringssl_keylog_offset.py` helper are documented in the
    [macOS Platform Guide](../platforms/macos.md#apple-boringssl-keylog-offsets).

## Plaintext from statically linked BoringSSL

Chrome (`libmonochrome*.so`, `libchrome.so`), WebView (`libwebviewchromium*.so`),
stripped Cronet builds, Flutter (`libflutter.so`) and Signal (`libsignal_jni.so`,
through the Rust `boring` crate) link BoringSSL statically and usually export
nothing. Keys come from the `ssl_log_secret` pattern and anchor
tiers. For plaintext (`-p`), the supplementary "BoringSSL plaintext (...)" rows in
the Android platform table need `SSL_read` and `SSL_write`, and resolve them in
this order, stopping at the first source that has at least one of them:

1. **Exports.** If the module exports `SSL_read`/`SSL_write`, the primary row
   already hooks them and the supplementary row stays out, so no record is
   captured twice.
2. **`--offsets`, keyed by module basename.** An entry named after the module's
   file name (not its path) supplies the addresses:

    ```json
    {
      "libflutter.so": {
        "SSL_read":  { "address": "0x5a1c40", "absolute": false },
        "SSL_write": { "address": "0x5a2010", "absolute": false }
      }
    }
    ```

    `absolute: false` is an offset from the module base, `absolute: true` a
    runtime address. Either function may be omitted. Other `--offsets` entries
    keep their usual meaning.
3. **Learned cache.** RVAs found by the locator on an earlier run of the same
   library build (see below). Each RVA is used only if the first 32 bytes at that
   address still hash to the recorded SHA-256.
4. **`ssl_lib.cc` anchor locator (arm64 only).** Finds the `OPENSSL_PUT_ERROR`
   sites in `ssl_lib.cc` and identifies `SSL_read`/`SSL_write` by the BoringSSL
   reason codes each function raises, with function bounds from `.eh_frame_hdr`.
   This scan is the slow step. It does not run on arm, x86 or x86_64.
5. **Miss.** friTap prints once per module:

    ```
    [!] libflutter.so: BoringSSL SSL_read/SSL_write not located; TCP TLS plaintext unavailable (keys only). Supply them via --offsets; see docs/libraries/boringssl.md#boringsecrethunter
    ```

    Key extraction is not affected. See [BoringSecretHunter](#boringsecrethunter).

On success friTap logs which source was used, for example
`hooked statically linked BoringSSL for TCP TLS plaintext (...; from --offsets)`.

### Learned offset cache

When the locator finds `SSL_read`/`SSL_write`, the result can be stored so the next
run on the same library build skips the scan.

- **File:** `learned_offsets.json` in friTap's user cache directory
  (`platformdirs.user_cache_dir("friTap")`, for example `~/.cache/friTap/` on
  Linux or `~/Library/Caches/friTap/` on macOS; `~/.cache/friTap/` if
  `platformdirs` is missing). Set `FRITAP_LEARNED_OFFSETS_DIR` to use another
  directory.
- **Key:** `build_id|size|arch` of the library, so a different build or ABI never
  reuses an entry. The build id is the ELF GNU build id, or the `LC_UUID` of a
  Mach-O image (macOS Chrome and Electron frameworks).
- **Stored per entry:** module basename, build id, file size, arch, the
  module-relative RVAs of `SSL_read`/`SSL_write`, the SHA-256 of each function's
  first 32 bytes, and a last-seen time. At most 512 entries are kept; the least
  recently seen are dropped first. Other cached functions (such as
  `ssl_log_secret`) are hashed over bytes 32–63, which a Frida hook never
  overwrites, so a function that was already hooked when it was found still
  verifies on the next run.
- **Precedence:** friTap hands every cached entry to the agent, and the agent
  uses an `--offsets` entry for the same module before the learned one.
- **Stale entries:** if the prologue hash no longer matches (the library was
  rebuilt), the entry is ignored and the locator runs again. A stale entry costs a
  scan, never a hook on the wrong code.
- **Clearing:** delete `learned_offsets.json`. Unreadable, oversized (>1 MiB) or
  malformed files are ignored.

### BoringSecretHunter

If the miss notice appears (non-arm64 target, or a build the locator does not
recognise), you have to find `SSL_read`/`SSL_write` yourself.
[BoringSecretHunter](https://github.com/monkeywave/BoringSecretHunter) does not
help with that: it only locates `ssl_log_secret`, the key-side function.

**Keys.** If keys are missing too, run BoringSecretHunter as described in
[Automating with BoringSecretHunter](../advanced/patterns.md#automating-with-boringsecrethunter):

```bash
mkdir -p binary results
adb pull /data/app/<...>/lib/arm64/libflutter.so binary/
docker run --rm \
  -v "$(pwd)/binary":/usr/local/src/binaries \
  -v "$(pwd)/results":/host_output \
  boringsecrethunter
```

It prints the `ssl_log_secret` offset and a Frida byte pattern. Pass the pattern
with `--patterns` (see [Pattern-Based Hooking](../advanced/patterns.md)) to get
keys with `-k`.

**Plaintext.** Find `SSL_read` and `SSL_write` by hand in Ghidra or radare2,
the same way the locator does:

1. Search for the string ending in `ssl/ssl_lib.cc` (BoringSSL's `__FILE__`
   for its error sites) and list the functions that reference it.
2. Among those, `SSL_write` is the one that raises `SSL_R_BAD_LENGTH` (`0x6f`)
   next to `SSL_R_UNINITIALIZED` (`0xe2`); the reason code is the `mov w2, #...`
   right before the call to `ERR_put_error`.
3. `SSL_read` is the function that calls `SSL_peek` (the one raising only
   `ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED`, `0x42`) and then consumes the buffer,
   or, in builds where `SSL_peek` is inlined, the peek-shaped function that also
   calls the buffer-consume helper.

Convert the function entries to module-relative offsets and put them in an
`--offsets` entry named after the module basename:

```json
{
  "libflutter.so": {
    "SSL_read":  { "address": "0x5a1c40", "absolute": false },
    "SSL_write": { "address": "0x5a2010", "absolute": false }
  }
}
```

```bash
fritap -m -p out.pcap -k keys.log --offsets offsets.json com.example.app
```

## Usage Examples

### Chrome Browser Analysis

```bash
# Desktop Chrome
fritap -k chrome_keys.log google-chrome

# Chrome with specific profile
fritap -k chrome_keys.log google-chrome --user-data-dir=/tmp/test-profile

# Debug mode for troubleshooting
fritap -do -k chrome_keys.log google-chrome
```

On macOS, attach to Chrome's network-service helper instead; see
[Chrome and Electron](../platforms/macos.md#chrome-and-electron).

### Android Chrome/Cronet

```bash
# Chrome on Android
fritap -m -k android_chrome_keys.log com.android.chrome

# App using Cronet
fritap -m -k cronet_keys.log com.example.app

# With anti-root detection bypass
fritap -m -ar -k keys.log com.android.chrome
```

### Flutter Applications

Flutter apps commonly use statically-linked BoringSSL (details, including
plaintext capture, on the [Flutter](flutter.md) page):

```bash
# Basic Flutter analysis
fritap -m -k flutter_keys.log com.example.flutter_app

# Generate patterns for stripped Flutter
mkdir -p binary results
cp /data/app/com.example.flutter_app/lib/arm64/libflutter.so binary/
docker run --rm -v "$(pwd)/binary":/usr/local/src/binaries -v "$(pwd)/results":/host_output boringsecrethunter

# Use generated patterns
fritap --patterns results/libflutter.so_patterns.json -m -k keys.log com.example.flutter_app
```

## Pattern-Based Hooking

For applications with stripped BoringSSL, use pattern-based hooking:

### Generating Patterns

Use BoringSecretHunter to automatically generate patterns:

```bash
# Setup directories
mkdir -p binary results

# Copy target libraries
cp libboringssl.so binary/
cp libflutter.so binary/

# Generate patterns with Docker (recommended)
docker run --rm \
  -v "$(pwd)/binary":/usr/local/src/binaries \
  -v "$(pwd)/results":/host_output \
  boringsecrethunter

# Use generated patterns
fritap --patterns results/libboringssl.so_patterns.json -k keys.log target_app
```

### Example Pattern File

friTap's default (legacy) hooking engine uses the **Schema B** object form — patterns
nested as `modules → module → platform → arch → function → {primary, fallback}`. See
[Pattern-Based Hooking](../advanced/patterns.md#pattern-file-format) for the full schema
(and the modern `--modern` Schema A list form).

```json
{
  "modules": {
    "libflutter.so": {
      "android": {
        "arm64": {
          "SSL_Read": {
            "primary":  "1F 20 03 D5 FD 7B BF A9 F4 4F 01 A9",
            "fallback": "1F 20 03 D5 ?? ?? ?? ?? F4 4F 01 A9"
          },
          "SSL_Write": {
            "primary":  "FF 83 00 D1 FD 7B 01 A9 F4 4F 02 A9",
            "fallback": "FF 83 00 D1 ?? ?? ?? ?? F4 4F 02 A9"
          }
        }
      }
    }
  }
}
```

## Advanced Usage

### Multiple Library Detection

BoringSSL can coexist with other SSL libraries:

```bash
# Enable verbose output to see all detected libraries
fritap -v -k keys.log target_app

# List all loaded libraries
fritap --list-libraries target_app
```

### Performance Considerations

BoringSSL applications may have high throughput:

```bash
# Use full capture mode for complete traffic
fritap -f -k keys.log -p traffic.pcap high_traffic_app

# Live analysis with Wireshark
fritap -l target_app
```

### Custom Scripts

For advanced BoringSSL analysis:

```bash
# Use custom JavaScript for specific BoringSSL functions
fritap -c custom_boringssl.js -k keys.log target_app
```

Example custom script (`custom_boringssl.js`):
```javascript
// Custom BoringSSL hooks
if (Process.platform === "linux") {
    const boringssl = Process.getModuleByName("libboringssl.so");
    if (boringssl) {
        console.log("BoringSSL base: " + boringssl.base);
        
        // Hook specific BoringSSL functions
        const ssl_get_version = boringssl.getExportByName("SSL_get_version");
        if (ssl_get_version) {
            Interceptor.attach(ssl_get_version, {
                onLeave: function(retval) {
                    const version = retval.readUtf8String();
                    console.log("SSL Version: " + version);
                }
            });
        }
    }
}
```

## Troubleshooting

### Common Issues

#### Library Not Detected

```bash
# Check if BoringSSL is loaded
fritap --list-libraries target_app 2>&1 | grep -i boring

# Enable debug output
fritap -do -v target_app

# Try pattern-based detection
fritap --patterns patterns.json -do target_app
```

#### No Keys Extracted

```bash
# Verify SSL traffic is occurring
fritap -p traffic.pcap target_app

# Check for statically linked BoringSSL
fritap --patterns auto -k keys.log target_app

# Try with spawn mode
fritap -s -k keys.log target_app
```

#### Pattern Matching Fails

```bash
# Generate new patterns
mkdir patterns && cp target_lib.so patterns/
docker run --rm -v "$(pwd)/patterns":/usr/local/src/binaries -v "$(pwd)/results":/host_output boringsecrethunter

# Test with verbose output
fritap --patterns results/target_lib.so_patterns.json -do -v target_app
```

### Platform-Specific Issues

#### Android

```bash
# Check for anti-root detection
fritap -m -ar -k keys.log com.android.chrome

# Use spawn mode for app initialization
fritap -m -s -k keys.log com.example.app

# Enable default socket info if FD lookup fails
fritap -m -ed -k keys.log com.example.app
```

#### iOS

```bash
# iOS requires jailbroken device
fritap -m -k keys.log com.apple.mobilesafari

# Check for iOS-specific BoringSSL
fritap -m --list-libraries com.apple.mobilesafari
```

#### Windows

```bash
# Windows may require administrator privileges
fritap -k keys.log chrome.exe

# Check for Windows-specific modules
fritap --list-libraries chrome.exe 2>&1 | grep -i ssl
```

## Integration Examples

### Wireshark Integration

```bash
# Extract keys and capture traffic
fritap -k boringssl_keys.log -p boringssl_traffic.pcap target_app

# Open in Wireshark with keys
wireshark -o "tls.keylog_file:boringssl_keys.log" boringssl_traffic.pcap
```

### Automated Analysis

```bash
#!/bin/bash
# Automated BoringSSL analysis script

APP_NAME="$1"
OUTPUT_DIR="analysis_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$OUTPUT_DIR"

# Run friTap analysis
fritap -k "$OUTPUT_DIR/keys.log" \
       -p "$OUTPUT_DIR/traffic.pcap" \
       -v "$APP_NAME" 2>&1 | tee "$OUTPUT_DIR/analysis.log"

# Generate report
echo "Analysis complete for $APP_NAME"
echo "Keys extracted: $(grep -c CLIENT_RANDOM "$OUTPUT_DIR/keys.log" 2>/dev/null || echo 0)"
echo "Traffic captured: $(ls -lh "$OUTPUT_DIR/traffic.pcap" 2>/dev/null || echo "No traffic file")"
```

## Version Compatibility

BoringSSL versions and compatibility:

| BoringSSL Version | Chrome Version | Status |
|-------------------|----------------|--------|
| Latest (main)     | Chrome 110+    | ✓ Supported |
| 2023 releases     | Chrome 100-109| ✓ Supported |
| 2022 releases     | Chrome 90-99   | ✓ Supported |
| 2021 releases     | Chrome 80-89   | ✓ Supported |
| Older versions    | Chrome <80     | Limited |

## Next Steps

- **Pattern Generation**: Learn more about [Pattern-Based Hooking](../advanced/patterns.md)
- **Android Analysis**: Check the [Android Platform Guide](../platforms/android.md)
- **Custom Scripts**: See [Advanced Usage Examples](../examples/index.md)
- **Troubleshooting**: Review [Common Issues](../troubleshooting/common-issues.md)

## Related Libraries

BoringSSL is related to these other SSL implementations:
- **[Other Libraries](others.md)**: OpenSSL and other SSL/TLS implementations
- **[Library Overview](index.md)**: Complete friTap library support matrix