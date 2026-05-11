# friTap Example Scripts

Standalone scripts demonstrating friTap's capabilities for traffic analysis, security research, and forensics.

All scripts can be run directly from this directory — they auto-detect the friTap package from the parent folder. For pip-installed friTap, the `sys.path` insert is harmless.

## Prerequisites

```bash
# Activate the virtual environment
source env/bin/activate

# For offline analysis scripts: a .tap capture file
# Generate one with: fritap -t <app> --tap capture.tap

# For live capture scripts: frida + a target device/app
pip install frida frida-tools
```

## Offline Analysis (`.tap` files)

These scripts analyze previously captured `.tap` files. No device or Frida required.

### `tap_to_har.py` — Export to HAR format

Convert a `.tap` capture to [HTTP Archive (HAR 1.2)](http://www.softwareishard.com/blog/har-12-spec/) format, compatible with Chrome DevTools, Burp Suite, and mitmproxy.

```bash
python tap_to_har.py capture.tap                          # → capture.har
python tap_to_har.py capture.tap -o output.har            # custom output path
python tap_to_har.py capture.tap --include-bodies         # include request/response bodies
```

### `diff_captures.py` — Semantic capture diff

Compare two captures at the HTTP layer: detect new/removed endpoints, changed status codes, new headers, and content type changes. Ideal for comparing app versions, consent flows, or VPN behavior.

```bash
python diff_captures.py before.tap after.tap              # Markdown report to stdout
python diff_captures.py v1.tap v2.tap -f json -o diff.json
```

### `extract_credentials.py` — Credential & secret scanner

Scan captured traffic for Bearer tokens, Basic auth, JWT tokens, API keys (AWS, GCP, Stripe, GitHub, etc.), passwords in form/JSON data, and high-entropy strings.

```bash
python extract_credentials.py capture.tap                 # table output
python extract_credentials.py capture.tap -f json -o creds.json
python extract_credentials.py capture.tap --min-severity high
```

### `extract_iocs.py` — Indicator of Compromise extractor

Extract domains, IPs, URLs, file hashes (SHA-256), User-Agent strings, email addresses, and server versions from captured traffic.

```bash
python extract_iocs.py capture.tap                        # table output
python extract_iocs.py capture.tap -f csv -o iocs.csv     # CSV for SIEM import
python extract_iocs.py capture.tap --type domain,ip,hash  # filter by IOC type
```

### `extract_images_from_tap.py` — Image extraction

Extract image files from HTTP responses using content-type headers and magic-byte detection. Supports gzip, brotli, zstd, and deflate decompression.

```bash
python extract_images_from_tap.py capture.tap
python extract_images_from_tap.py capture.tap -o ./my_images
```

## Live Capture

These scripts capture and analyze traffic from a running app in real-time.

### `library_attribution_report.py` — TLS library diversity report

Identify which TLS library (OpenSSL, BoringSSL, NSS, WolfSSL, etc.) handles each connection. This is a capability unique to friTap — no other tool can provide this data.

```bash
# Live mode (recommended — full library attribution)
python library_attribution_report.py --live com.example.app --mobile
python library_attribution_report.py --live com.example.app --mobile -d 60

# Offline mode (connection metadata only, no library identity)
python library_attribution_report.py capture.tap
```

### `chrome_ssl_intercept.py` — Chrome Android SSL interception

Standalone Frida script for intercepting Chrome's SSL/TLS traffic on Android.

```bash
python chrome_ssl_intercept.py
```

## Output Formats

Most analysis scripts support multiple output formats via `--format` / `-f`:

| Format | Flag | Best for |
|--------|------|----------|
| Table | `table` (default) | Terminal viewing |
| JSON | `json` | Machine processing, SIEM ingestion |
| CSV | `csv` | Spreadsheets, database import |
| Markdown | `markdown` | Reports, documentation |

## Creating `.tap` Files

To generate the `.tap` capture files these scripts consume:

```bash
# Capture from a mobile app
fritap -t com.example.app --mobile --tap capture.tap

# Capture from a desktop process
fritap -t firefox --tap capture.tap

# Capture with TUI (interactive)
fritap -t com.example.app --mobile --tui
# Then press 's' to save as .tap
```
