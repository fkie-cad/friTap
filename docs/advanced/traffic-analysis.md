# Traffic Analysis

friTap can do more than capture decrypted traffic — it can **passively analyze** it.
A set of composable *analyzers* walk every reconstructed flow and emit structured
**findings**: leaked credentials, indicators of compromise, decoded protobuf/gRPC,
and more.

## Overview

Traffic analysis is **passive**. Analyzers only read flows that friTap has *already*
captured and decrypted — they never touch the target process, send packets, probe
ports, or generate any network activity. The word "scan" here means *scan the captured
traffic*, not *scan the target*.

There are two ways to run analyzers:

| Mode | Trigger | Input | Page section |
|------|---------|-------|--------------|
| **Offline** | `fritap analyze capture.tap` | a captured `.tap` file | [The `analyze` CLI](#the-analyze-cli) |
| **Live** | `fritap --scan ...` during capture | flows as they complete | [Live scan](#live-scan) |

Both modes share the same analyzers, the same [`Finding`/`Severity`](#finding-and-severity-model)
model, the same [reporters](#reports-and-the-findings-sidecar), and the same
[CI gate](#cicd-gate) semantics.

!!! info "No network activity, ever"
    Even in live mode, `--scan` analyzes flows that friTap decrypted as a side effect
    of the capture you were already running. It is *observation*, not active scanning.

---

## Write your first analyzer

An analyzer is any object satisfying the `BaseAnalyzer` protocol: a `name` attribute
plus an `analyze_flow(self, flow) -> list[Finding]` method. Here is a complete,
working analyzer that flags any flow whose host ends in `.internal` — exactly the kind
of leak you want a CI pipeline to catch.

Save this as `my_analyzer.py`:

```python
from friTap.analysis import Finding, Severity


class InternalHostAnalyzer:
    """Flag requests to internal hostnames that should never leave the network."""

    # The user-facing name; also how you select it via --scanners.
    name = "internal-hosts"

    # Opt-in marker required for auto-discovery from a bare module reference.
    is_fritap_analyzer = True

    def analyze_flow(self, flow) -> list[Finding]:
        host = flow.display_host or ""
        if not host.endswith(".internal"):
            return []
        return [
            Finding(
                severity=Severity.MEDIUM,
                title="Request to internal host",
                description=f"Traffic observed to internal host {host}",
                source=self.name,
                flow_id=flow.flow_id,
                evidence={"type": "internal_host", "value": host},
            )
        ]
```

Load it with `--analyzer-path` and select it with `--scanners`:

```bash
fritap analyze capture.tap \
    --analyzer-path my_analyzer:InternalHostAnalyzer \
    --scanners internal-hosts \
    --report table
```

!!! tip "Two ways to reference an external analyzer"
    - **`module:Class`** (used above) — friTap instantiates that exact class. The
      `is_fritap_analyzer` marker is *not* required in this form; only the
      `BaseAnalyzer` protocol is checked.
    - **bare `module`** — friTap auto-discovers analyzer classes *defined in that
      module* that set `is_fritap_analyzer = True`. The marker stops the registry
      from blindly instantiating every class it finds.

### Ship it everywhere: discovery

Beyond the one-off `--analyzer-path`, an analyzer can be made **ambiently
available** — picked up automatically by every `fritap` run, including
`--list-analyzers`, the TUI, and offline analysis — through three discovery
channels.

#### 1. Drop-in analyzers directory

Drop a `.py` file containing a class with `is_fritap_analyzer = True` into the
platform analyzers directory and it is auto-discovered everywhere:

| Platform | Path |
|----------|------|
| Linux | `~/.local/share/friTap/analyzers/` |
| macOS | `~/Library/Application Support/friTap/analyzers/` |
| Windows | `C:\Users\<user>\AppData\Local\friTap\analyzers\` |

No `--analyzer-path` needed — friTap scans this directory the first time analyzers
are listed or run (discovery is lazy, then cached). This mirrors the existing
[plugins directory](../development/plugins.md) trust model.

#### 2. Packaged analyzers (entry points)

Third-party packages distribute analyzers by declaring the **`fritap.analyzers`**
entry-points group in their `setup.py` / `pyproject.toml`:

```python
entry_points={
    "fritap.analyzers": [
        "my-analyzer = my_pkg.analyzers:MyAnalyzer",
    ],
}
```

Once the package is `pip install`-ed, the analyzer is discovered automatically.

#### 3. Plugin bridge

A [`FriTapPlugin`](../development/plugins.md) can expose analyzers by implementing the optional
`register_analyzers()` hook, which returns a list of `BaseAnalyzer` instances.
This runs independently of the `on_load`/Session lifecycle, so the analyzers are
available offline, for `--list-analyzers`, and in the TUI:

```python
from friTap.plugins.base import FriTapPlugin


class MyPlugin(FriTapPlugin):
    name = "my-plugin"
    version = "1.0.0"

    def register_analyzers(self):
        return [MyAnalyzer()]
```

#### Listing discovered analyzers

Both commands list every analyzer — built-in **and** discovered:

```bash
fritap --list-analyzers           # top-level flag
fritap analyze --list-analyzers   # under the analyze subcommand
```

!!! danger "Security: discovery executes code"
    Dropping a `.py` file in the analyzers directory, installing a package that
    declares a `fritap.analyzers` entry point, or installing such a plugin causes
    **that code to execute** on the next `fritap` run that lists or resolves
    analyzers — even for `--list-analyzers`. This is the same trust model as the
    existing plugin directory: only place analyzers you trust there.

    To disable all ambient discovery (drop-in directory, entry points, and the
    plugin bridge), set the environment variable:

    ```bash
    export FRITAP_DISABLE_ANALYZER_DISCOVERY=1
    ```

    Explicit `--analyzer-path` references still work when discovery is disabled.

### Watch the CI gate trip

The `MEDIUM` severity above is deliberate. The default CI gate trips at **medium or
higher**, so a single match makes the command exit non-zero:

```bash
fritap analyze capture.tap --analyzer-path my_analyzer:InternalHostAnalyzer
echo $?   # -> 2  (a medium+ finding was reported)
```

If you lower the analyzer's severity to `Severity.LOW`, the same run exits `0` — the
finding is still reported, but it stays below the gate. See
[CI/CD gate](#cicd-gate) for the full exit-code contract.

---

## The `analyze` CLI

Run analyzers over a captured `.tap` file. Both forms are equivalent:

```bash
fritap analyze capture.tap          # bare subcommand
fritap --analyze capture.tap        # explicit flag
```

!!! note "Disambiguation"
    The bare `analyze` subcommand is only treated as analysis when the next argument
    looks like a `.tap` input. Capturing a process literally named `analyze` is not
    hijacked. The explicit `--analyze` form is always analysis.

### Flags

| Flag | Default | Effect |
|------|---------|--------|
| `--scanners <list>` | all built-ins | Comma-separated analyzer names, e.g. `credentials,ioc`. Selects which analyzers **run**. |
| `--report {csv,json,md,table}` | `table` | Output format. |
| `--report-out <path>` | stdout | Write the report to a file instead of printing it. |
| `--min-severity {critical,high,medium,low,info}` | `info` | Only report findings at or above this severity. |
| `--min-confidence <float>` | `0.0` | Only report findings with confidence at or above this value (0.0–1.0). |
| `--source <names>` | all | Comma-separated analyzer source names to include in the report (e.g. `credentials,privacy`). Filters which findings **show**; use `--scanners` to choose which analyzers **run**. |
| `--category <categories>` | all | Comma-separated finding categories to include (`secret,pii,network,protocol`). |
| `--show-pii` | off (redacted) | Reveal PII/secret values in the report instead of redacting them, including the query/fragment/userinfo values and e-mails otherwise masked in finding text (see [Reports](#reports-and-the-findings-sidecar)). |
| `--analyzer-path <module[:Class]>` | — | Load an external analyzer. |
| `--include-private-ips` | off | Include private/reserved IPs in IOC findings (default skips them). |
| `--protobuf-schema <path>` | — | Schema path for the protobuf analyzer. |

!!! note "`--scanners` (run) vs `--source`/`--category` (show)"
    `--scanners` chooses **which analyzers execute**. `--source` and `--category`
    are *report-side filters* that narrow which already-produced findings are shown
    (and which are written to the sidecar). They compose: run only what you need,
    then display only the categories you care about.

```bash
fritap analyze capture.tap --category pii --show-pii          # reveal redacted PII
fritap analyze capture.tap --source credentials --min-confidence 0.8
```

See [`api/cli.md`](../api/cli.md) for the canonical flag reference across all
subcommands.

---

## Live scan

Add `--scan` to any live capture to analyze flows **as they complete**, then print a
report when capture ends. This is a **functional, supported** feature, not experimental.

```bash
fritap --scan -m com.example.app                  # all built-in analyzers
fritap --scan credentials,ioc -m com.example.app  # a subset
```

`--scan` takes an optional comma-separated analyzer list; with no value it runs all
built-in analyzers (the argument is `nargs="?"` with a default of `all`).

| Flag | Default | Effect |
|------|---------|--------|
| `--scan [<analyzers>]` | all built-ins | Enable live analysis; optionally name analyzers. |
| `--scan-report {json,csv,md,table}` | `table` | Format of the end-of-capture report. |
| `--scan-report-out <path>` | stdout | Write the report to a file. |
| `--scan-min-severity {critical,high,medium,low,info}` | `info` | Severity filter for the report. |
| `--scan-min-confidence <float>` | `0.0` | Only report findings with confidence at or above this value. |
| `--scan-source <names>` | all | Comma-separated analyzer source names to include in the report. |
| `--scan-category <categories>` | all | Comma-separated finding categories to include (`secret,pii,network,protocol`). |
| `--scan-show-pii` | off (redacted) | Reveal PII/secret values in the report instead of redacting them. |
| `--analyzer-path <module[:Class]>` | — | Load an external analyzer for the live scan. **Repeatable.** |

Loading custom analyzers during a live capture now works the same as offline —
`--analyzer-path` is repeatable, so you can stack several:

```bash
fritap --scan all -m com.example.app \
    --analyzer-path my_analyzer:InternalHostAnalyzer \
    --analyzer-path another_pkg.analyzers
```

The live `--scan-*` filters mirror the offline `analyze` filters one-for-one
(`--scan-min-confidence` ≙ `--min-confidence`, `--scan-source` ≙ `--source`,
`--scan-category` ≙ `--category`, `--scan-show-pii` ≙ `--show-pii`).

!!! info "Same analyzers, live wiring"
    Internally the live path wraps each analyzer in an `AnalyzerPlugin` that subscribes
    to `FlowEvent` on the EventBus and analyzes flows on completion. The analyzer code
    is identical to the offline path — only the delivery mechanism differs.

---

## Analyzer catalog

friTap ships four built-in analyzers. Their names (used with `--scanners`/`--scan`)
are **`credentials`**, **`ioc`**, **`privacy`**, and **`protobuf`**. All four run by
default when you pass a bare `--scan` / `--scanners` (i.e. the full built-in set).

### `credentials`

Scans HTTP headers, query parameters, request bodies, response bodies, and URLs for
secrets. All reported secret values are **redacted** (first few characters only).

| Detection | Severity |
|-----------|----------|
| Bearer token in `Authorization` header | HIGH |
| Basic auth (decoded; username shown, password redacted) | CRITICAL |
| API-key headers (`X-API-Key`, `API-Key`, `ApiKey`, `X-Auth-Token`, `X-Access-Token`) | HIGH |
| Session/auth `Cookie` (contains `session`/`token`/`auth`/`jwt`/`sid`) | MEDIUM (confidence 0.7) |
| Sensitive URL query params (`token`, `access_token`, `api_key`, `apikey`, `key`, `secret`, `password`, `auth`, `session_id`, `sid`, `client_secret`, `refresh_token`) | HIGH |
| Password fields in JSON / form bodies (`password`, `passwd`, `pass`, `pwd`, `secret`, `*_password`) | CRITICAL |
| Token/key fields in JSON (`token`, `access_token`, `refresh_token`, `id_token`, `api_key`, `apikey`, `secret`, `client_secret`, `auth_token`, `session_token`) | HIGH |
| JWT (decoded; flags `alg:none` and expiry) | HIGH, or CRITICAL when `alg=none` |
| Digest/NTLM/Negotiate `Authorization` scheme | (credential-bearing) |
| Non-standard `Authorization` scheme (`'<scheme>'`) | (credential-bearing) |
| CSRF / anti-forgery token (header, JSON field, or form field) | — |
| High-entropy strings (≥ 4.5 bits, length 20–256) | LOW (confidence 0.4) |

JWTs are detected anywhere in the body via pattern `eyJ...`, decoded without
verification, and flagged CRITICAL if the header algorithm is `none`.

All reported secret values are **redacted by default**. The `credentials` analyzer
tags every finding with `metadata["category"] = "secret"` (see
[Category taxonomy](#category-taxonomy-and-compliance-tags)).

The API-key/secret pattern set:

| Pattern | Severity |
|---------|----------|
| AWS Access Key (`AKIA…`) | HIGH |
| AWS Secret Key (`aws_secret_access_key=…`) | CRITICAL |
| GitHub Token (`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`) | HIGH |
| GitHub Classic Token (`ghp_` + 36) | HIGH |
| GitHub Fine-Grained PAT (`github_pat_…`) | HIGH |
| GitLab Token (`glpat-…`) | HIGH |
| Slack Token (`xox[boaprs]-…`) | HIGH |
| Slack Webhook URL (`https://hooks.slack.com/services/…`) | HIGH |
| Stripe Secret Key (`sk_live_…`) | CRITICAL |
| Stripe Publishable Key (`pk_live_…`) | MEDIUM |
| Google API Key (`AIza…`) | HIGH |
| Google OAuth Access Token (`ya29.…`) | HIGH |
| Google OAuth Refresh Token (`1//…`, keyword-gated) | HIGH |
| GCP Service Account (`"type":"service_account"`) | CRITICAL |
| Twilio API Key (`SK` + 32 hex) | HIGH |
| SendGrid API Key (`SG.…`) | HIGH |
| npm Access Token (`npm_…`) | HIGH |
| PyPI Token (`pypi-AgEIcHlwaS5vcmc…`) | HIGH |
| Docker Personal Access Token (`dckr_pat_…`) | HIGH |
| Private Key (`-----BEGIN … PRIVATE KEY-----`) | CRITICAL |
| Encrypted Private Key (`-----BEGIN ENCRYPTED PRIVATE KEY-----`) | CRITICAL |
| PGP Private Key (`-----BEGIN PGP PRIVATE KEY BLOCK-----`) | CRITICAL |
| PuTTY Private Key (`PuTTY-User-Key-File-…`) | CRITICAL |
| SSH2 Encrypted Private Key (`---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----`) | CRITICAL |
| X.509 Certificate (`-----BEGIN CERTIFICATE-----`) | INFO |
| Private JWK (JSON with `kty` + private `d`/`k`) | CRITICAL |
| PKCS#12 / PFX key store (DER or content-type) | CRITICAL |

!!! note "De-noised high-entropy scanning"
    To cut false positives, low-signal high-entropy strings (UUIDs, common
    crypto-hash digests, encoded payloads) are **suppressed** and collapsed into a
    single per-flow **INFO** record titled
    `Entropy scan suppressed low-signal strings`, summarizing how many were dropped.
    Genuine high-entropy secrets are still reported as their own LOW findings.

### `ioc`

Extracts Indicators of Compromise from connection metadata, HTTP headers, URLs, and
response bodies. Most IOC findings are **INFO** — they are inventory, not alerts.

| Detection | Severity |
|-----------|----------|
| Destination IP (`dst_addr:dst_port`) | INFO |
| Request domain (from `Host`) | INFO |
| Full request URL (`METHOD host/path`) | INFO |
| `User-Agent` string | INFO |
| `Referer` URL | INFO |
| `Server` response header | INFO |
| `Location` redirect URL | INFO |
| `Set-Cookie` domain attribute | INFO |
| SHA-256 hash of response body (≥ 32 bytes) | INFO |
| IPv4 addresses found in response bodies | LOW (confidence 0.6) |
| Email addresses found in response bodies | LOW (confidence 0.7) |

!!! note "`--include-private-ips`"
    By default the IOC analyzer **skips private/reserved IP addresses** (both
    destination IPs and IPs found in bodies). Pass `--include-private-ips` to keep
    them — useful when analyzing internal/lab traffic.

### `protobuf`

Detects and decodes protobuf and gRPC content in HTTP flows.

| Detection | Severity |
|-----------|----------|
| gRPC endpoint (content-type `application/grpc*`) | INFO |
| Decoded protobuf structure (top-level field count + formatted preview) | INFO |
| Decode failure when content-type/heuristic suggests protobuf | LOW |
| Unusual fields (field numbers > 1000, nesting > 10 levels, fields > 1 MB) | MEDIUM |

Pass `--protobuf-schema <path>` to supply a schema. Non-gRPC bodies are decoded when
the content-type indicates protobuf *or* the bytes heuristically look like protobuf.

### `privacy`

Detects **personally identifiable information (PII)** leaking through observed
traffic — headers, query parameters, JSON/form bodies, and URLs. Every finding is
tagged `metadata["category"] = "pii"` and carries one or more **compliance** tags in
`metadata["compliance"]` (e.g. `GDPR`, `CCPA`, `PCI-DSS`, `HIPAA`).

| Detection | Severity | Compliance |
|-----------|----------|------------|
| Email address | LOW | GDPR, CCPA |
| Phone number (E.164) | LOW | GDPR, CCPA |
| Phone number (loose, key-gated) | LOW | GDPR, CCPA |
| Credit-card PAN (Luhn + IIN validated) | MEDIUM | PCI-DSS, GDPR |
| IBAN (mod-97 validated) | MEDIUM | GDPR, CCPA |
| US SSN (range-validated) | MEDIUM | GDPR, CCPA, HIPAA |
| IMEI (15-digit + Luhn) | MEDIUM | GDPR, CCPA |
| MAC address | LOW | GDPR, CCPA |
| Android ID (16-hex, key-gated) | — | GDPR, CCPA |
| Advertising ID (GAID/IDFA, UUID-v4) | MEDIUM | GDPR, CCPA |
| IP address in PII context (forwarding headers / `ip_*` keys; excludes private) | LOW | GDPR, CCPA |
| Geolocation — lat/lon sibling keys, a coord pair/array under a geo-ish key (`coordinates`/`geo`/`position`/`location`), Plus Codes / Open Location Codes (also matched in free text), or geohashes (only under an explicit `geohash` key) | MEDIUM | GDPR, CCPA |
| Postal address (≥2 of street/city/zip keys) | LOW | GDPR, CCPA |
| Date of birth | MEDIUM | GDPR, HIPAA |
| Passport number (key-gated) | MEDIUM | GDPR |
| Health data (diagnosis/ICD-10/prescription/blood type/medical record) | HIGH | HIPAA, GDPR |

!!! warning "PII is redacted by default"
    Detected PII values are **redacted** in findings, reports, and the sidecar (PAN
    keeps first-6/last-4, email keeps first char + domain, SSN/DOB/passport/health
    are fully masked, others keep the first 8 characters). Pass `--show-pii`
    (offline) or `--scan-show-pii` (live) to reveal the raw values. Each finding's
    evidence carries a `redacted` boolean.

The `privacy` analyzer runs as part of the default built-in set.

---

## Category taxonomy and compliance tags

Every finding now carries a **category** in `metadata["category"]`, surfaced as the
`Finding.category` property. The four categories are:

| Category | Meaning | Produced by |
|----------|---------|-------------|
| `secret` | Credentials, keys, tokens | `credentials` |
| `pii` | Personally identifiable information | `privacy` |
| `network` | Network/connection indicators (IPs, domains, URLs, UAs, hashes) | `ioc` |
| `protocol` | Decoded protocol structure (protobuf/gRPC) | `protobuf` |

Filter the report by category with `--category secret,pii` (offline) or
`--scan-category` (live). PII findings additionally carry `metadata["compliance"]`,
listing the regulatory regimes (`GDPR`, `CCPA`, `PCI-DSS`, `HIPAA`) implicated by
that data type.

---

## Finding and Severity model

Every analyzer emits `Finding` objects (`friTap.analysis.Finding`), an immutable
dataclass:

| Field | Type | Notes |
|-------|------|-------|
| `severity` | `Severity` | See below. |
| `title` | `str` | Short human-readable title. |
| `description` | `str` | Detailed description. |
| `source` | `str` | The analyzer's `name`. |
| `flow_id` | `str` | Flow that triggered it (empty for cross-flow). |
| `confidence` | `float` | 0.0–1.0 (default 1.0). |
| `timestamp` | `float` | Epoch seconds (auto-set). |
| `evidence` | `dict` | Structured evidence (matched data, location, host, …). |
| `metadata` | `dict` | Extension fields, incl. `category` (`secret`/`pii`/`network`/`protocol`), `compliance` (PII only), MITRE ATT&CK ID, CWE, … |

The finding's category is exposed directly as the `Finding.category` property
(reading `metadata["category"]`).

`Severity` (`friTap.analysis.Severity`) is declared **most-severe first**, so rank `0`
is the most severe:

| Severity | Rank |
|----------|------|
| `CRITICAL` | 0 |
| `HIGH` | 1 |
| `MEDIUM` | 2 |
| `LOW` | 3 |
| `INFO` | 4 |

`Finding.to_dict()` is the single serialization contract shared by reporters, the
`.tap` `REC_FINDING` record, and the findings sidecar (`severity` is stored as its
string value). See [`api/tap-format.md`](../api/tap-format.md) for how findings are
stored inside a `.tap` file.

---

## Reports and the findings sidecar

Four report formats are available. The flag name depends on the mode:
`--report <fmt>` selects the format for the **offline** `fritap --analyze <file>`
path, while `--scan-report <fmt>` selects it for the **live** `fritap --scan ...`
path. Both accept the same set of formats:

- **`table`** — aligned text table for the terminal (default), with a per-severity
  total line.
- **`json`** — `{meta, summary, findings}`; `summary` carries `total`, `by_severity`,
  and `by_source` counts.
- **`csv`** — columns `severity,title,source,flow_id,confidence,description`.
- **`md`** — Markdown report grouped by severity.

In addition, the **`analyze` CLI always writes a JSON findings sidecar** next to the
input file: `<tap_stem>.findings.json` (e.g. `capture.tap` → `capture.findings.json`).
This is independent of `--report` and is written even when `--report-out` redirects the
main report elsewhere.

!!! note "Values in finding text are redacted"
    In every report format and in the sidecar, the title, description and evidence
    of **every** finding (any category, including IOC `network` URL findings) are
    scrubbed: URLs keep their structure and parameter keys but lose query, fragment
    and userinfo values (`api.example.com/signup?email=<redacted>`), and e-mail
    addresses become `<email>`. Pass `--show-pii` (or `--scan-show-pii` live) to
    see the full values. The rules live in `friTap/analysis/redaction.py` and are
    shared by the reporters, the `privacy` and `credentials` analyzers and
    [`fritap report`](#capture-digest-for-ai-agents-fritap-report).

!!! note "Sidecar is CLI-only"
    The sidecar is written by the `analyze` command. The programmatic
    `analyze_tap_report(...)` performs **no** file writes — callers decide what to do
    with the returned findings.

---

## CI/CD gate

The `analyze` command is designed to be a CI gate. Its exit code:

| Exit code | Meaning |
|-----------|---------|
| `0` | Success; no finding at or above the gate severity. |
| `2` | A finding **at or above `medium`** was reported (the gate, `_GATE_SEVERITY = "medium"`). |
| `1` | Usage/IO error (missing `.tap` file, bad scanner name, unwritable output, read/analyze failure). |

Because `--min-severity` filters findings *before* the gate is evaluated, you can tune
sensitivity: filtering to `--min-severity critical` lets a HIGH finding through the
report list but, if nothing critical remains, the gate clears and the command exits `0`.

```yaml
# .github/workflows/traffic-analysis.yml
name: Traffic Analysis
on: [push, pull_request]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install friTap
      # Exit 2 (gate tripped by a medium+ finding) fails the job.
      - name: Analyze captured traffic
        run: fritap analyze capture.tap --report md --report-out analysis.md
      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: traffic-analysis
          path: |
            analysis.md
            capture.findings.json
```

---

## Programmatic API

The pure, presentation-agnostic entry point is `analyze_tap_report(...)`, exported from
the top-level `friTap` package. It performs **no stdout, no sidecar write, and never
calls `sys.exit`** — it returns an `AnalyzeReport` you inspect yourself.

```python
from friTap import analyze_tap_report

report = analyze_tap_report(
    "capture.tap",
    scanners="credentials,ioc",   # None / "all" / "" -> every built-in (which analyzers RUN)
    min_severity="info",
    report_format="table",
    include_private_ips=False,
    protobuf_schema=None,
    analyzer_path=None,           # "module" or "module:Class"
    min_confidence=0.0,           # report-side: drop findings below this confidence
    source=None,                  # report-side: comma-separated source names to SHOW
    category=None,                # report-side: "secret,pii,network,protocol" to SHOW
    show_pii=False,               # reveal PII/secret values instead of redacting
)

print(report.rendered)            # the formatted report string
print(report.analyzer_names)      # ['credentials', 'ioc']
for finding in report.findings:   # already severity-filtered
    print(finding.severity.value, finding.title)

# CLI-parity gate:
if report.gate_tripped:           # any finding >= report.gate_severity ("medium")
    raise SystemExit(report.exit_code)   # 2 when tripped, else 0
```

`AnalyzeReport` carries `findings`, `rendered`, `report_format`, `analyzer_names`,
`meta`, and `gate_severity`, plus the `gate_tripped` and `exit_code` properties.
`analyze_tap_report` raises `ValueError` for an unknown `report_format` or an
unresolvable analyzer spec, and `ImportError` for a bad `analyzer_path`.

### Lower-level building blocks

For finer control, compose the resolver and multi-analyzer runner directly:

```python
from friTap.analysis import analyze_tap_multi
from friTap.analysis.registry import resolve_analyzers

analyzers = resolve_analyzers(
    "credentials,ioc",            # None / "all" / "" -> every built-in
    include_private_ips=False,
)
findings = analyze_tap_multi(analyzers, "capture.tap")
```

`analyze_tap_multi` reads the `.tap` once and passes each flow to every analyzer.
There is also `analyze_tap(analyzer, tap_path)` for a single analyzer. The
helper functions `list_analyzers()` and `list_report_formats()` enumerate the
registered built-ins and formats. See [`api/python.md`](../api/python.md) for the wider
programmatic API.

---

## Capture digest for AI agents (`fritap report`)

`fritap report` condenses a `.tap` into a small, stable digest so an LLM can
answer *"what does this app send, to whom, and what leaks?"* in a few hundred
tokens instead of reading raw flows. Like `analyze`, it is passive and offline,
and `report` is only treated as the subcommand when followed by a `.tap` path.

```bash
fritap report capture.tap                           # JSON to stdout, ~1500-token budget
fritap report capture.tap --format md --budget 800  # compact Markdown
fritap report capture.tap --focus privacy           # only PII findings in the summary
fritap report capture.tap --app-protocol grpc -o digest.json
fritap report capture.tap --filter 'http.response.code >= 400'
fritap report capture.tap --flow f12                # drill into one digest ref
fritap report capture.tap --flow 'f12#m3' --format md
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--focus all\|privacy\|security` | `all` | Findings summarized: `privacy` = `pii`; `security` = `secret`/`network`/`protocol`. Hosts and endpoints are always shown. |
| `--protocol X` | – | Keep flows carrying `X` anywhere in their stack (`tls`, `quic`, `http2`, `signal`, `telegram`, ...). |
| `--app-protocol Y` | – | Keep flows whose digest group is `Y` (`http` = http1/2/3, `http2`, `grpc`, `websocket`, `mtproto`, `signal`, ...). |
| `--filter EXPR` | – | Any display-filter expression. |
| `--budget N` | `1500` | Approximate token budget, estimated as `len(json) / 4`. |
| `--format json\|md` | `json` | Output format. |
| `--show-values` | off | Reveal finding values and, with `--flow`, payload values (redacted by default). |
| `--flow REF` | – | Print one flow instead of the digest: a digest ref (`f12`, `f12#m3`) or a full flow id. See [Drill-down](#drill-down-into-a-flow-flow). |
| `--max-bytes N` | `2048` | With `--flow`: cap each body / message preview at `N` bytes. |
| `-o PATH` | stdout | Write to a file. |

Exit codes: `0` success, `1` missing file, bad filter, malformed or unknown
`--flow` ref, or unwritable output.

### What the digest contains

Flows are grouped **per protocol**: `grpc` when the request content-type is
gRPC, else the innermost E2E layer (`telegram_e2e`, `signal`, `mtproto`, `rc4`),
else the app layer (`websocket`, `http3`, `http2`, `http1`), else the transport.
Each group lists:

* **hosts**: Host / `:authority` / SNI (or the server `addr:port`), flow count, bytes, first-seen time.
* **endpoints**: method plus a **path template** (numeric, UUID, hex and opaque-token
  segments collapse to `{id}`), and the **keys** seen in the query string, the
  JSON or form body and the app-specific request headers. Each key carries only a
  value *shape*, such as `email:str(email-like)`, `authorization:str(bearer-auth)`
  or `user.id:int`. Requests with an identical shape are clustered into one row
  with a `count`. Non-HTTP RPCs (e.g. MTProto TL constructors) show the method with path `-`.
* **messages**: E2E transcript kinds (Signal, MTProto, Telegram secret chats),
  clustered by layer, direction and kind.

A **findings** summary from the built-in analyzers (`credentials`, `ioc`,
`privacy`, `protobuf`) follows: totals by severity and category, plus the top 10
clustered findings with a short description.

Every row carries a short `ref` for drill-down: `f<N>` is the N-th flow of the
capture (1-based, ordered by start time; ties keep the `.tap` flow-index order)
and `f<N>#m<k>` is the k-th decoded E2E message of that flow (0-based, counted
across all of the flow's transcript layers). Refs are a pure function of the
`.tap`, so they stay the same across runs and digest filters. To save tokens,
no ref → flow-id table is emitted; `--flow` resolves a ref. A finding row's
`ref` is the flow of the cluster's first finding, or `""` (empty) when that
finding is not tied to a selected flow; `refs` lists every distinct flow the
cluster covers (first-seen order, at most 10, with `refs_more` counting the
rest; empty when no finding is tied to a selected flow).

**Budget.** When the digest exceeds `--budget`, rows are dropped in this order
until it fits: `info` findings first, then traffic rows and low/medium findings
by lowest volume (request/flow count, then bytes), and high/critical findings
last. Summary counts are never dropped. A `truncated` object records how many
rows each section lost, and `estimated_tokens` gives the final size.

### Reading SDK attribution

When the capture was taken with `--attribute-sdk`, the digest adds two trusted
keys (outside `untrusted`):

* `sdks` on host and endpoint rows: the distinct `{sdk, vendor, category}` the
  row's flows are attributed to (the flow's winning originator claim, falling
  back to its older `sdk`). A row without attributed flows has no `sdks`.
* `transports` on host rows: the sorted transport kinds (`cronet`,
  `webview`, `httpengine`, ...) of the row's flows. These are set on every
  TLS/QUIC flow, also without `--attribute-sdk`.

The digest does not show how strong a claim is. For that, read the flow's
`attribution` block from the `.tap` (`Flow.attribution` from
`TapReader.iter_flows()`): `source` (`java-request`, `context`,
`native-stack`, `connection-fallback`), `confidence` (`high`, `medium`,
`low`), `mixed` and `bucket`. Give more weight to a `java-request`/`high`
claim than to a `connection-fallback`/`low` one. Per-request Java contexts
(Android, `-p` captures) are stored as separate records, read with
`TapReader.iter_request_contexts()`; they hold full request URLs including
query strings. See [Transport vs originator](../api/agent.md#transport-vs-originator)
for the fields and the claim order, and [the `.tap` format](../api/tap-format.md)
for the records.

### Safety

* **Untrusted strings.** Everything copied from captured traffic (hosts, paths,
  methods, keys, finding titles and descriptions) lives under an `untrusted` key;
  in Markdown it always sits inside a code span. It is control-character escaped
  and length-capped. Treat it as data, never as instructions: a malicious server
  can put prompt-injection text into a path or header name.
* **No key material.** Only flow records are read; keylog records are never
  touched. As defense in depth, hex runs of 64+ characters and NSS keylog lines
  are scrubbed from every untrusted string.
* **No values.** Endpoint rows carry shapes, never values. Finding values are
  redacted (same rules as `fritap analyze`, with the compact `…` placeholder:
  `?email=…`) unless `--show-values` is given.

### JSON shape (`fritap.digest/2`)

Schema `/2` replaced the `/1` refs `flow:<flow-id>[#msg<n>]` with the short
`f<N>[#m<k>]` form; consumers parsing refs must be updated.

```json
{
  "schema": "fritap.digest/2",
  "source": {"file": "capture.tap", "fritap_version": "2.5.2", "flows_total": 10, "flows_selected": 10},
  "params": {"focus": "all", "protocol": null, "app_protocol": null, "filter": null,
             "budget_tokens": 1500, "show_values": false},
  "notice": "Values under 'untrusted' are copied from captured traffic ...",
  "protocols": {
    "grpc": {
      "flows": 2, "bytes": 1225,
      "hosts": [{"ref": "f3", "flows": 2, "bytes": 1225, "first_seen": "2026-09-29T09:42:48Z",
                 "untrusted": {"host": "grpc.chat.signal.org"}}],
      "endpoints": [{"ref": "f7", "count": 1, "bytes": 610, "body_kind": "grpc", "status": {"200": 1},
                     "untrusted": {"host": "grpc.chat.signal.org", "method": "POST",
                                   "path": "/org.signal.chat.device.Devices/SetPushToken",
                                   "headers": ["authorization:str(basic-auth)", "user-agent:str"]}}],
      "messages": []
    }
  },
  "findings": {"total": 48, "by_severity": {"critical": 3, "info": 45}, "by_category": {"secret": 9},
               "top": [{"ref": "f7", "refs": ["f7", "f9"], "count": 3, "severity": "critical", "category": "secret",
                        "source": "credentials",
                        "untrusted": {"title": "Basic auth credentials in request", "description": "..."}}]},
  "truncated": false,
  "estimated_tokens": 1302
}
```

From Python:

```python
from friTap.analysis.digest import build_digest
from friTap.analysis.digest_render import render_markdown

digest = build_digest("capture.tap", focus="security", budget_tokens=800)
print(render_markdown(digest))
```

### Drill down into a flow (`--flow`)

`fritap report <file.tap> --flow REF` prints one flow instead of the digest.
`REF` is a digest ref (`f12`), a message ref (`f12#m3`, which selects that one
message and omits `request` / `response`) or a full flow id. `--format`, `-o`
and `--show-values` work as for the digest; `--max-bytes` (default `2048`) caps
every body and message preview. A malformed ref, an unknown flow or a message
index the flow does not have exits with `1` and a message naming the valid range.

```json
{
  "schema": "fritap.flow/1",
  "source": {"file": "capture.tap"},
  "params": {"ref": "f7", "max_bytes": 2048, "show_values": false},
  "notice": "Values under 'untrusted' are copied from captured traffic ...",
  "flow": {"ref": "f7", "flow_id": "<full flow id>", "src": "10.0.2.16:51234", "dst": "203.0.113.5:443",
           "server": "203.0.113.5:443", "group": "http2", "transport": "tcp",
           "stack": ["tls", "http2"], "state": "complete",
           "started": "2026-09-29T09:42:48Z", "ended": "2026-09-29T09:42:49Z", "bytes": 1840,
           "untrusted": {"host": "api.example.com"}},
  "request": {"direction": "write", "protocol": "HTTP/2", "body_kind": "json", "body_bytes": 41,
              "untrusted": {"method": "POST", "url": "https://api.example.com/v1/signup?email=<redacted>",
                            "headers": {"content-type": "application/json",
                                        "authorization": "<str(bearer-auth)>"},
                            "body": "{\"email\":\"<str(email-like)>\",\"age\":\"<int>\"}"}},
  "response": {"direction": "read", "protocol": "HTTP/2", "status": 200,
               "untrusted": {"status_text": "", "headers": {"...": "..."}}},
  "messages": [],
  "messages_total": 0
}
```

`messages` lists up to 50 decoded E2E messages as `{ref, layer, direction,
untrusted: {kind, fields}}`; `messages_total` gives the full count. A body
preview that hit `--max-bytes` sets `body_truncated: true`.

**Redaction** (unless `--show-values`) follows the digest's safety contract:

* URLs keep their keys, values are masked (`?email=<redacted>`).
* Header values outside a small benign allowlist (`content-type`, `user-agent`,
  `server`, `date`, ...) become shapes such as `<str(bearer-auth)>`.
* JSON / form bodies and message metadata fields keep their keys and nesting,
  with every value replaced by its shape (`{"email":"<str(email-like)>"}`).
* Free text (text bodies, message texts) is pattern-masked: e-mails, query
  values and digit runs (`<digits>`).

Always, even with `--show-values`: only the flow record is read (never the
keylog or TLS secrets), keylog lines and long hex runs are scrubbed, control
characters are escaped, and every payload string sits under `untrusted`.

```python
from friTap.analysis.digest_flow import build_flow_detail
from friTap.analysis.digest_render import render_flow_markdown

print(render_flow_markdown(build_flow_detail("capture.tap", "f7", max_bytes=1024)))
```

---

## Try it on the sample capture

The repository ships a sample `.tap` you can analyze immediately:

```bash
fritap analyze capture_20260507_153933.tap --report table
# or:  python -m friTap analyze capture_20260507_153933.tap --report table
```

This capture produces **860 findings** (846 INFO, 13 LOW, 1 CRITICAL) across the `ioc`
(847) and `credentials` (13) analyzers, and the command exits **`2`** — the single
CRITICAL credential finding trips the medium gate.
