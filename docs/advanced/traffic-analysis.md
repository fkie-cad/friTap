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
| `--scanners <list>` | all built-ins | Comma-separated analyzer names, e.g. `credentials,ioc`. |
| `--report {json,csv,md,table}` | `table` | Output format. |
| `--report-out <path>` | stdout | Write the report to a file instead of printing it. |
| `--min-severity {critical,high,medium,low,info}` | `info` | Only report findings at or above this severity. |
| `--analyzer-path <module[:Class]>` | — | Load an external analyzer. |
| `--include-private-ips` | off | Include private/reserved IPs in IOC findings (default skips them). |
| `--protobuf-schema <path>` | — | Schema path for the protobuf analyzer. |

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

!!! info "Same analyzers, live wiring"
    Internally the live path wraps each analyzer in an `AnalyzerPlugin` that subscribes
    to `FlowEvent` on the EventBus and analyzes flows on completion. The analyzer code
    is identical to the offline path — only the delivery mechanism differs.

---

## Analyzer catalog

friTap ships three built-in analyzers. Their names (used with `--scanners`/`--scan`)
are **`credentials`**, **`ioc`**, and **`protobuf`**.

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
| High-entropy strings (≥ 4.5 bits, length 20–256) | LOW (confidence 0.4) |

JWTs are detected anywhere in the body via pattern `eyJ...`, decoded without
verification, and flagged CRITICAL if the header algorithm is `none`.

The API-key/secret pattern set:

| Pattern | Severity |
|---------|----------|
| AWS Access Key (`AKIA…`) | HIGH |
| AWS Secret Key (`aws_secret_access_key=…`) | CRITICAL |
| GitHub Token (`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`) | HIGH |
| GitHub Classic Token (`ghp_` + 36) | HIGH |
| GitLab Token (`glpat-…`) | HIGH |
| Slack Token (`xox[boaprs]-…`) | HIGH |
| Stripe Secret Key (`sk_live_…`) | CRITICAL |
| Stripe Publishable Key (`pk_live_…`) | MEDIUM |
| Google API Key (`AIza…`) | HIGH |
| GCP Service Account (`"type":"service_account"`) | CRITICAL |
| Twilio API Key (`SK` + 32 hex) | HIGH |
| SendGrid API Key (`SG.…`) | HIGH |
| Private Key (`-----BEGIN … PRIVATE KEY-----`) | CRITICAL |

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
| `metadata` | `dict` | Optional extension fields (MITRE ATT&CK ID, CVE, …). |

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
    scanners="credentials,ioc",   # None / "all" / "" -> every built-in
    min_severity="info",
    report_format="table",
    include_private_ips=False,
    protobuf_schema=None,
    analyzer_path=None,           # "module" or "module:Class"
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

## Try it on the sample capture

The repository ships a sample `.tap` you can analyze immediately:

```bash
fritap analyze capture_20260507_153933.tap --report table
# or:  python -m friTap analyze capture_20260507_153933.tap --report table
```

This capture produces **860 findings** (846 INFO, 13 LOW, 1 CRITICAL) across the `ioc`
(847) and `credentials` (13) analyzers, and the command exits **`2`** — the single
CRITICAL credential finding trips the medium gate.
