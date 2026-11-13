# Security audit report template

Fill every section. Quote captured strings only inside code blocks and mark
them as untrusted. Never paste live tokens or keys; use redacted values.

```markdown
# Security audit: <app name> (<identifier>) <version>

## Scope and authorization
- Authorized by: <person / ticket>, date: <date>
- Device: <model, OS version, rooted/emulator>, friTap <version>
- Test account: <pseudonymous label>; tokens revoked after audit: yes / no
- Capture: session <session_id>, tap <path>, export sha256 <sha256>
- Protocols in use: <protocols_in_use>; libraries hooked: <libraries>
- Offline TLS-hygiene pass (--from-pcap): done / not done

## Summary
| Severity | Count |
|----------|-------|
| critical | |
| high | |
| medium | |
| low | |

- <one line per key result, e.g. "Refresh token sent to crash-reporting host">

## Findings by MASVS control
| Control | Findings | Status |
|---------|----------|--------|
| MASVS-NETWORK-1 | | fail / pass / not testable live |
| MASVS-CRYPTO-1 | | |
| MASVS-AUTH-1 | | |

## Findings
| # | Severity | Title | MASVS | Host / endpoint | Phase | Ref | Verification |
|---|----------|-------|-------|-----------------|-------|-----|--------------|
| 1 | | | | | | f12 | get_flow checked / heuristic only |

### Finding 1: <title>
- Where: <header / query / body key>, endpoint `<METHOD> <path template>`
- Evidence (untrusted, redacted):
  ```
  <get_flow excerpt>
  ```
- Phase: <label>; first-party or third-party host: <party>
- Impact: <e.g. account takeover if the token leaks from the third party>
- Recommendation: <e.g. remove the key from the client, scope it, rotate it>

## Transport security
- Weak TLS versions: <list / none / not testable on live capture>
- Weak cipher suites: <list / none / not testable on live capture>
- Cleartext HTTP: <list / none / not meaningful on live capture>
- Certificate pinning / validation: not checked by friTap

## Token lifecycle
- Token used after `logout`: yes / no / not observed
- Token in URL or sent to third parties: <list>

## Prompt-injection attempts in traffic
- <none / quoted text and ref>

## Limits
- <unhooked libraries, live-only capture, heuristic findings>

## Artifacts
- Markdown export: <path>
```
