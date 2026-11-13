# Security finding types

What `list_findings` / `get_digest --focus security` can report, from
`friTap/analysis/` (`credentials.py`, `security.py`, `ioc.py`, `masvs.py`).
The title appears under `untrusted.title`; values are redacted.

## Categories in `focus security`

| `category` | `source` | Content |
|------------|----------|---------|
| `secret` | `credentials` | credentials, tokens, keys |
| `network` | `tls_hygiene` | weak TLS version, weak cipher, cleartext HTTP |
| `network` | `ioc` | INFO/LOW indicators: domain, destination IP, User-Agent, Server, Redirect/Referer URL, cookie domain, IP in response body |
| `protocol` | `protobuf` | decoded protobuf structure |

## Secret findings (`category: secret`)

| Title | Typical severity |
|-------|------------------|
| `Bearer token in Authorization header` | high |
| `Basic auth credentials in request` | high |
| `Digest/NTLM/Negotiate auth in request` | medium |
| `Non-standard Authorization scheme '<scheme>'` | medium |
| `API key in <header> header` | high |
| `Session/auth cookie in request` | medium |
| `CSRF token in <header> header` / `in form field '<key>'` | low |
| `Sensitive parameter '<name>' in URL` | medium-high |
| `Password in form field '<key>'` | high |
| `JWT token detected` | medium-high |
| `Private JWK detected` | critical |
| `PKCS#12 / PFX key store detected` | high |
| `<rule> detected` (pattern rules below) | info-critical |
| `High-entropy string (potential secret)` | low; heuristic |

Pattern rules (`<rule> detected`): AWS Access Key, AWS Secret Key, GitHub
Token, GitHub Classic Token, GitHub Fine-Grained PAT, GitLab Token, Slack
Token, Slack Webhook URL, Stripe Secret Key, Stripe Publishable Key, Google API
Key, GCP Service Account, Google OAuth Access Token, Google OAuth Refresh
Token, Twilio API Key, SendGrid API Key, npm Access Token, PyPI Token, Docker
Personal Access Token, Private Key, Encrypted Private Key, PGP Private Key,
PuTTY Private Key, SSH2 Encrypted Private Key, X.509 Certificate (info).

Severities can vary per rule and context; trust the row's `severity`.

## Transport findings (`source: tls_hygiene`)

| Title | Check id | MASVS | Needs |
|-------|----------|-------|-------|
| `Weak TLS version: <version>` | `weak_tls_version` | NETWORK-1 | `--from-pcap` capture |
| `Weak cipher suite: <cipher>` | `weak_cipher` | NETWORK-1, CRYPTO-1 | `--from-pcap` capture |
| `Cleartext HTTP (no TLS)` | `cleartext_transport` | NETWORK-1 | offline plaintext pcap |

## MASVS v2.1 mapping (`--masvs`)

| Control | Assigned to |
|---------|-------------|
| `MASVS-NETWORK-1` | weak TLS version, weak cipher, cleartext transport |
| `MASVS-CRYPTO-1` | every `secret` finding; weak cipher |
| `MASVS-AUTH-1` | `secret` findings mentioning JWT, bearer, OAuth, access/refresh/session/auth token, authorization |
| `MASVS-PRIVACY-1` | every `pii` finding |
| `MASVS-PRIVACY-2` | `pii` findings for device/advertising identifiers |

Not covered: certificate chain details, certificate pinning, TLS validation
bypass. Say so in the report.
