# Privacy finding types

What `list_findings` / `get_digest --focus privacy` can report, from
`friTap/analysis/`. Severities are the analyzer defaults; `masvs` is set when
`--masvs` is passed.

## Categories

| `category` | Produced by (`source`) | Meaning in a privacy audit |
|------------|------------------------|----------------------------|
| `pii` | `privacy`, `ioc` (e-mail addresses in responses) | Personal data in traffic. The privacy core. |
| `secret` | `credentials` | Passwords, tokens, API keys. Report if sent to a third party. |
| `network` | `ioc`, `tls_hygiene` | Domains, IPs, User-Agent, cookies (INFO). Useful for the destination map. |
| `protocol` | `protobuf` | Decoded protobuf structure. |
| `uncategorized` | external analyzers | Anything else. |

`get_digest --focus privacy` keeps only `pii`.

## PII types (`untrusted.title` = `PII: <type>`)

| Type | Default severity | Notes |
|------|------------------|-------|
| `email` | low | |
| `phone_e164` | low | `+` international format |
| `phone_loose` | low | low confidence; verify |
| `android_id` | low | device identifier (MASVS-PRIVACY-2) |
| `advertising_id` | medium | AAID/GAID/IDFA (MASVS-PRIVACY-2) |
| `imei` | medium | Luhn-checked (MASVS-PRIVACY-2) |
| `mac_address` | low | MASVS-PRIVACY-2 |
| `ip_pii` | low | IP address in a payload |
| `geolocation` | medium | lat/lon pairs, keyed fields, geohash-like values |
| `postal_address` | low | low confidence; verify |
| `date_of_birth` | medium | |
| `passport` | medium | |
| `ssn_us` | medium | |
| `iban` | medium | checksum validated |
| `credit_card_pan` | high | Luhn validated |
| `health` | high | special-category data (GDPR Art. 9) |

## MASVS mapping

- every `pii` finding: `MASVS-PRIVACY-1` (data minimization);
- stable device or advertising identifiers additionally: `MASVS-PRIVACY-2`
  (cross-service identification);
- `secret` findings: `MASVS-CRYPTO-1`, plus `MASVS-AUTH-1` for tokens/JWTs.

## Host attribution

`get_digest --first-party auto` (or a list of the app's own domains) adds
trusted `owner`, `category` and `party` fields to each host row. Captures
taken with the CLI flag `--attribute-sdk` also carry the calling SDK as a
trusted `sdks` list on host and endpoint rows.
