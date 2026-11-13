# find_values reference

Source of truth: `friTap/analysis/canary.py`,
`docs/api/schemas/find_values.params.json`.

## Parameters

| Param | Type | Notes |
|-------|------|-------|
| `values` | array of `{value, label, kind?}` or `"[KIND=]VALUE"` strings, min 1 | Required. Objects: `value` and `label` non-empty. Strings: `KIND=VALUE` (known kind or alias before the first `=`) or a bare `VALUE` (kind `free`), labelled `<kind>-<n>`. At most 64 are used. |
| `tap` / `session_id` | string | Exactly one. `session_id` must be a stopped session of this server process. |
| `budget` | integer, default 1500, 100..8000 | Lowest-confidence hits drop first. |
| `show_values` | boolean, default false | Return the matched span. Needs `--allow-values` on mcp/serve. |

On the shell repeat `--values` once per value (commas are not split, so
`gps=48.137,11.575` is one value; a `{...}` argument is read as one JSON
object). The separator is `=` so IPv6 addresses and URLs are never mistaken
for a kind; text before the first `=` that is not a kind keeps the whole
string as a `free` value (`token=abc`). Use objects (`--json` or
`--params-file`) to pick your own labels.

```bash
fritap q find_values --tap run.tap --values email=alice.canary7@example.com --values phone=+4915123456789
fritap q find_values --tap run.tap --values 'geo=48.137,11.575' --values some-free-string
fritap q find_values --params-file canaries.json
fritap q find_values --session-id SID --json '{"values": [{"value": "+49 151 2345 6789", "kind": "phone", "label": "phone"}]}'
```

(`--session-id` works only inside the same server process, i.e. over MCP or
REST; with `fritap q` use `--tap`.)

## Normalization per kind (before encoding)

| Kind | Variants searched |
|------|-------------------|
| `email` | Lowercased/trimmed; plus a Gmail-style variant with dots and `+tag` removed from the local part |
| `phone` | E.164 (`+` and digits) and the digits-only form |
| `aaid` | Hyphenated lowercase, non-hyphenated lowercase, uppercase |
| `android_id` | Lowercase |
| `imei` | Digits only |
| `gps` | The coordinate as given, plus truncated (not rounded) to 1..5 decimals. One coordinate per entry. |
| `ip`, `free` | As given (trimmed) |

Aliases: `advertising_id`, `idfa`, `gaid`, `adid`, `idfv` -> `aaid`;
`geo`, `geolocation`, `location` -> `gps`. A missing or unknown kind becomes
`free`.

## Transforms (applied to every variant)

| `transform` | Form | Confidence |
|-------------|------|------------|
| `plain` | The variant itself | `high` if >= 12 chars and high entropy, `low` if < 8 chars or low entropy, else `medium` |
| `url`, `url_plus` | Percent-encoded (`%20` / `+` for spaces) | high |
| `base64`, `base64_nopad` | Standard base64, with/without padding | high |
| `base64url`, `base64url_nopad` | URL-safe base64, with/without padding | high |
| `hex`, `hex_upper` | Hex of the UTF-8 bytes | high |
| `md5`, `sha1`, `sha256` | Hex digest of the UTF-8 bytes | high |

Needles shorter than 3 characters are skipped. Identical needles keep the
highest confidence. Salted, HMAC'd, truncated or double-encoded forms are not
derived: search for those yourself with `get_flow` or a `filter`.

## Result (`fritap.find_values/1`)

- `source`: `file`, `flows_total`.
- `summary`: `hits`, `canaries`, `by_label`, `by_confidence`.
- `rows[]`: `label`, `kind`, `transform`, `confidence`, `direction`
  (`request` | `response`), `where` (`header` | `query` | `path` | `body`),
  `ref` (pass to `get_flow`), `untrusted` (captured context).
- `warnings[]`: `label`, `kind`, `warning` for short (< 8 chars) or
  low-entropy canaries; they are still searched.
- `truncated` when the budget dropped hits; `notice` about `untrusted`.

## Reporting a leak

For each label with `direction: request` hits, report: the label (not the raw
value), `transform`, `where`, the host and path from
`get_flow --ref <ref> --fields flow,request`, the endpoint's `party` from
`get_digest --attribute --first-party auto` or `diff`, and the confidence.
Treat `low` hits as unconfirmed until the flow shows the value in context.
