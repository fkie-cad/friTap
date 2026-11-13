# Error model

Every failure, on every surface, is one JSON document:

```json
{"error": "path '../x.tap' is outside the sandbox root",
 "error_type": "forbidden",
 "hint": "use a path under /home/me/captures",
 "exit_code": 2}
```

`hint` (optional) is the next step: valid values, a did-you-mean, or the call
to make first. Some errors add `param` (the offending parameter, e.g.
`protocols[0]`) or `position` (for `bad_filter`).

| `error_type` | Meaning | `fritap q` exit | HTTP |
|--------------|---------|:---:|:---:|
| `bad_param` | Invalid/missing parameter, schema violation, bad cursor | 2 | 400 |
| `bad_filter` | Display filter syntax error / unknown field | 2 | 400 |
| `bad_ref` | Malformed or unknown flow ref | 2 | 400 |
| `unknown_protocol` | Protocol name not known | 2 | 400 |
| `unsupported_option` | Capture option not supported by the chosen protocols | 2 | 400 |
| `already_exists` | Export target exists (use `overwrite`) | 2 | 400 |
| `limit_reached` | Too many concurrent captures (max 4) | 2 | 400 |
| `forbidden` | Sandbox escape, capture/secrets/values/target not allowed | 2 | 403 |
| `not_found` | File or session not found | 2 | 404 |
| `unknown_tool` | No such tool (hint lists them) | 2 | 404 |
| `capture_running` | Session still running; stop it first | 2 | 409 |
| `unauthorized` | Missing/wrong bearer token | | 401 |
| `body_too_large` | REST request body over 1 MiB | | 413 |
| `runtime_error` | Unexpected failure inside a tool | 1 | 500 |
| `missing_dependency` | `fritap mcp` without the `mcp` package | 2 | |

`fritap q` prints the error document on **stdout** and exits with
`exit_code` (`0` success, `2` usage/policy, `1` runtime).

## `forbidden` hints and what they mean

| Hint | Cause | Action |
|------|-------|--------|
| `start the server with --allow-capture` | `start_capture` on mcp/serve without the flag | Ask the user to restart the server with it |
| `start the server with --allow-values` | `show_values: true` on mcp/serve | Drop `show_values`, or ask the user |
| `use a path under <root>` | Path escapes `--root` | Use a path relative to the root |
| (keylog export) | Missing `--allow-secrets` or `confirm_secrets` | Both are required; ask the user first |

## Capture exit codes

`capture_status` reports the live capture's own `exit_code` (`0`, `1`, `2`,
`3`, `128+signum`) and `ended_by`:

| `ended_by` | Meaning |
|------------|---------|
| `target_exited` | Target exited or detached (exit code 3); normal end, `state: stopped` |
| `duration` | `duration_s` elapsed (exit code 0) |
| `stopped` | `stop_capture` or Ctrl+C |
| `error` | Failure, `state: failed`; read `stderr_tail` and `detach_reason` |
