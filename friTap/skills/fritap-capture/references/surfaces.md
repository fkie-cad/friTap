# Surfaces and server flags

One tool registry, four surfaces. All validate against the same JSON Schema and
return the same result and error documents.

| Surface | Command | Transport | Use for |
|---------|---------|-----------|---------|
| Shell | `fritap q <tool> ...` | one JSON document on stdout | Reading `.tap` files, one-shot timed captures, scripts |
| MCP | `fritap mcp` | stdio (default) or streamable HTTP (`--http`, port 8765, path `/mcp`) | Agent loops with live capture |
| REST | `fritap serve` | HTTP/JSON (port 8766), OpenAPI 3.1 at `/openapi.json` | Non-MCP agents, HTTP clients |
| Python | `friTap.agent_api.call(...)` | in-process | Python harnesses |

## Choosing

- Need `capture_status`, `mark_phase` or `stop_capture` between steps: use
  `fritap mcp` or `fritap serve`. Sessions live in that server process and stop
  when it exits.
- Only reading existing `.tap` files: `fritap q` is enough.
- `fritap q start_capture` blocks until the session ends (Ctrl+C calls
  `stop_capture`); `--no-wait` returns immediately but the capture stops when
  `fritap q` exits.

## Server flags

| Option | Applies to | Meaning |
|--------|-----------|---------|
| `--root DIR` | q, mcp, serve | Sandbox root (default: cwd). All `tap`, `out`, option-file paths must resolve inside it (symlinks included). Sessions go to `<root>/.fritap-sessions/`. |
| `--allow-secrets` | q, mcp, serve | Allow key material (keylog export); the call also needs `confirm_secrets: true` |
| `--max-response-bytes N` | q, mcp, serve | Cap on one JSON response (default 65536) |
| `--allow-capture` | mcp, serve | Enable `start_capture` (denied otherwise; `fritap q` always allows it) |
| `--allow-target PATTERN` | mcp, serve | Allowed capture targets, fnmatch, repeatable (e.g. `'com.example.*'`) |
| `--allow-values` | mcp, serve | Allow `show_values: true`; always on for `fritap q` |
| `--http` | mcp | Streamable HTTP instead of stdio |
| `--host HOST` | mcp `--http`, serve | Bind address (default `127.0.0.1`) |
| `--port PORT` | mcp `--http`, serve | Default 8765 (MCP) / 8766 (REST) |
| `--token TOKEN` | mcp `--http`, serve | Require `Authorization: Bearer TOKEN`; default `$FRITAP_API_TOKEN` |

Binding a non-loopback host without a token is refused (exit 2). No CORS
headers are sent.

```bash
fritap mcp --root ./captures --allow-capture --allow-target 'com.example.*'
fritap mcp --http --port 8765 --root ./captures
fritap serve --root ./captures --allow-capture --token "$FRITAP_API_TOKEN"
```

## MCP client config

```json
{
  "mcpServers": {
    "fritap": {
      "command": "fritap",
      "args": ["mcp", "--root", "/home/me/captures",
               "--allow-capture", "--allow-target", "com.example.*"]
    }
  }
}
```

If `fritap` is not on the client's `PATH`, use the absolute path of the
virtualenv's `fritap`, or `python` with `["-m", "friTap.friTap", "mcp", ...]`.
With stdio, stdout belongs to the protocol; friTap logs to stderr. Without the
`mcp` extra, `fritap mcp` fails with `missing_dependency` (exit 2).

MCP results carry the JSON document as `structuredContent` and as text; errors
set `isError: true`. Non-mutating tools are annotated `readOnlyHint`.

## REST routes

| Route | Result |
|-------|--------|
| `GET /healthz` | `{"status": "ok"}`, no token needed |
| `GET /v1/tools` | `{"tools": [{name, summary, kind, mutating, params_schema}, ...]}` |
| `GET /openapi.json` | OpenAPI 3.1 document |
| `POST /v1/tools/<tool>` | Tool result; JSON body = parameters (empty = `{}`, max 1 MiB, max 64 nesting levels) |

## `fritap q` parameter passing

```bash
fritap q --list
fritap q get_digest --help-json
fritap q get_digest --tap run.tap --budget 800 --compact
fritap q list_findings --json '{"tap": "run.tap", "category": "pii"}'
fritap q get_flow --params-file params.json
```

Parameters merge `--params-file` < `--json` < generated flags. Flags are the
param names with dashes (`--duration-s`); booleans have `--no-` forms; arrays
are comma-separated (arrays of objects such as `find_values --values` take one
item per repeated flag instead); objects take JSON. `--params-file -` reads stdin.

## Result envelope

Every success is a JSON object whose first key is
`"schema": "<name>/<version>"` (`fritap.digest/2`, `fritap.endpoints/1`,
`fritap.findings/1`, `fritap.flow/1`, `fritap.protocols/1`, `fritap.export/1`,
`fritap.capture_protocols/1`, ...). Read results add `source` and, when they
copy traffic, a `notice` about `untrusted` values.
