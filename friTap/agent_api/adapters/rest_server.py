"""
REST adapter: the tool registry over plain HTTP/JSON (stdlib only).

Routes::

    GET  /healthz            -> {"status": "ok"}   (never needs the token)
    GET  /v1/tools           -> {"tools": [descriptor, ...]}
    GET  /openapi.json       -> OpenAPI 3.1 document
    POST /v1/tools/{name}    -> tool result (JSON body = params, empty = {})

Errors use the :class:`ToolError` JSON shape. Status codes: usage errors 400,
``forbidden`` 403, ``not_found``/``unknown_tool`` 404, ``capture_running``
409, runtime errors 500. Binds 127.0.0.1 by default; if a token is set every
request except ``GET /healthz`` needs ``Authorization: Bearer <token>``.
``/healthz`` is a bare liveness probe: it only ever returns
``{"status": "ok"}`` (no tool or version info). No CORS headers are sent;
without a token, requests with a non-loopback ``Host`` or ``Origin`` are
refused (403) so web pages cannot drive the tools (CSRF / DNS rebinding).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

from friTap.agent_api.adapters.bind_policy import bearer_matches, is_loopback
from friTap.agent_api.adapters.openapi import TOOLS_PATH, build_openapi
from friTap.agent_api.context import ToolContext
from friTap.agent_api.envelope import dumps_compact
from friTap.agent_api.errors import ToolError
from friTap.agent_api.json_input import load_json_object
from friTap.agent_api.registry import Registry
from friTap.exit_codes import EXIT_USAGE_ERROR

#: Unauthenticated liveness probe (returns only :data:`HEALTH_DOC`).
HEALTH_PATH = "/healthz"
HEALTH_DOC: dict[str, str] = {"status": "ok"}

logger = logging.getLogger("friTap.agent_api.rest")

DEFAULT_PORT = 8766
MAX_BODY_BYTES = 1024 * 1024
_STATUS_BY_ERROR_TYPE = {
    "unauthorized": 401,
    "forbidden": 403,
    "not_found": 404,
    "unknown_tool": 404,
    "unknown_route": 404,
    "method_not_allowed": 405,
    "capture_running": 409,
    "body_too_large": 413,
}


def http_status(error: ToolError) -> int:
    """Map a :class:`ToolError` to an HTTP status code."""
    status = _STATUS_BY_ERROR_TYPE.get(error.error_type)
    if status is not None:
        return status
    return 400 if error.exit_code == EXIT_USAGE_ERROR else 500


@dataclass(frozen=True)
class RestApp:
    """Request-independent state shared by every handler thread."""

    registry: Registry
    context: ToolContext
    token: str | None = None

    def get(self, path: str) -> str:
        """JSON response body of ``GET path``."""
        if path == HEALTH_PATH:
            return dumps_compact(HEALTH_DOC)
        if path == TOOLS_PATH:
            return dumps_compact({"tools": [spec.describe() for spec in self.registry.specs()]})
        if path == "/openapi.json":
            return dumps_compact(build_openapi(self.registry))
        raise ToolError(f"no route GET {path}", "unknown_route")

    def post(self, path: str, params: dict[str, Any]) -> str:
        """JSON response body of ``POST path`` (the tool result, encoded once)."""
        prefix = TOOLS_PATH + "/"
        if not path.startswith(prefix) or "/" in path[len(prefix):]:
            raise ToolError(f"no route POST {path}", "unknown_route",
                            hint=f"POST {prefix}<tool>; GET {TOOLS_PATH} lists tools")
        return self.registry.call_json(path[len(prefix):], params, context=self.context)[1]


class _Handler(BaseHTTPRequestHandler):
    server_version = "friTap-agent"
    app: RestApp  # set on the per-server subclass

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        if self._path() == HEALTH_PATH:  # liveness probe: no token, no data
            self._send_body(200, dumps_compact(HEALTH_DOC))
            return
        self._respond(lambda: self.app.get(self._path()))

    def do_POST(self) -> None:  # noqa: N802
        self._respond(lambda: self.app.post(self._path(), self._read_params()))

    def do_PUT(self) -> None:  # noqa: N802
        self._method_not_allowed()

    do_DELETE = do_PATCH = do_PUT

    def _method_not_allowed(self) -> None:
        self._respond(lambda: _raise(ToolError(f"method {self.command} not allowed", "method_not_allowed")))

    def _path(self) -> str:
        return self.path.split("?", 1)[0].rstrip("/") or "/"

    def _respond(self, produce) -> None:
        try:
            self._check_token()
            self._send_body(200, produce())
        except ToolError as err:
            self._send_body(http_status(err), dumps_compact(err.to_dict()))
        except Exception as exc:  # noqa: BLE001 - never leak a traceback page
            logger.exception("REST handler failure")
            self._send_body(500, dumps_compact({"error": str(exc), "error_type": "runtime_error",
                                                "exit_code": 1}))

    def _check_token(self) -> None:
        token = self.app.token
        if not token:
            self._check_local_request()
        elif not bearer_matches(self.headers.get("Authorization"), token):
            raise ToolError("missing or invalid bearer token", "unauthorized",
                            hint="send 'Authorization: Bearer <token>'")

    def _check_local_request(self) -> None:
        """Token-less (loopback-only) server: refuse what a web page can send.

        Without this a page in the user's browser could drive the tools: a
        cross-site "simple" POST (``text/plain`` body, no preflight) carries
        a foreign ``Origin``, a DNS-rebinding request a foreign ``Host``. Same
        protection the MCP server gets from its transport security settings.
        """
        if not _is_loopback_authority(self.headers.get("Host")):
            raise ToolError("request Host is not a loopback address", "forbidden",
                            hint="connect via 127.0.0.1/localhost or start the server with --token")
        origin = self.headers.get("Origin")
        if origin is not None and not _is_loopback_authority(urlsplit(origin).netloc):
            raise ToolError("cross-origin browser requests are refused", "forbidden",
                            hint="start the server with --token to allow non-local clients")

    def _read_params(self) -> dict[str, Any]:
        length = self._content_length()
        if length > MAX_BODY_BYTES:
            self.close_connection = True
            raise ToolError(f"request body exceeds {MAX_BODY_BYTES} bytes", "body_too_large")
        raw = self.rfile.read(length) if length else b""
        return _parse_params(raw)

    def _content_length(self) -> int:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise ToolError("invalid Content-Length header", "bad_request") from None
        if length < 0:
            raise ToolError("invalid Content-Length header", "bad_request")
        return length

    def _send_body(self, status: int, text: str) -> None:
        """Send ``text`` (a JSON document) as the response body."""
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: Any) -> None:  # route access log to logging (stderr)
        logger.info("%s - %s", self.address_string(), fmt % args)


def _raise(error: ToolError) -> dict[str, Any]:
    raise error


def _is_loopback_authority(authority: str | None) -> bool:
    """True for a ``host[:port]`` (Host header / Origin netloc) naming a loopback host."""
    if not authority:
        return False
    try:
        hostname = urlsplit("//" + authority).hostname
    except ValueError:
        return False
    return bool(hostname) and is_loopback(hostname)


def _parse_params(raw: bytes) -> dict[str, Any]:
    if not raw.strip():
        return {}
    return load_json_object(raw, "request body", error_type="bad_request", max_bytes=MAX_BODY_BYTES)


def make_server(app: RestApp, host: str, port: int) -> ThreadingHTTPServer:
    """Bind a threading HTTP server for ``app`` (``port=0`` = ephemeral)."""
    handler = type("FriTapRestHandler", (_Handler,), {"app": app})
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    return server


def serve(app: RestApp, host: str, port: int) -> None:
    """Serve ``app`` until interrupted."""
    server = make_server(app, host, port)
    bound_host, bound_port = server.server_address[:2]
    logger.warning("friTap REST API listening on http://%s:%s", bound_host, bound_port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


__all__ = ["RestApp", "DEFAULT_PORT", "HEALTH_PATH", "HEALTH_DOC", "MAX_BODY_BYTES", "http_status", "make_server", "serve"]
