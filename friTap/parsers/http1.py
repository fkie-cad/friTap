"""Stateful HTTP/1.x parser backed by h11."""

import h11

from friTap.constants import PROTOCOL_HTTP1
from .base import BaseParser, ParseResult


_HTTP_METHODS = (
    b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ",
    b"OPTIONS ", b"PATCH ", b"CONNECT ",
)


class _MessageState:
    """Accumulates h11 events into a single HTTP message."""
    __slots__ = (
        "method", "url", "version", "status_code", "status_text",
        "headers", "body_size", "is_request", "host",
        "content_encoding", "content_type",
    )

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.method: str = ""
        self.url: str = ""
        self.version: str = ""
        self.status_code: int = 0
        self.status_text: str = ""
        self.headers: dict[str, str] = {}
        self.body_size: int = 0
        self.is_request: bool = True
        self.host: str = ""
        self.content_encoding: str = ""
        self.content_type: str = ""


def _send_fake_request(conn: h11.Connection) -> None:
    """Send a minimal fake request so CLIENT connection can receive responses."""
    conn.send(h11.Request(
        method="GET", target="/",
        headers=[("host", "fritap-passive")],
    ))
    conn.send(h11.EndOfMessage())


def _send_fake_response(conn: h11.Connection) -> None:
    """Send a minimal fake response so SERVER connection can receive next request."""
    conn.send(h11.Response(
        status_code=200,
        headers=[("content-length", "0")],
    ))
    conn.send(h11.EndOfMessage())


class Http1Parser(BaseParser):
    """Stateful HTTP/1.x parser backed by h11.

    Uses separate h11.Connection instances for each direction:
    - write direction: SERVER role (servers receive requests)
    - read direction: CLIENT role (clients receive responses)

    For passive interception, fake counterpart messages are sent to
    satisfy h11's state machine after each complete message.
    """

    PROTOCOL = PROTOCOL_HTTP1

    def __init__(self) -> None:
        self._conns: dict[str, h11.Connection] = {}
        self._states: dict[str, _MessageState] = {}
        # Set by feed() when a 101 Switching Protocols response is seen.
        # The collector checks this to swap the parser for the connection.
        self.upgrade_protocol: str = ""
        # Unconsumed bytes after the upgrade response (if any).
        self.trailing_data: bytes | None = None
        self.trailing_protocol: str = ""
        self.trailing_sub_parse: ParseResult | None = None

    def _get_conn(self, direction: str) -> h11.Connection:
        if direction not in self._conns:
            if direction == "write":
                # Server receives requests
                conn = h11.Connection(h11.SERVER)
            else:
                # Client receives responses — must first "send" a request
                conn = h11.Connection(h11.CLIENT)
                _send_fake_request(conn)
            self._conns[direction] = conn
            self._states[direction] = _MessageState()
        return self._conns[direction]

    def _get_state(self, direction: str) -> _MessageState:
        if direction not in self._states:
            self._get_conn(direction)
        return self._states[direction]

    def can_parse(self, data: bytes) -> bool:
        """Detect HTTP/1.x requests or responses."""
        if not data:
            return False
        for method in _HTTP_METHODS:
            if data.startswith(method):
                return True
        return data.startswith(b"HTTP/1.")

    def feed(self, data: bytes, direction: str,
             stream_id: int | None = None) -> list[ParseResult]:
        """Feed data and return any completed HTTP messages."""
        conn = self._get_conn(direction)
        state = self._get_state(direction)
        results: list[ParseResult] = []

        conn.receive_data(data)

        while True:
            try:
                event = conn.next_event()
            except h11.RemoteProtocolError:
                # h11 rejects 101 without a matching Upgrade request.
                # In passive interception, the fake request lacks Upgrade
                # headers, so we detect 101 from the raw data instead.
                if self._detect_101_upgrade(data, direction, results):
                    return results
                break

            if event is h11.NEED_DATA or event is h11.PAUSED:
                break

            if isinstance(event, h11.Request):
                state.reset()
                state.is_request = True
                state.method = event.method.decode("ascii", errors="replace")
                state.url = event.target.decode("ascii", errors="replace")
                state.version = f"HTTP/{event.http_version.decode('ascii', errors='replace')}"
                self._extract_headers(event.headers, state)

            elif isinstance(event, h11.InformationalResponse):
                if event.status_code == 101:
                    # 101 Switching Protocols — emit result and signal upgrade
                    state.reset()
                    state.is_request = False
                    state.status_code = 101
                    reason = getattr(event, "reason", b"") or b""
                    state.status_text = reason.decode("ascii", errors="replace")
                    state.version = f"HTTP/{event.http_version.decode('ascii', errors='replace')}"
                    self._extract_headers(event.headers, state)
                    upgrade_val = state.headers.get("Upgrade", "").lower()
                    self.upgrade_protocol = upgrade_val or "websocket"
                    result = self._build_result(state, is_complete=True)
                    results.append(result)
                    # Extract any trailing bytes h11 hasn't consumed
                    trailing = conn.trailing_data
                    if trailing and trailing[0]:
                        self._handle_trailing(trailing[0], direction)
                    state.reset()
                    break
                # Other 1xx informational — ignore, wait for the real response
                continue

            elif isinstance(event, h11.Response):
                state.reset()
                state.is_request = False
                state.status_code = event.status_code
                reason = getattr(event, "reason", b"") or b""
                state.status_text = reason.decode("ascii", errors="replace")
                state.version = f"HTTP/{event.http_version.decode('ascii', errors='replace')}"
                self._extract_headers(event.headers, state)

            elif isinstance(event, h11.Data):
                state.body_size += len(event.data)

            elif isinstance(event, h11.EndOfMessage):
                result = self._build_result(state, is_complete=True)
                results.append(result)
                state.reset()
                # Prepare connection for next message cycle
                try:
                    if direction == "write":
                        # SERVER needs to send a response before cycling
                        _send_fake_response(conn)
                    conn.start_next_cycle()
                    if direction == "read":
                        # CLIENT needs to send a request before receiving
                        _send_fake_request(conn)
                except h11.LocalProtocolError:
                    pass

        return results

    def _detect_101_upgrade(
        self, data: bytes, direction: str, results: list[ParseResult],
    ) -> bool:
        """Detect a 101 Switching Protocols response from raw bytes.

        Called when h11 raises RemoteProtocolError because the fake
        request lacked Upgrade headers.  Returns True if 101 was found.
        """
        if not data.startswith(b"HTTP/1.") or b" 101 " not in data[:50]:
            return False
        # Parse headers manually from the raw response
        header_end = data.find(b"\r\n\r\n")
        if header_end < 0:
            return False
        header_block = data[:header_end].decode("latin-1", errors="replace")
        lines = header_block.split("\r\n")
        if not lines:
            return False
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                name, _, value = line.partition(":")
                headers[name.strip().title()] = value.strip()
        upgrade_val = headers.get("Upgrade", "").lower()
        self.upgrade_protocol = upgrade_val or "websocket"
        result = ParseResult(
            protocol="HTTP/1.1",
            status_code=101,
            status_text="Switching Protocols",
            headers=headers,
            is_complete=True,
            is_request=False,
        )
        results.append(result)
        # Handle trailing bytes after the 101 response
        trailing = data[header_end + 4:]
        if trailing:
            self._handle_trailing(trailing, direction)
        return True

    def _handle_trailing(self, trailing_bytes: bytes, direction: str) -> None:
        """Process unconsumed bytes after a 101 upgrade response."""
        from .trailing import detect_trailing_protocol, try_sub_parse
        self.trailing_data = trailing_bytes
        protocol, cleaned, parser = detect_trailing_protocol(trailing_bytes)
        self.trailing_protocol = protocol
        self.trailing_sub_parse = try_sub_parse(
            cleaned, parser, direction,
        ) if protocol else None

    def flush(self) -> list[ParseResult]:
        """Return any partial messages as incomplete results."""
        results: list[ParseResult] = []
        for state in self._states.values():
            if state.method or state.status_code or state.body_size:
                result = self._build_result(state, is_complete=False)
                results.append(result)
                state.reset()
        return results

    @staticmethod
    def _extract_headers(
        raw_headers: list[tuple[bytes, bytes]], state: _MessageState,
    ) -> None:
        """Extract headers from h11's (name, value) tuples."""
        for name_bytes, value_bytes in raw_headers:
            # h11 lowercases header names; restore Title-Case for display
            raw_name = name_bytes.decode("latin-1", errors="replace")
            name = raw_name.title()
            value = value_bytes.decode("latin-1", errors="replace")
            state.headers[name] = value
            name_lower = raw_name.lower()
            if name_lower == "host":
                state.host = value
            elif name_lower == "content-encoding":
                state.content_encoding = value
            elif name_lower == "content-type":
                state.content_type = value

    @staticmethod
    def _build_result(
        state: _MessageState, is_complete: bool = True,
    ) -> ParseResult:
        """Build a ParseResult from current message state."""
        return ParseResult(
            protocol=state.version if state.version else "HTTP/1.x",
            method=state.method,
            url=state.url,
            host=state.host,
            status_code=state.status_code,
            status_text=state.status_text,
            headers=dict(state.headers),
            body=b"",
            body_size=state.body_size,
            is_complete=is_complete,
            is_request=state.is_request,
            content_encoding=state.content_encoding,
            content_type=state.content_type,
        )
