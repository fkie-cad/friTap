"""Stateful HTTP/1.x parser backed by h11.

Input is attacker-controlled decrypted traffic, so the parser never lets
h11 park in a terminal state (ERROR, MUST_CLOSE, SWITCHED_PROTOCOL, ...)
where every later byte would be buffered and never parsed. Instead the
direction's h11 connection is recreated and the parser resynchronizes on
the next plausible message start (see ``_recover``).
"""

from collections import deque

import h11

from friTap.constants import PROTOCOL_HTTP1

from .base import BaseParser, ParseResult, merge_header_value
from .boundary_scan import _HTTP_REQUEST_SIGS, _HTTP_RESPONSE_PREFIX, _try_http_at

_HTTP_METHODS = (
    b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ",
    b"OPTIONS ", b"PATCH ", b"CONNECT ",
)

# Error recorded on the message affected by (or following) a parser desync.
H1_DESYNC_ERROR = "h1-desync"
# Cap on unparsed bytes kept while hunting for the next message start.
MAX_RESYNC_BUFFER = 64 * 1024
# Request methods remembered for matching fake requests on the response side.
MAX_PENDING_METHODS = 256

# Window searched for the end of a rejected message head when salvaging it.
_MAX_SALVAGE_HEAD = 16 * 1024

# Bytes before the old end of the resync buffer that are rescanned when new
# data arrives (boundary_scan validates a candidate within 2048 bytes).
_RESCAN_OVERLAP = 2048 + 16

# Outcomes of draining one h11 connection.
_DRAIN_OK = "ok"              # waiting for more data
_DRAIN_STUCK = "stuck"        # legitimate terminal state (close/switch/tunnel)
_DRAIN_ERROR = "error"        # protocol violation -> desync
_DRAIN_UPGRADED = "upgraded"  # 101 Switching Protocols handed to the collector


class _MessageState:
    """Accumulates h11 events into a single HTTP message."""
    __slots__ = (
        "method", "url", "version", "status_code", "status_text",
        "headers", "body_size", "is_request", "host",
        "content_encoding", "content_type", "error",
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
        self.error: str = ""

    def has_content(self) -> bool:
        return bool(self.method or self.status_code or self.body_size)


def _send_fake_request(conn: h11.Connection, method: str = "GET") -> None:
    """Send a minimal fake request so CLIENT connection can receive responses.

    *method* mirrors the request observed on the wire, so h11 applies the
    right body rules (no body for HEAD responses, tunnel for CONNECT 2xx).
    """
    target = "fritap-passive:443" if method == "CONNECT" else "/"
    conn.send(h11.Request(
        method=method, target=target,
        headers=[("host", "fritap-passive")],
    ))
    conn.send(h11.EndOfMessage())


def _buffered_len(conn: h11.Connection) -> int:
    """Number of received bytes h11 has not parsed yet (cheap, no copy)."""
    receive_buffer = getattr(conn, "_receive_buffer", None)
    if receive_buffer is not None:
        return len(receive_buffer)
    return len(conn.trailing_data[0])


def _parse_raw_head(head: bytes) -> tuple[str, dict[str, str]]:
    """Split a raw message head into its start line and (merged) headers."""
    lines = head.decode("latin-1", errors="replace").split("\r\n")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            name, _, value = line.partition(":")
            merge_header_value(headers, name.strip().title(), value.strip())
    return lines[0], headers


def _apply_raw_headers(state: "_MessageState", headers: dict[str, str]) -> None:
    """Copy salvaged headers into *state*, filling the derived fields."""
    state.headers = headers
    state.host = headers.get("Host", "")
    state.content_encoding = headers.get("Content-Encoding", "")
    state.content_type = headers.get("Content-Type", "")


def _find_message_start(buf: bytes, sigs: tuple[bytes, ...], start: int) -> int:
    """Return the offset of the first validated HTTP/1 message start, or -1.

    Each signature's next position is cached so adversarial input full of
    near-miss candidates stays linear per signature.
    """
    next_pos = {sig: buf.find(sig, start) for sig in sigs}
    while True:
        live = [pos for pos in next_pos.values() if pos >= 0]
        if not live:
            return -1
        candidate = min(live)
        if _try_http_at(buf, candidate) is not None:
            return candidate
        for sig, pos in next_pos.items():
            if pos == candidate:
                next_pos[sig] = buf.find(sig, candidate + 1)


def _cap_resync_buffer(buf: bytearray) -> None:
    """Keep only the newest MAX_RESYNC_BUFFER bytes of a resync buffer."""
    if len(buf) > MAX_RESYNC_BUFFER:
        del buf[:len(buf) - MAX_RESYNC_BUFFER]


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
        # Methods of requests seen in the write direction, consumed (FIFO)
        # by the fake requests that prime the response-side connection.
        self._pending_methods: deque[str] = deque(maxlen=MAX_PENDING_METHODS)
        # Read-side connections whose fake request is deferred until the
        # next response bytes arrive (so the matching method is known).
        self._fake_request_due: set[str] = set()
        # Directions hunting for the next message start, with their
        # (capped) unparsed bytes.
        self._resync_bufs: dict[str, bytearray] = {}
        # Directions whose next emitted message carries H1_DESYNC_ERROR.
        self._desync_pending: set[str] = set()
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
                # Client receives responses — must first "send" a request,
                # deferred until data arrives (see _prime_read_conn).
                conn = h11.Connection(h11.CLIENT)
                self._fake_request_due.add(direction)
            self._conns[direction] = conn
            self._states.setdefault(direction, _MessageState())
        return self._conns[direction]

    def _prime_read_conn(self, conn: h11.Connection, direction: str) -> None:
        """Send the deferred fake request matching the next queued method."""
        if direction not in self._fake_request_due:
            return
        self._fake_request_due.discard(direction)
        method = self._pending_methods.popleft() if self._pending_methods else "GET"
        try:
            _send_fake_request(conn, method)
        except h11.LocalProtocolError:
            _send_fake_request(conn)

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
        results: list[ParseResult] = []
        if not data:
            # A zero-length hooked read/write is not end-of-stream, but h11
            # treats receive_data(b"") as EOF (then ConnectionClosed forever).
            return results
        pending = self._take_resync_input(direction, data)
        while pending is not None:
            conn = self._get_conn(direction)
            self._prime_read_conn(conn, direction)
            # h11 may consume a message head before rejecting it, so keep
            # the bytes this drain can see to recover the failing message.
            stream = conn.trailing_data[0] + pending
            conn.receive_data(pending)
            outcome, leftover = self._drain_events(conn, direction, results, stream)
            if outcome == _DRAIN_OK:
                break
            pending = self._recover(direction, outcome, leftover, len(stream))
        return results

    def _drain_events(
        self, conn: h11.Connection, direction: str,
        results: list[ParseResult], stream: bytes,
    ) -> tuple[str, bytes]:
        """Pull h11 events until it needs data or reaches a terminal state.

        Returns the drain outcome and the bytes h11 did not parse (for an
        error: everything from the start of the rejected message).
        """
        state = self._get_state(direction)
        while True:
            unparsed = _buffered_len(conn)
            try:
                event = conn.next_event()
            except h11.RemoteProtocolError:
                failed = stream[len(stream) - unparsed:]
                # h11 rejects 101 without a matching Upgrade request.
                # In passive interception, the fake request lacks Upgrade
                # headers, so we detect 101 from the raw bytes instead.
                if self._detect_101_upgrade(failed, direction, results):
                    return _DRAIN_UPGRADED, b""
                self._note_desync(state, direction, results, failed)
                return _DRAIN_ERROR, failed
            if event is h11.NEED_DATA or isinstance(event, h11.ConnectionClosed):
                # ConnectionClosed repeats on every next_event(): stop draining.
                return _DRAIN_OK, b""
            if event is h11.PAUSED:
                return self._on_paused(conn, state, direction, results)
            outcome = self._handle_event(event, conn, direction, state, results)
            if outcome is not None:
                return outcome, conn.trailing_data[0]

    def _handle_event(
        self, event, conn: h11.Connection, direction: str,
        state: _MessageState, results: list[ParseResult],
    ) -> str | None:
        """Apply one h11 event; return a drain outcome to stop, else None."""
        if isinstance(event, h11.Request):
            self._start_message(state, event, is_request=True)
            if direction == "write":
                self._pending_methods.append(state.method)
        elif isinstance(event, h11.InformationalResponse):
            if event.status_code == 101:
                return self._on_informational_101(event, conn, direction, state, results)
            # Other 1xx informational — ignore, wait for the real response
        elif isinstance(event, h11.Response):
            self._start_message(state, event, is_request=False)
        elif isinstance(event, h11.Data):
            state.body_size += len(event.data)
        elif isinstance(event, h11.EndOfMessage):
            self._emit(state, direction, results, is_complete=True)
            return self._start_next_cycle(conn, direction)
        return None

    def _start_message(self, state: _MessageState, event, is_request: bool) -> None:
        """Reset *state* and load the request line / status line of *event*."""
        state.reset()
        state.is_request = is_request
        state.version = f"HTTP/{event.http_version.decode('ascii', errors='replace')}"
        if is_request:
            state.method = event.method.decode("ascii", errors="replace")
            state.url = event.target.decode("ascii", errors="replace")
        else:
            state.status_code = event.status_code
            reason = getattr(event, "reason", b"") or b""
            state.status_text = reason.decode("ascii", errors="replace")
        self._extract_headers(event.headers, state)

    def _on_informational_101(
        self, event, conn: h11.Connection, direction: str,
        state: _MessageState, results: list[ParseResult],
    ) -> str:
        """101 Switching Protocols — emit result and signal upgrade."""
        self._start_message(state, event, is_request=False)
        upgrade_val = state.headers.get("Upgrade", "").lower()
        self.upgrade_protocol = upgrade_val or "websocket"
        self._emit(state, direction, results, is_complete=True)
        # Extract any trailing bytes h11 hasn't consumed
        trailing = conn.trailing_data
        if trailing and trailing[0]:
            self._handle_trailing(trailing[0], direction)
        return _DRAIN_UPGRADED

    def _on_paused(
        self, conn: h11.Connection, state: _MessageState, direction: str,
        results: list[ParseResult],
    ) -> tuple[str, bytes]:
        """h11 paused: a CONNECT 2xx (tunnel) or another protocol switch."""
        if conn.their_state is h11.SWITCHED_PROTOCOL and state.status_code:
            # The 2xx response to CONNECT has no EndOfMessage; emit it now.
            self._emit(state, direction, results, is_complete=True)
        return _DRAIN_STUCK, conn.trailing_data[0]

    def _start_next_cycle(self, conn: h11.Connection, direction: str) -> str | None:
        """Prepare connection for next message cycle; _DRAIN_STUCK if impossible."""
        try:
            if direction == "write":
                # SERVER needs to send a response before cycling
                _send_fake_response(conn)
            conn.start_next_cycle()
        except h11.LocalProtocolError:
            # Connection: close / HTTP/1.0 (MUST_CLOSE) or CONNECT accepted
            return _DRAIN_STUCK
        if direction == "read":
            # CLIENT needs to send a request before receiving; send it now
            # only if more response bytes are already buffered.
            self._fake_request_due.add(direction)
            if conn.trailing_data[0]:
                self._prime_read_conn(conn, direction)
        return None

    def _note_desync(
        self, state: _MessageState, direction: str,
        results: list[ParseResult], failed: bytes,
    ) -> None:
        """Flag the message hit by a protocol error (or the next one).

        A message whose head h11 rejected outright (bad header line, bogus
        Content-Length, ...) is salvaged from the raw bytes as an incomplete
        result, so malformed traffic cannot hide a request from the analyst.
        """
        self._desync_pending.add(direction)
        if not state.has_content():
            self._salvage_rejected_head(state, direction, failed)
            if direction == "write" and state.method:
                self._pending_methods.append(state.method)
        if state.has_content():
            self._emit(state, direction, results, is_complete=False)

    @staticmethod
    def _salvage_rejected_head(
        state: _MessageState, direction: str, failed: bytes,
    ) -> None:
        """Best-effort load of a rejected message head into *state*."""
        sigs = (_HTTP_RESPONSE_PREFIX,) if direction == "read" else _HTTP_REQUEST_SIGS
        if not failed.startswith(sigs) or _try_http_at(failed, 0) is None:
            return
        header_end = failed.find(b"\r\n\r\n", 0, _MAX_SALVAGE_HEAD)
        start_line, headers = _parse_raw_head(
            failed[:header_end if header_end >= 0 else _MAX_SALVAGE_HEAD])
        parts = start_line.split(" ", 2)
        state.reset()
        state.is_request = direction != "read"
        if state.is_request:
            state.method, state.url = parts[0], parts[1] if len(parts) > 1 else ""
            state.version = parts[2] if len(parts) > 2 else ""
        else:
            state.version = parts[0]
            code = parts[1] if len(parts) > 1 else ""
            state.status_code = int(code) if code.isascii() and code.isdigit() else 0
            state.status_text = parts[2] if len(parts) > 2 else ""
        _apply_raw_headers(state, headers)

    def _emit(
        self, state: _MessageState, direction: str,
        results: list[ParseResult], is_complete: bool,
    ) -> None:
        """Append the message in *state* to *results* and reset *state*."""
        result = self._build_result(state, is_complete=is_complete)
        if direction in self._desync_pending:
            self._desync_pending.discard(direction)
            result.error = H1_DESYNC_ERROR
        results.append(result)
        state.reset()

    # ------------------------------------------------------------------
    # Desync recovery
    # ------------------------------------------------------------------

    def _recover(
        self, direction: str, outcome: str, leftover: bytes, buffered: int,
    ) -> bytes | None:
        """Drop the stuck h11 connection and resync on its *leftover* bytes.

        Returns the bytes to feed a fresh connection, or None when no
        message start is buffered yet (the direction keeps hunting).
        """
        self._reset_direction(direction)
        # Skip the rejected message start on errors (and whenever no
        # bytes were consumed) so the same bytes cannot loop forever.
        no_progress = len(leftover) >= buffered
        skip = 1 if outcome == _DRAIN_ERROR or no_progress else 0
        if outcome == _DRAIN_UPGRADED:
            # Bytes after the 101 belong to the new protocol (already
            # handed over via trailing_data); never re-parse them as HTTP/1.
            leftover, skip = b"", 0
        # Drop the skipped byte so a later rescan cannot match it again.
        self._resync_bufs[direction] = bytearray(leftover[skip:])
        return self._resync_scan(direction, 0)

    def _reset_direction(self, direction: str) -> None:
        """Forget the direction's h11 connection and in-progress message."""
        self._conns.pop(direction, None)
        self._fake_request_due.discard(direction)
        state = self._states.get(direction)
        if state is not None:
            state.reset()

    def _take_resync_input(self, direction: str, data: bytes) -> bytes | None:
        """Route *data* through the resync buffer when the direction is hunting."""
        buf = self._resync_bufs.get(direction)
        if buf is None:
            return data
        buf += data
        if b"\n" not in data:
            # Buffered candidates all failed; one can only validate once a
            # CRLF ends in the new bytes, so without a LF skip the rescan.
            _cap_resync_buffer(buf)
            return None
        # Earlier bytes were already scanned; only candidates whose
        # validation window was cut off by the old buffer end can change.
        return self._resync_scan(direction, max(0, len(buf) - len(data) - _RESCAN_OVERLAP))

    def _resync_scan(self, direction: str, start: int) -> bytes | None:
        """Find the next message start in the direction's resync buffer."""
        buf = self._resync_bufs[direction]
        sigs = (_HTTP_RESPONSE_PREFIX,) if direction == "read" else _HTTP_REQUEST_SIGS
        offset = _find_message_start(buf, sigs, start)
        if offset >= 0:
            del self._resync_bufs[direction]
            return bytes(buf[offset:])
        _cap_resync_buffer(buf)
        return None

    def _detect_101_upgrade(
        self, data: bytes, direction: str, results: list[ParseResult],
    ) -> bool:
        """Detect a 101 Switching Protocols response from raw bytes.

        Called when h11 raises RemoteProtocolError because the fake
        request lacked Upgrade headers.  *data* is h11's unparsed buffer,
        which starts at the failing message even when its head spanned
        several chunks.  Returns True if 101 was found.
        """
        if not data.startswith(b"HTTP/1.") or data[8:13] != b" 101 ":
            return False
        # Parse headers manually from the raw response
        header_end = data.find(b"\r\n\r\n")
        if header_end < 0:
            return False
        _, headers = _parse_raw_head(data[:header_end])
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
        protocol, cleaned, parser = detect_trailing_protocol(
            trailing_bytes, transport=self.flow_transport)
        self.trailing_protocol = protocol
        self.trailing_sub_parse = try_sub_parse(
            cleaned, parser, direction,
        ) if protocol else None

    def flush(self) -> list[ParseResult]:
        """Return any partial messages as incomplete results."""
        results: list[ParseResult] = []
        for state in self._states.values():
            if state.has_content():
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
            # Repeated fields are joined, never overwritten (see
            # merge_header_value): Set-Cookie with "\n", others with ", ".
            merge_header_value(state.headers, name, value)
            name_lower = raw_name.lower()
            if name_lower == "host":
                state.host = state.host or value
            elif name_lower == "content-encoding":
                state.content_encoding = state.headers[name]
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
