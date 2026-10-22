"""One protobuf/gRPC decode for every viewer (TUI panes, modals, explorer).

:func:`decode_protobuf_view` turns a body into a :class:`ProtobufView`: it
validates gRPC framing (instead of blindly dropping 5 bytes), decompresses
compressed gRPC messages, applies a schema when one is configured and falls
back to the dependency-free wire decoder whenever something richer is not
available. Problems become ``notes``/``error`` strings instead of exceptions,
so a renderer can show partial results.

The view holds plain text only. Renderers that use Rich markup must escape
every line (see ``friTap.tui.widgets.protobuf_render``).

Usage::

    from friTap.parsers.protobuf import decode_protobuf_view

    view = decode_protobuf_view(body, content_type="application/grpc")
    print(view.text())
"""

from __future__ import annotations

import importlib.util
import json
from dataclasses import dataclass, field
from typing import Callable, NamedTuple, Optional

from .grpc import (
    GrpcFrame,
    decompress_grpc_payload,
    is_grpc_content_type,
    split_grpc_frames_lenient,
)
from .wire import decode_raw_lenient, format_message

BACKEND_WIRE = "wire"
BACKEND_BLACKBOX = "blackbox"
BACKENDS = (BACKEND_WIRE, BACKEND_BLACKBOX)

PROTO_EXTRA_HINT = "pip install fritap[proto]"
EMPTY_MESSAGE_TEXT = "(empty message)"

#: Line kinds produced by :meth:`ProtobufView.lines`.
LINE_NOTE, LINE_ERROR, LINE_HEADER, LINE_BODY = "note", "error", "header", "body"

#: A primary decoder renders one payload as text, or raises.
TextDecoder = Callable[[bytes], str]


class ViewLine(NamedTuple):
    """One output line of a :class:`ProtobufView` and what it represents."""

    kind: str
    text: str


@dataclass
class DecodedProtobufMessage:
    """One decoded protobuf message (a gRPC frame, or the whole bare body)."""

    index: int
    size: int
    compressed: bool = False
    truncated: bool = False
    text: str = ""
    error: str = ""
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True when something was decoded (a clean empty message counts)."""
        return bool(self.text) or not self.error

    def header(self) -> str:
        """``gRPC message N (S bytes, compressed, truncated)``."""
        flags = [f"{self.size} bytes"]
        if self.compressed:
            flags.append("compressed")
        if self.truncated:
            flags.append("truncated")
        return f"gRPC message {self.index} ({', '.join(flags)})"


@dataclass
class ProtobufView:
    """Result of :func:`decode_protobuf_view`; plain text, no markup.

    ``mode`` is the decoder actually used (``wire``, ``blackbox`` or
    ``schema``); ``framing`` is ``none``, ``grpc`` or ``grpc-invalid`` (gRPC
    was requested but the bytes are not gRPC framed, so they were decoded as
    bare protobuf).
    """

    mode: str = BACKEND_WIRE
    framing: str = "none"
    messages: list[DecodedProtobufMessage] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def ok(self) -> bool:
        """True when at least one message decoded."""
        return any(m.ok for m in self.messages)

    def lines(self) -> list[ViewLine]:
        """Every output line, tagged with its kind, in display order."""
        out = [ViewLine(LINE_NOTE, note) for note in self.notes]
        if self.error:
            out.append(ViewLine(LINE_ERROR, self.error))
        for message in self.messages:
            out.extend(self._message_lines(message))
        return out

    def _message_lines(self, message: DecodedProtobufMessage) -> list[ViewLine]:
        out: list[ViewLine] = []
        if self.framing == "grpc":
            out.append(ViewLine(LINE_HEADER, message.header()))
        out.extend(ViewLine(LINE_NOTE, note) for note in message.notes)
        if message.text:
            out.extend(ViewLine(LINE_BODY, line) for line in message.text.splitlines())
        if message.error:
            out.append(ViewLine(LINE_ERROR, message.error))
        return out

    def text(self) -> str:
        """The whole view as plain text."""
        prefixes = {LINE_NOTE: "note: ", LINE_ERROR: "error: "}
        rendered = []
        for kind, text in self.lines():
            if kind == LINE_HEADER:
                rendered.append(f"--- {text} ---")
            else:
                rendered.append(prefixes.get(kind, "") + text)
        return "\n".join(rendered)


@dataclass
class _Payload:
    """One protobuf payload to decode, plus what framing learned about it."""

    data: Optional[bytes]
    compressed: bool = False
    truncated: bool = False
    size: int = 0
    notes: list[str] = field(default_factory=list)
    error: str = ""


def blackbox_available() -> bool:
    """True when the optional ``blackboxprotobuf`` backend is importable."""
    try:
        return importlib.util.find_spec("blackboxprotobuf") is not None
    except (ImportError, ValueError):  # broken install / spec-less stub module
        return False


def decode_protobuf_view(
    data: bytes,
    *,
    grpc_mode: Optional[bool] = None,
    content_type: str = "",
    grpc_encoding: str = "",
    schema_path: str = "",
    message_type: str = "",
    backend: str = BACKEND_WIRE,
    max_depth: int = 16,
    max_input_bytes: Optional[int] = None,
) -> ProtobufView:
    """Decode *data* as protobuf, optionally gRPC framed, into a :class:`ProtobufView`.

    Args:
        data: The (already Content-Encoding-decompressed) body bytes.
        grpc_mode: ``True`` forces gRPC framing, ``False`` disables it and
            ``None`` decides from *content_type*.
        content_type: ``Content-Type`` header value.
        grpc_encoding: ``grpc-encoding`` header value, used for compressed
            gRPC messages.
        schema_path: ``.proto`` or ``.desc`` schema; used together with
            *message_type*. Falls back to the wire decoder with a note.
        message_type: Fully qualified message type for *schema_path*.
        backend: ``"wire"`` (built in) or ``"blackbox"`` (opt-in, needs
            ``blackboxprotobuf``; falls back to ``"wire"`` with a note).
        max_depth: Maximum nesting depth for the wire decoder.
        max_input_bytes: Decode at most this many leading bytes (a preview
            cap); the tail is reported as truncated, not as an error.

    Raises:
        ValueError: *backend* is not one of :data:`BACKENDS`.
    """
    if backend not in BACKENDS:
        raise ValueError(f"unknown protobuf backend {backend!r}; expected one of {BACKENDS}")
    view = ProtobufView(mode=backend)
    data, capped = _cap_input(bytes(data or b""), max_input_bytes, view)
    if not data:
        view.error = "no data to decode"
        return view
    use_grpc = grpc_mode if grpc_mode is not None else is_grpc_content_type(content_type)
    payloads = _split_payloads(data, use_grpc, grpc_encoding, view, capped)
    primary = _select_primary_decoder(backend, schema_path, message_type, view)
    view.messages = [
        _decode_payload(index, payload, primary, max_depth)
        for index, payload in enumerate(payloads, start=1)
    ]
    return view


# ── Input shaping ────────────────────────────────────────────────


def _cap_input(
    data: bytes, max_input_bytes: Optional[int], view: ProtobufView,
) -> tuple[bytes, bool]:
    """Apply the preview cap: ``(data, capped)``, noting what was left out."""
    if max_input_bytes is None or len(data) <= max_input_bytes:
        return data, False
    view.notes.append(
        f"preview limited to the first {max_input_bytes} of {len(data)} bytes"
    )
    return data[:max_input_bytes], True


def _split_payloads(
    data: bytes, use_grpc: bool, grpc_encoding: str, view: ProtobufView, capped: bool,
) -> list[_Payload]:
    """Split *data* into protobuf payloads, recording the framing on *view*.

    *capped* marks a bare body cut by the preview cap as truncated.
    """
    bare = _Payload(data, truncated=capped, size=len(data))
    if not use_grpc:
        return [bare]
    frames, error = split_grpc_frames_lenient(data)
    if not frames:
        view.framing = "grpc-invalid"
        view.notes.append(f"not valid gRPC framing ({error}); decoded as bare protobuf")
        return [bare]
    view.framing = "grpc"
    if error:
        view.notes.append(error)
    return [_grpc_payload(frame, grpc_encoding) for frame in frames]


def _grpc_payload(frame: GrpcFrame, grpc_encoding: str) -> _Payload:
    """A gRPC frame as a payload, decompressed when its flag says so."""
    payload = _Payload(frame.payload, compressed=frame.compressed,
                       truncated=frame.truncated, size=len(frame.payload))
    if not frame.compressed:
        return payload
    payload.data, note = decompress_grpc_payload(frame.payload, grpc_encoding)
    if payload.data is None:
        payload.error = note
    elif note:
        payload.notes.append(note)
    return payload


# ── Decoder selection ────────────────────────────────────────────


def _select_primary_decoder(
    backend: str, schema_path: str, message_type: str, view: ProtobufView,
) -> Optional[tuple[str, TextDecoder]]:
    """``(label, decoder)`` to try before the wire decoder, or ``None``.

    Sets ``view.mode`` to the decoder that will actually run.
    """
    if schema_path or message_type:
        return _schema_decoder(schema_path, message_type, view)
    if backend == BACKEND_BLACKBOX:
        return _blackbox_decoder(view)
    return None


def _schema_decoder(
    schema_path: str, message_type: str, view: ProtobufView,
) -> Optional[tuple[str, TextDecoder]]:
    """Load the schema; on any failure note why and let the wire decoder run."""
    view.mode = BACKEND_WIRE
    if not (schema_path and message_type):
        view.notes.append(
            "schema decoding needs both a schema file and a message type; "
            "showing the raw wire decode"
        )
        return None
    try:
        from .schema import SchemaDecoder

        decoder = SchemaDecoder()
        decoder.load_schema(schema_path, message_type)
    except ImportError:
        view.notes.append(
            f"schema decoding needs the protobuf package ({PROTO_EXTRA_HINT}); "
            "showing the raw wire decode"
        )
        return None
    except Exception as exc:  # SchemaError, OSError, KeyError, DecodeError, ...
        view.notes.append(f"schema not loaded ({exc}); showing the raw wire decode")
        return None
    view.mode = "schema"
    return "schema", decoder.decode_text


def _blackbox_decoder(view: ProtobufView) -> Optional[tuple[str, TextDecoder]]:
    """The opt-in blackboxprotobuf decoder, or ``None`` with an install note."""
    try:
        import blackboxprotobuf  # type: ignore[import-not-found]
    except ImportError:
        view.mode = BACKEND_WIRE
        view.notes.append(
            f"blackboxprotobuf is not installed ({PROTO_EXTRA_HINT}); "
            "using the built-in wire decoder"
        )
        return None

    def decode(data: bytes) -> str:
        message, _typedef = blackboxprotobuf.decode_message(data)
        return json.dumps(message, indent=2, default=str, ensure_ascii=False)

    return BACKEND_BLACKBOX, decode


# ── Per-message decoding ─────────────────────────────────────────


def _decode_payload(
    index: int, payload: _Payload,
    primary: Optional[tuple[str, TextDecoder]], max_depth: int,
) -> DecodedProtobufMessage:
    """Decode one payload: the primary decoder first, the wire decoder as fallback."""
    message = DecodedProtobufMessage(
        index=index, size=payload.size, compressed=payload.compressed,
        truncated=payload.truncated, notes=list(payload.notes), error=payload.error,
    )
    if payload.data is None:
        return message
    if payload.truncated and not payload.data:
        message.error = "no payload bytes captured"
        return message
    if primary is not None and _primary_decode(message, payload, primary):
        return message
    message.text, message.error = _wire_text(payload.data, max_depth)
    return message


def _primary_decode(
    message: DecodedProtobufMessage, payload: _Payload, primary: tuple[str, TextDecoder],
) -> bool:
    """Run the schema/blackbox decoder into *message*; False means use the wire decoder."""
    label, decoder = primary
    if payload.truncated:
        message.notes.append(f"message is truncated; {label} decode skipped, showing the raw wire decode")
        return False
    try:
        message.text = decoder(payload.data) or EMPTY_MESSAGE_TEXT
    except Exception as exc:  # third-party decoders raise assorted types
        message.notes.append(f"{label} decode failed ({exc}); showing the raw wire decode")
        return False
    return True


def _wire_text(data: bytes, max_depth: int) -> tuple[str, str]:
    """Lenient wire decode of *data*: ``(text, error)``."""
    decoded, error = decode_raw_lenient(data, max_depth=max_depth)
    if decoded.fields:
        return format_message(decoded), error
    if not data:
        return EMPTY_MESSAGE_TEXT, ""
    return "", error or "no protobuf fields decoded"
