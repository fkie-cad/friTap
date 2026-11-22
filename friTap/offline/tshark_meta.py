"""tshark ``-T ek`` field helpers and the TLS/QUIC/SSH metadata accumulators.

Pure folding of tshark rows (``-T fields`` columns or ``-T ek`` layers) into
per-stream metadata. No subprocess work; :mod:`friTap.offline.tshark`
re-exports every name here.
"""

from __future__ import annotations

from typing import Sequence

from ..client_random import normalize_client_random


def ek_field(layers: dict, dotted_name: str):
    """Return the raw value for *dotted_name* from a `-T ek` layers dict.

    `-T ek` may flatten ``.`` to ``_``, so both spellings are looked up.
    """
    value = layers.get(dotted_name)
    if value is None:
        value = layers.get(dotted_name.replace(".", "_"))
    return value


def ek_as_list(value) -> list:
    """Normalize a `-T ek` field value to a list (scalars become 1-element)."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def ek_first(value):
    """Return the first element of a list-or-scalar field, or None."""
    items = ek_as_list(value)
    return items[0] if items else None


def ek_columns(layers: dict, fields: Sequence[str]) -> list[str]:
    """Render *fields* of one `-T ek` row as ``-T fields`` columns.

    Joining each list with ``","`` reproduces the ``-T fields -E occurrence=a``
    column (absent -> ``""``), so the column parsers serve both exports.
"""
    return [",".join(str(v) for v in ek_as_list(ek_field(layers, name)))
            for name in fields]



# Common TLS ciphersuite codepoints to IANA/OpenSSL names; unknown ones pass through as hex.
CIPHER_SUITE_NAMES: dict[str, str] = {
    "0x1301": "TLS_AES_128_GCM_SHA256",
    "0x1302": "TLS_AES_256_GCM_SHA384",
    "0x1303": "TLS_CHACHA20_POLY1305_SHA256",
    "0xc02f": "ECDHE-RSA-AES128-GCM-SHA256",
    "0xc02b": "ECDHE-ECDSA-AES128-GCM-SHA256",
    "0xc030": "ECDHE-RSA-AES256-GCM-SHA384",
    "0xc02c": "ECDHE-ECDSA-AES256-GCM-SHA384",
}

# TLS version codepoints to display strings; unknown ones pass through as hex.
TLS_VERSION_NAMES: dict[str, str] = {
    "0x0304": "TLS 1.3",
    "0x0303": "TLS 1.2",
    "0x0302": "TLS 1.1",
    "0x0301": "TLS 1.0",
}

# Fields of one TLS-handshake row; TlsMetadataAccumulator reads them by position. The TLS 1.3 version field is dotted (``extensions.supported_version``), unlike its neighbours.
_TLS_META_FIELDS = (
    "tls.stream",
    "tls.handshake.type",
    "tls.handshake.extensions_server_name",
    "tls.handshake.ciphersuite",
    "tls.handshake.version",
    "tls.handshake.extensions.supported_version",
    "tls.handshake.extensions_alpn_str",
    "tls.handshake.random",
)


def _client_hello_random(raw: str) -> str:
    """The first ``tls.handshake.random`` of a ClientHello row as lower-case hex, or ``""``."""
    return normalize_client_random(_first_token(raw).replace(":", ""))


def _normalize_hex_codepoint(value: str) -> str:
    """*value* lowercased and zero-padded to ``0xNNNN`` when hex-like (so name lookups hit), else stripped."""
    token = value.strip()
    if not token:
        return ""
    low = token.lower()
    if low.startswith("0x"):
        digits = low[2:]
        if digits and all(c in "0123456789abcdef" for c in digits):
            return "0x" + digits.zfill(4)
        return low
    return token


def _map_cipher(raw: str) -> str:
    """Map a raw ciphersuite codepoint to a name, else pass the hex through."""
    canon = _normalize_hex_codepoint(raw)
    if not canon:
        return ""
    return CIPHER_SUITE_NAMES.get(canon, canon)


def _map_version(raw: str) -> str:
    """Map a raw TLS version codepoint to a name, else pass the hex through."""
    canon = _normalize_hex_codepoint(raw)
    if not canon:
        return ""
    return TLS_VERSION_NAMES.get(canon, canon)


def _first_token(value: str) -> str:
    """Return the first comma-joined token of *value* (tshark occurrence=a)."""
    for token in value.split(","):
        token = token.strip()
        if token:
            return token
    return ""


def _padded(cols: Sequence[str], width: int) -> list[str]:
    """*cols* as a list padded with ``""`` to *width* (positional access never fails)."""
    cols = list(cols)
    cols.extend([""] * (width - len(cols)))
    return cols


def _stream_index(column: str) -> int | None:
    """The stream index in a stream column, or ``None`` when it has none."""
    try:
        return int(_first_token(column))
    except (ValueError, TypeError):
        return None


class TlsMetadataAccumulator:
    """Fold TLS-handshake rows into per-``tls.stream`` metadata.

    A row is the columns of :data:`_TLS_META_FIELDS`. ClientHello (type ``1``) gives
    the SNI, ServerHello (type ``2``) the selected suite, version and ALPN. Values
    merge per stream without overwriting; a row without ``tls.stream`` is skipped.
"""

    def __init__(self) -> None:
        self._by_stream: dict[int, dict] = {}

    @property
    def by_stream(self) -> dict[int, dict]:
        """The live per-stream metadata (read-only use; see :meth:`result`)."""
        return self._by_stream

    def feed_ek(self, layers: dict) -> int | None:
        """Fold one `-T ek` row; return the ``tls.stream`` it touched, if any."""
        return self.feed_columns(ek_columns(layers, _TLS_META_FIELDS))

    def feed_columns(self, cols: Sequence[str]) -> int | None:
        """Fold one row of columns; return the ``tls.stream`` it touched, if any."""
        cols = _padded(cols, len(_TLS_META_FIELDS))
        stream = _stream_index(cols[0])
        if stream is None:
            return None
        entry = self._by_stream.setdefault(
            stream, {"sni": "", "cipher": "", "version": "", "alpn": "",
                     "client_random": ""})
        types = _split_types(cols[1])
        sni = cols[2].strip()
        if "1" in types and sni and not entry["sni"]:
            entry["sni"] = sni
        if "1" in types and not entry["client_random"]:
            entry["client_random"] = _client_hello_random(cols[7])
        if "2" in types:
            _merge_server_hello(entry, *(c.strip() for c in cols[3:7]))
        return stream

    def result(self) -> dict[int, dict]:
        """``{tls_stream: {"sni", "cipher", "version", "alpn", "client_random"}}`` (copies)."""
        return {stream: dict(entry) for stream, entry in self._by_stream.items()}


def _merge_server_hello(entry: dict, ciphersuite: str, version: str,
                        supported_version: str, alpn: str) -> None:
    """Fill *entry*'s empty cipher/version/alpn from one ServerHello row."""
    if ciphersuite and not entry["cipher"]:
        entry["cipher"] = _map_cipher(ciphersuite)
    # Prefer the TLS 1.3 supported_version extension over the legacy
    # handshake.version (which is frozen at 0x0303 for TLS 1.3).
    mapped_version = ""
    if supported_version:
        mapped_version = _map_version(_first_token(supported_version))
    elif version:
        mapped_version = _map_version(_first_token(version))
    if mapped_version and not entry["version"]:
        entry["version"] = mapped_version
    if alpn and not entry["alpn"]:
        entry["alpn"] = _first_token(alpn)


def _split_types(hs_type: str) -> list[str]:
    """Split a comma/space-joined ``tls.handshake.type`` field into tokens."""
    return [t.strip() for t in hs_type.replace(",", " ").split() if t.strip()]



# QUIC transport version codepoints (rendered "0x00000001") to short names; unknown ones pass through.
QUIC_VERSION_NAMES: dict[str, str] = {
    "0x00000001": "1",          # RFC 9000 (QUIC v1)
    "0x6b3343cf": "2",          # RFC 9369 (QUIC v2)
    "0xff00001d": "draft-29",   # common pre-RFC draft still seen in the wild
}

# Fields of one QUIC metadata row (read by position). quic.version is plaintext; SNI is decryptable from the Initial secret, cipher/ALPN need the keylog.
_QUIC_META_FIELDS = (
    "udp.stream",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "udp.srcport",
    "udp.dstport",
    "quic.version",
    "tls.handshake.type",
    "tls.handshake.ciphersuite",
    "tls.handshake.extensions_alpn_str",
    "tls.handshake.extensions_server_name",
    "tls.handshake.random",
)


def _map_quic_version(raw: str) -> str:
    """Map a raw QUIC version codepoint to a short name, else pass it through."""
    token = raw.strip().lower()
    if not token:
        return ""
    return QUIC_VERSION_NAMES.get(token, token)


def _anchor_endpoints(entry: dict, cols: list[str]) -> None:
    """Set *entry*'s endpoints from the first row carrying them.

    *cols* starts with the stream column, ``ip.src``, ``ipv6.src``, ``ip.dst``,
    ``ipv6.dst``, source port, destination port (shared prefix of
    :data:`_QUIC_META_FIELDS` and :data:`_SSH_FIELDS`).
"""
    src_addr = cols[1].strip() or cols[2].strip()
    if entry["src_addr"] or not src_addr:
        return
    entry["src_addr"] = src_addr
    entry["src_port"] = _safe_int(cols[5])
    entry["dst_addr"] = cols[3].strip() or cols[4].strip()
    entry["dst_port"] = _safe_int(cols[6])


class QuicMetadataAccumulator:
    """Fold QUIC rows into per-``udp.stream`` metadata.

    A row is the columns of :data:`_QUIC_META_FIELDS`. Merged per stream: endpoints
    and transport version (first seen), SNI and client random (ClientHello), cipher
    (ServerHello), ALPN (first token). A row without ``udp.stream`` is skipped.
"""

    def __init__(self) -> None:
        self._by_stream: dict[int, dict] = {}

    def feed_ek(self, layers: dict) -> int | None:
        """Fold one `-T ek` row; return the ``udp.stream`` it touched, if any."""
        return self.feed_columns(ek_columns(layers, _QUIC_META_FIELDS))

    def feed_columns(self, cols: Sequence[str]) -> int | None:
        """Fold one row of columns; return the ``udp.stream`` it touched, if any."""
        cols = _padded(cols, len(_QUIC_META_FIELDS))
        stream = _stream_index(cols[0])
        if stream is None:
            return None
        entry = self._by_stream.setdefault(stream, {
            "src_addr": "", "src_port": 0, "dst_addr": "", "dst_port": 0,
            "version": "", "sni": "", "alpn": "", "cipher": "", "client_random": "",
        })
        _anchor_endpoints(entry, cols)
        version, types = cols[7].strip(), _split_types(cols[8])
        cipher, alpn, sni = (c.strip() for c in cols[9:12])
        if version and not entry["version"]:
            entry["version"] = _map_quic_version(_first_token(version))
        if "1" in types and sni and not entry["sni"]:
            entry["sni"] = sni
        if "1" in types and not entry["client_random"]:
            entry["client_random"] = _client_hello_random(cols[12])
        if "2" in types and cipher and not entry["cipher"]:
            entry["cipher"] = _map_cipher(cipher)
        if alpn and not entry["alpn"]:
            entry["alpn"] = _first_token(alpn)
        return stream

    def result(self) -> dict[int, dict]:
        """``{udp_stream: {endpoints, "version", "sni", "alpn", "cipher", "client_random"}}`` (copies)."""
        return {stream: dict(entry) for stream, entry in self._by_stream.items()}



# Fields of one SSH metadata row. :class:`SshConnectionAccumulator` reads the
_SSH_FIELDS = (
    "tcp.stream",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "ssh.protocol",
    "ssh.kex_algorithms",
    "ssh.encryption_algorithms_client_to_server",
    "ssh.mac_algorithms_client_to_server",
)


def parse_ssh_fields(output: str) -> list[dict]:
    """Parse an SSH ``-T fields`` dump into one dict per connection.

    Rows are tab-separated :data:`_SSH_FIELDS`, merged per ``tcp.stream`` by
    :class:`SshConnectionAccumulator`. Banners are attributed by sender port, not
    order; ``kex``/``cipher``/``mac`` are the first token of each list. Malformed rows
    are skipped. Keys: ``src_addr, src_port, dst_addr, dst_port, client_version,
    server_version, kex, cipher, mac``. Field names are calibrated against tshark
    4.6.5 by ``tests/unit/test_offline_tshark_calibration.py``.
"""
    accumulator = SshConnectionAccumulator()
    for line in output.splitlines():
        if line.strip():
            accumulator.feed_columns(line.split("\t"))
    return accumulator.result()


class SshConnectionAccumulator:
    """Fold SSH rows into one connection dict per ``tcp.stream``.

    Banners go to client or server by sender port (:func:`_ssh_server_port`);
    ``kex``/``cipher``/``mac`` are the first token of the first non-empty list.
"""

    def __init__(self) -> None:
        self._by_stream: dict[int, dict] = {}

    def feed_ek(self, layers: dict) -> int | None:
        """Fold one `-T ek` row; return the ``tcp.stream`` it touched, if any."""
        return self.feed_columns(ek_columns(layers, _SSH_FIELDS))

    def feed_columns(self, cols: Sequence[str]) -> int | None:
        """Fold one row of columns; return the ``tcp.stream`` it touched, if any."""
        cols = _padded(cols, len(_SSH_FIELDS))
        stream = _stream_index(cols[0])
        if stream is None:
            return None
        entry = self._by_stream.setdefault(stream, {
            "src_addr": "", "src_port": 0, "dst_addr": "", "dst_port": 0,
            "client_version": "", "server_version": "",
            "kex": "", "cipher": "", "mac": "",
            "_banners": [],
        })
        _anchor_endpoints(entry, cols)
        banner = cols[7].strip()
        sent = (_safe_int(cols[5]), banner)  # (sender port, banner)
        if banner and sent not in entry["_banners"]:
            entry["_banners"].append(sent)
        for key, column in (("kex", cols[8]), ("cipher", cols[9]), ("mac", cols[10])):
            value = _first_token(column)
            if value and not entry[key]:
                entry[key] = value
        return stream

    def result(self) -> list[dict]:
        """One finalized connection dict per stream (fresh dicts, no ``_banners``)."""
        return [_finalized_ssh_connection(entry) for entry in self._by_stream.values()]


_SSH_WELL_KNOWN_PORT = 22


def _finalized_ssh_connection(entry: dict) -> dict:
    """*entry* without its private banner list, client -> server oriented, with versions."""
    connection = {key: value for key, value in entry.items() if key != "_banners"}
    server_port = _ssh_server_port(connection["src_port"], connection["dst_port"])
    if server_port is None:
        client, server = _banners_by_order(entry["_banners"])
    else:
        client, server = _banners_by_sender(entry["_banners"], server_port)
        if connection["src_port"] == server_port:
            _swap_endpoints(connection)
    connection["client_version"] = client
    connection["server_version"] = server
    return connection


def _ssh_server_port(port_a: int, port_b: int) -> int | None:
    """The SSH server's port, or ``None`` when the ports cannot tell.

    Port 22 is the server, else the lower port. ``ssh.direction`` is not used:
    under heuristic dissection tshark derives it from who sent first.
"""
    if not port_a or not port_b or port_a == port_b:
        return None
    if _SSH_WELL_KNOWN_PORT in (port_a, port_b):
        return _SSH_WELL_KNOWN_PORT
    return min(port_a, port_b)


def _banners_by_sender(banners: list[tuple[int, str]], server_port: int) -> tuple[str, str]:
    """(client, server) banner: the first one each side sent."""
    client = next((text for port, text in banners if port != server_port), "")
    server = next((text for port, text in banners if port == server_port), "")
    return client, server


def _banners_by_order(banners: list[tuple[int, str]]) -> tuple[str, str]:
    """(client, server) banner when the ports cannot tell: first seen, next distinct."""
    texts = list(dict.fromkeys(text for _port, text in banners))
    return (texts[0] if texts else ""), (texts[1] if len(texts) > 1 else "")


def _swap_endpoints(connection: dict) -> None:
    """Swap *connection*'s ``src_*`` and ``dst_*`` endpoints in place."""
    connection["src_addr"], connection["dst_addr"] = connection["dst_addr"], connection["src_addr"]
    connection["src_port"], connection["dst_port"] = connection["dst_port"], connection["src_port"]


def _safe_int(value: str, default: int = 0) -> int:
    """Best-effort int from a (possibly comma-joined) tshark field token."""
    token = _first_token(value)
    try:
        return int(token)
    except (ValueError, TypeError):
        return default

