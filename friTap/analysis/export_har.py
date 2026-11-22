"""
Export a ``.tap`` capture as an HTTP Archive (HAR 1.2) document.

Lifted from ``example/tap_to_har.py`` so library code (the agent ``export``
tool) can produce HAR files; the example script stays a standalone CLI.

HAR is consumed by Chrome DevTools, Burp Suite, mitmproxy and friends. Only
flows with a parsed HTTP request or response become entries. Header values,
URLs and (with ``include_bodies``) bodies are written verbatim: a HAR file is
a full-fidelity export, not a redacted report.

HAR 1.2 spec: http://www.softwareishard.com/blog/har-12-spec/
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable
from urllib.parse import parse_qs, urlparse

from friTap.synthetic_endpoints import flow_endpoints_synthetic

if TYPE_CHECKING:
    from friTap.flow.models import Flow
    from friTap.parsers.app_ciphers.applovin_keyring import AppLovinKeyring

HAR_VERSION = "1.2"
APP_CIPHER_FIELD = "_fritap_app_cipher"
APPLOVIN_CIPHER = "applovin_mediate"
_TEXT_MIME_MARKERS = ("text", "json", "xml", "html", "javascript", "css",
                      "x-www-form-urlencoded", "svg", "yaml")


def _fritap_version() -> str:
    try:
        from friTap import __version__

        return __version__
    except Exception:  # noqa: BLE001 - version is cosmetic
        return "unknown"


def _iso_timestamp(epoch: float) -> str:
    if not epoch or epoch <= 0:
        return datetime.now(timezone.utc).isoformat()
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def _name_values(headers: dict) -> list[dict]:
    return [{"name": str(k), "value": str(v)} for k, v in (headers or {}).items()]


def _query_string(url: str) -> list[dict]:
    if "?" not in (url or ""):
        return []
    try:
        params = parse_qs(urlparse(url).query, keep_blank_values=True)
    except ValueError:
        return []
    return [{"name": name, "value": value} for name, values in params.items() for value in values]


def _mime_type(content_type: str) -> str:
    if not content_type:
        return "x-unknown"
    return content_type.split(";", 1)[0].strip()


def body_to_har(body: bytes, content_type: str, include_body: bool) -> dict:
    """HAR ``content`` / ``postData`` object: text when decodable, else base64."""
    mime = _mime_type(content_type)
    if not body or not include_body:
        return {"size": len(body) if body else 0, "mimeType": mime}
    if any(marker in mime for marker in _TEXT_MIME_MARKERS):
        try:
            return {"size": len(body), "mimeType": mime, "text": body.decode("utf-8")}
        except UnicodeDecodeError:
            pass
    return {"size": len(body), "mimeType": mime,
            "text": base64.b64encode(body).decode("ascii"), "encoding": "base64"}


def _request_url(flow: "Flow") -> str:
    req = flow.request
    host = req.host or flow.get_request_header("host") or flow.dst_addr or "unknown"
    return f"https://{host}{req.url or '/'}"


def _har_request(flow: "Flow", include_bodies: bool) -> dict:
    req = flow.request
    body = flow.get_decompressed_request_body() if (req and include_bodies) else b""
    har: dict[str, Any] = {
        "method": req.method if req else "GET",
        "url": _request_url(flow) if req else "",
        "httpVersion": req.protocol if req else "HTTP/1.1",
        "cookies": [],
        "headers": _name_values(req.headers) if req else [],
        "queryString": _query_string(req.url if req else ""),
        "headersSize": -1,
        "bodySize": len(body) if include_bodies else (req.body_size if req else 0),
    }
    if body:
        har["postData"] = body_to_har(body, flow.request_content_type, include_bodies)
    return har


def _har_response(flow: "Flow", include_bodies: bool) -> dict:
    resp = flow.response
    body = flow.get_decompressed_response_body() if (resp and include_bodies) else b""
    return {
        "status": resp.status_code if resp else 0,
        "statusText": resp.status_text if resp else "",
        "httpVersion": resp.protocol if resp else "HTTP/1.1",
        "cookies": [],
        "headers": _name_values(resp.headers) if resp else [],
        "content": body_to_har(body, flow.response_content_type, include_bodies),
        "redirectURL": flow.get_response_header("location"),
        "headersSize": -1,
        "bodySize": len(body) if include_bodies else (resp.body_size if resp else 0),
    }


class LazyKeyring:
    """Builds ``AppLovinKeyring.from_sources()`` on first use only.

    Captures without AppLovin envelopes never pay for env parsing or
    bundle mining; an explicit *keyring* is returned as-is.
    """

    def __init__(self, keyring: "AppLovinKeyring | None" = None) -> None:
        self._keyring = keyring

    def get(self) -> "AppLovinKeyring":
        if self._keyring is None:
            from friTap.parsers.app_ciphers.applovin_keyring import AppLovinKeyring

            self._keyring = AppLovinKeyring.from_sources()
        return self._keyring


def app_cipher_field(flow: "Flow", keyring: LazyKeyring) -> dict | None:
    """``_fritap_app_cipher`` value for an AppLovin mediate request, else ``None``."""
    from friTap.analysis.applovin_mediate import find_mediate_envelope, variant_label

    envelope = find_mediate_envelope(flow)
    if envelope is None:
        return None
    result, reason = keyring.get().try_decrypt(envelope)
    record: dict[str, Any] = {"cipher": APPLOVIN_CIPHER, "protocol_id": envelope.protocol_id}
    if result is None:
        return {**record, "decrypted": False, "reason": reason}
    payload = result.json if result.json is not None else result.plaintext.decode("utf-8", "replace")
    return {**record, "decrypted": True, "timestamp_ms": result.timestamp_ms,
            "variant": variant_label(result), "json": payload}


def _entry_comment(flow: "Flow") -> str:
    parts = []
    if flow.ssl_session_id:
        parts.append(f"ssl_session_id={flow.ssl_session_id[:16]}...")
    if flow.flow_id:
        parts.append(f"flow_id={flow.flow_id}")
    return " | ".join(parts)


def _has_synthetic_server(flow: "Flow") -> bool:
    """True when *flow*'s endpoints are synthetic (see :func:`flow_endpoints_synthetic`)."""
    return flow_endpoints_synthetic(flow)


def flow_to_har_entry(
    flow: "Flow",
    include_bodies: bool = False,
    keyring: LazyKeyring | None = None,
) -> dict | None:
    """Convert one flow to a HAR entry; ``None`` for non-HTTP flows.

    With *include_bodies*, an AppLovin mediate request also gets its
    decrypted payload (or the failure reason) as ``_fritap_app_cipher``.
    """
    if flow.request is None and flow.response is None:
        return None
    duration_ms = max(0, int((flow.ended - flow.started) * 1000)) if flow.ended > 0 else 0
    entry: dict[str, Any] = {
        "startedDateTime": _iso_timestamp(flow.started),
        "time": duration_ms,
        "request": _har_request(flow, include_bodies),
        "response": _har_response(flow, include_bodies),
        "cache": {},
        "timings": {"send": 0, "wait": duration_ms, "receive": 0},
        "serverIPAddress": flow.dst_addr or "",
        "connection": flow.connection_id or "",
    }
    if _has_synthetic_server(flow):
        # Optional in HAR 1.2; a synthetic 198.18.0.0/15 address is no real server.
        del entry["serverIPAddress"]
    stream_id = flow.stream_id
    if stream_id is not None:
        # HAR permits custom fields with a leading underscore.
        entry["_streamId"] = stream_id
    comment = _entry_comment(flow)
    if comment:
        entry["comment"] = comment
    if include_bodies:
        _add_app_cipher(entry, flow, keyring or LazyKeyring())
    return entry


def _add_app_cipher(entry: dict, flow: "Flow", keyring: LazyKeyring) -> None:
    app_cipher = app_cipher_field(flow, keyring)
    if app_cipher is not None:
        entry[APP_CIPHER_FIELD] = app_cipher


def _selected_flows(reader: Any, keep: Callable[["Flow"], bool] | None):
    for _ordinal, _summary, flow in reader.iter_flows():
        if keep is None or keep(flow):
            yield flow


def tap_to_har(
    tap_path: str,
    include_bodies: bool = False,
    keep: Callable[["Flow"], bool] | None = None,
    keyring: "AppLovinKeyring | None" = None,
) -> dict:
    """Convert the capture at *tap_path* to a HAR 1.2 document.

    Args:
        tap_path: ``.tap`` capture.
        include_bodies: Embed request/response bodies (raw values) and
            decrypted app-layer cipher payloads (``_fritap_app_cipher``).
        keep: Optional flow predicate (e.g. ``FlowSelector(...).matches``).
        keyring: AppLovin key material; defaults to
            ``AppLovinKeyring.from_sources()``, built only when an envelope
            is encountered.
    """
    from friTap.flow.tap_reader import TapReader

    lazy_keyring = LazyKeyring(keyring)
    with TapReader(tap_path) as reader:
        entries = [entry for flow in _selected_flows(reader, keep)
                   if (entry := flow_to_har_entry(flow, include_bodies, lazy_keyring)) is not None]
    return {
        "log": {
            "version": HAR_VERSION,
            "creator": {"name": "friTap", "version": _fritap_version(),
                        "comment": "Converted from .tap capture file"},
            "entries": entries,
        }
    }


__all__ = [
    "APP_CIPHER_FIELD",
    "HAR_VERSION",
    "LazyKeyring",
    "app_cipher_field",
    "body_to_har",
    "flow_to_har_entry",
    "tap_to_har",
]
