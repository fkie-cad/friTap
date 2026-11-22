"""Host-side support for Fizz (Meta TLS 1.3 / mvfst QUIC) keylog lines.

The Fizz agent hooks emit the NSS TLS 1.3 labels, including
EARLY_EXPORTER_SECRET; the pipeline must recognise every one of them (the
client_random is extracted, so coverage/redaction/routing see a real TLS line).
"""

from friTap.pipeline import TLS_KEYLOG_LABELS, _extract_client_random
from friTap.protocols.tls_handler import TLS_LIBRARY_PATTERNS, TLSHandler

CR = "ab" * 32
SECRET = "cd" * 32

FIZZ_LABELS = (
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0",
    "SERVER_TRAFFIC_SECRET_0",
    "EXPORTER_SECRET",
    "CLIENT_EARLY_TRAFFIC_SECRET",
    "EARLY_EXPORTER_SECRET",
)


def test_every_fizz_label_is_a_tls_keylog_label():
    for label in FIZZ_LABELS:
        assert label in TLS_KEYLOG_LABELS, label


def test_early_exporter_line_yields_its_client_random():
    assert _extract_client_random(f"EARLY_EXPORTER_SECRET {CR} {SECRET}") == CR


def test_unknown_label_still_yields_no_client_random():
    assert _extract_client_random(f"FIZZ_SOMETHING {CR} {SECRET}") == ""


def test_fizz_is_a_tls_library_pattern():
    assert "fizz" in TLS_LIBRARY_PATTERNS
    assert "fizz" in TLSHandler.library_patterns


def test_redaction_still_covers_early_exporter():
    from friTap.analysis.redaction import _KEYLOG_LABEL_RE
    assert _KEYLOG_LABEL_RE.search(f"EARLY_EXPORTER_SECRET {CR} {SECRET}")
