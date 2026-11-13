"""SSL_Logger hands the option-5 pinner to PCAP and finalizes only the -p pcap."""

import types

from friTap.legacy.ssl_logger_core import SSL_Logger


class _RecordingPcap:
    def __init__(self):
        self.pinner = None
        self.finalized = 0

    def set_endpoint_pinner(self, pinner):
        self.pinner = pinner

    def finalize_plaintext_capture(self):
        self.finalized += 1


def _logger(pcap_obj, handlers_active=True, auxiliary=False):
    pinner = object()
    stub = types.SimpleNamespace(
        pcap_obj=pcap_obj, _handlers_active=handlers_active,
        _message_router=types.SimpleNamespace(endpoint_pinner=pinner),
        _config=types.SimpleNamespace(output=types.SimpleNamespace(auxiliary_session=auxiliary)))
    stub.hand = SSL_Logger._hand_endpoint_pinner_to_pcap.__get__(stub)
    stub.finalize = SSL_Logger._finalize_plaintext_pcap.__get__(stub)
    return stub, pinner


def test_pinner_handed_to_pcap():
    pcap = _RecordingPcap()
    stub, pinner = _logger(pcap)
    stub.hand()
    assert pcap.pinner is pinner


def test_hand_without_pcap_is_noop():
    stub, _ = _logger(None)
    stub.hand()


def test_finalize_runs_for_plaintext_capture():
    pcap = _RecordingPcap()
    stub, _ = _logger(pcap)
    stub.finalize(full_capture=False)
    assert pcap.finalized == 1


def test_finalize_skipped_for_full_capture_helper_and_inactive_handlers():
    for kwargs, full in (({}, True), ({"auxiliary": True}, False),
                         ({"handlers_active": False}, False)):
        pcap = _RecordingPcap()
        stub, _ = _logger(pcap, **kwargs)
        stub.finalize(full_capture=full)
        assert pcap.finalized == 0
