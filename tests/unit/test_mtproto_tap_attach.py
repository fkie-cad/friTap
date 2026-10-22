"""MTProto/Telegram attach pass in ``friTap.offline.mtproto.tap_attach``.

The post-collection fold of parsed Telegram metadata onto offline flows moved
out of ``friTap.offline.pcap_to_tap``; none of the old private names stays
bound there (import them from ``tap_attach``).
"""

from __future__ import annotations

from types import SimpleNamespace

from friTap.connection_index import normalize_4tuple
from friTap.offline import pcap_to_tap
from friTap.offline.mtproto import tap_attach
from friTap.offline.pipeline_api import chunk_key

MOVED_NAMES = [
    "_apply_e2e_peer", "_apply_ledger_envelope", "_apply_ledger_record",
    "_apply_mtproto_meta", "_attach_scoped_meta", "_attach_telegram_meta",
    "_cloud_flow_users", "_dedupe_users", "_fill_flow_ids",
    "_finalize_telegram_refs", "_flow_record_seq", "_message_user_ids",
    "_meta_from_ledger", "_scoped_cloud_meta", "_scoped_e2e_meta",
    "_single_chunk_key",
]



class _Layer:
    def __init__(self, name):
        self.NAME = name
        self.messages = []
        self.message_count = 0


class _Flow:
    """Minimal live flow: one chunk, lazily materialized inner layer."""

    def __init__(self, transport, data=b"REC", **attrs):
        self.transport = transport
        self.flow_id = "f1"
        self.chunks = [SimpleNamespace(direction="read", data=data)]
        self._layers = {}
        self.__dict__.update(attrs)

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        return self._layers.setdefault(name, _Layer(name))

    def layer(self, name):
        return self._layers.get(name)


def test_moved_names_importable_from_new_module():
    for name in MOVED_NAMES:
        assert callable(getattr(tap_attach, name)), name


def test_aliases_are_dropped_from_pcap_to_tap():
    for name in MOVED_NAMES:
        assert not hasattr(pcap_to_tap, name), name
    assert not hasattr(pcap_to_tap, "_TELEGRAM_TRANSPORTS")


def test_attach_scopes_cloud_messages_by_4tuple_and_chunk():
    flow = _Flow("mtproto", src_addr="10.0.0.1", src_port=5000,
                 dst_addr="149.154.167.50", dst_port=443)
    key = normalize_4tuple(flow.src_addr, flow.src_port, flow.dst_addr, flow.dst_port)
    own = {"method": "help.getConfig", "_chunk_key": chunk_key("read", b"REC")}
    other = {"method": "ping", "_chunk_key": chunk_key("read", b"OTHER")}
    tap_attach._attach_telegram_meta([flow], {key: {"messages": [own, other]}}, None)
    layer = flow.layer("mtproto")
    assert layer.messages == [{"method": "help.getConfig"}]
    assert layer.message_count == 1


def test_attach_e2e_by_session_id_keeps_public_fields_only():
    flow = _Flow("telegram_e2e", ssl_session_id="telegram_e2e:ab")
    meta = {"telegram_e2e:ab": {"messages": [{"text": "hi"}], "_private": 1}}
    tap_attach._attach_telegram_meta([flow], None, meta)
    assert flow.layer("telegram_e2e").messages == [{"text": "hi"}]


def test_attach_skips_non_telegram_flows_and_missing_meta():
    tls_flow = _Flow("tls")
    cloud_flow = _Flow("mtproto", src_addr="a", src_port=1, dst_addr="b", dst_port=2)
    tap_attach._attach_telegram_meta([tls_flow, cloud_flow], {}, {})
    assert tls_flow.layer("tls") is None
    assert cloud_flow.layer("mtproto") is None


def test_finalize_refs_degrades_without_state():
    tap_attach._finalize_telegram_refs([object()], None)
