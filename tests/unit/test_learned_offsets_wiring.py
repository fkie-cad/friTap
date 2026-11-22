"""End-to-end host wiring of the learned plaintext-RVA cache: schema, router,
session (load / user-offsets precedence / record / save) and config_batch."""

import inspect
import json
import logging
import threading
import time

import pytest
from pydantic import TypeAdapter

from friTap.config import FriTapConfig
from friTap.constants import ContentType
from friTap.learned_offsets import LearnedOffsetsStore, make_key
from friTap.legacy import learned_offsets_session as los
from friTap.legacy.learned_offsets_session import LearnedOffsetsSession
from friTap.legacy.ssl_logger_core import SSL_Logger
from friTap.message_router import MessageRouter
from friTap.schemas.agent_messages import (
    AgentMessage,
    ModuleOffsetsLearnedMessage,
    PlaintextApiLearnedMessage,
)

BUILD_ID = "cd" * 20
SIZE = 0x200000
KEY = make_key(BUILD_ID, SIZE, "arm64")
LOGGER = "friTap.learned_offsets"


def learned_payload(**overrides):
    payload = {
        "contentType": "plaintext_api_learned",
        "protocol": "tls",
        "module": "libcronet.so",
        "build_id": BUILD_ID,
        "size": SIZE,
        "arch": "arm64",
        "rvas": {"SSL_read": 0x1000, "SSL_write": 0x2000},
        "prologue_sha256": {"SSL_read": "1" * 64, "SSL_write": "2" * 64},
    }
    payload.update(overrides)
    return payload


class _Bus:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


@pytest.fixture
def cache_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("FRITAP_LEARNED_OFFSETS_DIR", str(tmp_path))
    monkeypatch.delenv(los.LEARNED_OFFSETS_DISABLE_ENV, raising=False)
    return tmp_path


def cache_file(cache_dir):
    return cache_dir / "learned_offsets.json"


def seed_cache(cache_dir, *payloads):
    store = LearnedOffsetsStore()
    for payload in payloads:
        assert store.record(payload)
    assert store.save()


def read_cache(cache_dir):
    return json.loads(cache_file(cache_dir).read_text(encoding="utf-8"))["entries"]


def wait_for_cache_key(cache_dir, key, timeout=5.0):
    """The background saver writes asynchronously; poll until *key* lands."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cache_file(cache_dir).exists() and key in read_cache(cache_dir):
            return read_cache(cache_dir)
        time.sleep(0.01)
    raise AssertionError(f"{key} never reached the cache file")


# --- schema -----------------------------------------------------------------

def test_content_type_constant():
    assert ContentType.PLAINTEXT_API_LEARNED == "plaintext_api_learned"


def test_schema_validates_through_agent_message_union():
    msg = TypeAdapter(AgentMessage).validate_python(learned_payload())
    assert isinstance(msg, PlaintextApiLearnedMessage)
    assert msg.rvas.SSL_write == 0x2000
    assert msg.prologue_sha256.SSL_read == "1" * 64


# --- router -----------------------------------------------------------------

def test_router_forwards_to_the_sink_and_emits_no_event():
    bus, seen = _Bus(), []
    router = MessageRouter(bus)
    router.set_learned_offsets_sink(seen.append)
    router.route(learned_payload(), b"")
    assert seen == [learned_payload()]
    assert bus.events == []


def test_router_without_sink_drops_the_message():
    bus = _Bus()
    MessageRouter(bus).route(learned_payload(), b"")
    assert bus.events == []


def test_router_survives_a_failing_sink():
    def boom(_payload):
        raise OSError("disk full")

    router = MessageRouter(_Bus())
    router.set_learned_offsets_sink(boom)
    router.route(learned_payload(), b"")


def test_router_records_into_the_store(cache_dir):
    session = LearnedOffsetsSession.open()
    router = MessageRouter(_Bus())
    router.set_learned_offsets_sink(session.record)
    router.route(learned_payload(), b"")
    wait_for_cache_key(cache_dir, KEY)


# --- session ----------------------------------------------------------------

def test_open_loads_existing_entries(cache_dir):
    seed_cache(cache_dir, learned_payload())
    session = LearnedOffsetsSession.open()
    assert set(session.agent_entries()) == {KEY}


def test_disabled_by_env(cache_dir, monkeypatch):
    monkeypatch.setenv(los.LEARNED_OFFSETS_DISABLE_ENV, "1")
    assert LearnedOffsetsSession.open() is None
    monkeypatch.setenv(los.LEARNED_OFFSETS_DISABLE_ENV, "0")
    assert LearnedOffsetsSession.open() is not None


def test_record_persists_promptly_in_background(cache_dir, fritap_log_records):
    records = fritap_log_records(LOGGER)
    session = LearnedOffsetsSession.open()
    session.record(learned_payload())
    entries = wait_for_cache_key(cache_dir, KEY)
    assert entries[KEY]["rvas"] == {"SSL_read": 0x1000, "SSL_write": 0x2000}
    assert any("libcronet.so" in r.getMessage() for r in records if r.levelno == logging.INFO)


def test_invalid_report_is_not_saved(cache_dir):
    session = LearnedOffsetsSession.open()
    session.record(learned_payload(build_id="nothex"))
    assert not cache_file(cache_dir).exists()


def test_failed_save_is_retried_at_shutdown(cache_dir, monkeypatch):
    session = LearnedOffsetsSession.open()
    real_save = LearnedOffsetsStore.save
    monkeypatch.setattr(LearnedOffsetsStore, "save", lambda self: False)
    session.record(learned_payload())
    assert not cache_file(cache_dir).exists()
    monkeypatch.setattr(LearnedOffsetsStore, "save", real_save)
    session.save_if_dirty()
    assert KEY in read_cache(cache_dir)


def test_io_errors_never_raise(tmp_path, monkeypatch):
    blocker = tmp_path / "not_a_dir"
    blocker.write_text("x")
    monkeypatch.setenv("FRITAP_LEARNED_OFFSETS_DIR", str(blocker))
    monkeypatch.delenv(los.LEARNED_OFFSETS_DISABLE_ENV, raising=False)
    session = LearnedOffsetsSession.open()
    session.record(learned_payload())
    session.save_if_dirty()
    assert KEY in session.agent_entries()


def test_store_factory_errors_disable_the_cache():
    def broken():
        raise RuntimeError("no cache dir")

    assert LearnedOffsetsSession.open(store_factory=broken) is None


def test_store_exceptions_are_swallowed():
    class Exploding:
        path = "x"

        def load(self):
            return 0

        def entries_for_agent(self):
            raise RuntimeError

        def record(self, _payload):
            raise RuntimeError

        def save(self):
            raise RuntimeError

    session = LearnedOffsetsSession.open(store_factory=Exploding)
    assert session.agent_entries() == {}
    session.record(learned_payload())
    session._dirty = True
    session.save_if_dirty()


# --- SSL_Logger ---------------------------------------------------------------

def bare_logger(offsets_data=None):
    obj = SSL_Logger.__new__(SSL_Logger)
    obj.offsets_data = offsets_data
    obj.pattern_data = None
    obj.scan_results_data = None
    obj._config = FriTapConfig.from_legacy_params(app="com.example.app")
    obj._message_router = MessageRouter(_Bus())
    return obj


def test_config_batch_carries_all_learned_entries_despite_user_offsets(cache_dir):
    # The agent prefers --offsets per module itself, so the host must not filter.
    seed_cache(cache_dir, learned_payload(), learned_payload(module="libother.so", build_id="ef" * 20))
    logger = bare_logger(json.dumps({"libcronet.so": {"SSL_read": {"address": "0x1"}, "SSL_write": {"address": "0x2"}}}))
    logger._open_learned_offsets()
    batch = logger._build_config_batch()
    assert set(batch["learned_plaintext"]) == {KEY, make_key("ef" * 20, SIZE, "arm64")}


def test_config_batch_without_session_is_empty():
    assert bare_logger()._build_config_batch()["learned_plaintext"] == {}


def test_logger_routes_reports_into_the_cache_and_saves_on_shutdown(cache_dir, monkeypatch):
    logger = bare_logger()
    logger._open_learned_offsets()
    real_save = LearnedOffsetsStore.save
    monkeypatch.setattr(LearnedOffsetsStore, "save", lambda self: False)
    logger._emit_event_from_payload(learned_payload(), b"")
    assert not cache_file(cache_dir).exists()
    monkeypatch.setattr(LearnedOffsetsStore, "save", real_save)
    logger._save_learned_offsets()
    assert KEY in read_cache(cache_dir)


def test_session_is_opened_at_init_and_saved_after_the_consumer_drains():
    assert "self._open_learned_offsets()" in inspect.getsource(SSL_Logger.__init__)
    cleanup = inspect.getsource(SSL_Logger._run_cleanup_steps)
    # The consumer is stopped + drained inside the shutdown helper (after the
    # agent's graceful_detach RPC), which runs before the save.
    assert cleanup.index("self._shutdown_agent_and_drain()") < cleanup.index("self._save_learned_offsets()")
    shutdown = inspect.getsource(SSL_Logger._shutdown_agent_and_drain)
    assert "self._stop_consumer_thread()" in shutdown


def test_save_without_session_is_a_no_op():
    SSL_Logger.__new__(SSL_Logger)._save_learned_offsets()


# --- background saver -----------------------------------------------------------

class _GatedStore(LearnedOffsetsStore):
    """Counts saves and records which thread ran them; the first save blocks on a gate."""

    def __init__(self, path):
        super().__init__(path=path)
        self.gate = threading.Event()
        self.save_threads = []

    def save(self):
        self.save_threads.append(threading.current_thread().name)
        self.gate.wait(5)
        return super().save()


def test_record_does_no_file_io_on_the_calling_thread(tmp_path):
    store = _GatedStore(str(tmp_path / "learned_offsets.json"))
    session = LearnedOffsetsSession(store, save_debounce_s=0.0)
    session.record(learned_payload())  # returns although save() is blocked
    assert threading.current_thread().name not in store.save_threads
    store.gate.set()
    wait_for_cache_key(tmp_path, KEY)
    session.save_if_dirty()


def test_burst_of_reports_coalesces_into_few_saves(tmp_path):
    store = _GatedStore(str(tmp_path / "learned_offsets.json"))
    session = LearnedOffsetsSession(store, save_debounce_s=0.0)
    session.record(learned_payload())
    for i in range(50):
        session.record(learned_payload(build_id=f"{i:02x}" * 20))
    store.gate.set()
    session.save_if_dirty()
    assert len(store.save_threads) <= 3  # first, one coalesced follow-up, final
    assert len(read_cache(tmp_path)) == 51


def test_debounce_collapses_a_burst_into_one_background_write(tmp_path):
    store = _GatedStore(str(tmp_path / "learned_offsets.json"))
    store.gate.set()
    session = LearnedOffsetsSession(store, save_debounce_s=0.05)
    for i in range(10):
        session.record(learned_payload(build_id=f"{i:02x}" * 20))
    wait_for_cache_key(tmp_path, make_key("09" * 20, SIZE, "arm64"))
    session.save_if_dirty()
    assert store.save_threads == ["fritap-learned-offsets-saver"]


def test_shutdown_interrupts_the_debounce_and_still_saves(tmp_path):
    store = _GatedStore(str(tmp_path / "learned_offsets.json"))
    store.gate.set()
    session = LearnedOffsetsSession(store, save_debounce_s=60.0)
    session.record(learned_payload())
    assert store.save_threads == []
    started = time.monotonic()
    session.save_if_dirty()
    assert time.monotonic() - started < 1.0
    assert store.save_threads == [threading.current_thread().name]
    assert KEY in read_cache(tmp_path)
    assert not session._saver.is_alive()


def test_shutdown_save_is_synchronous_and_stops_the_saver(tmp_path):
    store = _GatedStore(str(tmp_path / "learned_offsets.json"))
    store.gate.set()
    session = LearnedOffsetsSession(store)
    session.record(learned_payload())
    session.save_if_dirty()
    assert KEY in read_cache(tmp_path)
    assert not session._saver.is_alive()
    assert session._saver.daemon


def test_cache_hit_refreshes_last_seen_without_info_log(cache_dir, fritap_log_records):
    seed_cache(cache_dir, learned_payload())
    before = read_cache(cache_dir)[KEY]["last_seen"]
    records = fritap_log_records(LOGGER)
    session = LearnedOffsetsSession.open()
    time.sleep(0.01)
    session.record(learned_payload(cache_hit=True))
    session.save_if_dirty()
    assert read_cache(cache_dir)[KEY]["last_seen"] > before
    assert not [r for r in records if r.levelno == logging.INFO]


def test_cache_hit_with_bad_key_fields_is_ignored(cache_dir):
    session = LearnedOffsetsSession.open()
    session.record(learned_payload(cache_hit=True, arch="sparc"))
    session.save_if_dirty()
    assert not cache_file(cache_dir).exists()


def test_ssl_logger_tests_never_touch_the_real_cache():
    # Guard for the autouse conftest fixture: SSL_Logger() must not read ~/.cache.
    import os
    from friTap.cache_files import fritap_cache_dir
    assert os.environ["FRITAP_LEARNED_OFFSETS_DIR"] != fritap_cache_dir()


# --- module_offsets_learned -----------------------------------------------------

def module_payload(**overrides):
    payload = {
        "contentType": "module_offsets_learned",
        "protocol": "tls",
        "module": "libcronet.so",
        "build_id": BUILD_ID,
        "size": SIZE,
        "arch": "arm64",
        "functions": {"quiche.frame.OnStreamFrame": {"rva": 0x3000, "prologue_sha256": "3" * 64}},
        "layout": {"quiche.stream_id": 0x10},
    }
    payload.update(overrides)
    return payload


def test_module_offsets_content_type_constant():
    assert ContentType.MODULE_OFFSETS_LEARNED == "module_offsets_learned"


def test_module_offsets_schema_validates_through_agent_message_union():
    msg = TypeAdapter(AgentMessage).validate_python(module_payload())
    assert isinstance(msg, ModuleOffsetsLearnedMessage)
    assert msg.functions["quiche.frame.OnStreamFrame"].rva == 0x3000
    assert msg.layout == {"quiche.stream_id": 0x10}
    bare = TypeAdapter(AgentMessage).validate_python(
        module_payload(functions=None, layout=None, cache_hit=True))
    assert bare.functions is None and bare.cache_hit is True


def test_router_forwards_module_offsets_to_the_sink():
    bus, seen = _Bus(), []
    router = MessageRouter(bus)
    router.set_learned_offsets_sink(seen.append)
    router.route(module_payload(), b"")
    assert seen == [module_payload()]
    assert bus.events == []


def test_session_records_module_offsets_beside_ssl_fields(cache_dir, fritap_log_records):
    seed_cache(cache_dir, learned_payload())
    records = fritap_log_records(LOGGER)
    session = LearnedOffsetsSession.open()
    router = MessageRouter(_Bus())
    router.set_learned_offsets_sink(session.record)
    router.route(module_payload(), b"")
    session.save_if_dirty()
    entry = read_cache(cache_dir)[KEY]
    assert entry["rvas"] == {"SSL_read": 0x1000, "SSL_write": 0x2000}
    assert entry["functions"] == module_payload()["functions"]
    assert entry["layout"] == {"quiche.stream_id": 0x10}
    info = [r.getMessage() for r in records if r.levelno == logging.INFO]
    assert any("quiche.frame.OnStreamFrame" in m and "libcronet.so" in m for m in info)


def test_session_module_offsets_cache_hit_touches(cache_dir, fritap_log_records):
    seed_cache(cache_dir, module_payload())
    before = read_cache(cache_dir)[KEY]
    records = fritap_log_records(LOGGER)
    session = LearnedOffsetsSession.open()
    time.sleep(0.01)
    session.record(module_payload(cache_hit=True, layout={"quiche.stream_id": 0x99}))
    session.save_if_dirty()
    after = read_cache(cache_dir)[KEY]
    assert after["last_seen"] > before["last_seen"]
    assert after["layout"] == {"quiche.stream_id": 0x10}  # a hit refreshes, never rewrites
    assert not [r for r in records if r.levelno == logging.INFO]


def test_config_batch_carries_functions_and_layout(cache_dir):
    seed_cache(cache_dir, learned_payload(), module_payload())
    logger = bare_logger()
    logger._open_learned_offsets()
    entry = logger._build_config_batch()["learned_plaintext"][KEY]
    assert entry == {
        "module": "libcronet.so",
        "rvas": {"SSL_read": 0x1000, "SSL_write": 0x2000},
        "prologue_sha256": {"SSL_read": "1" * 64, "SSL_write": "2" * 64},
        "functions": module_payload()["functions"],
        "layout": {"quiche.stream_id": 0x10},
    }
