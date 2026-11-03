#!/usr/bin/env python3
"""Unit tests pinning the *per-script* startup-handshake contract.

Bug class under test (friTap discussion #65)
--------------------------------------------
The agent's top level blocks in ``recv(<name>).wait()` inside ``script.load()``
until the host posts the matching reply. An unanswered request is therefore not
a dropped message but an **unbounded hang**: ``load()`` never returns and the
whole session stalls.

Two ways that used to happen:

1. *One-shot gating.* ``self.startup`` was cleared by the terminal ``'anti'``
   reply, so the second script (spawn-gated child, second target, re-attach)
   asked for ``config_batch``/``anti`` and was never answered.
2. *Wrong reply target.* ``instrument()`` overwrites ``self.script``, so a reply
   for the parent's in-flight handshake landed on a freshly created child
   script, leaving the parent blocked forever.

On top of that, the reply must never travel through ``self._message_queue``:
the thread waiting on ``load()`` can be the very thread that drains that queue
(deadlock), and a full queue would drop the reply outright. So the responder is
invoked synchronously on Frida's callback thread and its payload is never
enqueued.

These tests build a bare ``SSL_Logger`` via ``__new__`` (no device, no
``__init__``) in the style of ``tests/unit/test_crash_attribution.py``.
"""

import logging
import queue
import threading
import types
from unittest.mock import MagicMock

from friTap.config import OutputConfig
from friTap.legacy.ssl_logger_core import SSL_Logger


def _make_logger(startup=True, queue_maxsize=0, anti_root=True):
    """A bare SSL_Logger with only what the handshake path touches.

    Most of ``_build_config_batch`` reads through ``getattr(..., default)``, so a
    single permissive ``SimpleNamespace`` config covers it plus the read-only
    properties (``socket_trace``, ``keylog``, ``anti_root``, ...).
    """
    obj = SSL_Logger.__new__(SSL_Logger)
    obj.logger = logging.getLogger("test.startup_handshake")
    obj._backend = MagicMock()
    obj.script = MagicMock(name="self.script")
    obj.startup = startup
    obj._message_queue = queue.Queue(maxsize=queue_maxsize)
    obj._queue_drop_count = 0
    # Plain attributes read by _build_config_batch / handle_startup_legacy.
    obj.offsets_data = None
    obj.pattern_data = None
    obj.scan_results_data = None
    obj.use_modern = False
    obj._config = types.SimpleNamespace(
        protocol="",
        install_lsass_hook=False,
        debug_output=False,
        hooking=types.SimpleNamespace(
            anti_root=anti_root, experimental=True, enable_default_fd=False,
            library_scan=False, scan_keys_region=None,
        ),
        output=OutputConfig(
            socket_trace=False, keylog=True, pcap=None, full_capture=False,
        ),
        device=types.SimpleNamespace(spawn=True),
    )
    return obj


def _targets(backend):
    """The script each ``post_message`` reply was addressed to."""
    return [call.args[0] for call in backend.post_message.call_args_list]


def _types(backend):
    return [call.args[1] for call in backend.post_message.call_args_list]


def test_second_script_config_batch_is_answered():
    """The old one-shot ``startup`` flag hung every script after the first."""
    obj = _make_logger()
    script_a = MagicMock(name="script_a")
    script_b = MagicMock(name="script_b")

    assert obj._answer_startup_handshake('config_batch', script_a) is True
    assert obj._answer_startup_handshake('config_batch', script_b) is True

    assert _targets(obj._backend) == [script_a, script_b]
    assert _types(obj._backend) == ['config_batch', 'config_batch']


def test_second_script_anti_is_answered():
    obj = _make_logger()
    script_a = MagicMock(name="script_a")
    script_b = MagicMock(name="script_b")

    assert obj._answer_startup_handshake('anti', script_a) is True
    # The first 'anti' clears self.startup; the second script must still be
    # answered or its script.load() never returns.
    assert obj._answer_startup_handshake('anti', script_b) is True

    assert _targets(obj._backend) == [script_a, script_b]
    assert _types(obj._backend) == ['antiroot', 'antiroot']


def test_startup_false_does_not_suppress_blocking_channels():
    obj = _make_logger(startup=False)
    script = MagicMock(name="script")

    assert obj._answer_startup_handshake('config_batch', script) is True
    assert obj._answer_startup_handshake('anti', script) is True

    assert _types(obj._backend) == ['config_batch', 'antiroot']


def test_reply_goes_to_asking_script_not_self_script():
    """``instrument()`` moves ``self.script`` on; the reply must not follow it."""
    obj = _make_logger()
    asking_script = MagicMock(name="asking_script")
    assert asking_script is not obj.script

    assert obj._answer_startup_handshake('config_batch', asking_script) is True

    assert _targets(obj._backend) == [asking_script]
    assert obj.script not in _targets(obj._backend)


def test_legacy_per_field_channel_still_gated_by_startup():
    obj = _make_logger(startup=True)
    script = MagicMock(name="script")

    assert obj._answer_startup_handshake('experimental', script) is True
    assert _types(obj._backend) == ['experimental']

    obj._backend.reset_mock()
    obj.startup = False
    assert obj._answer_startup_handshake('experimental', script) is False
    obj._backend.post_message.assert_not_called()


def test_anti_clears_startup():
    obj = _make_logger(startup=True)
    assert obj._answer_startup_handshake('anti', MagicMock()) is True
    assert obj.startup is False


def test_handshake_reply_is_not_enqueued():
    obj = _make_logger()
    script = MagicMock(name="script")
    handler = obj._internal_callback_wrapper(script)

    handler({'type': 'send', 'payload': 'config_batch'}, None)

    assert obj._message_queue.empty()
    assert _targets(obj._backend) == [script]

    # Contrast: a normal (dict) payload is enqueued and never answered.
    handler({'type': 'send', 'payload': {'contentType': 'console'}}, b'x')
    assert obj._message_queue.qsize() == 1
    assert obj._backend.post_message.call_count == 1


def test_handshake_answered_even_when_queue_is_full():
    obj = _make_logger(queue_maxsize=1)
    obj._message_queue.put_nowait(('filler', None))
    script = MagicMock(name="script")

    obj._internal_callback_wrapper(script)({'type': 'send', 'payload': 'anti'}, None)

    assert _types(obj._backend) == ['antiroot']
    # The handshake never touched the queue, so nothing was dropped.
    assert obj._queue_drop_count == 0
    assert obj._message_queue.qsize() == 1


def test_handshake_answered_without_consumer_thread():
    """The reply must not depend on ``_start_consumer_thread`` running.

    No consumer is started here on purpose: if the reply were ever routed
    through ``_message_queue`` it would never be posted. The ``wait(2)`` is a
    bound, not a synchronisation point — the reply is already posted by the time
    ``wrapped_handler`` returns, so a regression fails in ~2s instead of
    hanging until the pytest timeout.
    """
    obj = _make_logger()
    posted = threading.Event()
    obj._backend.post_message.side_effect = lambda *a, **k: posted.set()
    threads_before = threading.active_count()

    obj._internal_callback_wrapper(MagicMock())({'type': 'send', 'payload': 'config_batch'}, None)

    assert posted.wait(2) is True
    assert threading.active_count() == threads_before


def test_afm_job_script_is_the_reply_target():
    """AndroidFridaManager forwards straight into ``on_fritap_message``."""
    obj = _make_logger()
    job_script = MagicMock(name="job.script")
    job = types.SimpleNamespace(script=job_script)

    obj.on_fritap_message(job, {'type': 'send', 'payload': 'config_batch'}, None)

    assert _targets(obj._backend) == [job_script]


def test_non_str_and_unknown_payloads_are_not_answered():
    obj = _make_logger()
    script = MagicMock(name="script")

    # Non-str payloads are never handshake requests, in any startup state.
    assert obj._answer_startup_handshake({'contentType': 'console'}, script) is False
    assert obj._answer_startup_handshake(None, script) is False
    assert obj._answer_startup_handshake(b'config_batch', script) is False

    # An unknown string is never claimed, in either startup state. Claiming it
    # while startup is open would be the same unbounded hang from a different
    # door: the caller stops routing the payload, yet nothing was ever posted,
    # so an agent blocked on that name waits in recv().wait() forever.
    assert obj.startup is True
    assert obj._answer_startup_handshake('not_a_handshake_request', script) is False

    obj.startup = False
    assert obj._answer_startup_handshake('not_a_handshake_request', script) is False

    obj._backend.post_message.assert_not_called()


def test_raising_post_message_does_not_escape_wrapped_handler():
    obj = _make_logger()
    obj._backend.post_message.side_effect = RuntimeError("script is destroyed")

    # Must not propagate onto Frida's callback thread, and must not enqueue.
    obj._internal_callback_wrapper(MagicMock())({'type': 'send', 'payload': 'config_batch'}, None)

    assert obj._message_queue.empty()
    assert obj._queue_drop_count == 0
