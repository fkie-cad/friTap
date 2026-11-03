#!/usr/bin/env python3
"""Deadlock-faithful tests for the multi-script startup handshake (friTap discussion #65).

What is being modelled
----------------------
friTap's agent does **not** finish its top-level code on its own. Twice during
``script.load()`` it parks the JS thread in ``recv(<channel>).wait()`` and waits
for the host to answer:

    stage ``config-handshake``  ->  agent sends the bare string ``'config_batch'``
                                    and blocks until the host posts ``config_batch``
    stage ``anti-handshake``    ->  agent sends the bare string ``'anti'``
                                    and blocks until the host posts ``antiroot``

Only after the second reply lands does the agent's top-level return, and only
then does ``script.load()`` return on the host side. So ``load()`` is a *blocking
rendezvous with two round trips*, driven from Frida's message callback thread
while the instrumenting thread sits inside ``load()``.

Why a MagicMock cannot catch this class of bug
----------------------------------------------
The pre-existing coverage (``test_gated_instrumentation.py`` and friends) stubs
the backend with ``MagicMock``. ``MagicMock.load_script(...)`` returns instantly
and unconditionally, so *not answering the handshake at all* is indistinguishable
from answering it correctly: the mock asserts only the **shape** of calls
(``post_message`` was called with ``'config_batch'``), never that the agent was
actually unblocked, never *which* script the reply reached, and never that a
second script's rendezvous also completed. The regression this file pins —
``self.startup`` being a one-shot flag that the terminal ``anti`` reply cleared,
plus replying on ``self.script`` after ``instrument()`` had already overwritten
it — is invisible to a call-shape assertion but hangs the second script forever
in the real world. That is exactly what broke ``--enable_child_gating`` /
``--enable_spawn_gating`` (fkie-cad/friTap discussion #65).

So the fake backend here reproduces frida's *blocking* semantics:
``FakeScript.load()` does not return until both handshake round trips have been
observed on **that** script object. A regression therefore shows up as the wait
expiring, and every wait is bounded (``timed_out`` flag + short timeouts) so the
failure mode is a fast assertion failure and never a hung CI job.

Code under test (not stubbed): ``SSL_Logger._internal_callback_wrapper``,
``SSL_Logger._answer_startup_handshake``, ``SSL_Logger._build_config_batch``,
plus the real ``instrument()`` / gated-instrumentation worker.

Following ``tests/unit/test_crash_attribution.py``, the logger is built with
``SSL_Logger.__new__`` and only the attributes these paths touch: no device, no
session, no Android, no real Frida.
"""

import logging
import queue
import threading
import types

from friTap.config import OutputConfig
from friTap.legacy.ssl_logger_core import SSL_Logger

# Every wait in this file is bounded. HANDSHAKE_WAIT is the "healthy" bound:
# the reply is posted synchronously from inside the handler call, so a passing
# run never waits at all, which leaves 2 s as a very generous margin on a loaded
# CI box while keeping a regression's failure fast. FAST_WAIT is used by the
# pre-fix proof, which *expects* to time out and must do so quickly.
HANDSHAKE_WAIT = 2.0
FAST_WAIT = 0.5

FAKE_DEVICE = "FAKE-DEVICE"


# ----------------------------------------------------------------------
# Faithful fake frida: load() blocks until the handshake is answered
# ----------------------------------------------------------------------

class FakeScript:
    """A frida ``Script`` whose ``load()`` blocks on the startup handshake.

    ``load()`` starts a driver thread that plays the agent's side of the
    rendezvous — it sends ``'config_batch'``, waits for the matching reply, then
    sends ``'anti'`` and waits for ``'antiroot'`` — and only returns once the
    driver reports both round trips complete. The driver stands in for Frida's
    message callback thread; ``load()``'s caller stands in for the thread inside
    ``script.load()``.
    """

    # (request the agent sends, reply message type it blocks on)
    HANDSHAKE = (('config_batch', 'config_batch'), ('anti', 'antiroot'))

    def __init__(self, name, wait=HANDSHAKE_WAIT):
        self.name = name
        self._wait = wait
        self.handler = None
        # Replies observed on *this* script, in arrival order.
        self.replies = []
        self.requests_sent = []
        self._reply_events = {
            reply: threading.Event() for _, reply in self.HANDSHAKE
        }
        self.handshake_complete = threading.Event()
        self.load_returned = threading.Event()
        self.timed_out = False
        # Optional {request: callable} hooks fired just before the agent sends
        # that request — used to simulate host-side state moving on mid-load.
        self.before_request = {}

    # -- host side -----------------------------------------------------
    def record_reply(self, msg_type, payload):
        """Called by the backend when the host posts a message to this script."""
        self.replies.append(msg_type)
        event = self._reply_events.get(msg_type)
        if event is not None:
            event.set()

    def answered(self):
        """The handshake reply types that actually reached this script."""
        return {msg_type for msg_type, event in self._reply_events.items()
                if event.is_set()}

    # -- agent side ----------------------------------------------------
    def load(self, timeout=None):
        """Block until the handshake completes (or the bound expires)."""
        driver = threading.Thread(target=self._drive_handshake, daemon=True,
                                  name=f"fake-frida-callback-{self.name}")
        driver.start()
        if not self.handshake_complete.wait(self._wait):
            # Real frida would leave the caller wedged here forever; we bound it
            # and report it so the assertion (not the test runner) fails.
            self.timed_out = True
        self.load_returned.set()

    def _drive_handshake(self):
        """Play the agent's blocking ``recv().wait()`` sequence."""
        for request, reply in self.HANDSHAKE:
            hook = self.before_request.get(request)
            if hook is not None:
                hook()
            self.requests_sent.append(request)
            handler = self.handler
            if handler is None:
                self.timed_out = True
                return
            # Deliver the bare-string request exactly as frida does.
            handler({'type': 'send', 'payload': request}, None)
            if not self._reply_events[reply].wait(self._wait):
                # The agent is still parked in recv().wait() — this is the
                # deadlock the fix exists to prevent.
                self.timed_out = True
                return
        self.handshake_complete.set()


class FakeProcess:
    """Stand-in for a frida ``Session`` handle."""

    def __init__(self, pid):
        self.pid = pid


class FakeBackend:
    """Only the backend surface ``SSL_Logger.instrument()`` actually calls."""

    def __init__(self, wait=HANDSHAKE_WAIT):
        self._wait = wait
        self.scripts = []
        # Global post log as (script, msg_type, payload) — proves *which*
        # script each reply was routed to.
        self.posts = []
        self.resumed = []
        self.attached = []

    @property
    def name(self):
        return "fake"

    def version_at_least(self, major, minor=0):
        return True

    def enable_debugger(self, target, port):
        pass

    def attach(self, device, target):
        self.attached.append((device, target))
        return FakeProcess(int(target))

    def resume(self, device, pid):
        self.resumed.append(pid)

    def create_script(self, process, script_source, runtime="qjs"):
        script = FakeScript(f"script{len(self.scripts) + 1}", wait=self._wait)
        self.scripts.append(script)
        return script

    def on_message(self, script, callback):
        script.handler = callback

    def load_script(self, script, *, timeout=None):
        script.load(timeout=timeout)

    def post_message(self, script, msg_type, payload):
        self.posts.append((script, msg_type, payload))
        script.record_reply(msg_type, payload)

    # -- helpers for assertions ---------------------------------------
    def posts_for(self, script):
        return [msg_type for target, msg_type, _ in self.posts if target is script]


# ----------------------------------------------------------------------
# Logger construction (pattern from test_crash_attribution.py)
# ----------------------------------------------------------------------

def _make_logger(backend):
    """A bare ``SSL_Logger`` with exactly what the handshake path touches.

    The read-only properties (``debug``, ``anti_root``, ``pcap_name``, ...) are
    backed by a ``SimpleNamespace`` config, which also has to satisfy
    ``_build_config_batch()`` and ``effective_script_load_timeout()``.
    ``_internal_callback_wrapper`` / ``_answer_startup_handshake`` /
    ``_build_config_batch`` are deliberately left real — they are the code under
    test.
    """
    obj = SSL_Logger.__new__(SSL_Logger)
    obj.logger = logging.getLogger("test.multi_script_handshake")
    obj.logger.setLevel(logging.DEBUG)

    obj._backend = backend
    obj.device = FAKE_DEVICE
    obj.script = None
    obj.own_message_handler = None
    obj.running = True
    obj.startup = True
    obj.agent_script = "fritap_agent.js"

    # Message plumbing: the queue must stay EMPTY — handshake payloads are
    # answered synchronously on the callback thread and never enqueued.
    obj._message_queue = queue.Queue(maxsize=10000)
    obj._queue_drop_count = 0
    obj._consumer_stop = threading.Event()
    obj._consumer_thread = None  # never started on purpose (see test 4)

    # Gated-instrumentation worker machinery (real queue/lock/event).
    obj._instrument_queue = queue.Queue(maxsize=16)
    obj._instrument_stop = threading.Event()
    obj._instrument_thread = None
    obj._instrument_thread_lock = threading.Lock()
    obj._suspended_pids = set()
    obj._suspended_pids_lock = threading.Lock()

    obj.offsets_data = None
    obj.pattern_data = None
    obj.scan_results_data = None
    obj._observer = None
    obj._last_hook_breadcrumb = ""
    obj._handlers_active = True

    obj._event_bus = types.SimpleNamespace(emit=lambda *a, **k: None)

    obj._config = types.SimpleNamespace(
        target="com.example.app",
        target_argv=None,
        protocol="tls",
        debug=False,
        debug_output=False,
        install_lsass_hook=False,
        device=types.SimpleNamespace(
            spawn=False,
            device_id="TESTSERIAL",
            mobile=True,
            enable_child_gating=True,
            enable_spawn_gating=False,
            spawn_gating_all=False,
            # Bounded, but far above the fake handshake cost.
            script_load_timeout=10,
        ),
        output=OutputConfig(
            pcap="out.pcap",
            keylog=True,
            full_capture=False,
            socket_trace=False,
            verbose=False,
            live=False,
            json_output=None,
        ),
        hooking=types.SimpleNamespace(
            anti_root=False,
            enable_default_fd=False,
            experimental=False,
            library_scan=False,
            ohttp_enabled=True,
            quic_capture_mode="stream",
            quic_only=False,
            no_loader_hook=False,
            stealth_loader=False,
            pairip_safe=False,
            quic_egress_headers_layer="auto",
            scan_keys_region=None,
            patterns=None,
            offsets=None,
            payload_modification=False,
        ),
    )

    # Cheap stubs for everything instrument() reaches that is not under test.
    obj.get_agent_script = lambda: "// fake agent bundle"
    obj._check_agent_abi = lambda: None
    return obj


def _assert_handshake_ok(script, backend):
    """Both round trips completed, on this very script, within the bound."""
    assert not script.timed_out, (
        f"{script.name}: startup handshake never completed — the agent would "
        f"still be parked in recv().wait(). Replies seen: {script.replies}"
    )
    assert script.handshake_complete.is_set(), f"{script.name}: handshake incomplete"
    assert script.load_returned.is_set(), f"{script.name}: load() never returned"
    assert script.answered() == {'config_batch', 'antiroot'}, (
        f"{script.name}: answered {script.answered()}"
    )
    assert backend.posts_for(script) == ['config_batch', 'antiroot'], (
        f"{script.name}: replies routed elsewhere, got {backend.posts_for(script)}"
    )


# ----------------------------------------------------------------------
# 1 + 2: sequential instrument() calls must all complete
# ----------------------------------------------------------------------

def test_two_sequential_instruments_both_complete_handshake():
    """The second script must not hang: nothing about the reply is one-shot."""
    backend = FakeBackend()
    obj = _make_logger(backend)

    first = obj.instrument(FakeProcess(100), None)
    second = obj.instrument(FakeProcess(200), None)

    assert first is not second
    assert backend.scripts == [first, second]
    _assert_handshake_ok(first, backend)
    _assert_handshake_ok(second, backend)

    # Each reply landed on the asking script, never on the first one.
    for target, msg_type, _ in backend.posts:
        assert target in (first, second)
    assert [t is first for t, _, _ in backend.posts[:2]] == [True, True]
    assert [t is second for t, _, _ in backend.posts[2:]] == [True, True]
    # self.script has moved on, but the first script was still served.
    assert obj.script is second


def test_third_instrument_also_completes_handshake():
    """Pins that the responder is not one-shot, two-shot, or session-scoped."""
    backend = FakeBackend()
    obj = _make_logger(backend)

    scripts = [obj.instrument(FakeProcess(100 + i), None) for i in range(3)]

    assert len(set(id(s) for s in scripts)) == 3
    for script in scripts:
        _assert_handshake_ok(script, backend)


def test_reply_targets_asking_script_after_self_script_moved_on():
    """A reply must follow the *asking* script, not ``self.script``.

    Models the real overlap: a gated child arrives while the parent is still
    parked between ``config_batch`` and ``anti``, so ``instrument()`` has already
    overwritten ``self.script``. The pre-fix code posted on ``self.script`` and
    left the parent blocked forever.
    """
    backend = FakeBackend()
    obj = _make_logger(backend)
    usurper = FakeScript("usurper")

    def hijack_self_script():
        obj.script = usurper

    original_create = backend.create_script

    def create_with_hook(process, source, runtime="qjs"):
        script = original_create(process, source, runtime=runtime)
        script.before_request['anti'] = hijack_self_script
        return script

    backend.create_script = create_with_hook

    script = obj.instrument(FakeProcess(100), None)

    assert obj.script is usurper, "hook did not fire — test would be vacuous"
    _assert_handshake_ok(script, backend)
    assert backend.posts_for(usurper) == [], "reply leaked onto the wrong script"


# ----------------------------------------------------------------------
# 3: the gated-child path end to end
# ----------------------------------------------------------------------

def test_gated_child_completes_handshake_and_is_resumed():
    """``on_child_added`` -> worker -> attach -> load -> resume, for real."""
    backend = FakeBackend()
    obj = _make_logger(backend)

    parent = obj.instrument(FakeProcess(100), None)
    _assert_handshake_ok(parent, backend)

    child = types.SimpleNamespace(pid=4242, identifier="com.example.app:child")
    try:
        obj.on_child_added(child)

        # The worker creates the child's script asynchronously; wait for it.
        deadline = threading.Event()
        child_script = None
        for _ in range(int(HANDSHAKE_WAIT / 0.05)):
            if len(backend.scripts) > 1:
                child_script = backend.scripts[1]
                break
            deadline.wait(0.05)
        assert child_script is not None, "child was never instrumented"

        assert child_script.load_returned.wait(HANDSHAKE_WAIT), (
            "child script.load() never returned — the gated child is wedged in "
            "the startup handshake"
        )
        _assert_handshake_ok(child_script, backend)

        # ...and the suspended child was resumed, so no watchdog kill.
        for _ in range(int(HANDSHAKE_WAIT / 0.05)):
            if 4242 in backend.resumed:
                break
            deadline.wait(0.05)
        assert 4242 in backend.resumed, "gated child left suspended"
        assert backend.attached == [(FAKE_DEVICE, "4242")]
    finally:
        obj._stop_instrument_thread()


# ----------------------------------------------------------------------
# 4: the reply must not depend on the message-consumer thread
# ----------------------------------------------------------------------

def test_handshake_answered_without_consumer_thread():
    """No ``_start_consumer_thread``, yet both loads still complete.

    An empty ``_message_queue`` afterwards proves the handshake payloads were
    answered synchronously on the callback thread and never enqueued — routing
    them through the queue is what deadlocked whenever the thread inside
    ``load()`` was the very thread that drains it.
    """
    backend = FakeBackend()
    obj = _make_logger(backend)
    assert obj._consumer_thread is None

    first = obj.instrument(FakeProcess(100), None)
    second = obj.instrument(FakeProcess(200), None)

    _assert_handshake_ok(first, backend)
    _assert_handshake_ok(second, backend)
    assert obj._consumer_thread is None, "test must not start the consumer thread"
    assert obj._message_queue.empty(), (
        "handshake payloads were enqueued instead of answered synchronously; "
        "queue depth = " + str(obj._message_queue.qsize())
    )
    assert obj._queue_drop_count == 0


# ----------------------------------------------------------------------
# 5: pre-fix regression proof — the OLD logic must fail this rig
# ----------------------------------------------------------------------

def _old_answer_startup_handshake(obj):
    """Faithful re-implementation of the PRE-FIX responder.

    Reconstructed from ``git show HEAD:friTap/legacy/ssl_logger_core.py`` and
    ``git show HEAD:friTap/legacy/message_handler.py``:

    * ``ssl_logger_core.py:967``  — ``if self.startup and isinstance(payload, str):``
      the one-shot gate around the whole handshake.
    * ``ssl_logger_core.py:968``  — ``if payload == 'config_batch':``
    * ``ssl_logger_core.py:1028`` — ``self._backend.post_message(self.script,
      'config_batch', batch)`` — replies on ``self.script``, not on the asking
      script.
    * ``ssl_logger_core.py:1030-1031`` — falls through to
      ``handle_startup_legacy(self, payload)``.
    * ``message_handler.py:70-72`` — ``elif payload == 'anti':`` posts
      ``antiroot`` on ``logger_instance.script`` and then sets
      ``logger_instance.startup = False``, closing the gate for every later
      script.

    Both defects are reproduced: the one-shot ``startup`` gate and replying on
    ``self.script`` instead of the asking script.
    """
    def old_answer(payload, script, answered=None):
        if not isinstance(payload, str):
            return False
        # ssl_logger_core.py:967 — one-shot gate.
        if not obj.startup:
            return False
        if payload == 'config_batch':
            # ssl_logger_core.py:1028 — reply on self.script.
            obj._backend.post_message(obj.script, 'config_batch',
                                      obj._build_config_batch())
            if answered is not None:
                answered.add(payload)
            return True
        if payload == 'anti':
            # message_handler.py:70-72
            obj._backend.post_message(obj.script, 'antiroot', obj.anti_root)
            obj.startup = False
            if answered is not None:
                answered.add(payload)
            return True
        return False

    return old_answer


def test_pre_fix_logic_hangs_the_second_script():
    """The old responder must fail this rig — that is why the fix matters.

    With the pre-fix logic the first script still completes (the gate is open
    and ``self.script`` happens to be right), but the terminal ``anti`` reply
    clears ``self.startup``, so the second script's ``config_batch`` request is
    never answered and its ``load()`` never returns. Bounds are ``FAST_WAIT`` so
    the expected deadlock is observed in well under two seconds.
    """
    backend = FakeBackend(wait=FAST_WAIT)
    obj = _make_logger(backend)
    obj._answer_startup_handshake = _old_answer_startup_handshake(obj)

    first = obj.instrument(FakeProcess(100), None)
    # Sanity: the OLD code did work for the very first script, otherwise this
    # test would "pass" for the wrong reason.
    assert not first.timed_out, "pre-fix rig broken: even script 1 failed"
    assert first.answered() == {'config_batch', 'antiroot'}
    assert obj.startup is False, "the old anti reply must clear the one-shot gate"

    second = obj.instrument(FakeProcess(200), None)

    # THE BUG: the second script is stuck in recv('config_batch').wait().
    assert second.timed_out, (
        "pre-fix logic unexpectedly answered the second script — the rig is no "
        "longer able to observe the deadlock this test exists to prove"
    )
    assert second.answered() == set(), (
        f"second script should have received nothing, got {second.answered()}"
    )
    assert backend.posts_for(second) == []
    assert not second.handshake_complete.is_set()
    # It never even reached the 'anti' stage: it blocked on the first request.
    assert second.requests_sent == ['config_batch']


def test_current_logic_passes_the_same_rig():
    """Same rig, same short bounds, real responder: no deadlock.

    Paired with ``test_pre_fix_logic_hangs_the_second_script`` this is the
    before/after: identical fake backend and identical ``FAST_WAIT`` bounds, so
    the only difference is which ``_answer_startup_handshake`` runs.
    """
    backend = FakeBackend(wait=FAST_WAIT)
    obj = _make_logger(backend)

    first = obj.instrument(FakeProcess(100), None)
    second = obj.instrument(FakeProcess(200), None)

    _assert_handshake_ok(first, backend)
    _assert_handshake_ok(second, backend)
    # The fix keeps answering after startup was cleared by the first 'anti'.
    assert obj.startup is False
