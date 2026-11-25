"""A gated process instrumented BEFORE the main target exists stays a child.

Profile mode with spawn (``--profile -s``) enables spawn gating and
force-stops the delegates before the main target is spawned. A delegate that
respawned in that window (e.g. GSA ``:googleapp``) was gated while
``self.process`` and ``self.script`` were still None, so the "first script is
the main one" inference made the delegate's agent ``self.script``; the main
target's agent then overwrote it. The delegate's events lost their origin
(``pid: None``) and teardown never unloaded its agent. Callers now say
whether a process is the main target (``instrument(..., is_main=...)``).
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock

from friTap.legacy.ssl_logger_core import SSL_Logger, _InstrumentRequest

DELEGATE_PID = 23412
DELEGATE_NAME = "com.google.android.googlequicksearchbox:googleapp"


def _make_logger(scripts):
    """A real SSL_Logger, before the main target is spawned, handing out *scripts* in order."""
    obj = SSL_Logger("com.example.app", spawn=True, enable_spawn_gating=True, mobile=True)
    obj.logger = logging.getLogger("test.gated_before_main")
    obj._backend = MagicMock()
    obj._backend.create_script.side_effect = list(scripts)
    obj.device = MagicMock(name="device")
    obj.process = None
    obj.get_agent_script = lambda: "// agent"
    obj._warn_on_stale_agent_bundle = lambda _source: None
    obj._load_script_bounded = lambda _script: None
    obj._check_agent_abi = MagicMock()
    obj._build_script_context = lambda *_a: None
    obj.wait_for_agent_ready = lambda *_a: None
    return obj


def _instrument_gated_delegate(obj, session):
    """Drive the spawn-gating path exactly as on_spawn_added queues it."""
    obj._backend.attach.return_value = session
    obj._instrument_gated_process(_InstrumentRequest(
        pid=DELEGATE_PID, label="spawned process", identifier=DELEGATE_NAME,
        watch_as_main=False))


def test_gated_delegate_before_main_spawn_is_a_child_agent():
    delegate = MagicMock(name="delegate-script")
    obj = _make_logger([delegate])
    obj.set_process_roles({DELEGATE_NAME: "delegate"})
    delegate_session = MagicMock(name="delegate-session")

    _instrument_gated_delegate(obj, delegate_session)

    assert obj.script is None
    assert obj.process is None
    [child] = obj._child_agents
    assert (child.pid, child.session, child.script) == (DELEGATE_PID, delegate_session, delegate)
    assert obj._origin_for_script(delegate) == {
        "pid": DELEGATE_PID, "process": DELEGATE_NAME, "role": "delegate"}
    assert DELEGATE_PID in obj.tracked_child_pids()
    obj._check_agent_abi.assert_not_called()  # the main agent only


def test_main_target_spawned_after_the_delegate_becomes_the_main_script():
    delegate, main = MagicMock(name="delegate-script"), MagicMock(name="main-script")
    obj = _make_logger([delegate, main])
    obj.set_process_roles({DELEGATE_NAME: "delegate"})
    _instrument_gated_delegate(obj, MagicMock(name="delegate-session"))

    main_session = MagicMock(name="main-session")
    assert obj.start_fritap_session_instrumentation(None, main_session) is main

    assert obj.script is main
    assert obj.process is main_session
    assert [c.script for c in obj._child_agents] == [delegate]
    assert obj._origin_for_script(main)["role"] == SSL_Logger.MAIN_ORIGIN_ROLE
    assert obj._origin_for_script(delegate)["pid"] == DELEGATE_PID
    obj._check_agent_abi.assert_called_once_with()


def test_explicit_is_main_false_overrides_the_no_script_yet_inference():
    child = MagicMock(name="child-script")
    obj = _make_logger([child])

    obj.instrument(MagicMock(name="session"), None, is_main=False)

    assert obj.script is None
    assert [c.script for c in obj._child_agents] == [child]


def test_explicit_is_main_true_sets_the_main_script():
    main = MagicMock(name="main-script")
    obj = _make_logger([main])

    obj.instrument(MagicMock(name="session"), None, is_main=True)

    assert obj.script is main
    assert obj._child_agents == []


def test_without_is_main_the_first_process_is_still_inferred_main():
    """Backward compatible: API callers and the Wine watcher pass no is_main."""
    first, second = MagicMock(name="first"), MagicMock(name="second")
    obj = _make_logger([first, second])

    obj.instrument(MagicMock(name="a"), None)
    obj.instrument(MagicMock(name="b"), None)

    assert obj.script is first
    assert [c.script for c in obj._child_agents] == [second]


def test_without_is_main_the_main_session_is_inferred_main():
    main, child = MagicMock(name="main"), MagicMock(name="child")
    obj = _make_logger([child, main])
    obj.process = MagicMock(name="main-session")

    obj.instrument(MagicMock(name="other-session"), None)
    obj.instrument(obj.process, None)

    assert obj.script is main
    assert [c.script for c in obj._child_agents] == [child]


def test_resolve_is_main_prefers_the_explicit_value():
    obj = _make_logger([])
    obj.process = session = MagicMock(name="main-session")

    assert obj._resolve_is_main(session, False) is False
    assert obj._resolve_is_main(MagicMock(), True) is True
    assert obj._resolve_is_main(session, None) is True
