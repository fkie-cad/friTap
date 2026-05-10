"""Unit tests for the LLDB callback dispatcher in agent_debugger.runner.

The dispatcher is the load-bearing piece that wires firing LLDB
breakpoints to ``ExtractionRunner.run_extraction`` + ``write_results``.
Before this fix, ``create_lldb_runner`` constructed but never used a
reader/runner pair — these tests guard against that regression.

LLDB's Python module (``lldb``) ships with the LLDB binary and is not
available in the test environment.  ``agent_debugger.runner`` itself
does not import ``lldb`` at module scope, so importing it here is fine.
The runtime adapter import inside ``_make_lldb_reader`` is bypassed by
patching that helper to return a mock reader.
"""

from unittest.mock import MagicMock

import pytest

from agent_debugger import runner
from agent_debugger.definitions.base import (
    BreakpointSpec,
    StructExtraction,
    StructField,
)


# ----------------------------------------------------------------------
# Fakes for SBFrame / SBProcess / SBTarget / SBBreakpoint{,Location}
# ----------------------------------------------------------------------


class _FakeBreakpoint:
    def __init__(self, bp_id):
        self._id = bp_id
        self._one_shot = False
        self._callback_body = None

    def GetID(self):
        return self._id

    def IsValid(self):
        return True

    def SetOneShot(self, value):
        self._one_shot = value

    def SetScriptCallbackBody(self, body):
        self._callback_body = body


class _FakeBpLocation:
    def __init__(self, bp):
        self._bp = bp

    def GetBreakpoint(self):
        return self._bp


class _FakeTarget:
    def __init__(self, return_bp_id=999):
        self._return_bp_id = return_bp_id
        self.created_addresses = []
        self.last_return_bp = None

    def BreakpointCreateByAddress(self, addr):
        self.created_addresses.append(addr)
        bp = _FakeBreakpoint(self._return_bp_id)
        self.last_return_bp = bp
        return bp


class _FakeProcess:
    def __init__(self, target):
        self._target = target

    def GetTarget(self):
        return self._target


class _FakeThread:
    def __init__(self, process):
        self._process = process

    def GetProcess(self):
        return self._process


class _FakeFrame:
    def __init__(self, target, parent_pc=0xDEADBEEF, valid_parent=True):
        self._target = target
        self._process = _FakeProcess(target)
        self._thread = _FakeThread(self._process)
        self._parent_pc = parent_pc
        self._valid_parent = valid_parent

    def GetThread(self):
        return self._thread

    def GetParentFrame(self):
        parent = MagicMock()
        parent.IsValid.return_value = self._valid_parent
        parent.GetPC.return_value = self._parent_pc
        return parent


def _bp_loc_with_id(bp_id):
    return _FakeBpLocation(_FakeBreakpoint(bp_id))


# ----------------------------------------------------------------------
# Test fixtures: clean registries + patched reader factory
# ----------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_registries():
    """Each test starts with empty dispatch registries."""
    runner._LLDB_BP_REGISTRY.clear()
    runner._LLDB_RETURN_REGISTRY.clear()
    yield
    runner._LLDB_BP_REGISTRY.clear()
    runner._LLDB_RETURN_REGISTRY.clear()


@pytest.fixture
def reader_factory_calls(monkeypatch):
    """Patch _make_lldb_reader and record (process, frame) for each call."""
    calls = []

    def _fake_factory(process, frame):
        reader = MagicMock(name="LldbMemoryReader")
        calls.append({"process": process, "frame": frame, "reader": reader})
        return reader

    monkeypatch.setattr(runner, "_make_lldb_reader", _fake_factory)
    return calls


@pytest.fixture
def target_and_frame():
    """A fake (target, frame) pair with a configurable return-bp id."""
    target = _FakeTarget()
    frame = _FakeFrame(target)
    return target, frame


def _make_field(name="key", read_type="pointer"):
    return StructField(name=name, offset=0, read_type=read_type)


def _make_extraction(base_arg="arg0"):
    return StructExtraction(base_arg=base_arg, fields=[_make_field()])


def _make_spec(
    function_name="target_fn",
    timing="on_entry",
    extractions=None,
    capture_args_on_entry=False,
):
    return BreakpointSpec(
        function_name=function_name,
        timing=timing,
        struct_extractions=extractions if extractions is not None else [],
        output_labels={"key": "KEY {hex}"},
        capture_args_on_entry=capture_args_on_entry,
    )


# ----------------------------------------------------------------------
# Tests
# ----------------------------------------------------------------------


class TestDispatchEntryPath:
    """Cases where the firing breakpoint is the entry-site breakpoint."""

    def test_logging_only_does_not_call_runner(
        self, reader_factory_calls, target_and_frame
    ):
        spec = _make_spec(extractions=[])  # no struct_extractions
        runner_mock = MagicMock()
        runner._LLDB_BP_REGISTRY[42] = (spec, runner_mock, "TEST")
        _, frame = target_and_frame

        result = runner._lldb_dispatch(frame, _bp_loc_with_id(42))

        assert result is False
        runner_mock.run_extraction.assert_not_called()
        runner_mock.write_results.assert_not_called()
        # Logging-only path also should not need to construct a reader.
        assert reader_factory_calls == []

    def test_default_path_runs_extraction_with_frame_aware_reader(
        self, reader_factory_calls, target_and_frame
    ):
        spec = _make_spec(timing="on_entry", extractions=[_make_extraction()])
        runner_mock = MagicMock()
        runner_mock.run_extraction.return_value = ["KEY abc"]
        runner._LLDB_BP_REGISTRY[7] = (spec, runner_mock, "SSH")
        target, frame = target_and_frame

        result = runner._lldb_dispatch(frame, _bp_loc_with_id(7))

        assert result is False
        # The whole point of the fix: reader is constructed *with the live
        # frame*, not with frame=None.
        assert len(reader_factory_calls) == 1
        assert reader_factory_calls[0]["frame"] is frame
        runner_mock.run_extraction.assert_called_once_with(
            reader_factory_calls[0]["reader"], spec
        )
        runner_mock.write_results.assert_called_once_with(["KEY abc"])
        # No return-site breakpoint should have been scheduled.
        assert target.created_addresses == []

    def test_unknown_bp_id_is_silent_noop(
        self, reader_factory_calls, target_and_frame
    ):
        _, frame = target_and_frame

        result = runner._lldb_dispatch(frame, _bp_loc_with_id(404))

        assert result is False
        assert reader_factory_calls == []


class TestDispatchOnReturnScheduling:
    """timing='on_return' and capture_args_on_entry both schedule a return-site bp."""

    def test_on_return_schedules_one_shot_and_defers_extraction(
        self, reader_factory_calls
    ):
        spec = _make_spec(
            timing="on_return", extractions=[_make_extraction()]
        )
        runner_mock = MagicMock()
        runner._LLDB_BP_REGISTRY[1] = (spec, runner_mock, "SSH")

        target = _FakeTarget(return_bp_id=999)
        frame = _FakeFrame(target, parent_pc=0xCAFEF00D)

        runner._lldb_dispatch(frame, _bp_loc_with_id(1))

        # No extraction at entry time — that runs at the return-site hit.
        runner_mock.run_extraction.assert_not_called()
        runner_mock.write_results.assert_not_called()

        # A return-site address breakpoint was registered, marked one-shot,
        # and given the dispatch callback body.
        assert target.created_addresses == [0xCAFEF00D]
        assert target.last_return_bp._one_shot is True
        assert "_lldb_dispatch" in target.last_return_bp._callback_body
        assert 999 in runner._LLDB_RETURN_REGISTRY
        bp_spec, bound_runner, proto, captured = (
            runner._LLDB_RETURN_REGISTRY[999]
        )
        assert bp_spec is spec
        assert bound_runner is runner_mock
        assert proto == "SSH"
        assert captured is None  # on_return without capture_args

    def test_capture_args_on_entry_captures_then_defers(self, monkeypatch):
        ext = _make_extraction(base_arg="arg2")
        spec = _make_spec(
            timing="on_entry",
            extractions=[ext],
            capture_args_on_entry=True,
        )
        runner_mock = MagicMock()
        runner._LLDB_BP_REGISTRY[5] = (spec, runner_mock, "IPSEC")

        # Pre-configure the reader so the captured value is a real int —
        # otherwise the assertion below would just compare a MagicMock to
        # itself and tell us nothing.
        captured_value = 0xDEADBEEF
        readers = []

        def _factory(process, frame):
            reader = MagicMock(name="LldbMemoryReader")
            reader.read_register.return_value = captured_value
            readers.append(reader)
            return reader

        monkeypatch.setattr(runner, "_make_lldb_reader", _factory)

        target = _FakeTarget(return_bp_id=888)
        frame = _FakeFrame(target, parent_pc=0xBEEF)

        runner._lldb_dispatch(frame, _bp_loc_with_id(5))

        assert len(readers) == 1
        readers[0].read_register.assert_called_once_with("arg2")
        runner_mock.run_extraction.assert_not_called()
        runner_mock.write_results.assert_not_called()

        assert 888 in runner._LLDB_RETURN_REGISTRY
        _, _, _, captured = runner._LLDB_RETURN_REGISTRY[888]
        assert captured == {"arg2": captured_value}

    def test_return_site_dispatch_runs_extraction_and_clears_registry(
        self, reader_factory_calls, target_and_frame
    ):
        spec = _make_spec(
            timing="on_return", extractions=[_make_extraction()]
        )
        runner_mock = MagicMock()
        runner_mock.run_extraction.return_value = ["KEY xyz"]
        captured_args = {"arg0": 0x1000}
        runner._LLDB_RETURN_REGISTRY[999] = (
            spec,
            runner_mock,
            "SSH",
            captured_args,
        )
        _, frame = target_and_frame

        result = runner._lldb_dispatch(frame, _bp_loc_with_id(999))

        assert result is False
        runner_mock.run_extraction.assert_called_once_with(
            reader_factory_calls[0]["reader"], spec, captured_args
        )
        runner_mock.write_results.assert_called_once_with(["KEY xyz"])
        # One-shot bp ids should not leak into the registry for reuse.
        assert 999 not in runner._LLDB_RETURN_REGISTRY


class TestSchedulerEdgeCases:
    """_schedule_on_return handles missing parent frame / null PC gracefully."""

    def test_no_parent_frame_logs_and_skips(self, reader_factory_calls, capsys):
        spec = _make_spec(timing="on_return", extractions=[_make_extraction()])
        runner_mock = MagicMock()
        runner._LLDB_BP_REGISTRY[1] = (spec, runner_mock, "SSH")

        # Parent frame is invalid — _schedule_on_return must abort.
        target = _FakeTarget()
        frame = _FakeFrame(target, valid_parent=False)

        runner._lldb_dispatch(frame, _bp_loc_with_id(1))

        assert target.created_addresses == []
        assert runner._LLDB_RETURN_REGISTRY == {}
        runner_mock.run_extraction.assert_not_called()
        out = capsys.readouterr().out
        assert "no parent frame" in out
