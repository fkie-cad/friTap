"""Unit tests for the Android profile capture (--profile/--discover/--also-package)."""

import argparse
import logging
from types import SimpleNamespace
from unittest import mock

import pytest

from friTap import friTap as cli
from friTap.android_discovery import profile_from_dict
from friTap.cli_config import _apply_profile_flags
from friTap.config import FriTapConfig
from friTap.legacy import profile_capture as pc
from friTap.legacy.exec_follow import ProcessTracker
from friTap.legacy.ssl_logger_core import SSL_Logger

from .test_android_discovery import GEMINI_PROFILE

TARGET = "com.google.android.apps.bard"
GSA = "com.google.android.googlequicksearchbox"
GOOGLEAPP = GSA + ":googleapp"
SHARED = "com.google.android.gms.persistent"


@pytest.fixture
def profile():
    return profile_from_dict(GEMINI_PROFILE)


def _parse(argv):
    return cli.build_capture_parser().parse_args(argv)


class TestFlags:
    def test_flags_reach_device_config(self):
        parsed = _parse(["-m", "--profile", "p.json", "--also-package", "a.b",
                         "--also-package", "c.d", TARGET])
        device = FriTapConfig.from_legacy_params(app=TARGET).device
        _apply_profile_flags(device, parsed)
        assert device.profile_path == "p.json"
        assert device.also_packages == ["a.b", "c.d"]
        assert device.profile_capture_requested

    def test_defaults_request_nothing(self):
        device = FriTapConfig.from_legacy_params(app=TARGET).device
        _apply_profile_flags(device, _parse(["-m", TARGET]))
        assert not device.profile_capture_requested and device.also_packages == []

    @pytest.mark.parametrize("argv", [
        ["--profile", "p.json", "app"],
        ["--discover", "5", "app"],
        ["--also-package", "a.b", "app"],
        ["-m", "--profile", "p.json", "--discover", "5", "app"],
        ["-m", "--discover", "0", "app"],
    ])
    def test_invalid_combinations_exit(self, argv):
        parser = cli.build_capture_parser()
        with pytest.raises(SystemExit):
            cli._validate_profile_capture_options(parser.parse_args(argv), parser)

    def test_valid_mobile_combination_passes(self):
        parser = cli.build_capture_parser()
        cli._validate_profile_capture_options(
            parser.parse_args(["-m", "--discover", "10", "--also-package", "x.y", "app"]), parser)


class TestPureHelpers:
    def test_gate_packages_merge_and_dedupe(self, profile):
        assert pc.gate_packages(profile, [GSA, "x.y"]) == [TARGET, GSA, "x.y"]
        assert pc.gate_packages(None, ["x.y"]) == ["x.y"]

    def test_force_stop_excludes_target_and_shared(self, profile):
        assert pc.packages_to_force_stop(profile, ["x.y"], TARGET) == [GSA, "x.y"]

    def test_parse_ps_and_still_running(self, profile):
        running = pc.parse_ps_names("  PID NAME\n18124 %s\n18278 other\n" % GOOGLEAPP)
        assert running == {18124: GOOGLEAPP, 18278: "other"}
        assert [c.pid for c in pc.still_running(profile.candidates, running)] == [18124]

    def test_summary_marks_shared_as_reported_only(self, profile):
        lines = pc.summary_lines(profile, [TARGET, GSA])
        assert GSA in lines[0]
        assert any(SHARED in line and "reported only" in line for line in lines)

    @pytest.mark.parametrize("active,started,children,expected", [
        (True, True, {5}, True),
        (True, True, set(), False),
        (False, True, {5}, False),
        (True, False, {5}, False),
    ])
    def test_lifetime_predicate(self, active, started, children, expected):
        assert pc.capture_continues_after_main_detach(active, started, children) is expected


def _workflow(profile, shell_output=""):
    calls = mock.Mock()
    def shell(cmd):
        calls.shell(cmd)
        return shell_output

    ssl_logger = mock.Mock(target_app=TARGET)
    ssl_logger.tracked_child_pids.return_value = set()
    calls.attach_mock(ssl_logger, "logger")
    workflow = pc.ProfileCaptureWorkflow(ssl_logger, profile, [], shell)
    return workflow, calls, ssl_logger


class TestWorkflow:
    def test_gating_enabled_before_force_stop(self, profile):
        workflow, calls, _ = _workflow(profile)
        workflow.prepare(enable_gating=calls.enable_gating)
        names = [c[0] for c in calls.mock_calls]
        gate_at = names.index("enable_gating")
        stop_at = next(i for i, c in enumerate(calls.mock_calls)
                       if c[0] == "shell" and c.args[0].startswith("am force-stop"))
        assert names.index("logger.add_spawn_packages") < gate_at < stop_at
        stops = [c.args[0] for c in calls.mock_calls
                 if c[0] == "shell" and c.args[0].startswith("am force-stop")]
        assert stops == [f"am force-stop {GSA}"]

    def test_prepare_records_roles_and_lifetime(self, profile):
        workflow, calls, ssl_logger = _workflow(profile)
        workflow.prepare(enable_gating=calls.enable_gating)
        ssl_logger.add_spawn_packages.assert_called_once_with(TARGET, GSA)
        roles = ssl_logger.set_process_roles.call_args.args[0]
        assert roles[GOOGLEAPP] == "delegate" and SHARED not in roles
        ssl_logger.keep_capture_while_children_alive.assert_called_once()

    def test_usap_pool_warns(self, profile, caplog):
        workflow, calls, _ = _workflow(profile, shell_output="true\n")
        with caplog.at_level(logging.WARNING, logger="friTap.profile_capture"):
            workflow.prepare(enable_gating=calls.enable_gating)
        assert "USAP" in caplog.text and pc.USAP_POOL_PROPERTY in caplog.text

    def test_attach_survivors_skips_shared_and_main(self, profile):
        ps = f"PID NAME\n18278 {TARGET}\n18124 {GOOGLEAPP}\n900 {SHARED}\n"
        workflow, _, ssl_logger = _workflow(profile, shell_output=ps)
        workflow.attach_survivors()
        ssl_logger.instrument_running.assert_called_once_with(18124, GOOGLEAPP, "delegate")

    def test_attach_survivors_skips_dead_and_tracked(self, profile):
        workflow, _, ssl_logger = _workflow(profile, shell_output=f"18124 {GOOGLEAPP}\n")
        ssl_logger.tracked_child_pids.return_value = {18124}
        workflow.attach_survivors()
        ssl_logger.instrument_running.assert_not_called()

    def test_for_logger_none_without_flags(self):
        ssl_logger = SimpleNamespace(mobile=True, _config=FriTapConfig.from_legacy_params(app=TARGET))
        assert pc.ProfileCaptureWorkflow.for_logger(ssl_logger) is None


def _bare_logger():
    obj = SSL_Logger.__new__(SSL_Logger)
    obj.logger = logging.getLogger("test.profile")
    obj.running = True
    obj.pid = 1
    obj._tracker = ProcessTracker()
    obj._tracker.track(1, session="main", is_main=True, gated=False)
    obj._held_exec_watchdog = mock.Mock()
    obj._finish_detach = mock.Mock()
    return obj


class TestLoggerIntegration:
    def test_instrument_running_warns_and_enqueues(self, caplog):
        obj = _bare_logger()
        obj._enqueue_instrumentation = mock.Mock()
        with caplog.at_level(logging.WARNING, logger="test.profile"):
            obj.instrument_running(42, GOOGLEAPP, "delegate")
        assert "attached late: existing connections not decryptable" in caplog.text
        obj._enqueue_instrumentation.assert_called_once_with(
            42, "running process", GOOGLEAPP, resume=False, watch_as_main=False)
        assert obj.origin_for_pid(42)["role"] == "delegate"

    def test_gated_spawn_gets_profile_role(self):
        obj = _bare_logger()
        obj.set_process_roles({GOOGLEAPP: "delegate"})
        obj._note_instrumented_origin(SimpleNamespace(pid=7, identifier=GOOGLEAPP,
                                                      label="spawned process"))
        assert obj.origin_for_pid(7)["role"] == "delegate"

    def test_main_detach_waits_for_children_then_ends(self):
        obj = _bare_logger()
        obj.keep_capture_while_children_alive()
        obj._tracker.track(7, session="child", is_main=False, gated=False)
        obj.on_detach("process-terminated-by-user")
        obj._finish_detach.assert_not_called()
        obj._on_child_detached(7, "child", "process-terminated")
        obj._finish_detach.assert_called_once_with("process-terminated-by-user", captured=True)

    def test_main_detach_without_profile_ends_at_once(self):
        obj = _bare_logger()
        obj._tracker.track(7, session="child", is_main=False, gated=False)
        obj.on_detach("process-terminated-by-user")
        obj._finish_detach.assert_called_once()

    def test_parser_has_flags(self):
        options = {o for a in cli.build_capture_parser()._actions for o in a.option_strings}
        assert {"--profile", "--discover", "--also-package"} <= options
        assert isinstance(cli.build_capture_parser(), argparse.ArgumentParser)


class TestHardening:
    @pytest.mark.parametrize("bad", ["com.x;reboot", "app", "$(id).x"])
    def test_invalid_also_package_exits(self, bad):
        parser = cli.build_capture_parser()
        with pytest.raises(SystemExit):
            cli._validate_profile_capture_options(
                parser.parse_args(["-m", "--also-package", bad, "app"]), parser)

    def test_gate_packages_drop_shared_system_packages(self):
        data = {**GEMINI_PROFILE,
                "gate_packages": [*GEMINI_PROFILE["gate_packages"], "com.google.android.gms"]}
        assert pc.gate_packages(profile_from_dict(data), []) == [TARGET, GSA]

    def test_gate_packages_keep_explicit_also_package(self, profile):
        assert "com.google.android.gms" in pc.gate_packages(profile, ["com.google.android.gms"])

    def test_force_stop_quotes_and_skips_invalid(self, caplog):
        workflow, calls, _ = _workflow(None)
        with caplog.at_level(logging.WARNING, logger="friTap.profile_capture"):
            workflow._force_stop(["com.ok.app", "com.x;reboot"])
        stops = [c.args[0] for c in calls.mock_calls if c[0] == "shell"]
        assert stops == ["am force-stop com.ok.app"]
        assert "Not force-stopping" in caplog.text

    def test_summary_escapes_untrusted_strings(self):
        shared = {"pid": 9, "process": "evil\x1b[2J", "package": "android",
                  "role": "shared_system"}
        lines = pc.summary_lines(profile_from_dict({**GEMINI_PROFILE, "candidates": [shared]}),
                                 ["a.b"])
        assert all("\x1b" not in line for line in lines)
        assert any("evil\\x1b[2J" in line for line in lines)

    def test_late_attach_warning_escapes(self, caplog):
        obj = _bare_logger()
        obj._enqueue_instrumentation = mock.Mock()
        with caplog.at_level(logging.WARNING, logger="test.profile"):
            obj.instrument_running(42, "x\x1b]0;t\x07", "role\x1b[31m")
        assert "\x1b" not in caplog.text and "\\x1b" in caplog.text


class TestDiscoveryAbort:
    def _manager(self):
        from friTap.legacy.session_manager import SessionManager
        return SessionManager(mock.Mock())

    def test_discovery_failure_exits_cleanly(self, monkeypatch):
        from friTap.android_discovery import DiscoveryFailedError
        manager = self._manager()
        manager._abort_startup = mock.Mock(side_effect=SystemExit(1))
        monkeypatch.setattr(pc.ProfileCaptureWorkflow, "for_logger",
                            mock.Mock(side_effect=DiscoveryFailedError("process discovery failed")))
        with pytest.raises(SystemExit):
            manager._profile_capture_or_abort(mock.Mock())
        message = manager._abort_startup.call_args.args[2]
        assert "Cannot use the discovery profile" in message and "discovery failed" in message
