import subprocess
import sys
from types import SimpleNamespace

import pytest

from friTap.backends.capture import select_capture_backend
from friTap.config import DeviceConfig


@pytest.mark.parametrize("entrypoint", [
    "from friTap import FriTap; FriTap('target').backend('ebpf').start()",
    "from friTap.friTap import cli; sys.argv = ['fritap', '--backend', 'ebpf', 'target']; cli()",
])
def test_explicit_ebpf_never_imports_frida(entrypoint):
    script = """
import os
import sys

class BlockFrida:
    def find_spec(self, fullname, *args):
        if fullname.split('.')[0].lower() in ('frida', 'androidfridamanager'):
            os._exit(97)

sys.meta_path.insert(0, BlockFrida())
try:
    exec(sys.argv[1])
except Exception as exc:
    print(exc, file=sys.stderr)
    raise SystemExit(1)
"""
    result = subprocess.run([sys.executable, "-c", script, entrypoint],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 1
    assert "eBPF" in result.stderr


def test_android_readiness_checks_the_selected_device(monkeypatch):
    responses = {
        ("get-serialno",): ("", "error: more than one device/emulator\n", 1),
        ("-s", "second", "get-state"): ("device\n", "", 0),
        ("-s", "second", "shell", "getprop", "ro.build.version.sdk"): ("35\n", "", 0),
        ("-s", "second", "shell", "uname", "-rm"): ("6.1 aarch64\n", "", 0),
    }

    def run(argv, **kwargs):
        assert kwargs.get("start_new_session") is True  # run_adb: Ctrl+C isolation
        stdout, stderr, code = responses[tuple(argv[1:])]
        return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=code)

    monkeypatch.setattr(subprocess, "run", run)
    backend = select_capture_backend("ebpf")
    report = backend.readiness(DeviceConfig(mobile=True))
    assert report.status == "setup_required"
    assert report.detail == "Select an Android ADB serial"
    report = backend.readiness(DeviceConfig(mobile="second"))
    assert report.target == "second"
    assert report.status == "unknown"
    assert not report.capture_supported


def test_agent_capture_preserves_explicit_backend(tmp_path):
    from friTap.agent_api.capture.runner import CaptureRequest, build_argv

    request = CaptureRequest("target", tmp_path, backend="ebpf", device="serial")
    argv = build_argv(request, ["fritap"])
    assert argv[1:5] == ["--backend", "ebpf", "-m", "serial"]


class FixtureProducer:
    def __init__(self, *, fail=False):
        self.fail = fail
        self.stops = 0

    def start(self, emit, finished):
        self.finished = finished
        emit({"contentType": "keylog", "keylog": "CLIENT_RANDOM fixture fixture"}, None)
        emit({"contentType": "keylog", "keylog": "CLIENT_RANDOM fixture fixture"}, None)
        if self.fail:
            raise RuntimeError("startup failed")

    def stop(self):
        self.stops += 1


def test_producers_share_keylog_processing_and_finalize(tmp_path, monkeypatch):
    from friTap.config import FriTapConfig
    from friTap.core import CoreController
    from friTap.sinks.keylog import KeylogFileSink

    monkeypatch.setattr("friTap.core.get_backend", lambda name: SimpleNamespace(name=name))
    outputs = []
    for backend in ("frida", "ebpf"):
        path = tmp_path / backend
        producer = FixtureProducer()
        session = CoreController().create_session(
            FriTapConfig(target="fixture", backend=backend), producer=producer,
        )
        session.register_sink(KeylogFileSink(str(path)))
        session.start()
        assert session.is_running
        producer.finished(None)
        session.stop()
        assert session.wait_timeout(0)
        assert producer.stops == 1
        outputs.append(path.read_text())
    assert outputs == ["CLIENT_RANDOM fixture fixture\n"] * 2


def test_partial_producer_startup_finalizes_once():
    from friTap.config import FriTapConfig
    from friTap.core import CoreController

    producer = FixtureProducer(fail=True)
    session = CoreController().create_session(
        FriTapConfig(target="fixture", backend="ebpf"), producer=producer,
    )
    with pytest.raises(RuntimeError, match="startup failed"):
        session.start()
    session.stop()
    assert session.wait_timeout(0)
    assert not session.is_running
    assert producer.stops == 1


def test_producer_disconnect_during_startup_never_announces_running():
    from friTap.config import FriTapConfig
    from friTap.core import CoreController
    from friTap.session import CaptureLifecycleEvent

    class DisconnectingProducer(FixtureProducer):
        def start(self, emit, finished):
            finished(ConnectionError("device disconnected"))

    producer = DisconnectingProducer()
    session = CoreController().create_session(
        FriTapConfig(target="fixture", backend="ebpf"), producer=producer,
    )
    events = []
    session.lifecycle_bus.subscribe(CaptureLifecycleEvent, lambda event: events.append(event.event_type))
    session.start()
    assert events == ["stopped"]
    assert isinstance(session.failure, ConnectionError)
    assert session.wait_timeout(0)
    assert producer.stops == 1


@pytest.mark.parametrize(("failure", "status"), [
    (FileNotFoundError(), "setup_required"),
    (subprocess.TimeoutExpired("bpftool", 5), "unknown"),
])
def test_kernel_diagnostic_reports_tool_failures(monkeypatch, failure, status):
    def run(*args, **kwargs):
        raise failure

    monkeypatch.setattr("friTap.backends.capture.platform.system", lambda: "Linux")
    monkeypatch.setattr(subprocess, "run", run)
    report = select_capture_backend("ebpf").diagnose(DeviceConfig())
    assert report.checks[-1].status == status
    assert not report.capture_supported


def test_stop_from_started_callback_finalizes_after_announcement():
    from friTap.config import FriTapConfig
    from friTap.core import CoreController
    from friTap.session import CaptureLifecycleEvent

    producer = FixtureProducer()
    session = CoreController().create_session(
        FriTapConfig(target="fixture", backend="ebpf"), producer=producer,
    )
    events = []

    def stop_on_start(event):
        if event.event_type == "started":
            session.stop()

    session.lifecycle_bus.subscribe(CaptureLifecycleEvent, stop_on_start, priority=10)
    session.lifecycle_bus.subscribe(CaptureLifecycleEvent, lambda event: events.append(event.event_type))
    session.start()
    assert events == ["started", "stopped"]
    assert session.wait_timeout(0)
    assert producer.stops == 1


def test_producer_and_frida_router_have_payload_and_tap_parity(tmp_path, monkeypatch):
    from friTap import FriTap, ssl_logger
    from friTap.config import FriTapConfig
    from friTap.core import CoreController
    from friTap.events import DatalogEvent, EventBus
    from friTap.flow.tap_reader import TapReader
    from friTap.message_router import MessageRouter
    from friTap.output.tap_handler import TapOutputHandler

    record = {
        "contentType": "datalog", "function": "SSL_write", "ssl_session_id": "fixture",
        "src_addr": "192.0.2.1", "dst_addr": "198.51.100.2",
        "src_port": 12345, "dst_port": 443, "ss_family": "AF_INET",
    }
    payload = b"GET /fixture HTTP/1.1\r\nHost: example.test\r\n\r\n"

    class PayloadProducer(FixtureProducer):
        def start(self, emit, finished):
            emit({}, b"malformed")
            emit(record, payload)

    frida_tap = tmp_path / "frida.tap"
    class FridaFixtureLogger:
        def __init__(self, config):
            self._event_bus = EventBus()
            self.handler = TapOutputHandler(config.output.tap_output, target=config.target)
            self.running = False

        def start_fritap_session(self):
            self.handler.setup(self._event_bus)
            MessageRouter(self._event_bus, active_protocol=["tls"]).route(record, payload)
            self.running = True

        def stop_fritap_session(self):
            self.handler.close()
            self.running = False

    monkeypatch.setattr(ssl_logger, "SSL_Logger", FridaFixtureLogger)
    frida_events = []
    frida_session = FriTap("fixture").tap(str(frida_tap)).on_data(frida_events.append).start()
    assert frida_session.is_running
    frida_session.stop()
    frida_session.stop()
    assert not frida_session.is_running

    producer_tap = tmp_path / "producer.tap"
    config = FriTapConfig(target="fixture", backend="ebpf")
    config.output.tap_output = str(producer_tap)
    session = CoreController().create_session(config, producer=PayloadProducer())
    producer_events = []
    session.lifecycle_bus.subscribe(DatalogEvent, producer_events.append)
    session.start()
    session.stop()

    assert [(event.direction, event.data) for event in producer_events] == [
        (event.direction, event.data) for event in frida_events
    ] == [("write", payload)]
    for path in (frida_tap, producer_tap):
        with TapReader(str(path)) as reader:
            flows = reader.read_flow_summaries()
            assert len(flows) == 1
            assert [chunk.data for chunk in reader.read_flow(flows[0].flow_id).chunks] == [payload]


def test_native_kernel_helper_classifies_success_and_denial(monkeypatch):
    from friTap.backends.capture import EbpfCaptureBackend

    def run(command, **kwargs):
        assert command == ["/tmp/check-kernel"]
        assert kwargs["timeout"] == 5
        return SimpleNamespace(stdout='{"map_errno":0,"program_errno":13}')

    monkeypatch.setattr(subprocess, "run", run)
    checks = EbpfCaptureBackend._probe_helper(["/tmp/check-kernel"])
    assert [(check.name, check.status) for check in checks] == [
        ("bpf_map_create", "verified"), ("bpf_socket_filter_load", "denied")
    ]


@pytest.mark.parametrize("allow_keys", [False, True])
def test_producer_json_uses_existing_key_material_opt_in(tmp_path, allow_keys):
    import json

    from friTap.config import FriTapConfig
    from friTap.core import CoreController

    class KeyProducer(FixtureProducer):
        def start(self, emit, finished):
            emit({"contentType": "keylog", "keylog": f"CLIENT_RANDOM {'a' * 64} {'b' * 96}"}, None)

    output = tmp_path / "capture.jsonl"
    config = FriTapConfig(target="fixture", backend="ebpf")
    config.output.json_output = str(output)
    config.output.json_keys = allow_keys
    capture = CoreController().create_session(config, producer=KeyProducer())
    capture.start()
    capture.stop()

    records = [json.loads(line) for line in output.read_text().splitlines()]
    keys = [record for record in records if record.get("event_type") == "KeylogEvent"]
    assert len(keys) == 1
    assert ("b" * 96 in json.dumps(keys[0])) is allow_keys


def test_producer_reports_dropped_records():
    from friTap.config import FriTapConfig
    from friTap.core import CoreController
    from friTap.events import ErrorEvent

    class LossyProducer(FixtureProducer):
        def start(self, emit, finished):
            emit({"contentType": "capture_loss", "count": 7}, None)

    session = CoreController().create_session(
        FriTapConfig(target="fixture", backend="ebpf"), producer=LossyProducer(),
    )
    events = []
    session.lifecycle_bus.subscribe(ErrorEvent, events.append)
    session.start()
    session.stop()
    assert session.dropped_records == 7
    assert [event.error for event in events] == ["capture_loss"]


def test_core_readiness_never_initializes_default_backend(monkeypatch):
    from friTap.core import CoreController

    def unexpected(*args, **kwargs):
        pytest.fail("readiness consulted the default script backend")

    monkeypatch.setattr("friTap.core.get_backend", unexpected)
    monkeypatch.setattr("friTap.backends.capture.platform.system", lambda: "Linux")
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: SimpleNamespace(
        stdout='{"map_errno":0,"program_errno":0}',
    ))
    report = CoreController().capture_readiness(
        "ebpf", DeviceConfig(), diagnostic=True, kernel_helper="/tmp/check-kernel",
    )
    assert report.status == "kernel_verified"
    assert not report.capture_supported


def test_native_runtime_reports_missing_and_incompatible(monkeypatch, tmp_path):
    from friTap.backends import ebpf_native

    scripts = tmp_path / "bin"
    scripts.mkdir()
    (scripts / "fritap-ebpf-agent").touch()
    module = tmp_path / "friTap" / "backends" / "ebpf_native.py"
    monkeypatch.setattr(ebpf_native, "__file__", str(module))
    monkeypatch.setattr(ebpf_native.sysconfig, "get_path", lambda name: str(scripts))
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: SimpleNamespace(stdout=b"fritap-ebpf/0\n"))

    with pytest.raises(ebpf_native.NativeError) as error:
        ebpf_native.resolve_runtime()

    assert error.value.status == "setup_required"
    detail = str(error.value)
    assert f"{scripts}/fritap-ebpf-agent (incompatible runtime ABI)" in detail
    assert f"{tmp_path}/agent_ebpf/build/fritap-ebpf-agent (missing)" in detail
    assert "make -C agent_ebpf" in detail


def test_target_free_linux_readiness_discovers_kernel_helper(monkeypatch, tmp_path):
    from friTap.backends import capture, ebpf_native

    monkeypatch.setattr(capture.platform, "system", lambda: "Linux")
    monkeypatch.setattr(ebpf_native.sysconfig, "get_path", lambda name: str(tmp_path))
    helper = tmp_path / "fritap-ebpf-check-kernel"
    helper.touch()
    helper.chmod(0o700)
    commands = []

    def run(command, **kwargs):
        commands.append(command)
        return SimpleNamespace(stdout='{"map_errno":0,"program_errno":0}')

    monkeypatch.setattr(subprocess, "run", run)
    backend = select_capture_backend("ebpf")
    assert backend.diagnose(DeviceConfig()).status == "kernel_verified"
    assert commands == [[str(helper)]]


# --- CLI: --backend-readiness and the eBPF capture driver --------------------

import json  # noqa: E402
import signal  # noqa: E402
import threading  # noqa: E402

from friTap import friTap as fritap_cli  # noqa: E402
from friTap.backends import BackendInvalidArgumentError  # noqa: E402
from friTap.backends.capture import CaptureReadiness  # noqa: E402
from friTap.cli_config import build_capture_config  # noqa: E402
from friTap.output import stdout_stream  # noqa: E402


@pytest.fixture
def cli_args(monkeypatch):
    """Parse argv the way cli() does; returns ``(parser, parsed)``."""
    def parse(*argv):
        monkeypatch.setattr(sys, "argv", ["fritap", *argv])
        return fritap_cli._parse_capture_args()
    return parse


def _run_readiness(monkeypatch, *argv):
    monkeypatch.setattr(sys, "argv", ["fritap", *argv])
    fritap_cli.cli()


def test_readiness_cli_delegates_to_core_with_a_diagnostic(monkeypatch, capsys):
    calls = []

    def readiness(self, backend, device, **kwargs):
        calls.append((backend, device, kwargs))
        return CaptureReadiness(backend=backend, target="local", status="ready", detail="", capture_supported=True)

    monkeypatch.setattr("friTap.core.CoreController.capture_readiness", readiness)
    _run_readiness(monkeypatch, "--backend", "ebpf", "--backend-readiness", "1234")

    backend, _device, kwargs = calls[0]
    assert backend == "ebpf"
    assert kwargs == {"diagnostic": True, "kernel_helper": None, "target": "1234"}
    assert json.loads(capsys.readouterr().out)["status"] == "ready"


def test_readiness_cli_keeps_its_message_for_unsupported_backends(monkeypatch, capsys):
    def readiness(self, backend, device, **kwargs):
        raise ValueError(f"Readiness is unavailable for backend {backend!r}")

    monkeypatch.setattr("friTap.core.CoreController.capture_readiness", readiness)
    with pytest.raises(SystemExit) as exited:
        _run_readiness(monkeypatch, "--backend-readiness")
    assert exited.value.code == 2
    assert "Readiness is available for Frida and eBPF" in "".join(capsys.readouterr())


def test_readiness_cli_reports_invalid_arguments_as_usage_errors(monkeypatch, capsys):
    def readiness(self, backend, device, **kwargs):
        raise BackendInvalidArgumentError("eBPF attach requires one positive numeric PID")

    monkeypatch.setattr("friTap.core.CoreController.capture_readiness", readiness)
    with pytest.raises(SystemExit) as exited:
        _run_readiness(monkeypatch, "--backend", "ebpf", "--backend-readiness", "app")
    assert exited.value.code == 2
    assert "one positive numeric PID" in "".join(capsys.readouterr())


def test_build_capture_config_sets_the_tap_output(cli_args):
    _parser, parsed = cli_args("--tap", "out.tap", "1234")
    assert build_capture_config(parsed, install_lsass_hook=False).output.tap_output == "out.tap"


class _FakeEbpfSession:
    """A Session stand-in: ends when stop() runs, or when told to."""

    def __init__(self, *, ends_on_its_own=False, failure=None):
        self.config = SimpleNamespace(target="1234")
        self.failure = failure
        self.stops = 0
        self._done = threading.Event()
        if ends_on_its_own:
            self._done.set()

    is_running = True

    def start(self):
        pass

    def stop(self):
        self.stops += 1
        self._done.set()

    def wait(self):
        self._done.wait(5)

    def wait_timeout(self, timeout):
        return self._done.wait(timeout)


@pytest.fixture
def ebpf_driver(monkeypatch):
    """Patch the eBPF driver's collaborators; returns the recorded calls."""
    recorded = SimpleNamespace(logging=[], session=_FakeEbpfSession())
    logger = fritap_cli.logging.getLogger("test.ebpf")
    monkeypatch.setattr(fritap_cli, "_configure_console_logging",
                        lambda parsed: recorded.logging.append("console") or (logger, logger))
    monkeypatch.setattr(fritap_cli, "_prime_debug_log_if_requested",
                        lambda parsed, lg: recorded.logging.append("debug-log"))
    monkeypatch.setattr(fritap_cli, "_create_ebpf_session", lambda parsed, parser: recorded.session)
    stdout_stream._reset_for_tests()
    yield recorded
    stdout_stream._reset_for_tests()


def test_ebpf_driver_configures_logging_before_the_capture(ebpf_driver, cli_args):
    ebpf_driver.session = _FakeEbpfSession(ends_on_its_own=True)
    parser, parsed = cli_args("--backend", "ebpf", "--debug", "1234")
    fritap_cli._run_ebpf_capture(parsed, parser)
    assert ebpf_driver.logging == ["console", "debug-log"]


def test_ebpf_driver_stops_the_session_after_the_duration(ebpf_driver, cli_args):
    parser, parsed = cli_args("--backend", "ebpf", "--duration", "0.05", "1234")
    fritap_cli._run_ebpf_capture(parsed, parser)
    assert ebpf_driver.session.stops >= 1
    assert stdout_stream._noted_end_reason == stdout_stream.ENDED_BY_DURATION


def test_ebpf_driver_signal_stops_the_session_and_restores_handlers(ebpf_driver, cli_args):
    before = signal.getsignal(signal.SIGINT)
    parser, parsed = cli_args("--backend", "ebpf", "1234")
    threading.Timer(0.05, lambda: signal.raise_signal(signal.SIGINT)).start()
    fritap_cli._run_ebpf_capture(parsed, parser)
    assert ebpf_driver.session.stops >= 1
    assert stdout_stream._noted_end_reason is None
    assert signal.getsignal(signal.SIGINT) is before


def test_ebpf_driver_maps_a_session_failure_to_a_runtime_error(ebpf_driver, cli_args, capsys):
    ebpf_driver.session = _FakeEbpfSession(ends_on_its_own=True, failure=RuntimeError("probe lost"))
    parser, parsed = cli_args("--backend", "ebpf", "1234")
    with pytest.raises(SystemExit) as exited:
        fritap_cli._run_ebpf_capture(parsed, parser)
    assert exited.value.code == fritap_cli.EXIT_RUNTIME_ERROR
    assert "probe lost" in capsys.readouterr().err


def test_ebpf_wait_without_duration_uses_bounded_slices():
    from friTap import friTap as fritap_cli

    class _Session:
        def __init__(self):
            self.timeouts = []

        def wait_timeout(self, timeout):
            self.timeouts.append(timeout)
            return len(self.timeouts) >= 3

    session = _Session()
    fritap_cli._wait_for_ebpf_session(session, None, None, None)
    assert session.timeouts == [fritap_cli._EBPF_WAIT_SLICE_SECONDS] * 3
