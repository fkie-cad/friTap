"""Unit tests for the eBPF native runtime glue (no device, no kernel)."""

import json
import subprocess
import threading
from types import SimpleNamespace

import pytest

from friTap.backends import capture, ebpf_android, ebpf_native
from friTap.backends.capture import EbpfCaptureBackend, ReadinessCheck
from friTap.config import DeviceConfig

SERIAL = "emulator-5570"


# --- _read_status / preflight: malformed native records ---------------------

@pytest.mark.parametrize("record", [
    {"type": "error"},
    {"type": "error", "status": "permission_denied", "stage": "attach"},
    {"type": "error", "status": "permission_denied", "stage": "attach", "errno": "13"},
    {"type": "error", "status": "permission_denied", "stage": "attach", "errno": 10**30},
    {"type": "error", "status": None, "stage": "attach", "errno": 13},
    ["not", "a", "record"],
    None,
])
def test_malformed_native_records_are_unsupported(record):
    with pytest.raises(ebpf_native.NativeError) as error:
        ebpf_native._read_status(record)
    assert error.value.status == "unsupported"


def test_well_formed_native_error_keeps_its_status():
    record = {"type": "error", "status": "permission_denied", "stage": "attach", "errno": 1}
    with pytest.raises(ebpf_native.NativeError, match="permission_denied at attach") as error:
        ebpf_native._read_status(record)
    assert error.value.status == "permission_denied"


def test_preflight_reports_malformed_error_record(monkeypatch):
    monkeypatch.setattr(ebpf_native, "resolve_runtime", lambda: "/opt/agent")
    stdout = json.dumps({"type": "error", "status": "denied"}).encode()
    monkeypatch.setattr(subprocess, "run",
                        lambda *a, **kw: SimpleNamespace(stdout=stdout, returncode=1))
    with pytest.raises(ebpf_native.NativeError) as error:
        ebpf_native.preflight("1234")
    assert error.value.status == "unsupported"


def test_remote_runtime_commands_run_in_their_own_session(monkeypatch):
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs.get("start_new_session")))
        if argv[-1] == "--version":
            return SimpleNamespace(stdout=ebpf_native._ABI.encode(), stderr=b"", returncode=0)
        return SimpleNamespace(stdout=json.dumps({"type": "ready", "build_id": "b", "kernel": "6"}).encode(),
                               returncode=0)

    monkeypatch.setattr(subprocess, "run", run)
    assert ebpf_native.preflight("1234", serial=SERIAL)["build_id"] == "b"
    assert [isolated for _, isolated in calls] == [True, True]
    assert calls[0][0][:3] == ["adb", "-s", SERIAL]


# --- shared native binary lookup -------------------------------------------

def _fake_layout(monkeypatch, tmp_path):
    scripts = tmp_path / "bin"
    scripts.mkdir()
    monkeypatch.setattr(ebpf_native, "__file__", str(tmp_path / "friTap" / "backends" / "ebpf_native.py"))
    monkeypatch.setattr(ebpf_native.sysconfig, "get_path", lambda name: str(scripts))
    return scripts


def _executable(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch()
    path.chmod(0o700)
    return path


def test_native_binary_prefers_scripts_dir(monkeypatch, tmp_path):
    scripts = _fake_layout(monkeypatch, tmp_path)
    installed = _executable(scripts / "tool")
    _executable(tmp_path / "dev" / "build" / "tool")
    assert ebpf_native._find_native_binary("tool", "dev/build") == installed.resolve()


def test_native_binary_falls_back_to_build_dir_and_skips_non_executables(monkeypatch, tmp_path):
    scripts = _fake_layout(monkeypatch, tmp_path)
    (scripts / "tool").touch()  # not executable
    built = _executable(tmp_path / "dev" / "build" / "tool")
    assert ebpf_native._find_native_binary("tool", "dev/build") == built
    assert ebpf_native._find_native_binary("missing", "dev/build") is None


def test_kernel_helper_lookup_uses_dev_build_dir(monkeypatch, tmp_path):
    _fake_layout(monkeypatch, tmp_path)
    helper = _executable(tmp_path / "dev" / "ebpf" / "build" / "fritap-ebpf-check-kernel")
    assert EbpfCaptureBackend._find_kernel_helper() == str(helper)


# --- EbpfCaptureProducer.stop ------------------------------------------------

class FakeStdin:
    def __init__(self, broken=False):
        self.broken = broken
        self.written = b""
        self.closed = False

    def write(self, data):
        if self.broken:
            raise BrokenPipeError
        self.written += data

    def flush(self):
        pass

    def close(self):
        self.closed = True


class FakeProcess:
    def __init__(self, *, exits=True, stdin=None):
        self.exits = exits
        self.stdin = stdin
        self.returncode = None
        self.terminated = self.killed = False
        self.pid = 4242

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        if self.exits:
            self.returncode = 0

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self, timeout=None):
        return self.returncode


def _producer(process, reader=None, serial=None):
    producer = ebpf_native.EbpfCaptureProducer("1234", serial=serial)
    producer._process = process
    producer._reader = reader
    return producer


def _reader_until(event):
    thread = threading.Thread(target=event.wait, daemon=True)
    thread.start()
    return thread


@pytest.fixture(autouse=True)
def no_real_process_group_kill(monkeypatch):
    """FakeProcess pids are not ours: never let kill_adb_child os.killpg them."""
    def kill(process, wait_seconds):
        process.kill()
        return True

    monkeypatch.setattr(ebpf_native, "kill_adb_child", kill)


@pytest.fixture
def short_joins(monkeypatch):
    monkeypatch.setattr(ebpf_native, "_READER_JOIN_SECONDS", 0.05)
    monkeypatch.setattr(ebpf_native, "_READER_DRAIN_SECONDS", 0.3)


def test_stop_waits_for_a_slow_reader_drain(monkeypatch, short_joins):
    release = threading.Event()
    reader = _reader_until(release)
    threading.Timer(0.1, release.set).start()  # after the first join, inside the drain bound
    process = FakeProcess()
    _producer(process, reader).stop()
    assert process.terminated and not reader.is_alive()


def test_stop_raises_when_the_reader_never_drains(short_joins):
    release = threading.Event()
    process = FakeProcess()
    try:
        with pytest.raises(ebpf_native.NativeError, match="incomplete") as error:
            _producer(process, _reader_until(release)).stop()
        assert error.value.status == "unsupported"
    finally:
        release.set()


def test_stop_kills_a_runtime_that_ignores_terminate(short_joins):
    process = FakeProcess(exits=False)
    with pytest.raises(RuntimeError, match="did not stop cleanly"):
        _producer(process).stop()
    assert process.killed


def test_remote_stop_sends_drain_request_and_closes_stdin(short_joins):
    stdin = FakeStdin()
    process = FakeProcess(stdin=stdin)
    process.returncode = None

    def drained(data):
        FakeStdin.write(stdin, data)
        process.returncode = 0

    stdin.write = drained
    _producer(process, serial=SERIAL).stop()
    assert stdin.written == b"stop\n" and stdin.closed and not process.terminated


def test_remote_stop_tolerates_broken_pipe(short_joins):
    stdin = FakeStdin(broken=True)
    process = FakeProcess(stdin=stdin)
    process.returncode = 0  # already gone: no write, still closed
    _producer(process, serial=SERIAL).stop()
    assert stdin.closed

    stdin = FakeStdin(broken=True)
    process = FakeProcess(stdin=stdin)
    with pytest.raises(RuntimeError):  # pipe broke and the adb child never exited
        _producer(process, serial=SERIAL).stop()
    assert stdin.closed


def test_remote_stop_kills_the_adb_session(monkeypatch, short_joins):
    killed = []
    monkeypatch.setattr(ebpf_native, "kill_adb_child",
                        lambda process, wait_seconds: killed.append(process) or True)
    process = FakeProcess(stdin=FakeStdin())
    with pytest.raises(RuntimeError):
        _producer(process, serial=SERIAL).stop()
    assert killed == [process]


def test_stop_from_the_reader_thread_does_not_join_itself(short_joins):
    process = FakeProcess()
    producer = _producer(process)
    errors = []

    def call_stop():
        try:
            producer.stop()
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    reader = threading.Thread(target=call_stop)
    producer._reader = reader
    reader.start()
    reader.join(2)
    assert not reader.is_alive() and errors == []


def test_stop_without_process_is_a_noop():
    ebpf_native.EbpfCaptureProducer("1234").stop()


def test_remote_capture_uses_isolated_adb_popen(monkeypatch):
    seen = {}

    def popen(argv, **kwargs):
        seen.update(kwargs, argv=argv)
        raise OSError("no adb")

    monkeypatch.setattr(ebpf_native, "_runtime_command", lambda serial: ["adb", "-s", serial, "shell"])
    monkeypatch.setattr(subprocess, "Popen", popen)
    with pytest.raises(ebpf_native.NativeError):
        ebpf_native.EbpfCaptureProducer("1234", serial=SERIAL).start(None, None)
    assert seen["start_new_session"] is True
    assert seen["argv"][-2:] == ["capture-remote", "1234"]
    assert seen["stdin"] == subprocess.PIPE


# --- ebpf_android ------------------------------------------------------------

def test_probe_is_built_from_the_config_keys():
    names = "BPF_SYSCALL|ARCH_SUPPORTS_UPROBES|UPROBES|UPROBE_EVENTS|DEBUG_INFO_BTF"
    assert (f"grep -E '^(CONFIG_({names})=|# CONFIG_({names}) is not set)'"
            in ebpf_android._PROBE)


def test_kernel_checks_return_readiness_checks(monkeypatch):
    output = "6.6.30\nCONFIG_BPF_SYSCALL=y\n# CONFIG_DEBUG_INFO_BTF is not set\nkernel_btf=present\n"
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: SimpleNamespace(stdout=output))
    checks = ebpf_android.kernel_checks(SERIAL)
    assert all(isinstance(check, ReadinessCheck) for check in checks)
    by_name = {check.name: check for check in checks}
    assert by_name["kernel_version"] == ReadinessCheck("kernel_version", "observed", "6.6.30")
    assert by_name["CONFIG_BPF_SYSCALL"].detail == "enabled"
    assert by_name["CONFIG_DEBUG_INFO_BTF"].detail == "disabled"
    assert by_name["CONFIG_UPROBES"] == ReadinessCheck("CONFIG_UPROBES", "unknown", "unconfirmed")
    assert by_name["uprobe_events"].detail == "not visible to ADB shell"


# --- capture.py: Android readiness over adb get-state ------------------------

def _adb_responses(monkeypatch, responses):
    def run(argv, **kwargs):
        response = responses[tuple(argv[1:])]
        if isinstance(response, BaseException):
            raise response
        stdout, stderr, code = response
        return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=code)

    monkeypatch.setattr(subprocess, "run", run)


@pytest.mark.parametrize(("state", "detail"), [
    (("", f"error: device '{SERIAL}' not found\n", 1), "ADB device state: missing"),
    (("", "error: device unauthorized.\nThis adb server's $ADB_VENDOR_KEYS\n", 1),
     "ADB device state: unauthorized"),
    (("", "error: device offline\n", 1), "ADB device state: offline"),
    (("recovery\n", "", 0), "ADB device state: recovery"),
])
def test_android_readiness_maps_adb_states(monkeypatch, state, detail):
    _adb_responses(monkeypatch, {("-s", SERIAL, "get-state"): state})
    report = EbpfCaptureBackend().readiness(DeviceConfig(mobile=SERIAL))
    assert (report.target, report.status, report.detail) == (SERIAL, "setup_required", detail)


@pytest.mark.parametrize(("serialno", "detail"), [
    (("", "error: no devices/emulators found\n", 1), "No Android ADB device found"),
    (("", "error: more than one device/emulator\n", 1), "Select an Android ADB serial"),
])
def test_android_readiness_without_serial_needs_exactly_one_device(monkeypatch, serialno, detail):
    _adb_responses(monkeypatch, {("get-serialno",): serialno})
    report = EbpfCaptureBackend().readiness(DeviceConfig(mobile=True))
    assert (report.target, report.status, report.detail) == ("Android", "setup_required", detail)


def test_android_readiness_selects_the_only_device(monkeypatch):
    _adb_responses(monkeypatch, {
        ("get-serialno",): (f"{SERIAL}\n", "", 0),
        ("-s", SERIAL, "get-state"): ("device\n", "", 0),
        ("-s", SERIAL, "shell", "getprop", "ro.build.version.sdk"): ("35\n", "", 0),
        ("-s", SERIAL, "shell", "uname", "-rm"): ("6.6.30 aarch64\n", "", 0),
    })
    report = EbpfCaptureBackend().readiness(DeviceConfig(mobile=True))
    assert (report.target, report.status, report.target_os) == (SERIAL, "unknown", "android")
    assert report.detail.startswith("Android API 35, kernel 6.6.30 aarch64.")


@pytest.mark.parametrize(("failure", "status", "detail"), [
    (FileNotFoundError(), "setup_required", "Install Android platform-tools (adb)"),
    (subprocess.TimeoutExpired("adb", 5), "unknown", "ADB readiness check timed out"),
    (("", "error: protocol fault\n", 1), "unknown", "ADB readiness check failed"),
])
def test_android_readiness_reports_adb_failures(monkeypatch, failure, status, detail):
    _adb_responses(monkeypatch, {("-s", SERIAL, "get-state"): failure})
    report = EbpfCaptureBackend().readiness(DeviceConfig(mobile=SERIAL))
    assert report.status == status and report.detail.startswith(detail)


def test_android_readiness_rejects_non_android_targets(monkeypatch):
    _adb_responses(monkeypatch, {
        ("-s", SERIAL, "get-state"): ("device\n", "", 0),
        ("-s", SERIAL, "shell", "getprop", "ro.build.version.sdk"): ("\n", "", 0),
    })
    report = EbpfCaptureBackend().readiness(DeviceConfig(mobile=SERIAL))
    assert (report.status, report.detail) == ("unsupported", "ADB target did not identify as Android")


# --- capture.py: diagnose helpers --------------------------------------------

@pytest.mark.parametrize(("statuses", "expected"), [
    (("verified", "verified"), "kernel_verified"),
    (("verified", "denied"), "permission_denied"),
    (("unsupported", "unsupported"), "unsupported"),
    (("setup_required",), "setup_required"),
    (("verified", "unknown"), "fallback"),
])
def test_status_from_checks(statuses, expected):
    checks = tuple(ReadinessCheck("probe", status, "") for status in statuses)
    assert EbpfCaptureBackend._status_from_checks(checks, "fallback") == expected


def test_android_diagnose_appends_kernel_checks_then_bpftool(monkeypatch):
    kernel = (ReadinessCheck("kernel_version", "observed", "6.6.30"),)
    monkeypatch.setattr(EbpfCaptureBackend, "readiness", lambda self, device: capture.CaptureReadiness(
        "ebpf", SERIAL, "unknown", "Android", False, (), "android"))
    monkeypatch.setattr(ebpf_android, "kernel_checks", lambda serial: kernel)
    commands = []
    probe = ReadinessCheck("bpf_syscall", "observed", "bpftool detected the BPF syscall")
    monkeypatch.setattr(EbpfCaptureBackend, "_probe_kernel",
                        staticmethod(lambda command: commands.append(command) or probe))
    report = EbpfCaptureBackend().diagnose(DeviceConfig(mobile=SERIAL))
    assert report.checks == (*kernel, probe)
    assert report.status == "unknown"
    assert commands == [["adb", "-s", SERIAL, "shell", "bpftool"]]


def test_android_target_diagnose_reports_kernel_gate(monkeypatch):
    monkeypatch.setattr(EbpfCaptureBackend, "readiness", lambda self, device: capture.CaptureReadiness(
        "ebpf", SERIAL, "unknown", "Android", False, (), "android"))

    def gate(serial):
        raise ebpf_native.NativeError("unsupported", "below 5.4")

    monkeypatch.setattr(ebpf_android, "kernel_checks", gate)
    report = EbpfCaptureBackend().diagnose(DeviceConfig(mobile=SERIAL), target="1234")
    assert (report.target, report.status, report.detail) == ("1234", "unsupported", "below 5.4")


def test_explicit_helper_must_be_absolute(monkeypatch):
    monkeypatch.setattr(capture.platform, "system", lambda: "Linux")
    with pytest.raises(capture.BackendInvalidArgumentError, match="absolute"):
        EbpfCaptureBackend().diagnose(DeviceConfig(), kernel_helper="relative/helper")


def test_discovered_helper_that_cannot_run_falls_back_to_bpftool(monkeypatch):
    monkeypatch.setattr(capture.platform, "system", lambda: "Linux")
    monkeypatch.setattr(EbpfCaptureBackend, "_find_kernel_helper", staticmethod(lambda: "/opt/helper"))
    monkeypatch.setattr(EbpfCaptureBackend, "_probe_helper", staticmethod(
        lambda command: (ReadinessCheck("kernel_helper", "setup_required", "x"),)))
    probe = ReadinessCheck("bpf_syscall", "unknown", "bpftool timed out")
    monkeypatch.setattr(EbpfCaptureBackend, "_probe_kernel", staticmethod(lambda command: probe))
    report = EbpfCaptureBackend().diagnose(DeviceConfig())
    assert report.checks[-1] == probe and report.status == "unknown"


def test_require_capture_was_removed():
    assert not hasattr(capture.CaptureBackend, "require_capture")
