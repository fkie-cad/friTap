"""Owned OpenSSL loopback capture on an explicitly selected Android device."""

import json
import os
import re
import select
import shlex
import subprocess
import sys
import threading
import time
from contextlib import ExitStack, contextmanager
from pathlib import Path

import pytest

from friTap import FriTap
from friTap.backends import ebpf_native
from friTap.config import DeviceConfig, FriTapConfig
from friTap.core import CoreController
from friTap.events import ErrorEvent
from friTap.flow.tap_reader import TapReader
from friTap.synthetic_endpoints import SYNTHETIC_SERVER_PORT

SERIAL = os.environ.get("FRITAP_ANDROID_EBPF_SERIAL")
FIXTURE = os.environ.get("FRITAP_ANDROID_EBPF_FIXTURE")
TRANSPORT = os.environ.get("FRITAP_ANDROID_EBPF_TRANSPORT", "ring")
TEST_CONTROLS = os.environ.get("FRITAP_ANDROID_EBPF_TEST_CONTROLS") == "1"
pytestmark = pytest.mark.skipif(
    not SERIAL or not FIXTURE,
    reason="requires an explicitly selected Android device and built OpenSSL fixture",
)
REQUEST = b"owned fixture request\n"
RESPONSE = b"owned fixture response\n"


def _adb(*args):
    return ["adb", "-s", SERIAL, *args]


def _cli(*args):
    return [sys.executable, "-m", "friTap.friTap", "--backend", "ebpf", "--mobile", SERIAL, *args]


def _readline(stream):
    deadline = time.monotonic() + 15
    line = bytearray()
    while not line.endswith(b"\n"):
        remaining = max(0, deadline - time.monotonic())
        assert select.select([stream], [], [], remaining)[0], bytes(line)
        byte = os.read(stream.fileno(), 1)
        assert byte, bytes(line)
        line.extend(byte)
    return line.decode().strip()


@pytest.fixture(scope="module")
def fixture_dir(tmp_path_factory):
    build = Path(FIXTURE)
    tmp = tmp_path_factory.mktemp("android-tls")
    key, cert = tmp / "key.pem", tmp / "cert.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
         "-nodes", "-subj", "/CN=localhost", "-days", "1", "-keyout", key, "-out", cert],
        check=True, capture_output=True, timeout=15,
    )
    remote = subprocess.check_output(
        _adb("shell", "-T", "mktemp -d /data/local/tmp/fritap-fixture.XXXXXX"),
        text=True, timeout=10,
    ).strip()
    assert re.fullmatch(r"/data/local/tmp/fritap-fixture\.[A-Za-z0-9]+", remote)
    for source in (build / "client", build / "android_server", build / "libssl.so",
                   build / "libcrypto.so", cert, key):
        subprocess.run(_adb("push", str(source), remote + "/"), check=True, timeout=20)
    return remote


@contextmanager
def _loopback(directory, *, pause_after=False, count=1, extended=False):
    with ExitStack() as stack:
        def launch(argv, *, prefix=""):
            argv = [f"LD_LIBRARY_PATH={directory}", *argv]
            process = stack.enter_context(subprocess.Popen(
                _adb("shell", "-T", prefix + "exec env " + shlex.join(argv)),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0,
            ))
            stack.callback(lambda: process.kill() if process.poll() is None else None)
            return process

        server_args = [f"{directory}/android_server", f"{directory}/cert.pem", f"{directory}/key.pem"]
        if count != 1 or extended:
            server_args += [str(count), str(int(extended))]
        server = launch(server_args)
        port = int(_readline(server.stdout))
        client = launch([f"{directory}/client", str(port), str(count), str(int(pause_after)),
                         str(int(extended)), "0", "1"],
                        prefix='echo "$$"; ')
        pid = _readline(client.stdout)
        assert pid.isdecimal()
        assert _readline(client.stdout) == "paused"
        yield client, pid
        assert client.wait(timeout=10) == 0
        assert server.wait(timeout=10) == 0


def _assert_tap(path, request=REQUEST):
    with TapReader(str(path)) as reader:
        flows = list(reader.iter_flows())
    assert len(flows) == 1
    writes = [("write", request[i:i + 16384]) for i in range(0, len(request), 16384)]
    assert [(chunk.direction, chunk.data) for chunk in flows[0][2].chunks] == [
        *writes, ("read", RESPONSE),
    ]


@pytest.mark.parametrize("extended", [False, True])
def test_android_cli_preflight_and_exit(fixture_dir, tmp_path, extended):
    from scapy.all import TCP, rdpcap

    path = tmp_path / "android-cli.tap"
    pcap = tmp_path / "android-cli.pcap"
    request = b"x" * 40000 if extended else REQUEST
    with _loopback(fixture_dir, extended=extended) as (client, pid):
        info = json.loads(subprocess.check_output(_cli("--backend-readiness", pid), timeout=20))
        assert info["status"] == "ready", info
        assert info["target_os"] == "android"
        assert re.search(r"OpenSSL build ID [a-f0-9]+", info["detail"])
        assert f"transport: {TRANSPORT}" in info["detail"]
        print(info["detail"])
        with subprocess.Popen(_cli("--tap", str(path), "-p", str(pcap), pid), stderr=subprocess.PIPE) as capture:
            try:
                while _readline(capture.stderr) != f"eBPF capture running for PID {pid}":
                    pass
                client.stdin.write(b"\n")
                assert capture.wait(timeout=10) == 0, capture.stderr.read()
            finally:
                if capture.poll() is None:
                    capture.kill()
    _assert_tap(path, request)
    packets = rdpcap(str(pcap))
    assert b"".join(bytes(packet[TCP].payload) for packet in packets
                    if packet[TCP].dport == SYNTHETIC_SERVER_PORT) == request
    assert b"".join(bytes(packet[TCP].payload) for packet in packets
                    if packet[TCP].sport == SYNTHETIC_SERVER_PORT) == RESPONSE


def test_android_builder_drains_on_explicit_stop(fixture_dir, tmp_path):
    records = []
    response_seen = threading.Event()

    def receive(event):
        records.append((event.direction, event.data))
        if event.direction == "read":
            response_seen.set()

    path = tmp_path / "android-builder.tap"
    with _loopback(fixture_dir, pause_after=True) as (client, pid):
        session = FriTap(pid).backend("ebpf").mobile(SERIAL).on_data(receive).tap(str(path)).start()
        try:
            client.stdin.write(b"\n")
            assert _readline(client.stdout) == "exchanged"
            assert response_seen.wait(5)
            session.stop()
            assert session._coordinator.wait_timeout(5)
            assert session._coordinator.failure is None
            assert session._coordinator._producer.metadata["transport"] == TRANSPORT
            assert session._coordinator.dropped_records == 0
            assert client.poll() is None
        finally:
            session.stop()
            client.stdin.write(b"\n")
    assert records == [("write", REQUEST), ("read", RESPONSE)]
    _assert_tap(path)


def _test_control(monkeypatch, name):
    command_for = ebpf_native._runtime_command
    monkeypatch.setattr(ebpf_native, "_runtime_command",
                        lambda serial: [*command_for(serial)[:-1], "env", f"{name}=1",
                                        f"/data/local/tmp/{ebpf_native._NAME}"])


@pytest.mark.skipif(not TEST_CONTROLS, reason="requires the Android loader built with TEST_CONTROLS")
def test_android_attachment_rollback(fixture_dir, monkeypatch, tmp_path):
    path = tmp_path / "rollback.tap"
    with _loopback(fixture_dir) as (client, pid):
        with monkeypatch.context() as patch:
            _test_control(patch, "FRITAP_TEST_FAIL_ATTACHMENT")
            with pytest.raises(ebpf_native.NativeError, match="SSL_write entry"):
                FriTap(pid).backend("ebpf").mobile(SERIAL).start()

        session = FriTap(pid).backend("ebpf").mobile(SERIAL).tap(str(path)).start()
        try:
            client.stdin.write(b"\n")
            assert session._coordinator.wait_timeout(8)
            assert session._coordinator.failure is None
        finally:
            session.stop()
    _assert_tap(path)


@pytest.mark.skipif(not TEST_CONTROLS or TRANSPORT != "perf",
                    reason="requires a perf loader built with TEST_CONTROLS")
def test_android_perf_overflow(fixture_dir, monkeypatch):
    _test_control(monkeypatch, "FRITAP_TEST_DELAY_DRAIN")
    with _loopback(fixture_dir, count=40, extended=True) as (client, pid):
        config = FriTapConfig(target=pid, backend="ebpf", device=DeviceConfig(mobile=SERIAL))
        session = CoreController().create_session(config)
        errors = []
        session.lifecycle_bus.subscribe(ErrorEvent, errors.append)
        session.start()
        try:
            assert session._producer.metadata["transport"] == "perf"
            client.stdin.write(b"\n")
            assert session.wait_timeout(10)
            assert session.failure is None
            assert session.dropped_records > 0
            assert any(event.error == "capture_loss" and "Incomplete capture" in event.description
                       for event in errors)
            print(f"Perf overflow reported {session.dropped_records} lost records")
        finally:
            session.stop()
