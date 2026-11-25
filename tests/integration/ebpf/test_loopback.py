"""Opt-in kernel acceptance for the owned OpenSSL loopback fixture."""

import importlib.util
import json
import os
import re
import selectors
import shutil
import socket
import ssl
import subprocess
import sys
import sysconfig
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

from friTap import FriTap
from friTap.backends import ebpf_native
from friTap.config import FriTapConfig
from friTap.core import CoreController
from friTap.events import ErrorEvent
from friTap.session import CaptureLifecycleEvent
from friTap.flow.tap_reader import TapReader
from friTap.synthetic_endpoints import SYNTHETIC_SERVER_PORT, is_synthetic_ip

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.environ.get("FRITAP_RUN_EBPF_TESTS") != "1",
    reason="requires an opted-in privileged Linux test environment",
)
ROOT = Path(__file__).resolve().parents[3]
REQUEST = b"owned fixture request\n"
RESPONSE = b"owned fixture response\n"
LARGE_REQUEST = b"x" * 40000


def _line(stream):
    with selectors.DefaultSelector() as selector:
        selector.register(stream, selectors.EVENT_READ)
        assert selector.select(10), "timed out waiting for fixture startup"
        return stream.readline()


def _capture_ready(stream, pid, *, keylog=False):
    ready = f"eBPF capture running for PID {pid}".encode()
    deadline = time.monotonic() + 10
    output = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(stream, selectors.EVENT_READ)
        while ready not in output:
            assert selector.select(max(0, deadline - time.monotonic())), bytes(output)
            chunk = os.read(stream.fileno(), 4096)
            assert chunk, bytes(output)
            output.extend(chunk)
    if keylog:
        assert b"TLS key extraction is currently not implemented" in output


def _command(*args):
    return subprocess.check_output(args, text=True, timeout=15)


def _cli(*args):
    return [str(Path(sysconfig.get_path("scripts")) / "fritap"), "--backend", "ebpf", *args]


def _ssl_library(pid):
    for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) == 6 and fields[-1].endswith("/libssl.so.3"):
            return Path(fields[-1])
    pytest.fail(f"no libssl.so.3 mapped by PID {pid}")


@pytest.fixture(scope="module")
def binaries(tmp_path_factory):
    assert os.geteuid() == 0
    assert importlib.util.find_spec("frida") is None
    tmp = tmp_path_factory.mktemp("ebpf-fixture")
    client = tmp / "client"
    key, cert = tmp / "key.pem", tmp / "cert.pem"
    _command("cc", "-Wall", "-Wextra", "-Werror", str(Path(__file__).with_name("client.c")),
             "-o", str(client), "-lssl", "-lcrypto", "-pthread")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
         "-nodes", "-subj", "/CN=localhost", "-days", "1", "-keyout", key, "-out", cert],
        check=True, capture_output=True, timeout=15,
    )
    build = tmp / "small-build"
    subprocess.run(
        ["make", "-C", ROOT / "agent_ebpf", f"BUILD={build}", "BPF_FLAGS=-DBUFFER_SIZE=32768",
         "LOADER_FLAGS=-DTEST_CONTROLS"], check=True, timeout=30,
    )
    return client, key, cert, build / "fritap-ebpf-agent"


@contextmanager
def _fixture(binaries, count=1, *, pause_after_exchange=False, extended=False,
             worker=0, connections=1):
    client, key, cert, _ = binaries
    errors = []
    request = LARGE_REQUEST if extended else REQUEST
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(10)

        def serve():
            try:
                for _ in range(connections):
                    conn, _ = listener.accept()
                    with conn, context.wrap_socket(conn, server_side=True) as tls:
                        tls.settimeout(10)
                        for _ in range(count):
                            data = bytearray()
                            while len(data) < len(request):
                                chunk = tls.recv(len(request) - len(data))
                                if not chunk:
                                    raise EOFError("fixture client disconnected")
                                data.extend(chunk)
                            assert data == request
                            tls.sendall(RESPONSE)
            except Exception as exc:
                errors.append(exc)

        server = threading.Thread(target=serve, daemon=True)
        server.start()
        with subprocess.Popen(
            [client, str(listener.getsockname()[1]), str(count), str(int(pause_after_exchange)),
             str(int(extended)), str(worker), str(connections)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
        ) as proc:
            try:
                assert _line(proc.stdout) == "paused\n"
                assert _ssl_library(proc.pid).samefile(_ssl_library(os.getpid()))
                yield proc
                assert proc.wait(timeout=10) == 0
                server.join(timeout=10)
                assert not server.is_alive()
                assert not errors
            finally:
                if proc.poll() is None:
                    proc.kill()


def _release(proc):
    proc.stdin.write("\n")
    proc.stdin.flush()


def _assert_tap(path):
    with TapReader(str(path)) as reader:
        flows = list(reader.iter_flows())
    assert len(flows) == 1
    assert {chunk.direction: chunk.data for chunk in flows[0][2].chunks} == {
        "read": RESPONSE, "write": REQUEST,
    }
    assert len(flows[0][2].chunks) == 2


def test_real_readiness_cli_and_exit(binaries, tmp_path):
    with _fixture(binaries) as proc:
        pid = str(proc.pid)
        ready = json.loads(_command(*_cli("--backend-readiness", pid)))
        build_id = re.search(r"Build ID: ([a-f0-9]+)", _command("readelf", "-n", _ssl_library(proc.pid)))[1]
        assert ready["status"] == "ready", ready
        assert build_id in ready["detail"]
        assert os.uname().release in ready["detail"]
        assert "transport: ring" in ready["detail"]
        print(f"OpenSSL build ID {build_id}, Linux {os.uname().release}")
        denied = json.loads(_command("runuser", "-u", "nobody", "--", *_cli("--backend-readiness", pid)))
        assert denied["status"] == "permission_denied", denied
        path = tmp_path / "cli.tap"
        with subprocess.Popen(
            _cli("--protocol", "tls", "--tap", str(path), pid),
            stderr=subprocess.PIPE,
        ) as capture:
            try:
                _capture_ready(capture.stderr, pid)
                _release(proc)
                assert capture.wait(timeout=10) == 0, capture.stderr.read()
            finally:
                if capture.poll() is None:
                    capture.kill()
        gone = json.loads(_command(*_cli("--backend-readiness", pid)))
        assert gone["status"] == "target_disappeared"
    _assert_tap(path)


def test_builder_callbacks_and_exit(binaries, tmp_path):
    path = tmp_path / "builder.tap"
    data = []
    with _fixture(binaries) as proc:
        capture = FriTap(str(proc.pid)).backend("ebpf").on_data(data.append).tap(str(path)).start()
        try:
            assert capture.is_running
            _release(proc)
            assert proc.wait(timeout=8) == 0
            assert capture._coordinator.wait_timeout(5)
            assert capture._coordinator.failure is None
        finally:
            capture.stop()
    assert [(item.direction, item.data) for item in data] == [("write", REQUEST), ("read", RESPONSE)]
    assert all(not item.src_addr and not item.dst_addr for item in data)
    _assert_tap(path)


def test_callback_stop_finalizes_tap_before_target_exit(binaries, tmp_path):
    path = tmp_path / "stopped.tap"

    def stop_on_response(event):
        if event.direction == "read":
            capture.stop()

    with _fixture(binaries, pause_after_exchange=True) as proc:
        capture = (FriTap(str(proc.pid)).backend("ebpf").tap(str(path))
                   .on_data(stop_on_response).start())
        try:
            _release(proc)
            assert _line(proc.stdout) == "exchanged\n"
            assert capture._coordinator.wait_timeout(5)
            assert capture._coordinator.failure is None
            assert proc.poll() is None
            _assert_tap(path)
        finally:
            capture.stop()
            _release(proc)


def test_unsupported_and_rollback(binaries, monkeypatch):
    with subprocess.Popen(["sleep", "10"]) as unsupported:
        try:
            info = json.loads(_command(*_cli("--backend-readiness", str(unsupported.pid))))
            assert info["status"] == "unsupported"
            assert "mapped_openssl" in info["detail"]
        finally:
            unsupported.terminate()
    monkeypatch.setattr(ebpf_native, "resolve_runtime", lambda: binaries[-1])
    monkeypatch.setenv("FRITAP_TEST_FAIL_ATTACHMENT", "1")
    with _fixture(binaries) as proc:
        events = []
        config = FriTapConfig(target=str(proc.pid), backend="ebpf")
        session = CoreController().create_session(config)
        session.lifecycle_bus.subscribe(CaptureLifecycleEvent, events.append)
        with pytest.raises(ebpf_native.NativeError, match="SSL_write entry"):
            session.start()
        assert [event.event_type for event in events] == ["stopped"]
        assert session.wait_timeout(0)
        monkeypatch.delenv("FRITAP_TEST_FAIL_ATTACHMENT")
        capture = FriTap(str(proc.pid)).backend("ebpf").start()
        try:
            assert capture.is_running
            _release(proc)
            assert capture._coordinator.wait_timeout(5)
            assert capture._coordinator.failure is None
        finally:
            capture.stop()


def test_kernel_loss_reports_incomplete_capture(binaries, monkeypatch):
    monkeypatch.setattr(ebpf_native, "resolve_runtime", lambda: binaries[-1])
    monkeypatch.setenv("FRITAP_TEST_DELAY_DRAIN", "1")
    with _fixture(binaries, count=80) as proc:
        session = CoreController().create_session(FriTapConfig(target=str(proc.pid), backend="ebpf"))
        errors = []
        session.lifecycle_bus.subscribe(ErrorEvent, errors.append)
        session.start()
        try:
            _release(proc)
            assert session.wait_timeout(8)
            assert session.failure is None
            assert session.dropped_records > 0
            assert any(event.error == "capture_loss" and "Incomplete capture" in event.description
                       for event in errors)
        finally:
            session.stop()


def test_real_runtime_discovery(tmp_path, monkeypatch):
    source = ROOT / "agent_ebpf" / "build" / "fritap-ebpf-agent"
    assert source.is_file()
    assert ebpf_native.resolve_runtime() == Path(sysconfig.get_path("scripts")) / source.name
    monkeypatch.setattr(sysconfig, "get_path", lambda name: str(tmp_path))
    assert ebpf_native.resolve_runtime() == source
    shutil.copy2(source, tmp_path / source.name)
    assert ebpf_native.resolve_runtime() == tmp_path / source.name



def _read_pcap_streams(path):
    from scapy.all import IP, TCP, rdpcap

    streams = {}
    for packet in rdpcap(str(path)):
        ip, tcp = packet[IP], packet[TCP]
        assert is_synthetic_ip(ip.src) and is_synthetic_ip(ip.dst)
        reading = tcp.sport == SYNTHETIC_SERVER_PORT
        client = (ip.dst, tcp.dport) if reading else (ip.src, tcp.sport)
        directions = streams.setdefault(client, {"read": bytearray(), "write": bytearray()})
        directions["read" if reading else "write"].extend(bytes(tcp.payload))
    return list(streams.values())


@pytest.mark.parametrize("container,worker", [("pcap", 1), ("pcapng", 2)])
def test_plaintext_pcaps_extended_api_workers_and_process_scope(binaries, tmp_path, container, worker):
    path = tmp_path / f"data.{container}"
    keylog = tmp_path / "unused.keys"
    keylog.write_bytes(b"existing output")
    events = []
    with _fixture(binaries, extended=worker, worker=worker, connections=2) as target:
        with _fixture(binaries) as other:
            if container == "pcap":
                with subprocess.Popen(_cli("-p", str(path), "-k", str(keylog), str(target.pid)),
                                      stderr=subprocess.PIPE) as capture:
                    try:
                        _capture_ready(capture.stderr, target.pid, keylog=True)
                        _release(other)
                        assert other.wait(timeout=10) == 0
                        _release(target)
                        assert capture.wait(timeout=10) == 0, capture.stderr.read()
                    finally:
                        if capture.poll() is None:
                            capture.kill()
            else:
                session = (FriTap(str(target.pid)).backend("ebpf").pcap(str(path))
                           .keylog(str(keylog)).on_data(events.append).start())
                try:
                    _release(other)
                    assert other.wait(timeout=10) == 0
                    _release(target)
                    assert session._coordinator.wait_timeout(8)
                    assert session._coordinator.failure is None
                    assert session._coordinator.dropped_records == 0
                finally:
                    session.stop()
    assert keylog.read_bytes() == b"existing output"
    assert _read_pcap_streams(path) == [{"read": RESPONSE, "write": LARGE_REQUEST}] * 2
    if container == "pcapng":
        assert {event.function for event in events} == {"SSL_read_ex", "SSL_write_ex"}
        assert len({event.ssl_session_id for event in events}) == 2
        assert all(not event.src_addr and not event.dst_addr for event in events)

@pytest.mark.parametrize("container", ["pcap", "pcapng"])
def test_full_capture_with_keylog_stub_preserves_wire_packets(binaries, tmp_path, container):
    from scapy.all import IP, TCP, rdpcap

    path = tmp_path / f"wire.{container}"
    keylog = tmp_path / "requested.keys"
    with _fixture(binaries) as target:
        args = _cli("-k", str(keylog), "-p", str(path), "-f", "--loopback", str(target.pid))
        with subprocess.Popen(args, stderr=subprocess.PIPE) as capture:
            try:
                _capture_ready(capture.stderr, target.pid, keylog=True)
                _release(target)
                assert capture.wait(timeout=10) == 0, capture.stderr.read()
            finally:
                if capture.poll() is None:
                    capture.kill()

    assert not keylog.exists()
    wire_payloads = [
        bytes(packet[TCP].payload) for packet in rdpcap(str(path))
        if IP in packet and TCP in packet and packet[IP].src == packet[IP].dst == "127.0.0.1"
    ]
    assert any(payload.startswith(b"\x17\x03\x03") for payload in wire_payloads)
    assert REQUEST not in b"".join(wire_payloads) and RESPONSE not in b"".join(wire_payloads)
