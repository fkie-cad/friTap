"""Capture-side BPF honours --loopback and --no-filter-infrastructure.

Android full capture (-f) used to record Frida's own frida-server<->agent
loopback link even without --loopback, and --no-filter-infrastructure never
reached the BPF. These tests pin the composer and every capture path that
consumes it.
"""

from unittest.mock import MagicMock, patch

import pytest

from friTap.constants import (
    build_capture_bpf,
    build_infrastructure_bpf,
    build_loopback_exclusion,
)

INFRA = "not (tcp port 5037 or tcp port 5555 or tcp port 27042 or tcp port 27043)"
LOOPBACK = ("not (src net 127.0.0.0/8 and dst net 127.0.0.0/8) "
            "and not (ip6 src host ::1 and ip6 dst host ::1)")


# ---------------------------------------------------------------- composer

def test_loopback_exclusion_requires_both_ends_loopback():
    assert build_loopback_exclusion() == LOOPBACK


def test_infrastructure_bpf_unchanged():
    assert build_infrastructure_bpf() == INFRA


@pytest.mark.parametrize("filter_infra, include_loopback, expected", [
    (True, False, f"{INFRA} and {LOOPBACK}"),
    (True, True, INFRA),
    (False, False, LOOPBACK),
    (False, True, ""),
])
def test_build_capture_bpf_flag_combinations(filter_infra, include_loopback, expected):
    assert build_capture_bpf(filter_infrastructure=filter_infra,
                             include_loopback=include_loopback) == expected


def test_build_capture_bpf_defaults_filter_both():
    assert build_capture_bpf() == f"{INFRA} and {LOOPBACK}"


def test_build_capture_bpf_custom_ports():
    assert build_capture_bpf(include_loopback=True, ports=frozenset({1234})) == \
        "not (tcp port 1234)"


# ---------------------------------------------------------- android tcpdump

def _android_with_mock_adb():
    from friTap.android import Android
    android = Android()
    android.is_Android = True
    android.is_tcpdump_available = True  # tcpdump_path -> "tcpdump"
    android.__dict__["adb"] = MagicMock()  # bypass the cached_property lookup
    return android


def _tcpdump_command(**kwargs):
    android = _android_with_mock_adb()
    android.run_tcpdump_capture("_cap.pcap", **kwargs)
    (cmd,), call_kwargs = android.adb.shell.call_args
    assert call_kwargs == {"background": True}
    return cmd


def test_android_tcpdump_default_excludes_infrastructure_and_loopback():
    cmd = _tcpdump_command()
    assert cmd.endswith(f'_cap.pcap "{INFRA} and {LOOPBACK}"')
    assert cmd.startswith("tcpdump -U -i any -s 0 -w ")


def test_android_tcpdump_include_loopback_keeps_loopback():
    cmd = _tcpdump_command(include_loopback=True)
    assert cmd.endswith(f'_cap.pcap "{INFRA}"')
    assert "127.0.0.0/8" not in cmd


def test_android_tcpdump_no_filter_infrastructure_keeps_control_ports():
    cmd = _tcpdump_command(filter_infrastructure=False)
    assert cmd.endswith(f'_cap.pcap "{LOOPBACK}"')
    assert "27042" not in cmd


def test_android_tcpdump_both_off_has_no_filter_argument():
    cmd = _tcpdump_command(include_loopback=True, filter_infrastructure=False)
    assert cmd.endswith("_cap.pcap")
    assert '"' not in cmd


# ------------------------------------------------------ live auto-decrypt

def _live_tcpdump_argv(**kwargs):
    from friTap.output.live_autodecrypt_handler import LiveAutoDecryptHandler
    handler = LiveAutoDecryptHandler(**kwargs)
    with patch("friTap.output.live_autodecrypt_handler.subprocess.Popen") as popen, \
            patch.object(handler, "_read_pcap_stream"):
        handler._capture_local_tcpdump()
    return popen.call_args[0][0]


def test_live_autodecrypt_tcpdump_default_appends_bpf():
    argv = _live_tcpdump_argv()
    assert argv == ["tcpdump", "-U", "-i", "any", "-s", "0", "-w", "-",
                    f"{INFRA} and {LOOPBACK}"]


def test_live_autodecrypt_tcpdump_honours_flags():
    argv = _live_tcpdump_argv(include_loopback=True)
    assert argv[-1] == INFRA


def test_live_autodecrypt_tcpdump_no_bpf_when_both_off():
    argv = _live_tcpdump_argv(include_loopback=True, filter_infrastructure=False)
    assert argv == ["tcpdump", "-U", "-i", "any", "-s", "0", "-w", "-"]


# --------------------------------------------------------------- pcap.py

def _pcap_without_init(**attrs):
    from friTap.pcap import PCAP
    pcap = object.__new__(PCAP)
    pcap.pcap_file_name = "/tmp/out.pcap"
    pcap.is_Mobile = True
    pcap.owner_capture = False
    pcap.logger = MagicMock()
    for name, value in attrs.items():
        setattr(pcap, name, value)
    return pcap


@pytest.mark.parametrize("include_loopback, filter_infra", [
    (False, True), (True, False),
])
def test_full_mobile_capture_passes_flags(include_loopback, filter_infra):
    android = MagicMock()
    android.is_Android = True
    android.adb_check_root.return_value = True
    android.is_tcpdump_available = True
    pcap = _pcap_without_init(android_Instance=android,
                              include_loopback=include_loopback,
                              filter_infrastructure=filter_infra)
    thread = pcap.get_instance_of_FullCaptureThread()
    thread.full_mobile_capture()
    android.run_tcpdump_capture.assert_called_once_with(
        "_out.pcap", include_loopback=include_loopback,
        filter_infrastructure=filter_infra)


def test_pcap_init_stores_filter_infrastructure():
    from friTap.pcap import PCAP
    with patch.object(PCAP, "write_pcap_header", create=True), \
            patch("builtins.open", MagicMock()):
        pcap = PCAP("/tmp/out.pcap", 0, 1, doFullCapture=False, isMobile=False,
                    include_loopback=True, filter_infrastructure=False)
    assert pcap.include_loopback is True
    assert pcap.filter_infrastructure is False


@pytest.mark.parametrize("include_loopback, filter_infra, expected", [
    (False, True, f"{INFRA} and {LOOPBACK}"),
    (True, False, None),
])
def test_full_local_capture_sniff_filter(include_loopback, filter_infra, expected):
    pcap = _pcap_without_init(include_loopback=include_loopback,
                              filter_infrastructure=filter_infra, is_Mobile=False)
    thread = pcap.get_instance_of_FullCaptureThread()
    with patch("friTap.pcap.conf") as conf, patch("friTap.pcap.sniff") as sniff, \
            patch.object(thread, "_open_loopback_socket", return_value=None):
        conf.L2listen.return_value = MagicMock()
        thread.full_local_capture()
    assert sniff.call_args.kwargs["filter"] == expected
