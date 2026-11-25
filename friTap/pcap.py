#!/usr/bin/env python3
import logging
import os
import random
import re
import secrets
import shlex
import struct
import time
import warnings
from threading import RLock, Thread

import psutil

# Capture names used by pcap_full_capture are read from this module at call
# time (scapy names, build_capture_bpf, linktype and temp-path helpers), so
# patching friTap.pcap.<name> reaches the capture thread.
from friTap.constants import build_capture_bpf  # noqa: F401

from ._fs_util import is_non_empty_file
from .android import Android, kill_background_adb_children
from .constants import is_read_function
from .pcap_full_capture import FullCaptureThread
from .pcap_manifest import (  # noqa: F401 - _existing_keylog_files is imported from here
    _MTIME_SLACK_SECONDS,
    _existing_keylog_files,
    _written_this_session,
    write_capture_manifest,
)
from .pcap_utility import (
    MANIFEST_SUFFIX,
    PCAP_FORMAT_AUTO,
    PCAP_FORMAT_PCAPNG,
    PCAP_MAGIC_TO_ENDIAN,
    resolve_pcap_format,
)
from .sinks.tcp_state import (
    InvalidEndpointError,
    ipv4_address_int,
    max_segment_payload,
    split_payload,
    validate_port,
    warn_dropped_record,
)

# scapy logs "No libpcap provider available" from "scapy.loading" at import time.
# Only -f/--full_capture and live local capture need libpcap (they raise their own
# platform-aware error); -k and -p are built by hand with struct.pack. The banner
# is noise on Windows without Npcap.
# scapy/error.py claims the "scapy" logger level only while it is NOTSET, so a level
# set before the import sticks. It is restored afterwards so real runtime scapy
# warnings are not swallowed.
_scapy_logger = logging.getLogger("scapy")
_scapy_prev_level = _scapy_logger.level
_scapy_logger.setLevel(logging.ERROR)
try:
    from scapy.all import ETH_P_ALL, Scapy_Exception, conf, sniff, wrpcap
    from scapy.utils import PcapReader
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    # Stand-ins so the module imports without scapy.
    class Scapy_Exception(Exception):
        pass

    def wrpcap(*args, **kwargs):
        pass

    class conf:
        pass

    ETH_P_ALL = None

    def sniff(*args, **kwargs):
        return []

    class PcapReader:
        def __init__(self, *args, **kwargs):
            self.linktype = 1
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def __iter__(self): return iter(())
        def close(self): pass
    
    import sys
    if 'pytest' not in sys.modules:
        logging.getLogger('friTap').warning('scapy is not installed, please install it by running: pip3 install scapy')
finally:
    # NOTSET means scapy had not been imported before; WARNING is the level
    # scapy/error.py would otherwise have installed itself.
    _scapy_logger.setLevel(
        _scapy_prev_level if _scapy_prev_level != logging.NOTSET else logging.WARNING
    )
    del _scapy_prev_level

INVALID_IPV4 = "0.0.0.0"
INVALID_IPV6 = "::"

# Silence scapy's runtime chatter (e.g. "Mac address to reach destination not found").
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
warnings.simplefilter("ignore", ResourceWarning)


def _libpcap_hint() -> str:
    """Platform-aware guidance for a missing/unusable libpcap provider.

    Imported lazily to avoid an import cycle with fritap_utility.
    """
    from .fritap_utility import libpcap_provider_hint
    return libpcap_provider_hint()


DLT_EN10MB = 1
_ETHERTYPE_IPV4 = 0x0800
_ETHERTYPE_IPV6 = 0x86DD
_PCAP_MAGIC_TO_ENDIAN = PCAP_MAGIC_TO_ENDIAN  # shared table (friTap.pcap_utility)


def _packet_linktype(packet):
    """DLT scapy's pcap writer would record for ``packet`` (Ethernet if unknown)."""
    return conf.l2types.layer2num.get(type(packet), DLT_EN10MB)


def _existing_pcap_linktype(path):
    """Linktype from the header of an existing classic pcap at ``path``, else None.

    ``wrpcap(append=True)`` keeps an existing header, so that linktype (not the
    first packet of this run) is what appended packets must match.
    """
    try:
        with open(path, "rb") as fh:
            header = fh.read(24)
    except OSError:
        return None
    endian = _PCAP_MAGIC_TO_ENDIAN.get(header[:4])
    if endian is None or len(header) < 24:
        return None
    return struct.unpack(endian + "I", header[20:24])[0]


def _normalize_to_linktype(packet, target_linktype):
    """Return ``packet`` framed for a pcap of ``target_linktype``, or None.

    A classic pcap has one linktype, but ``--loopback`` merges the Ethernet NIC with
    the loopback adapter (DLT_NULL on macOS lo0 and Npcap loopback); written as-is,
    the minority packets parse as garbage. IP/IPv6 packets are re-wrapped in a
    synthetic Ethernet header for an Ethernet file. Anything else is dropped
    (None) rather than stored corrupt.
    """
    if _packet_linktype(packet) == target_linktype:
        return packet
    if target_linktype != DLT_EN10MB:
        return None
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether
    for layer, ethertype in ((IP, _ETHERTYPE_IPV4), (IPv6, _ETHERTYPE_IPV6)):
        if packet.haslayer(layer):
            framed = Ether(src="00:00:00:00:00:00", dst="00:00:00:00:00:00",
                           type=ethertype) / packet[layer].copy()
            framed.time = packet.time
            return framed
    return None


def _ipv6_bytes(addr) -> bytes:
    """Return the 16-byte form of an IPv6 address given as a hex string.

    Content-only packets (no socket 5-tuple) carry "", None or 0; those map to
    the :: placeholder.
    """
    if isinstance(addr, str):
        try:
            raw = bytes.fromhex(addr)
        except ValueError:
            raw = b""
        if len(raw) == 16:
            return raw
    return bytes(16)


def _write_pcap_record(pcap_file, fields, data) -> None:
    """Write one pcap record (packed *fields* then *data*) in a single write.

    The ``-p`` file may be shared by several sessions (Windows LSASS worker, see
    :mod:`friTap.output.shared_output_file`); one write keeps each record contiguous.
    """
    header = b"".join(struct.pack(fmt, value) for fmt, value in fields)
    pcap_file.write(header + data)


# --- Synthetic IP/TCP/UDP records for the plaintext (-p) pcap -------------
# Checksums are zero (valid for synthetic pcap data); TCP flags are PSH+ACK.

def _pcap_record_fields(t, frame_length):
    return (
        ("=I", int(t)),                         # Timestamp seconds
        ("=I", int(t * 1000000) % 1000000),     # Timestamp microseconds
        ("=I", frame_length),                   # Number of octets saved
        ("=i", frame_length))                   # Actual length of packet


def _ipv4_header_fields(total_length, protocol, src_addr, dst_addr):
    return (
        (">B", 0x45),               # Version and Header Length
        (">B", 0),                  # Type of Service
        (">H", total_length),       # Total Length
        (">H", 0),                  # Identification
        (">H", 0x4000),             # Flags and Fragment Offset
        (">B", 0xFF),               # Time to Live
        (">B", protocol),           # Protocol
        (">H", 0),                  # Header Checksum
        (">I", src_addr),           # Source Address
        (">I", dst_addr))           # Destination Address


def _ipv6_header_fields(payload_length, next_header, src_addr, dst_addr):
    return (
        (">I", 0x60000000),                 # Version, traffic class and Flow label
        (">H", payload_length),             # Payload length
        (">B", next_header),                # Next Header
        (">B", 0xFF),                       # Hop limit
        (">16s", _ipv6_bytes(src_addr)),    # Source Address
        (">16s", _ipv6_bytes(dst_addr)))    # Destination Address


def _tcp_header_fields(src_port, dst_port, seq, ack):
    return (
        (">H", src_port),           # Source Port
        (">H", dst_port),           # Destination Port
        (">I", seq),                # Sequence Number
        (">I", ack),                # Acknowledgment Number
        (">H", 0x5018),             # Header Length and Flags
        (">H", 0xFFFF),             # Window Size
        (">H", 0),                  # Checksum
        (">H", 0))                  # Urgent Pointer


def _udp_header_fields(src_port, dst_port, udp_length):
    return (
        (">H", src_port),           # Source Port
        (">H", dst_port),           # Destination Port
        (">H", udp_length),         # UDP Length
        (">H", 0))                  # Checksum


def _write_ip_record(pcap_file, ss_family, t, protocol, src_addr, dst_addr,
                     transport_fields, l4_length, segment):
    """Write one IPv4/IPv6 record whose transport part is *l4_length* bytes."""
    if ss_family == "AF_INET":
        ip_length = 20 + l4_length
        ip_fields = _ipv4_header_fields(ip_length, protocol, src_addr, dst_addr)
    else:
        ip_length = 40 + l4_length
        ip_fields = _ipv6_header_fields(l4_length, protocol, src_addr, dst_addr)
    _write_pcap_record(pcap_file, _pcap_record_fields(t, ip_length)
                       + ip_fields + transport_fields, segment)


def _write_tcp_segment(pcap_file, ss_family, t, src_addr, src_port,
                       dst_addr, dst_port, seq, ack, segment):
    tcp_fields = _tcp_header_fields(src_port, dst_port, seq, ack)
    _write_ip_record(pcap_file, ss_family, t, 6, src_addr, dst_addr,
                     tcp_fields, 20 + len(segment), segment)


def _write_udp_datagram(pcap_file, ss_family, t, src_addr, src_port,
                        dst_addr, dst_port, segment):
    udp_fields = _udp_header_fields(src_port, dst_port, 8 + len(segment))
    _write_ip_record(pcap_file, ss_family, t, 17, src_addr, dst_addr,
                     udp_fields, 8 + len(segment), segment)


def _validate_capture(path):
    """Reject a capture whose record lengths scapy would trust blindly.

    Imported lazily: friTap.offline's __init__ imports pcap_to_tap (circular).
    """
    from .offline.net.capture_validation import validate_capture_file
    validate_capture_file(path)


def _endpoints_packable(ss_family, src_addr, src_port, dst_addr, dst_port, logger):
    """Whether the ports (and IPv4 addresses) fit their header fields.

    Values come from agent messages; an out-of-range port or IPv4 int drops the
    record with a once-per-kind warning instead of raising struct.error.
    """
    try:
        validate_port(src_port)
        validate_port(dst_port)
        if ss_family != "AF_INET6":
            ipv4_address_int(src_addr)
            ipv4_address_int(dst_addr)
    except InvalidEndpointError as exc:
        warn_dropped_record(exc.kind, logger)
        return False
    return True


def terminate_lingering_processes(parent_pid):
    logger = logging.getLogger('friTap')
    parent = psutil.Process(parent_pid)
    for child in parent.children(recursive=True):
        logger.info(f"Terminating child process: {child.pid} ({child.name()})")
        child.terminate()
        try:
            child.wait(timeout=2)
        except psutil.TimeoutExpired:
            logger.warning(f"Forcing kill of child process: {child.pid}")
            child.kill()


# The full capture goes to a temp file next to the output and is renamed or
# converted to the final name on finalize. The Android tcpdump file shares the basename.
TEMP_CAPTURE_PREFIX = "_"


def temp_capture_basename(pcap_file_name) -> str:
    """Basename of the temp capture for *pcap_file_name* (``cap.pcap`` -> ``_cap.pcap``)."""
    head, tail = os.path.split(pcap_file_name)
    return TEMP_CAPTURE_PREFIX + (tail or os.path.basename(head))


def temp_capture_path(pcap_file_name) -> str:
    """Temp capture path next to *pcap_file_name*: ``dirname/_basename``.

    The prefix goes on the basename only (``/tmp/cap.pcap`` -> ``/tmp/_cap.pcap``).
    """
    head = os.path.split(pcap_file_name)[0]
    base = temp_capture_basename(pcap_file_name)
    return os.path.join(head, base) if head else base


_UNSAFE_DEVICE_NAME_CHARS = re.compile(r"[^A-Za-z0-9._-]")


def device_capture_basename(pcap_file_name) -> str:
    """Per-run unique name of the on-device tcpdump file for *pcap_file_name*.

    ``cap.pcap`` -> ``_cap.<host pid>-<random>.pcap``: two runs with the same
    ``-p`` basename must not share (and truncate or delete) one device file.
    Shell-unsafe characters become ``_``. ``Android.run_tcpdump_capture`` keeps
    the name for the pull and the removal.
    """
    root, ext = os.path.splitext(temp_capture_basename(pcap_file_name))
    unique = f"{root}.{os.getpid()}-{secrets.token_hex(3)}{ext}"
    return _UNSAFE_DEVICE_NAME_CHARS.sub("_", unique)


class PCAP:

    # On-device teardown state (see stop_device_capture). Class-level defaults so
    # tests that build instances via __new__ still work.
    _device_capture_lock = RLock()
    _device_capture_stopped = False
    _device_capture_result = None
    # True once the device capture was pulled completely (the forced exit then
    # has nothing to recover).
    _device_capture_pulled = False

    def __init__(self,pcap_file_name,SSL_READ,SSL_WRITE, doFullCapture, isMobile, print_debug_infos=False,
                 owner_capture=False, owner_capture_opts=None, target_package=None, target_pid=None,
                 include_loopback=False, filter_infrastructure=True, pcap_format=PCAP_FORMAT_AUTO,
                 managed_full_capture=False):
        self.pcap_file_name = pcap_file_name
        # The -p container ("pcap"/"pcapng"), resolved once; read by writes_pcapng.
        self.pcap_container = resolve_pcap_format(pcap_file_name, pcap_format)
        self.logger = logging.getLogger('friTap')
        # --loopback (-f): also sniff the loopback interface; localhost traffic is
        # invisible on the primary NIC. Best-effort: if the adapter cannot be
        # opened (e.g. Npcap without loopback support) the primary capture still runs.
        self.include_loopback = include_loopback
        # False (--no-filter-infrastructure): frida/adb ports are not excluded by the BPF.
        self.filter_infrastructure = filter_infrastructure
        # --owner-capture: AppTap acquires an app (UID) scoped pcap instead of a
        # whole-device one. These are config; runtime state is apptap_session,
        # capture_tier and apptap_result, set once a session starts.
        self.owner_capture = owner_capture
        self.owner_capture_opts = owner_capture_opts or {}
        self.target_package = target_package
        self.target_pid = target_pid
        self.apptap_session = None
        self.apptap_result = None
        self.capture_tier = None

        if isMobile is True:  # No device ID provided
            self.device_id = None
        else:
            self.device_id = isMobile
        self.pkt ={}
        self.print_debug_infos = print_debug_infos


        self.is_Mobile = isMobile

        # ssl_session[<SSL_SESSION id>] = (<bytes sent by client>,
        #                                  <bytes sent by server>)
        self.ssl_sessions = {}
        self.SSL_READ = SSL_READ
        self.SSL_WRITE = SSL_WRITE

        # Distinct server ports per transport, written to the <pcap>.fritap.json
        # manifest so offline replay knows which ports to Decode-As.
        self._observed_server_ports = {"tcp": set(), "udp": set()}
        # SSLKEYLOGFILE path when exported; populated externally.
        self.keylog_path = None
        # Un-split base ``-k`` path. In a split capture only the per-protocol paths
        # arrive; on Windows (SChannel) the <base>.tls split is never written and
        # the TLS secrets land in the base file (LSASS session), so it is the
        # manifest fallback. Populated externally.
        self.base_keylog_path = None
        # Memory-scan sidecars older than this belong to an earlier run.
        self._session_started_at = time.time()
        # Active protocol ("mtproto", "signal", "tls", ...), populated externally;
        # selects the protocol-specific manifest keylog field for offline decrypt.
        self.capture_protocol = None
        # {protocol: path} split keylogs (``--protocol all|auto``), populated externally.
        self.active_keylogs = {}
        # {protocol: path} memory-scan (-ms) keylogs; see set_memory_scan_keylogs().
        self.memory_scan_keylogs = {}
        # Path the memory-scan engine intends to write for the mid-stream TLS secret
        # bundle (set_tls_midstream_secrets_path); authoritative for the manifest.
        self._tls_midstream_secrets_path = None
        # --attribute-sdk request-context sidecar of a -f run; see set_request_contexts_path().
        self._request_contexts_path = None
        # -p sidecar with the synthetic QUIC connections' secrets; see set_quic_synthetic_keylog_path().
        self._quic_synthetic_keylog_path = None
        self._device_capture_lock = RLock()

        if doFullCapture:
            if isMobile:
                self.logger.debug(f"Applying debug mode: {self.print_debug_infos}")
                self.android_Instance = Android(device_id=self.device_id)
            self.full_capture_thread = self.get_instance_of_FullCaptureThread()
            if managed_full_capture:
                self.full_capture_thread.managed_local = True
            self.full_capture_thread.start()
            if self.full_capture_thread.is_alive():
                self.logger.info("capturing whole traffic of target app")
        else:
            self.logger.info("capturing only plaintext data")
            # PcapngOutputHandler owns the file for pcapng; a classic header
            # here would be overwritten.
            if self.writes_pcapng():
                self.pcap_file = None
            else:
                self.pcap_file = self.__create_plaintext_pcap()
            
    

    def _build_apptap_session(self, output):
        """Build an AppTap CaptureSession for owner-capture, or None to fall back.

        Uses friTap's adb plumbing (Android) or AppTap's LocalExecutor (Linux).
        None when AppTap is missing or no target is known (whole-device fallback).
        """
        from .apptap_adapter import FritapAdbExecutor, apptap_available
        if not apptap_available():
            self.logger.warning(
                "--owner-capture requested but the AppTap library is not installed; "
                "falling back to whole-device capture.")
            return None
        import apptap

        opts = self.owner_capture_opts or {}
        if opts.get('strict'):
            breadth = apptap.Breadth.APP_ONLY
        elif opts.get('no_dns'):
            breadth = apptap.Breadth.APP_ISOLATED
        else:
            breadth = apptap.Breadth.APP_ISOLATED_DNS

        if self.is_Mobile:
            executor = FritapAdbExecutor(self.android_Instance.adb)
        else:
            executor = apptap.LocalExecutor()

        pid = self.target_pid
        if isinstance(pid, str) and pid.isdigit():
            pid = int(pid)
        package = self.target_package if isinstance(self.target_package, str) else None
        try:
            target = apptap.Target(package=package, pid=pid if isinstance(pid, int) else None)
        except ValueError:
            self.logger.warning(
                "--owner-capture: no target package/pid available; falling back to "
                "whole-device capture.")
            return None
        return apptap.CaptureSession(
            target, executor, output,
            breadth=breadth, tier=apptap.Tier.AUTO,
            nflog_group=opts.get('nflog_group', 30),
        )

    def stop_owner_capture(self):
        """Stop the AppTap session (if any), recording its result. Idempotent."""
        session = getattr(self, 'apptap_session', None)
        if session is None:
            return
        self.apptap_session = None
        try:
            self.apptap_result = session.stop()
            self.capture_tier = self.apptap_result.tier
            for warning in (self.apptap_result.warnings or []):
                self.logger.warning("owner-capture: %s", warning)
        except Exception as exc:
            self.logger.error("owner-capture: stopping AppTap failed: %s", exc)
            try:
                session.teardown()
            except Exception:
                pass

    def stop_device_capture(self):
        """Stop the on-device tcpdump, pull its pcap and delete the device file.

        The device file is deleted only after a complete pull; a failed pull
        keeps it and logs the adb command that recovers it.

        Idempotent and thread-safe: signals, target death, errors, normal exit and
        the atexit net may all call it; teardown runs once and later callers get the
        same result. Returns the local temp capture path, or ``None`` if none started.
        """
        with self._device_capture_lock:
            if not self._device_capture_stopped:
                self._device_capture_stopped = True
                try:
                    self._device_capture_result = self._teardown_device_capture()
                except Exception as exc:  # teardown must never break the exit path
                    self.logger.error(f"Error tearing down the device capture: {exc}")
            return self._device_capture_result

    def _teardown_device_capture(self):
        # No wait for a still-starting thread: it launches tcpdump under
        # _device_capture_lock (held by the caller) and skips once stopped, so the
        # process handle read here is final.
        thread = getattr(self, "full_capture_thread", None)
        if thread is None or getattr(self, "android_Instance", None) is None:
            return None
        process = getattr(thread, "android_capture_process", -1)
        if process == -1:
            self.logger.info("Full capture was not started on the device; nothing to pull.")
            return None
        android = self.android_Instance
        android.stop_tcpdump_gracefully(process)
        try:
            pulled = android.pull_pcap_from_device(
                os.path.dirname(self.pcap_file_name) or ".",
                local_path=temp_capture_path(self.pcap_file_name))
        except Exception as exc:
            self.logger.error(f"Error pulling the device capture: {exc}")
            pulled = None
        if pulled:
            self._device_capture_pulled = True
            android.remove_device_capture()
        else:  # deleting it now would lose the only copy
            android.keep_device_capture_for_recovery(
                os.path.abspath(temp_capture_path(self.pcap_file_name)))
        return temp_capture_path(self.pcap_file_name) if pulled else None

    # Bound of the forced-exit kill below; the user already asked to quit.
    FORCED_KILL_ADB_TIMEOUT = 5

    def kill_device_capture(self):
        """Forced-exit net: SIGKILL friTap's device tcpdump now, without pulling.

        os._exit skips the atexit net, so a forced exit calls this instead. It
        takes no lock (the graceful stop_device_capture() may be holding it
        mid-teardown) and makes one bounded adb call. Only friTap's own tcpdump
        (pidfile pid, still named tcpdump) is killed. Returns True if the kill
        was sent; never raises.
        """
        thread = getattr(self, "full_capture_thread", None)
        android = getattr(self, "android_Instance", None)
        process = getattr(thread, "android_capture_process", -1)
        if android is None or process in (-1, None):
            return False
        sent = False
        try:
            result = android.adb.shell(self._forced_kill_command(android),
                                       timeout=self.FORCED_KILL_ADB_TIMEOUT)
            sent = True
            if "killed" in (getattr(result, "stdout", "") or ""):
                self.logger.info(
                    "full capture: device tcpdump killed; its unpulled capture stays at "
                    f"{android.dst_path}{android.pcap_name} on the device")
        except Exception as exc:
            self.logger.debug("forced kill of the device tcpdump failed: %s", exc)
        try:
            process.kill()  # the local adb client
        except Exception:
            pass
        return sent

    def device_pull_progress(self):
        """Bytes the running device-capture pull wrote so far, or None when no pull runs."""
        progress = getattr(getattr(self, "android_Instance", None), "pull_progress", None)
        return progress() if callable(progress) else None

    def abort_device_capture_pull(self):
        """Forced-exit net: stop a running pull, then say how to recover the device capture.

        Logs the recovery command whenever a device capture was started and not
        pulled completely, unless the failed-pull path already logged it. Local
        only (no adb call), so it cannot eat the forced exit's time budget.
        Returns True when the recovery line was logged; never raises.
        """
        android = getattr(self, "android_Instance", None)
        thread = getattr(self, "full_capture_thread", None)
        if android is None or getattr(thread, "android_capture_process", -1) in (-1, None):
            return False
        try:
            android.abort_pull()
            if self._device_capture_pulled or getattr(android, "recovery_logged", False) is True:
                return False
            android.keep_device_capture_for_recovery(
                os.path.abspath(temp_capture_path(self.pcap_file_name)), remove_pidfile=False)
            return True
        except Exception as exc:  # noqa: BLE001 - the exit must happen regardless
            self.logger.debug("forced-exit pull abort failed: %s", exc)
            return False

    # Bound of the forced AppTap stop; its stop() makes several adb calls.
    FORCED_OWNER_CAPTURE_STOP_SECONDS = 4.0

    def abort_owner_capture(self):
        """Forced-exit net: stop a running AppTap session, bounded. True if one was running."""
        if getattr(self, "apptap_session", None) is None:
            return False
        worker = Thread(target=self.stop_owner_capture, daemon=True,
                        name="fritap-forced-apptap-stop")
        worker.start()
        worker.join(self.FORCED_OWNER_CAPTURE_STOP_SECONDS)
        return True

    @staticmethod
    def kill_adb_children():
        """Forced-exit net: stop friTap's background adb children (they ignore the terminal's Ctrl+C)."""
        return kill_background_adb_children()

    @staticmethod
    def _forced_kill_command(android):
        """One device shell command: SIGKILL the pidfile's pid if it is still tcpdump."""
        pid = getattr(android, "tcpdump_pid", None)
        pid_expr = str(int(pid)) if pid is not None else (
            f'$(cat "{android._capture_pidfile()}" 2>/dev/null)')
        script = (f'p={pid_expr}; [ -n "$p" ] && grep -q tcpdump /proc/$p/comm 2>/dev/null'
                  ' && kill -9 $p && echo killed')
        # sh -c: the su elevators must run the whole script as root.
        return f"sh -c {shlex.quote(script)}"

    def _log_root_unavailable(self):
        """Log why the Android full capture cannot run (unrooted vs. unknown)."""
        from .android import RootState
        try:
            state = self.android_Instance.root_state
        except Exception:
            state = RootState.NOT_ROOTED
        if state is RootState.UNKNOWN:
            self.logger.error(
                "Full packet capture (-f) skipped: friTap could not determine whether "
                "the device is rooted (the root check timed out and no `su` was found). "
                "Plaintext/keylog capture is unaffected.")
            return
        self.logger.error(
            "Full packet capture (-f) on Android requires a rooted device "
            "(tcpdump must run as root). Continuing without full capture; "
            "plaintext/keylog capture is unaffected.")

    def get_instance_of_FullCaptureThread(self):
        """A new, unstarted :class:`~friTap.pcap_full_capture.FullCaptureThread` for this capture."""
        return FullCaptureThread(self)


    def write_pcap_header(self, pcap_file):
        self.pcap_file = pcap_file
        for writes in (
            ("=I", 0xa1b2c3d4),     # Magic number
            ("=H", 2),              # Major version number
            ("=H", 4),              # Minor version number
            ("=i", time.timezone),  # GMT to local correction
            ("=I", 0),              # Accuracy of timestamps
            ("=I", 65535),          # Max length of captured packets
            ("=I", 101)):           # Data link type (LINKTYPE_IPV4 = 228) CHANGED TO RAW
            pcap_file.write(struct.pack(writes[0], writes[1]))
        return pcap_file    
    
    def __create_plaintext_pcap(self):
        # Shared per path: the Windows LSASS session writes the same -p file, and a
        # second private "wb" open would truncate it. Only the first opener writes the header.
        from .output.shared_output_file import open_shared_output_file
        pcap_file, _created = open_shared_output_file(
            self.pcap_file_name, "wb", 0, initializer=self.write_pcap_header)
        return pcap_file
    
    def log_plaintext_payload(self, ss_family, function, src_addr, src_port,
                 dst_addr, dst_port, data, transport="tcp", timestamp=None):
        """Write decrypted *data* to the ``-p`` pcap as synthetic IP+TCP (or IP+UDP) records.

        *function* ("SSL_read"/"SSL_write") gives the direction. *transport* is
        "udp" for QUIC plaintext. *timestamp* is epoch seconds; None means now.
        """

        t = time.time() if timestamp is None else timestamp

        # Plaintext from app-level decrypt hooks (Signal, Telegram Secret Chat) often
        # has no socket 5-tuple, so addr/port arrive as "" or None. The headers pack
        # integers, so non-integers become a 0.0.0.0:0 placeholder instead of raising
        # struct.error. IPv6 hex strings are packed by _ipv6_bytes, so only IPv4 is forced.
        if ss_family != "AF_INET6":
            if not isinstance(src_addr, int):
                src_addr = 0
            if not isinstance(dst_addr, int):
                dst_addr = 0
        if not isinstance(src_port, int):
            src_port = 0
        if not isinstance(dst_port, int):
            dst_port = 0

        if not _endpoints_packable(ss_family, src_addr, src_port,
                                   dst_addr, dst_port, self.logger):
            return

        self._record_server_port(transport, function, src_port, dst_port)

        if transport == "udp":
            self._log_plaintext_payload_udp(
                ss_family, src_addr, src_port, dst_addr, dst_port, data, t)
            return

        if ss_family not in ("AF_INET", "AF_INET6"):
            self.logger.warning("Packet has unknown/unsupported family!")
            return

        is_read = is_read_function(function)
        if is_read:
            session_unique_key = str(src_addr) + str(src_port) + \
                str(dst_addr) + str(dst_port)
        else:
            session_unique_key = str(dst_addr) + str(dst_port) + \
                str(src_addr) + str(src_port)
        if session_unique_key not in self.ssl_sessions:

            self.ssl_sessions[session_unique_key] = (random.randint(0, 0xFFFFFFFF),
                                                random.randint(0, 0xFFFFFFFF))

        # Payloads over one IP packet are split; each segment advances its
        # direction's sequence number so they reassemble to the original bytes.
        client_sent, server_sent = self.ssl_sessions[session_unique_key]
        for segment in split_payload(data, max_segment_payload(ss_family, "tcp")):
            seq, ack = (server_sent, client_sent) if is_read else (client_sent, server_sent)
            _write_tcp_segment(self.pcap_file, ss_family, t, src_addr, src_port,
                               dst_addr, dst_port, seq, ack, segment)
            if is_read:
                server_sent = (server_sent + len(segment)) & 0xFFFFFFFF
            else:
                client_sent = (client_sent + len(segment)) & 0xFFFFFFFF
        self.ssl_sessions[session_unique_key] = (client_sent, server_sent)


    def _log_plaintext_payload_udp(self, ss_family, src_addr, src_port,
                 dst_addr, dst_port, data, t):
        """Write QUIC plaintext as IP+UDP datagrams.

        No seq/ack or ssl_sessions state; a payload over one IP packet becomes
        several datagrams.
        """
        if ss_family not in ("AF_INET", "AF_INET6"):
            self.logger.warning("Packet has unknown/unsupported family!")
            return
        for segment in split_payload(data, max_segment_payload(ss_family, "udp")):
            _write_udp_datagram(self.pcap_file, ss_family, t, src_addr, src_port,
                                dst_addr, dst_port, segment)


    @staticmethod
    def get_filter_from_traced_sockets(traced_Socket_Set, filter_type="bpf"):
        """Build a "bpf" or Wireshark "display" filter string from a set of socket frozensets."""
        filters = []
        for socket_info in traced_Socket_Set:
            socket_dict = dict(socket_info)  # Convert frozenset back to a dictionary
            src_addr = socket_dict.get("src_addr", "0.0.0.0")
            dst_addr = socket_dict.get("dst_addr", "0.0.0.0")

            if src_addr == "::" or dst_addr == "::" or not src_addr or not dst_addr:
                continue # Skip invalid entries
            
            if filter_type == "bpf":
                filter_part = PCAP.get_bpf_filter(src_addr, dst_addr)
            elif filter_type == "display":
                filter_part = PCAP.get_display_filter(src_addr, dst_addr)
            else:
                raise ValueError("Invalid filter_type. Use 'bpf' or 'display'.")
            
            if filter_part:
                filters.append(filter_part)
        
        return " or ".join(filters)



        
    def _temp_pcap_path(self):
        """Temp capture path produced by FullCaptureThread (``/tmp/c.pcapng`` -> ``/tmp/_c.pcapng``)."""
        return temp_capture_path(self.pcap_file_name)

    @staticmethod
    def _write_minimal_pcapng_with_keys(output_pcapng, formatted_keys, link_type=1):
        """Write a zero-packet pcapng (SHB + IDB + optional DSB).

        Used by ``_emit_pcapng_with_dsb`` when the source pcap is missing or
        unreadable, so the keys survive. Default link type is DLT_EN10MB (1).
        """
        from .output.pcapng_blocks import build_dsb, build_idb, build_shb
        with open(output_pcapng, "wb") as fh:
            fh.write(build_shb())
            fh.write(build_idb(link_type=link_type))
            if formatted_keys:
                secrets = ("\n".join(formatted_keys) + "\n").encode("utf-8")
                fh.write(build_dsb(secrets))

    def _emit_pcapng_with_dsb(self, source_pcap, output_pcapng,
                              formatted_keys, bpf_filter=None):
        """Emit a pcapng of *source_pcap* with a DSB block embedding *formatted_keys*.

        Streams via PcapReader so multi-GB captures stay out of memory; a BPF
        filter falls back to ``sniff`` (scapy's BPF needs the L2 layer). A missing
        or empty source still yields a minimal SHB+IDB(+DSB) pcapng so the keys survive.

        Returns True when *source_pcap* is no longer needed, False when it could
        not be read (the caller then keeps the raw capture).
        """
        from .output.pcapng_blocks import build_dsb, build_epb, build_idb, build_shb

        source_missing = (
            not source_pcap
            or not os.path.exists(source_pcap)
            or os.path.getsize(source_pcap) == 0
        )
        if source_missing:
            self.logger.warning(
                "Full-capture source pcap missing or empty (%s); "
                "writing zero-packet %s with embedded keys",
                source_pcap, output_pcapng,
            )
            self._write_minimal_pcapng_with_keys(output_pcapng, formatted_keys)
            return True

        try:
            _validate_capture(source_pcap)
            with PcapReader(source_pcap) as reader:
                linktype = reader.linktype
                with open(output_pcapng, "wb") as fh:
                    fh.write(build_shb())
                    fh.write(build_idb(link_type=linktype))
                    if formatted_keys:
                        secrets = ("\n".join(formatted_keys) + "\n").encode("utf-8")
                        fh.write(build_dsb(secrets))
                    packets = (
                        sniff(offline=source_pcap, filter=bpf_filter)
                        if bpf_filter else reader
                    )
                    for pkt in packets:
                        t_us = int(float(pkt.time) * 1_000_000)
                        fh.write(build_epb(bytes(pkt), t_us))
            return True
        except (EOFError, struct.error, Scapy_Exception, ValueError, MemoryError) as exc:
            # Truncated/corrupt source (ValueError covers CaptureFormatError from
            # the length pre-check): still produce a usable keys-only output.
            self.logger.error(
                "PCAPNG finalization failed reading %s: malformed or truncated "
                "capture (%s: %s) — emitting keys-only output",
                source_pcap, type(exc).__name__, exc,
            )
            self._write_minimal_pcapng_with_keys(output_pcapng, formatted_keys)
            return False

    def writes_pcapng(self):
        """True when the -p file is pcapng (the resolved ``pcap_container``)."""
        return self.pcap_container == PCAP_FORMAT_PCAPNG

    def _emit_final(self, source_pcap, formatted_keys, bpf_filter=None):
        """Emit the final -p file in the resolved container format.

        pcapng: fresh file with an embedded DSB. Classic with a filter: filtered
        pcap. Classic without: rename in place (same filesystem, since the temp
        sits beside the final).

        The temp capture is removed once the final file holds its packets. One
        that could not be converted (or an exception mid-write) is kept and
        logged, so no packets are lost.
        """
        consumed = False
        try:
            consumed = self._write_final_from(source_pcap, formatted_keys, bpf_filter)
        finally:
            self._dispose_temp_capture(source_pcap, consumed)

    def _write_final_from(self, source_pcap, formatted_keys, bpf_filter):
        """Write the final -p file; True when *source_pcap* is no longer needed."""
        if self.writes_pcapng():
            return self._emit_pcapng_with_dsb(
                source_pcap, self.pcap_file_name, formatted_keys, bpf_filter,
            )
        if bpf_filter:
            return self._write_filtered_pcap(source_pcap, bpf_filter)
        os.replace(source_pcap, self.pcap_file_name)
        return True

    def _dispose_temp_capture(self, source_pcap, consumed):
        """Remove the staged temp capture once consumed; otherwise report it."""
        if not source_pcap or not os.path.exists(source_pcap):
            return
        if not consumed:
            self.logger.warning(f"The raw full capture was kept at {source_pcap}")
            return
        try:
            os.remove(source_pcap)
        except OSError as exc:
            self.logger.warning(f"Could not remove the temp capture {source_pcap}: {exc}")

    def _write_filtered_pcap(self, source_pcap, bpf_filter):
        """Write the BPF-filtered packets of *source_pcap* as the final classic pcap.

        A malformed temp capture is left in place and reported instead of raising.
        Returns True when the final file was written.
        """
        try:
            _validate_capture(source_pcap)
            wrpcap(self.pcap_file_name, sniff(offline=source_pcap, filter=bpf_filter))
            return True
        except (EOFError, struct.error, Scapy_Exception, ValueError, MemoryError) as exc:
            self.logger.error(
                "Full-capture finalization failed reading %s: malformed or "
                "truncated capture (%s: %s); the unfiltered temp capture is kept",
                source_pcap, type(exc).__name__, exc,
            )
            return False

    def _record_server_port(self, transport, function, src_port, dst_port):
        """Record the distinct server (destination) port for the manifest.

        On a read the server is the source; on a write it is the destination.
        Best-effort, never raises.
        """
        try:
            # The server side depends on direction only, never on transport.
            if is_read_function(function):
                server_port = src_port
            else:
                server_port = dst_port
            # QUIC plaintext rides on UDP; everything else is filed as TCP.
            transport_key = "udp" if transport == "udp" else "tcp"
            if isinstance(server_port, int) and server_port > 0:
                self._observed_server_ports[transport_key].add(server_port)
        except Exception:
            self.logger.debug("Could not record server port for manifest", exc_info=True)

    def _seed_server_ports_from_sockets(self, valid_sockets):
        """Best-effort: add destination ports from traced sockets to the manifest sets.

        Socket dicts may lack port/transport keys, so every lookup is optional.
        The agent's socket descriptors carry no transport field (see
        ssl_logger_core._on_message), so a ``ss_protocol``/``protocol`` hint is
        honored only if present; otherwise ports are filed under TCP. UDP/QUIC
        ports seeded only from a socket trace are therefore filed as TCP; ports
        from ``_record_server_port`` have a real transport, and ``--quic-port``
        records QUIC ports explicitly.
        """
        try:
            for sock in valid_sockets:
                dst_port = sock.get("dst_port") or sock.get("dstport")
                if not isinstance(dst_port, int):
                    try:
                        dst_port = int(dst_port)
                    except (TypeError, ValueError):
                        continue
                if dst_port <= 0:
                    continue
                proto = str(sock.get("ss_protocol") or sock.get("protocol") or "").lower()
                transport_key = "udp" if "udp" in proto else "tcp"
                self._observed_server_ports[transport_key].add(dst_port)
        except Exception:
            self.logger.debug("Could not seed server ports from sockets", exc_info=True)

    @staticmethod
    def _keylog_with_content(*candidates) -> "str | None":
        """First candidate keylog path that exists and is non-empty.

        On Windows the LSASS worker writes TLS secrets to the base ``-k`` file and
        never creates the split ``<base>.tls.log``; recording that phantom path
        makes offline replay fail with "keylog file not found". Falls back to the
        first non-empty-name candidate when none has content.
        """
        for path in candidates:
            if PCAP._is_written_keylog(path):
                return str(path)
        for path in candidates:
            if path:
                return str(path)
        return None

    @staticmethod
    def _is_written_keylog(path) -> bool:
        """Whether *path* names an existing keylog file that holds content."""
        return is_non_empty_file(path)

    @staticmethod
    def _tls_keylog_candidates(pcap) -> tuple:
        """TLS keylog candidates in manifest priority: split, base ``-k``, last handler."""
        active_keylogs = getattr(pcap, "active_keylogs", None) or {}
        return (
            active_keylogs.get("tls"),
            getattr(pcap, "base_keylog_path", None),
            getattr(pcap, "keylog_path", None),
        )

    @staticmethod
    def _resolve_written_keylog(pcap) -> "str | None":
        """First TLS keylog candidate of *pcap* that exists with content.

        Static so ``_write_capture_manifest`` also works on the stubs tests bind it to.
        """
        for path in PCAP._tls_keylog_candidates(pcap):
            if PCAP._is_written_keylog(path):
                return str(path)
        return None

    def written_keylog_path(self) -> "str | None":
        """The TLS keylog that was really written (exists, non-empty), else ``None``.

        The manifest and the shutdown decryption hint both ask this so they agree.
        Resolved at call time, since the first key may arrive after startup.
        """
        return self._resolve_written_keylog(self)

    def set_active_keylogs(self, mapping: dict) -> None:
        """Record the per-protocol split keylog paths for the manifest.

        Called when the single ``-k`` path was split per protocol. Stored as a
        shallow copy; surfaced in the manifest as "keylogs".
        """
        self.active_keylogs = dict(mapping or {})

    def set_base_keylog(self, path) -> None:
        """Record the un-split base ``-k`` path for the manifest fallback.

        Called with :meth:`set_active_keylogs`. A SChannel/LSASS TLS session writes
        its secrets here when the ``<base>.tls`` split is never produced, so the
        manifest falls back to it instead of a phantom split path.
        """
        self.base_keylog_path = path or None

    def set_memory_scan_keylogs(self, mapping: dict) -> None:
        """Record the memory-scan (``-ms``) keylog paths for the manifest.

        *mapping* is ``{protocol: path}`` (``"tls"`` = the NSS memscan keylog,
        ``"mtproto"``/``"telegram"`` = its ``.mtproto.keylog`` sidecar). Fallback
        key source when no hooked-key keylog exists. Only paths the scanner
        actually wrote are recorded, since the files are created lazily.
        """
        self.memory_scan_keylogs = dict(mapping or {})

    def set_tls_midstream_secrets_path(self, path) -> None:
        """Record the mid-stream TLS secret-bundle sidecar path the engine intends.

        The engine owns this path (including its current-directory fallback);
        recording it avoids recomputing it from the keylog stem and diverging
        from the writer. A falsy path is ignored.
        """
        if path:
            self._tls_midstream_secrets_path = str(path)

    def set_request_contexts_path(self, path) -> None:
        """Record the ``.request_contexts.jsonl`` sidecar for the manifest. A falsy path is ignored."""
        if path:
            self._request_contexts_path = str(path)

    def set_quic_synthetic_keylog_path(self, path) -> None:
        """Record the ``-p`` synthetic-QUIC keylog sidecar for the manifest. A falsy path is ignored."""
        if path:
            self._quic_synthetic_keylog_path = str(path)

    def set_endpoint_pinner(self, pinner) -> None:
        """Hand over the router's option-5 :class:`~friTap.endpoint_pinner.EndpointPinner`.

        Its synthetic -> real mapping table drives the ``-p`` rewrite at stop
        (:meth:`finalize_plaintext_capture`).
        """
        self._endpoint_pinner = pinner

    def finalize_plaintext_capture(self) -> None:
        """Finalize the closed ``-p`` pcap: rewrite synthetic streams, record the summary.

        Only acts when the pinner pinned synthetic connections and the -p file
        is a regular file (not a live FIFO). Never raises.
        """
        try:
            manifest = {}
            summary = self._rewrite_synthetic_streams()
            if summary is not None:
                manifest["synthetic_endpoints"] = summary
            quic_keylog = getattr(self, "_quic_synthetic_keylog_path", None)
            if is_non_empty_file(quic_keylog):
                manifest["quic_synthetic_keylog"] = quic_keylog
            if manifest:
                self._write_plaintext_manifest(manifest)
        except Exception:  # noqa: BLE001 - finalize must never break teardown
            self.logger.debug("plaintext pcap finalize failed", exc_info=True)

    def _rewrite_synthetic_streams(self):
        """Rewrite the pinned synthetic streams; the summary, or None when nothing to do."""
        pinner = getattr(self, "_endpoint_pinner", None)
        mappings = pinner.mappings() if pinner is not None else []
        if not mappings or not os.path.isfile(self.pcap_file_name):
            return None
        from .pcap_tuple_rewrite import rewrite_synthetic_endpoints
        summary = rewrite_synthetic_endpoints(self.pcap_file_name, mappings, self.logger)
        self._add_mapping_overflow(summary, pinner)
        return summary

    @staticmethod
    def _add_mapping_overflow(summary: dict, pinner) -> None:
        """Record ``mapping_overflow`` (pins left out of a full mapping table) when > 0."""
        overflow = getattr(pinner, "mapping_overflow_count", 0) or 0
        if overflow > 0:
            summary["mapping_overflow"] = overflow

    def _write_plaintext_manifest(self, manifest: dict) -> None:
        """Write ``<pcap>.fritap.json`` for a ``-p`` capture (plaintext-only keys).

        TLS port and keylog keys are left out: they would make offline replay try
        to decrypt plaintext.
        """
        import json as _json
        manifest_path = self.pcap_file_name + MANIFEST_SUFFIX
        try:
            with open(manifest_path, "w", encoding="utf-8") as fh:
                _json.dump(manifest, fh, indent=2)
            self.logger.debug(f"Wrote capture manifest {manifest_path}")
        except OSError as e:
            self.logger.warning(f"Could not write capture manifest: {e}")

    def _add_known_server_ports(self, transport_key, ports) -> None:
        """Seed explicit server ports into ``_observed_server_ports[transport_key]``.

        Behind ``set_known_tls_ports`` / ``set_known_quic_ports``. Each port is
        coerced to a positive int; anything else is skipped.
        """
        if not ports:
            return
        try:
            for port in ports:
                try:
                    port_int = int(port)
                except (TypeError, ValueError):
                    continue
                if port_int > 0:
                    self._observed_server_ports[transport_key].add(port_int)
        except Exception:
            self.logger.debug("Could not seed known server ports", exc_info=True)

    def set_known_tls_ports(self, ports) -> None:
        """Record explicit TLS (TCP) server ports for the manifest.

        Seeds ``tls_ports`` from ``--tls-port`` so a pure ``--full_capture`` that
        never sees a non-standard TLS server (e.g. 127.0.0.1:8443) still lets
        offline Decode-As recover TLS (and nested RC4) streams there.
        """
        self._add_known_server_ports("tcp", ports)

    def set_known_quic_ports(self, ports) -> None:
        """Record explicit QUIC (UDP) server ports for the manifest.

        UDP counterpart of ``set_known_tls_ports`` for ``--quic-port``.
        """
        self._add_known_server_ports("udp", ports)

    def _write_capture_manifest(self):
        """Write a best-effort ``<pcap>.fritap.json`` sidecar manifest.

        Records the TLS (TCP) and QUIC (UDP) server ports plus keylog paths so
        offline ``--from-pcap`` can auto-load Decode-As ports and keys. A write
        failure never breaks finalize.

        Ports come from ``log_plaintext_payload``, which a pure full capture never
        calls, so they are also seeded from traced sockets. Without
        ``--socket_trace`` the sets may stay empty; ``--tls-port``/``--quic-port``
        record ports explicitly.
        """
        write_capture_manifest(self)

    def finalize_full_capture(self, formatted_keys=(), traced_Socket_Set=None):
        """Finalize the unfiltered full capture at ``self.pcap_file_name`` (DSB for pcapng).

        ``traced_Socket_Set`` (frozenset socket descriptors) seeds the manifest
        ports, since a pure ``--full_capture`` never records them via plaintext
        logging. A capture that never started (unrooted device, failed spawn)
        leaves no temp file; that is logged as information, not an error.
        """
        if not os.path.exists(self._temp_pcap_path()):
            self.logger.info(
                f"No full-capture data to finalize ({self._temp_pcap_path()} does not "
                f"exist; the capture never started), so {self.pcap_file_name} was not written.")
            return
        try:
            self._emit_final(self._temp_pcap_path(), formatted_keys, bpf_filter=None)
        except Exception as e:
            self.logger.error(f"Error finalizing full capture: {e}")
        else:
            self.logger.info(f"Full capture written to {self.pcap_file_name}")
            # A full capture holds only ciphertext; point at offline replay.
            self.logger.info(
                f"To replay/decrypt this capture, run:  fritap -r {self.pcap_file_name}")
        # The only chance to record ports for a pure full capture.
        if traced_Socket_Set:
            socket_dicts = [dict(entry) for entry in traced_Socket_Set]
            self._seed_server_ports_from_sockets(socket_dicts)
        if not (self._observed_server_ports.get("tcp")
                or self._observed_server_ports.get("udp")):
            # Common for pure --full_capture without --socket_trace. Ports are not
            # faked; standard-port protocols need no hint, so this stays at debug.
            self.logger.debug(
                "No server ports recorded for this full capture. This is "
                "informational and harmless for standard-port protocols "
                "(e.g. Signal/HTTPS on 443). For non-standard server ports, "
                "pass --tls-port/--quic-port (or --socket_trace) so offline "
                "custom-port auto-detection works."
            )
        self._write_capture_manifest()

    def create_application_traffic_pcap(self, traced_Socket_Set, pcap_obj,
                                        is_verbose=False, formatted_keys=()):
        """Reduce the temp full capture to the traced app's traffic via a BPF filter.

        Writes ``self.pcap_file_name`` (pcap or pcapng+DSB). With no usable sockets
        or filter it falls back to ``finalize_full_capture`` so a final file exists.
        """
        def is_valid_socket(socket_info):
            return (
                socket_info.get("src_addr") and socket_info.get("dst_addr")
                and socket_info.get("src_addr") != INVALID_IPV4
                and socket_info.get("dst_addr") != INVALID_IPV4
                and socket_info.get("src_addr") != INVALID_IPV6
                and socket_info.get("dst_addr") != INVALID_IPV6
            )

        if not traced_Socket_Set:
            self.logger.error("No sockets traced. Falling back to full capture.")
            return self.finalize_full_capture(formatted_keys)

        socket_dicts = [dict(frozenset_entry) for frozenset_entry in traced_Socket_Set]
        valid_sockets = [s for s in socket_dicts if is_valid_socket(s)]
        if not valid_sockets:
            self.logger.error("No valid sockets found. Falling back to full capture.")
            return self.finalize_full_capture(formatted_keys)

        self._seed_server_ports_from_sockets(valid_sockets)

        bpf_filter = PCAP.get_filter_from_traced_sockets(valid_sockets, filter_type="bpf")
        if not bpf_filter:
            self.logger.error("Failed to generate a valid BPF filter. Falling back to full capture.")
            return self.finalize_full_capture(formatted_keys)

        if is_verbose:
            self.logger.info(f"Filtering with BPF filter:\n{bpf_filter}")
        try:
            """
            There is currently a bug which is happening when invoking sniff. Currently we just ignore this warning:
            Exception ignored in: <function Popen.__del__ at 0x10ad64180>
            Traceback (most recent call last):
            File ".../subprocess.py", line 1127, in __del__
                _warn("subprocess %s is still running" % self.pid,
            ResourceWarning: subprocess 63901 is still running
            reading from file <name>.pcap, link-type LINUX_SLL2 (Linux cooked v2)
            """
            self._emit_final(self._temp_pcap_path(), formatted_keys, bpf_filter=bpf_filter)
        except Exception as e:
            self.logger.error(f"Error during PCAP filtering: {e}")
        else:
            self.logger.info(f"Successfully filtered. Output written to {self.pcap_file_name}")
        self._write_capture_manifest()

    
    
    def get_pcap_name(self):
        return self.pcap_file_name
    
    
    @staticmethod
    def get_display_filter(src_addr,dst_addr):
        return f"ip.src == {src_addr} and ip.dst == {dst_addr}"
    
    
    @staticmethod
    def get_bpf_filter(src_addr,dst_addr):
        if src_addr == "::" or dst_addr == "::" or not src_addr or not dst_addr:
            return ""  # Skip invalid entries
        return f"(src host {src_addr} and dst host {dst_addr})"
