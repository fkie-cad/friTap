#!/usr/bin/env python3
import logging
import ntpath
import os
import random
import struct
import subprocess
import time
import traceback
import warnings
from threading import Event, Thread

import psutil

from friTap.constants import build_infrastructure_bpf

from .android import Android
from .pcap_utility import is_pcapng_filename

# scapy emits "WARNING: No libpcap provider available ! pcap won't be used" from
# logging.getLogger("scapy.loading") at IMPORT time (scapy/config.py,
# _set_conf_sockets). friTap's core features do not need a host libpcap
# provider: -k (keylog) and -p (decrypted-payload pcap) are assembled by hand
# with struct.pack from bytes streamed by the Frida agent (write_pcap_header /
# log_plaintext_payload below), and wrpcap/PcapReader are pure-Python file I/O.
# Only -f/--full_capture and live auto-decrypt local capture need one, and those
# now raise their own actionable, platform-aware error. So the banner is pure
# noise on every Windows machine without Npcap.
#
# scapy/error.py only claims the "scapy" logger level while it is still NOTSET,
# so a level set *before* the import sticks; the NOTSET child "scapy.loading"
# inherits it. The level is restored afterwards so genuine runtime scapy
# warnings are not swallowed for the rest of the process.
_scapy_logger = logging.getLogger("scapy")
_scapy_prev_level = _scapy_logger.level
_scapy_logger.setLevel(logging.ERROR)
try:
    from scapy.all import ETH_P_ALL, Scapy_Exception, conf, sniff, wrpcap
    from scapy.utils import PcapReader
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    # Create dummy objects for testing environments
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
    
    # Only print warning if not in testing mode
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

# Silence scapy's *runtime* chatter (e.g. "Mac address to reach destination not
# found"). The *load-time* "No libpcap provider available" banner is handled by
# the logger guard around the scapy import above.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
warnings.simplefilter("ignore", ResourceWarning)


def _libpcap_hint() -> str:
    """Platform-aware guidance for a missing/unusable libpcap provider.

    Lazy import keeps friTap.pcap free of any import cycle with fritap_utility
    and matches the function-local-import convention used by other consumers.
    """
    from .fritap_utility import libpcap_provider_hint
    return libpcap_provider_hint()


DLT_EN10MB = 1
_ETHERTYPE_IPV4 = 0x0800
_ETHERTYPE_IPV6 = 0x86DD
_PCAP_MAGIC_TO_ENDIAN = {
    b"\xd4\xc3\xb2\xa1": "<", b"\x4d\x3c\xb2\xa1": "<",
    b"\xa1\xb2\xc3\xd4": ">", b"\xa1\xb2\x3c\x4d": ">",
}


def _packet_linktype(packet):
    """DLT scapy's pcap writer would record for ``packet`` (Ethernet if unknown)."""
    return conf.l2types.layer2num.get(type(packet), DLT_EN10MB)


def _existing_pcap_linktype(path):
    """Linktype from the header of an existing classic pcap at ``path``, else None.

    ``wrpcap(append=True)`` keeps an existing file's header, so its linktype —
    not the first packet of this run — is what every appended packet must match.
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

    A classic pcap has ONE linktype (fixed by its header), but ``--loopback``
    merges the primary NIC (Ethernet) with the loopback adapter, which is
    DLT_NULL on macOS (lo0) and Windows (Npcap loopback). Written as-is, the
    minority-linktype packets parse as garbage. Packets already of the target
    linktype pass through untouched; an IP/IPv6 packet is re-wrapped in a
    synthetic Ethernet header for an Ethernet file. Anything else cannot be
    represented faithfully and is dropped (None) rather than stored corrupt.
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

    Content-only packets (no socket 5-tuple) carry "", None or 0 instead; those
    map to the :: placeholder so the synthetic header can still be written.
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
    """Write one pcap record (packed *fields* followed by *data*) in ONE write.

    The plaintext pcap may be shared by several sessions (the Windows LSASS
    worker writes the same ``-p`` file, see :mod:`friTap.output.shared_output_file`);
    a single write keeps each record contiguous. The bytes are identical to
    writing every field separately.
    """
    header = b"".join(struct.pack(fmt, value) for fmt, value in fields)
    pcap_file.write(header + data)


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


# Slack for coarse filesystem mtime resolution (FAT/exFAT store 2 s steps), so a
# sidecar written in the first instant of this run is never mistaken for stale.
_MTIME_SLACK_SECONDS = 2.0


def _written_this_session(path, not_before) -> bool:
    """Whether *path* is a non-empty file last modified at/after *not_before*.

    ``not_before=None`` skips the age check (callers without a session clock).
    """
    try:
        stat = os.stat(path)
    except OSError:
        return False
    if stat.st_size == 0:
        return False
    return not_before is None or stat.st_mtime >= not_before - _MTIME_SLACK_SECONDS


def _existing_keylog_files(mapping, not_before=None) -> dict:
    """Keep only the ``{protocol: path}`` entries this session actually wrote.

    Memory-scan sidecars (e.g. ``<base>.memscan.mtproto.keylog``) have stable
    names and are only opened (``"w"``) when their first key arrives, so a file
    left behind by an EARLIER run survives untouched when this run finds no
    key. Existence alone would record that stale file in this run's manifest
    and merge foreign keys offline; requiring content written at/after
    *not_before* (the session start) excludes it without deleting anything.
    """
    return {proto: path for proto, path in (mapping or {}).items()
            if path and os.path.isfile(path) and _written_this_session(path, not_before)}


class PCAP:

    def __init__(self,pcap_file_name,SSL_READ,SSL_WRITE, doFullCapture, isMobile, print_debug_infos=False,
                 owner_capture=False, owner_capture_opts=None, target_package=None, target_pid=None,
                 include_loopback=False):
        self.pcap_file_name = pcap_file_name
        self.logger = logging.getLogger('friTap')
        # Full local capture (-f): also sniff the loopback interface so localhost
        # traffic (127.0.0.1 / ::1) is recorded. Default OFF — opt-in via --loopback
        # when a client talks to a local server (e.g. an RC4-in-TLS test server on
        # 127.0.0.1:8443), which is otherwise invisible to a capture on the primary NIC.
        # Best-effort: if the loopback adapter can't be opened (e.g. Npcap without
        # loopback support), the primary capture still runs.
        self.include_loopback = include_loopback
        # --owner-capture: delegate full capture to the AppTap library to acquire an
        # app-scoped (UID-scoped) pcap instead of capturing the whole device. These
        # are intent (config); the *runtime* state lives in apptap_session/
        # capture_tier/apptap_result, set once a session actually starts.
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

        # Distinct SERVER (destination) ports observed per transport, used to
        # write the best-effort <pcap>.fritap.json sidecar manifest so the
        # offline pcap-to-tap pipeline knows which ports to Decode-As.
        # {"tcp": {443, ...}, "udp": {443, ...}}
        self._observed_server_ports = {"tcp": set(), "udp": set()}
        # Keylog file path, if friTap is also exporting an SSLKEYLOGFILE.
        # Populated externally; recorded in the manifest when present.
        self.keylog_path = None
        # Un-split base ``-k`` path (config.output.keylog). In a multi-protocol
        # split capture the factory only hands us the per-protocol split paths,
        # never the base; on Windows the target's TLS is SChannel, so the
        # <base>.tls split is never written and the real TLS secrets land in this
        # base file (written by the separate LSASS session). Kept as a manifest
        # fallback so we record a keylog that actually exists. Populated externally.
        self.base_keylog_path = None
        # Wall-clock start of this capture session: memory-scan sidecars older
        # than this belong to an earlier run and are kept out of the manifest.
        self._session_started_at = time.time()
        # Active capture protocol (e.g. "mtproto", "telegram", "signal", "tls").
        # Populated externally; used to record a protocol-specific keylog field
        # in the manifest so offline decrypt routes the keys to the right
        # decryptor (not just the generic TLS SSLKEYLOGFILE).
        self.capture_protocol = None
        # Per-protocol split keylog paths, populated externally when multiple
        # protocol formatters are active (``--protocol all|auto``). Recorded in
        # the manifest under "keylogs" alongside the single "keylog" field so
        # the offline pipeline can locate every split keylog. {protocol: path}.
        self.active_keylogs = {}
        # Memory-scan (-ms) keylog paths, {protocol: path}; see
        # set_memory_scan_keylogs(). Populated externally.
        self.memory_scan_keylogs = {}

        if doFullCapture:
            if isMobile:
                self.logger.debug(f"Applying debug mode: {self.print_debug_infos}")
                self.android_Instance = Android(device_id=self.device_id)
            self.full_capture_thread = self.get_instance_of_FullCaptureThread()
            self.full_capture_thread.start()
            if self.full_capture_thread.is_alive():
                self.logger.info("capturing whole traffic of target app")
        else:
            self.logger.info("capturing only plaintext data")
            # When the user requested pcapng, PcapngOutputHandler will own
            # the file and write a proper SHB. Skip the legacy classic-pcap
            # header write that would otherwise be immediately overwritten.
            if is_pcapng_filename(self.pcap_file_name):
                self.pcap_file = None
            else:
                self.pcap_file = self.__create_plaintext_pcap()
            
    

    def _build_apptap_session(self, output):
        """Build an AppTap CaptureSession for owner-capture, or None to fall back.

        Reuses friTap's adb/root plumbing via the executor adapter (Android) or
        AppTap's LocalExecutor (Linux). Returns None when AppTap is unavailable or
        no target identity is known, so the caller falls back to whole-device.
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

    def get_instance_of_FullCaptureThread(self):

        pcap_class = self
        
        class FullCaptureThread(Thread):
            
            def __init__(self):
                super(FullCaptureThread,self).__init__()
                self.pcap_file_name = pcap_class.pcap_file_name
                self.daemon = True
                self.socket = None
                self.loopback_socket = None
                self.stop_capture = Event()
                self.tmp_pcap_name = self._get_tmp_pcap_name()
                self._file_linktype = None
                self._warned_linktype_drop = False

                self.mobile_subprocess = -1
                self.android_capture_process = -1    
                self.is_Mobile = pcap_class.is_Mobile
                
            
            def _get_pcap_base_name(self):
                head, tail = ntpath.split(self.pcap_file_name)
                return tail or ntpath.basename(head)
                
            
            def _get_pcap_dir_path(self):
                dirname_wihtout_last_delimiter = ntpath.dirname(self.pcap_file_name)
                if len(dirname_wihtout_last_delimiter) > 1:
                    return dirname_wihtout_last_delimiter + self.pcap_file_name[len(dirname_wihtout_last_delimiter):(len(dirname_wihtout_last_delimiter)+1)]
                else:
                    return dirname_wihtout_last_delimiter
            
            
            def _get_tmp_pcap_name(self):
                return self._get_pcap_dir_path()+"_"+self._get_pcap_base_name()
                
            
            def write_packet_to_pcap(self,packet):
                """Append ``packet`` to the temp pcap, matching the file's linktype.

                With --loopback, packets from two adapters of different
                linktypes share one classic pcap; see _normalize_to_linktype.
                """
                if self._file_linktype is None:
                    existing = _existing_pcap_linktype(self.tmp_pcap_name)
                    self._file_linktype = (existing if existing is not None
                                           else _packet_linktype(packet))
                normalized = _normalize_to_linktype(packet, self._file_linktype)
                if normalized is None:
                    self._warn_dropped_packet(packet)
                    return
                wrpcap(self.tmp_pcap_name, normalized, append=True)  #appends packet to output file

            def _warn_dropped_packet(self, packet):
                if self._warned_linktype_drop:
                    return
                self._warned_linktype_drop = True
                pcap_class.logger.warning(
                    "full capture: dropping %s packets that cannot be stored in a "
                    "linktype-%d pcap (mixed-interface capture via --loopback)",
                    type(packet).__name__, self._file_linktype)
            
            
            def clean_up_and_exit(self):
                """Gracefully exit the FullCaptureThread"""
                pcap_class.logger.info("Cleaning up FullCaptureThread resources.")

                if getattr(pcap_class, "apptap_session", None) is not None:
                    pcap_class.stop_owner_capture()

                if self.socket:
                    try:
                        pcap_class.logger.info("Closing network socket.")
                        self.socket.close()
                    except Exception as e:
                        pcap_class.logger.error(f"Error while closing the socket: {e}")
                if self.loopback_socket:
                    try:
                        self.loopback_socket.close()
                    except Exception as e:
                        pcap_class.logger.debug(f"Error while closing the loopback socket: {e}")
                if self.android_capture_process != -1:
                    try:
                        pcap_class.logger.info("Terminating android capture process.")
                        self.android_capture_process.terminate()
                        self.android_capture_process.wait(timeout=2)
                    except Exception as e:
                        pcap_class.logger.error(f"Error while terminating android capture process: {e}")

            
            
            def _open_loopback_socket(self):
                """Open an L2 listener on the loopback interface, or None (best-effort).

                On Windows this needs Npcap's loopback adapter (``conf.loopback_name``,
                e.g. "\\Device\\NPF_Loopback"); on Linux/macOS it is ``lo``/``lo0``. Any
                failure (no loopback adapter, no permission) is logged and returns None
                so the primary capture proceeds unaffected.
                """
                loop_name = getattr(conf, "loopback_name", None)
                if not loop_name:
                    pcap_class.logger.debug(
                        "loopback capture: scapy knows no loopback adapter; skipping "
                        "(on Windows, install Npcap with loopback support).")
                    return None
                try:
                    sock = conf.L2listen(type=ETH_P_ALL, iface=loop_name)
                    pcap_class.logger.info(
                        "also capturing loopback traffic on %s (enabled via --loopback)",
                        loop_name)
                    return sock
                except Exception as e:
                    pcap_class.logger.warning(
                        "loopback capture unavailable on %s (%s); continuing with the "
                        "primary interface. On Windows, install Npcap with loopback "
                        "support to capture 127.0.0.1 traffic.", loop_name, e)
                    return None

            def full_local_capture(self):
                if getattr(pcap_class, "owner_capture", False):
                    session = pcap_class._build_apptap_session(self.tmp_pcap_name)
                    if session is not None:
                        try:
                            session.start()
                            pcap_class.apptap_session = session
                            pcap_class.capture_tier = getattr(session, "_chosen", None)
                            pcap_class.logger.info(
                                "owner-capture: AppTap acquiring app-scoped pcap (tier=%s)",
                                pcap_class.capture_tier)
                            return
                        except Exception as exc:
                            pcap_class.logger.error(
                                "owner-capture: AppTap failed to start (%s); falling back "
                                "to whole-device capture", exc)
                            try:
                                session.teardown()
                            except Exception:
                                pass
                    # fall through to the legacy scapy capture below
                try:

                    self.socket = conf.L2listen(
                        type=ETH_P_ALL
                    )

                    # Also sniff loopback so localhost traffic (127.0.0.1 / ::1) is
                    # captured — a client talking to a local server is otherwise
                    # invisible on the primary NIC. Opt-in via --loopback and
                    # best-effort; a failure to open the loopback adapter degrades to
                    # primary-only.
                    sockets = [self.socket]
                    if getattr(pcap_class, "include_loopback", False):
                        self.loopback_socket = self._open_loopback_socket()
                        if self.loopback_socket is not None:
                            sockets.append(self.loopback_socket)

                    pcap_class.logger.info("doing full local capture")

                    sniff(
                        opened_socket=sockets if len(sockets) > 1 else self.socket,
                        filter=build_infrastructure_bpf(),
                        prn=self.write_packet_to_pcap,
                        stop_filter=self.stop_capture_thread
                    )
                except PermissionError as e:
                    pcap_class.logger.error(f"Full capture (-f) failed: {e}")
                    pcap_class.logger.error(_libpcap_hint())
                    self.clean_up_and_exit()
                except RuntimeError as e:
                    # Windows without Npcap: conf.L2listen resolves to scapy's
                    # _NotAvailableSocket, whose __init__ raises RuntimeError
                    # ("winpcap is not installed"). Catch it before the generic
                    # handler so the user gets the Npcap hint, not "Unknown error".
                    pcap_class.logger.error(f"Full capture (-f) failed: {e}")
                    pcap_class.logger.error(_libpcap_hint())
                    self.clean_up_and_exit()
                except Scapy_Exception as e:
                    pcap_class.logger.error(f"Full capture (-f) failed: {e}")
                    pcap_class.logger.error(_libpcap_hint())
                    self.clean_up_and_exit()
                except Exception as e:
                    pcap_class.logger.error(f"Full capture (-f) failed with an unexpected error: {e}")
                    pcap_class.logger.error(_libpcap_hint())
                    pcap_class.logger.debug("Full traceback for debugging:")
                    pcap_class.logger.debug(traceback.format_exc())
                    self.clean_up_and_exit()
                
                
            def run(self):
                if self.is_Mobile:
                    try:
                        self.mobile_subprocess = self.full_mobile_capture()
                    except Exception as e:
                        pcap_class.logger.error(f"Full mobile capture unavailable: {e}")
                        pcap_class.logger.debug(traceback.format_exc())
                        self.mobile_subprocess = -1
                else:
                    self.full_local_capture()
            
            
            def join(self, timeout=None):
                self.stop_capture.set()

                # owner-capture: AppTap owns its own capture process + teardown.
                if getattr(pcap_class, "apptap_session", None) is not None:
                    pcap_class.stop_owner_capture()
                    super().join(timeout)
                    return

                # Terminate the tcpdump process if running
                #if self.android_capture_process and self.android_capture_process.poll() in {None, -2, -15}:
                if self.is_Mobile and pcap_class.android_Instance.is_Android:
                    if self.android_capture_process != -1 and self.android_capture_process.poll() is None:
                        pcap_class.android_Instance.send_ctrlC_over_adb()
                        self.android_capture_process.terminate()
                        try:
                            self.android_capture_process.wait(timeout=2)  # Wait for graceful termination
                        except subprocess.TimeoutExpired:
                            pcap_class.logger.error("Android capture thread did not terminate. Forcing kill.")
                            self.android_capture_process.kill()

                super().join(timeout)
            
            
            def stop_capture_thread(self, packet):
                if hasattr(self.stop_capture, "is_set"):
                    status = self.stop_capture.is_set()
                else:
                    status = self.stop_capture.isSet()
                return status
                
                
            def full_mobile_capture(self):
                if pcap_class.android_Instance.is_Android:
                    if not pcap_class.android_Instance.adb_check_root():
                        pcap_class.logger.error(
                            "Full packet capture (-f) on Android requires a rooted device "
                            "(tcpdump must run as root). Continuing without full capture; "
                            "plaintext/keylog capture is unaffected.")
                        return -1

                    if getattr(pcap_class, "owner_capture", False):
                        session = pcap_class._build_apptap_session(self.tmp_pcap_name)
                        if session is not None:
                            try:
                                session.start()
                                pcap_class.apptap_session = session
                                pcap_class.capture_tier = getattr(session, "_chosen", None)
                                pcap_class.logger.info(
                                    "owner-capture: AppTap acquiring app-scoped pcap (tier=%s)",
                                    pcap_class.capture_tier)
                                # mobile_subprocess stays -1: AppTap owns its own
                                # capture process and teardown; legacy tcpdump skipped.
                                return -1
                            except Exception as exc:
                                pcap_class.logger.error(
                                    "owner-capture: AppTap failed to start (%s); falling back "
                                    "to whole-device capture", exc)
                                try:
                                    session.teardown()
                                except Exception:
                                    pass
                        # fall through to the legacy whole-device capture below

                    if not pcap_class.android_Instance.is_tcpdump_available:
                        pcap_class.android_Instance.install_tcpdump()
                    self.android_capture_process = pcap_class.android_Instance.run_tcpdump_capture("_"+self._get_pcap_base_name())

                    pcap_class.logger.info("doing full capture on Android")
                    return self.android_capture_process
                else:
                    pcap_class.logger.error("currently a full capture on iOS is not supported\nAbborting...")
                    exit(2)
                    
        ## End of inner class FullCaptureThread 
        instance_of_thread_class = FullCaptureThread()
        return instance_of_thread_class
   
     
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
        # Shared per path: the Windows LSASS session logs plaintext into the same
        # -p file, and a second private "wb" open would truncate this one. Only
        # the first opener writes the global header.
        from .output.shared_output_file import open_shared_output_file
        pcap_file, _created = open_shared_output_file(
            self.pcap_file_name, "wb", 0, initializer=self.write_pcap_header)
        return pcap_file
    
    def log_plaintext_payload(self, ss_family, function, src_addr, src_port,
                 dst_addr, dst_port, data, transport="tcp"):
        """Writes the captured data to a pcap file.
        Args:
        pcap_file: The opened pcap file.
        ss_family: The family of the connection, IPv4/IPv6
        function: The function that was intercepted ("SSL_read" or "SSL_write").
        src_addr: The source address of the logged packet.
        src_port: The source port of the logged packet.
        dst_addr: The destination address of the logged packet.
        dst_port: The destination port of the logged packet.
        data: The decrypted packet data.
        transport: "tcp" (default) or "udp". QUIC plaintext rides on UDP and
                   must be framed as IP+UDP (protocol 17) rather than IP+TCP.
        """

        t = time.time()

        # Plaintext captured at an application decrypt boundary (Signal / Telegram
        # Secret-Chat E2E and other out-of-band-content hooks) frequently has no
        # socket 5-tuple, so src/dst addr+port arrive as "" (or None). The
        # synthetic IP/TCP(/UDP) header below packs them as integers, so normalize
        # any non-integer to 0 — a 0.0.0.0:0 placeholder. The addresses are purely
        # cosmetic for these content-only packets; this keeps the pcap writer from
        # raising struct.error and dropping the payload.
        # IPv6 addresses legitimately arrive as 32-char hex strings; those are
        # packed via _ipv6_bytes() below, so only IPv4 addresses are forced to int.
        if ss_family != "AF_INET6":
            if not isinstance(src_addr, int):
                src_addr = 0
            if not isinstance(dst_addr, int):
                dst_addr = 0
        if not isinstance(src_port, int):
            src_port = 0
        if not isinstance(dst_port, int):
            dst_port = 0

        # Record the server-side port for the manifest. On a read the server is
        # the source; on a write it is the destination.
        self._record_server_port(transport, function, src_port, dst_port)

        if transport == "udp":
            self._log_plaintext_payload_udp(
                ss_family, src_addr, src_port, dst_addr, dst_port, data, t)
            return

        if function in self.SSL_READ:
            session_unique_key = str(src_addr) + str(src_port) + \
                str(dst_addr) + str(dst_port)
        else:
            session_unique_key = str(dst_addr) + str(dst_port) + \
                str(src_addr) + str(src_port)
        if session_unique_key not in self.ssl_sessions:

            self.ssl_sessions[session_unique_key] = (random.randint(0, 0xFFFFFFFF),
                                                random.randint(0, 0xFFFFFFFF))

        client_sent, server_sent = self.ssl_sessions[session_unique_key]

        if function in self.SSL_READ:
            seq, ack = (server_sent, client_sent)
        else:
            seq, ack = (client_sent, server_sent)
        if ss_family == "AF_INET":
            _write_pcap_record(self.pcap_file, (
                # PCAP record (packet) header
                # Timestamp seconds
                ("=I", int(t)),
                # Timestamp microseconds
                ("=I", int(t * 1000000) % 1000000),
                # Number of octets saved
                ("=I", 40 + len(data)),
                # Actual length of packet
                ("=i", 40 + len(data)),
                # IPv4 header
                # Version and Header Length
                (">B", 0x45),
                # Type of Service
                (">B", 0),
                # Total Length
                (">H", 40 + len(data)),
                # Identification
                (">H", 0),
                # Flags and Fragment Offset
                (">H", 0x4000),
                # Time to Live
                (">B", 0xFF),
                # Protocol
                (">B", 6),
                # Header Checksum
                (">H", 0),
                (">I", src_addr),                 # Source Address
                (">I", dst_addr),                 # Destination Address
                # TCP header
                (">H", src_port),                 # Source Port
                (">H", dst_port),                 # Destination Port
                (">I", seq),                      # Sequence Number
                (">I", ack),                      # Acknowledgment Number
                (">H", 0x5018),                   # Header Length and Flags
                (">H", 0xFFFF),                   # Window Size
                (">H", 0),                        # Checksum
                    (">H", 0)), data)                 # Urgent Pointer

        elif ss_family == "AF_INET6":
            _write_pcap_record(self.pcap_file, (
                # PCAP record (packet) header
                # Timestamp seconds
                ("=I", int(t)),
                # Timestamp microseconds
                ("=I", int(t * 1000000) % 1000000),
                # Number of octets saved
                ("=I", 60 + len(data)),
                # Actual length of packet
                ("=i", 60 + len(data)),
                # IPv6 header
                # Version, traffic class and Flow label
                (">I", 0x60000000),
                # Payload length
                (">H", 20 + len(data)),
                # Next Header
                (">B", 6),
                # Hop limit
                (">B", 0xFF),
                # Source Address
                (">16s", _ipv6_bytes(src_addr)),
                # Destination Address
                (">16s", _ipv6_bytes(dst_addr)),
                # TCP header
                (">H", src_port),                 # Source Port
                (">H", dst_port),                 # Destination Port
                (">I", seq),                      # Sequence Number
                (">I", ack),                      # Acknowledgment Number
                (">H", 0x5018),                   # Header Length and Flags
                (">H", 0xFFFF),                   # Window Size
                (">H", 0),                        # Checksum
                    (">H", 0)), data)                 # Urgent Pointer

        else:
            self.logger.warning("Packet has unknown/unsupported family!")

        if function in self.SSL_READ:
            server_sent += len(data)
        else:
            client_sent += len(data)
        self.ssl_sessions[session_unique_key] = (client_sent, server_sent)


    def _log_plaintext_payload_udp(self, ss_family, src_addr, src_port,
                 dst_addr, dst_port, data, t):
        """Writes the captured data to the pcap file framed as IP+UDP.

        Used for QUIC plaintext, which rides on UDP (protocol 17). Unlike the
        TCP path there is no seq/ack and no ssl_sessions bookkeeping — UDP is
        connectionless, so each datagram stands alone.
        """
        if ss_family == "AF_INET":
            _write_pcap_record(self.pcap_file, (
                # PCAP record (packet) header
                # Timestamp seconds
                ("=I", int(t)),
                # Timestamp microseconds
                ("=I", int(t * 1000000) % 1000000),
                # Number of octets saved
                ("=I", 28 + len(data)),
                # Actual length of packet
                ("=i", 28 + len(data)),
                # IPv4 header
                # Version and Header Length
                (">B", 0x45),
                # Type of Service
                (">B", 0),
                # Total Length
                (">H", 28 + len(data)),
                # Identification
                (">H", 0),
                # Flags and Fragment Offset
                (">H", 0x4000),
                # Time to Live
                (">B", 0xFF),
                # Protocol
                (">B", 17),
                # Header Checksum
                (">H", 0),
                (">I", src_addr),                 # Source Address
                (">I", dst_addr),                 # Destination Address
                # UDP header
                (">H", src_port),                 # Source Port
                (">H", dst_port),                 # Destination Port
                (">H", 8 + len(data)),            # UDP Length
                    (">H", 0)), data)                 # Checksum

        elif ss_family == "AF_INET6":
            _write_pcap_record(self.pcap_file, (
                # PCAP record (packet) header
                # Timestamp seconds
                ("=I", int(t)),
                # Timestamp microseconds
                ("=I", int(t * 1000000) % 1000000),
                # Number of octets saved
                ("=I", 48 + len(data)),
                # Actual length of packet
                ("=i", 48 + len(data)),
                # IPv6 header
                # Version, traffic class and Flow label
                (">I", 0x60000000),
                # Payload length
                (">H", 8 + len(data)),
                # Next Header
                (">B", 17),
                # Hop limit
                (">B", 0xFF),
                # Source Address
                (">16s", _ipv6_bytes(src_addr)),
                # Destination Address
                (">16s", _ipv6_bytes(dst_addr)),
                # UDP header
                (">H", src_port),                 # Source Port
                (">H", dst_port),                 # Destination Port
                (">H", 8 + len(data)),            # UDP Length
                    (">H", 0)), data)                 # Checksum

        else:
            self.logger.warning("Packet has unknown/unsupported family!")


    # creating a filter for scapy or wiresharks display filter depending on the provided socket_trace_set which looks like
    @staticmethod
    def get_filter_from_traced_sockets(traced_Socket_Set, filter_type="bpf"):
        """
        Generate a filter string from traced sockets.
        
        :param traced_Socket_Set: Set of frozensets containing socket info.
        :param filter_type: "bpf" for BPF filters or "display" for Wireshark display filters.
        :return: Filter string.
        """
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
        """Return the temp file path produced by FullCaptureThread.

        Mirrors ``_get_tmp_pcap_name`` in the inner thread class so the
        finalization helpers work for both relative and absolute filenames.
        For ``capture.pcapng`` → ``_capture.pcapng``; for
        ``/tmp/capture.pcapng`` → ``/tmp/_capture.pcapng``.
        """
        head, tail = os.path.split(self.pcap_file_name)
        base = tail or os.path.basename(head)
        return os.path.join(head, "_" + base) if head else "_" + base

    @staticmethod
    def _write_minimal_pcapng_with_keys(output_pcapng, formatted_keys, link_type=1):
        """Write a zero-packet pcapng (SHB + IDB + optional DSB).

        Used by ``_emit_pcapng_with_dsb`` when the source pcap is
        unavailable or unreadable, to ensure the user still keeps the
        TLS keys instead of getting a scapy traceback. Default link
        type is DLT_EN10MB (1) for the no-source-to-probe case.
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
        """Emit a pcapng of source_pcap to output_pcapng with a DSB block
        embedding all formatted_keys. Linktype is preserved from the source.

        Streams packets via PcapReader so multi-GB captures don't materialise
        the full PacketList in memory. When a BPF filter is supplied we fall
        back to ``sniff`` because scapy's BPF compilation needs the L2 layer.

        Defensive: if the source pcap is missing or zero-sized (e.g. the
        sniff thread saw no packets, or the temp file was already moved
        away), still write a minimal valid pcapng with SHB+IDB(+DSB) so
        the user keeps the TLS keys instead of getting a scapy traceback.
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
            return

        try:
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
        except (EOFError, struct.error, Scapy_Exception) as exc:
            # Truncated/corrupt source: log the path so the user can
            # inspect, but still produce a usable output with the keys.
            self.logger.error(
                "PCAPNG finalization failed reading %s: %s — emitting keys-only output",
                source_pcap, exc,
            )
            self._write_minimal_pcapng_with_keys(output_pcapng, formatted_keys)

    def _emit_final(self, source_pcap, formatted_keys, bpf_filter=None):
        """Decide format from self.pcap_file_name extension and emit accordingly.

        For .pcapng targets: emit a fresh pcapng with embedded DSB block.
        For .pcap (or unrecognised) with a filter: write filtered classic pcap.
        For .pcap with no filter: rename the temp file in place — source is
        already classic pcap, and the rename is on the same filesystem
        because _temp_pcap_path puts the temp alongside the final.
        """
        if is_pcapng_filename(self.pcap_file_name):
            self._emit_pcapng_with_dsb(
                source_pcap, self.pcap_file_name, formatted_keys, bpf_filter,
            )
        elif bpf_filter:
            wrpcap(self.pcap_file_name, sniff(offline=source_pcap, filter=bpf_filter))
        else:
            os.replace(source_pcap, self.pcap_file_name)

    def _record_server_port(self, transport, function, src_port, dst_port):
        """Record the distinct server (destination) port for the manifest.

        On a read the remote server is the *source*; on a write it is the
        *destination*. Best-effort and fully guarded — never raises.
        """
        try:
            # The server side of the 4-tuple is determined purely by the
            # *direction* of the call, never by transport (TCP vs UDP/QUIC):
            #   - on a READ the peer wrote to us, so the peer (server) is the
            #     source -> server_port = src_port
            #   - on a WRITE we wrote to the peer, so the peer (server) is the
            #     destination -> server_port = dst_port
            if function in self.SSL_READ:
                server_port = src_port
            else:
                server_port = dst_port
            # Choosing the transport bucket is an independent decision: QUIC
            # plaintext rides on UDP, everything else is recorded as TCP.
            transport_key = "udp" if transport == "udp" else "tcp"
            if isinstance(server_port, int) and server_port > 0:
                self._observed_server_ports[transport_key].add(server_port)
        except Exception:
            self.logger.debug("Could not record server port for manifest", exc_info=True)

    def _seed_server_ports_from_sockets(self, valid_sockets):
        """Best-effort: add destination ports from traced sockets to the manifest sets.

        Socket dicts are not guaranteed to carry port/transport keys, so every
        lookup is optional and the whole helper is guarded.

        Transport-bucket caveat: the traced-socket descriptors emitted by the
        agent (see ssl_logger_core._on_message) only carry src/dst addr+port and
        ss_family — there is *no* protocol/transport field. We therefore honor a
        transport hint *if one is ever present* (``ss_protocol``/``protocol``),
        but when none is available we fall back to TCP. This means UDP/QUIC
        server ports seeded purely from a socket trace are filed under TCP; we do
        not invent a transport we cannot observe. Ports recorded via the
        plaintext-logging path (``_record_server_port``) carry a real transport
        and are bucketed correctly, and the user can always pass
        ``--quic-port`` to record QUIC ports explicitly.
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
                # Honor a transport hint when the socket dict provides one;
                # otherwise default to TCP (see transport-bucket caveat above).
                proto = str(sock.get("ss_protocol") or sock.get("protocol") or "").lower()
                transport_key = "udp" if "udp" in proto else "tcp"
                self._observed_server_ports[transport_key].add(dst_port)
        except Exception:
            self.logger.debug("Could not seed server ports from sockets", exc_info=True)

    @staticmethod
    def _keylog_with_content(*candidates) -> "str | None":
        """Return the first candidate keylog path that exists AND is non-empty.

        Used to pick the TLS keylog for the manifest: the per-protocol split path
        is preferred, but on Windows the LSASS hook worker writes the TLS secrets to
        the BASE ``-k`` file, not the split ``<base>.tls.log`` (which is then never
        created). Recording that phantom split path makes an offline replay fail with
        "keylog file not found". Falling back to the base keylog (which actually holds
        the secrets) fixes it. Falls back to the first candidate when none has content
        (so the field is still populated for diagnostics).
        """
        for path in candidates:
            if not path:
                continue
            try:
                if os.path.isfile(path) and os.path.getsize(path) > 0:
                    return str(path)
            except OSError:
                continue
        for path in candidates:
            if path:
                return str(path)
        return None

    def set_active_keylogs(self, mapping: dict) -> None:
        """Record the per-protocol split keylog paths for the manifest.

        Called externally when multiple protocol formatters are active and the
        single ``-k`` path has been split per protocol. Stored defensively (a
        shallow copy) and surfaced in the manifest under the "keylogs" field.
        """
        self.active_keylogs = dict(mapping or {})

    def set_base_keylog(self, path) -> None:
        """Record the un-split base ``-k`` path for the manifest fallback.

        Called externally alongside :meth:`set_active_keylogs` in a multi-protocol
        split capture. The base file (``config.output.keylog``) is where a
        SChannel/LSASS TLS session writes its secrets when the ``<base>.tls`` split
        is never produced, so the manifest can fall back to it instead of recording
        a phantom split path.
        """
        self.base_keylog_path = path or None

    def set_memory_scan_keylogs(self, mapping: dict) -> None:
        """Record the memory-scan (``-ms``) keylog paths for the manifest.

        *mapping* is ``{protocol: path}`` (``"tls"`` = the NSS memscan keylog,
        ``"mtproto"``/``"telegram"`` = its ``.mtproto.keylog`` sidecar). Used as
        the fallback key source when no hooked-key keylog exists (e.g. a
        memory-scan-only full capture). Paths are only recorded if the scanner
        actually wrote them, since the files are created lazily.
        """
        self.memory_scan_keylogs = dict(mapping or {})

    def _add_known_server_ports(self, transport_key, ports) -> None:
        """Seed explicit server ports into ``_observed_server_ports[transport_key]``.

        Shared, fully-guarded helper behind ``set_known_tls_ports`` /
        ``set_known_quic_ports``. Each port is coerced to a positive int;
        anything else is skipped. Side-effect-free when *ports* is falsy, so a
        capture with no explicit ``--tls-port``/``--quic-port`` is unaffected.
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

        Called at capture-configure time when the user passes a capture-side
        ``--tls-port``; seeds ``_observed_server_ports["tcp"]`` so the manifest's
        ``tls_ports`` is populated even for a pure ``--full_capture`` that never
        observes the loopback/non-standard TLS server (e.g. 127.0.0.1:8443).
        This lets the offline Decode-As pipeline recover TLS (and nested RC4)
        streams on non-standard ports. Best-effort and side-effect-free when unset.
        """
        self._add_known_server_ports("tcp", ports)

    def set_known_quic_ports(self, ports) -> None:
        """Record explicit QUIC (UDP) server ports for the manifest.

        Capture-side counterpart of ``set_known_tls_ports`` for a capture-time
        ``--quic-port``; seeds ``_observed_server_ports["udp"]`` so the manifest's
        ``quic_ports`` covers non-standard QUIC server ports. Best-effort and
        side-effect-free when unset.
        """
        self._add_known_server_ports("udp", ports)

    def _write_capture_manifest(self):
        """Write a best-effort ``<pcap>.fritap.json`` sidecar manifest.

        Records the distinct TLS (TCP) and QUIC (UDP) server ports observed
        during capture plus the keylog path when known, so the offline
        ``--from-pcap`` pipeline can auto-load Decode-As ports and the keylog.

        Fully guarded: a manifest write failure never breaks capture finalize.

        NOTE: ports come from the plaintext-logging path (``log_plaintext_payload``),
        which sees every decrypted record's 4-tuple. In pure full-capture mode
        with no plaintext logging that path is never exercised, so the sets are
        additionally seeded from traced-socket destination ports when available:
        ``create_application_traffic_pcap`` seeds from its valid sockets and
        ``finalize_full_capture`` seeds from any ``traced_Socket_Set`` the caller
        passes. When no per-connection socket data exists at all (pure
        ``--full_capture`` without ``--socket_trace``) the sets may still be
        empty; this is acceptable for a best-effort convenience file and the
        user can pass ``--tls-port``/``--quic-port`` to record ports explicitly.
        """
        try:
            import json as _json
            manifest = {
                "tls_ports": sorted(self._observed_server_ports.get("tcp", set())),
                "quic_ports": sorted(self._observed_server_ports.get("udp", set())),
            }
            # When multiple protocol formatters are active (e.g. --protocol signal
            # also emits TLS keys) the single -k path is split per protocol into
            # <base>.<proto>.log siblings; the authoritative per-protocol paths
            # live in active_keylogs.
            active_keylogs = getattr(self, "active_keylogs", None) or {}
            # Heap-scanner keylogs that were actually written. They only fill in
            # when no hooked-key keylog exists (memory-scan-only capture), so an
            # offline replay still finds e.g. the .mtproto.keylog sidecar.
            memscan_keylogs = _existing_keylog_files(
                getattr(self, "memory_scan_keylogs", None),
                not_before=getattr(self, "_session_started_at", None),
            )
            if not self.keylog_path and memscan_keylogs:
                if "tls" in memscan_keylogs:
                    manifest["keylog"] = str(memscan_keylogs["tls"])
                try:
                    from friTap.offline.registry import get_offline_decryptor_registry
                    for entry in get_offline_decryptor_registry().list():
                        if entry.protocol_name == self.capture_protocol \
                                and entry.protocol_name in memscan_keylogs:
                            manifest[entry.cli_dest] = str(memscan_keylogs[entry.protocol_name])
                            break
                except Exception as e:
                    self.logger.debug(f"manifest memory-scan keylog mapping skipped: {e}")
            if memscan_keylogs:
                manifest["memory_scan_keylogs"] = {
                    proto: str(path) for proto, path in memscan_keylogs.items()
                }
            # Prefer the per-protocol TLS split, then the BASE -k file, then the
            # last-handler split path. On Windows the target's TLS is SChannel, so
            # the <base>.tls split is never written and the real TLS secrets land in
            # the base -k keylog (written by the separate LSASS session). The base
            # path is not carried in active_keylogs (the factory only hands us the
            # splits), so it is passed separately via set_base_keylog() and slotted
            # in here as the middle candidate. Resolved once, only when a keylog
            # field below will record it.
            base_keylog_path = getattr(self, "base_keylog_path", None)
            tls_keylog = (
                self._keylog_with_content(
                    active_keylogs.get("tls"), base_keylog_path, self.keylog_path)
                if self.keylog_path or "tls" in active_keylogs or base_keylog_path
                else None
            )
            # _keylog_with_content falls back to the first candidate even when none
            # exists; that tail is exactly what produced the phantom .tls path in the
            # manifest. Gate every keylog write below on a file that really exists
            # with content, so a never-written split is omitted, not recorded.
            tls_keylog_has_content = bool(
                tls_keylog
                and os.path.isfile(tls_keylog)
                and os.path.getsize(tls_keylog) > 0
            )
            if self.keylog_path:
                # Generic "keylog" = the TLS keylog (the SSLKEYLOGFILE a back-compat
                # consumer feeds to tshark to strip TLS first). In a multi-protocol
                # split capture (e.g. --protocol signal also emits TLS keys),
                # active_keylogs carries a per-protocol "tls" entry — prefer it so
                # this field is DETERMINISTICALLY the TLS split, not whichever
                # KeylogOutputHandler happened to set self.keylog_path last (the
                # protocol split would point a TLS consumer at the wrong keys and
                # decrypt nothing). Single-protocol captures have no "tls" split and
                # fall back to self.keylog_path unchanged. Only record it when the
                # resolved keylog actually exists — never emit a phantom path.
                if tls_keylog_has_content:
                    manifest["keylog"] = tls_keylog
                # Also record the keylog under the active protocol's offline
                # decryptor field (its registry cli_dest, e.g. "mtproto_keylog" /
                # "signal_keylog") so the manifest-driven offline pipeline routes
                # the keys to friTap's own decryptor instead of treating them as a
                # generic TLS SSLKEYLOGFILE (which yields 0 flows for MTProto/Signal).
                # CRITICAL: use the per-protocol SPLIT path when one exists — for a
                # multi-protocol capture the base -k path holds the TLS keys, NOT
                # the protocol's keys, so writing it here would point e.g.
                # signal_keylog at the TLS log and decrypt 0 Signal messages. A split
                # is recorded only when it was actually written (exists + non-empty);
                # a never-written split is dropped rather than recorded as a phantom,
                # while the base -k fallback (the hooked-key writer's own file) is kept.
                try:
                    from friTap.offline.registry import get_offline_decryptor_registry
                    for entry in get_offline_decryptor_registry().list():
                        if entry.protocol_name == self.capture_protocol:
                            proto_split = active_keylogs.get(entry.protocol_name)
                            if proto_split:
                                if os.path.isfile(proto_split) \
                                        and os.path.getsize(proto_split) > 0:
                                    manifest[entry.cli_dest] = str(proto_split)
                            else:
                                manifest[entry.cli_dest] = str(self.keylog_path)
                            break
                except Exception as e:
                    self.logger.debug(f"manifest protocol-keylog mapping skipped: {e}")
            # Record every per-protocol split path that was ACTUALLY written so the
            # offline pipeline can locate each keylog without chasing a phantom path
            # (a never-written <base>.tls/<base>.rc4 split is dropped). Only a
            # multi-protocol split capture populates active_keylogs; a single-protocol
            # capture leaves it empty and gets no "keylogs" field (unchanged). The
            # single "keylog" field above is preserved for back-compat.
            if active_keylogs:
                existing_active_keylogs = _existing_keylog_files(
                    active_keylogs,
                    not_before=getattr(self, "_session_started_at", None),
                )
                resolved_keylogs = {
                    proto: str(path) for proto, path in existing_active_keylogs.items()
                }
                # Overlay the resolved TLS keylog (which may be the base -k file, not
                # the split) so the offline pipeline's per-protocol map also points at
                # a keylog that exists.
                if tls_keylog_has_content:
                    resolved_keylogs["tls"] = tls_keylog
                if resolved_keylogs:
                    manifest["keylogs"] = resolved_keylogs
            manifest_path = f"{self.pcap_file_name}.fritap.json"
            with open(manifest_path, "w", encoding="utf-8") as fh:
                _json.dump(manifest, fh, indent=2)
            self.logger.debug(f"Wrote capture manifest {manifest_path}")
        except Exception as e:
            self.logger.warning(f"Could not write capture manifest: {e}")

    def finalize_full_capture(self, formatted_keys=(), traced_Socket_Set=None):
        """Finalize the *unfiltered* full capture: emit the temp file at
        ``self.pcap_file_name`` in the user-requested format. Embeds DSB
        when the target is pcapng.

        ``traced_Socket_Set`` (optional) is the caller's set of frozenset
        socket descriptors. When supplied, its destination ports seed the
        manifest's TLS/QUIC port sets so the offline pipeline's custom-port
        zero-config (Decode-As) still works even though pure ``--full_capture``
        never exercises the plaintext-logging path that normally records ports.
        """
        try:
            self._emit_final(self._temp_pcap_path(), formatted_keys, bpf_filter=None)
        except Exception as e:
            self.logger.error(f"Error finalizing full capture: {e}")
        else:
            self.logger.info(f"Full capture written to {self.pcap_file_name}")
            # A full capture holds only ciphertext; point the user at friTap's own
            # offline replay so they can decrypt it with the keylog they captured.
            self.logger.info(
                f"To replay/decrypt this capture, run:  fritap -r {self.pcap_file_name}")
        # Seed manifest ports from any per-connection socket data the caller has.
        # Pure full captures (no plaintext logging) never hit
        # log_plaintext_payload, so this is the only chance to record ports.
        if traced_Socket_Set:
            socket_dicts = [dict(entry) for entry in traced_Socket_Set]
            self._seed_server_ports_from_sockets(socket_dicts)
        if not (self._observed_server_ports.get("tcp")
                or self._observed_server_ports.get("udp")):
            # No reliable per-connection port/transport data was available at
            # finalize time (the common case for pure --full_capture without
            # --socket_trace). Don't fake ports — but this is harmless for
            # standard-port protocols (e.g. Signal/HTTPS on 443), where offline
            # decryption needs no custom-port hint. Only matters for non-standard
            # server ports; the user can record them with --tls-port/--quic-port
            # (or --socket_trace) when needed. Keep at debug to avoid alarming the
            # common case.
            self.logger.debug(
                "No server ports recorded for this full capture. This is "
                "informational and harmless for standard-port protocols "
                "(e.g. Signal/HTTPS on 443). For non-standard server ports, "
                "pass --tls-port/--quic-port (or --socket_trace) so offline "
                "custom-port auto-detection works."
            )
        self._write_capture_manifest()

    # this function is able to reduce a capture to the traffic from the traced target application by using the information from the socket trace and applying a bpf filter of those traced packets
    def create_application_traffic_pcap(self, traced_Socket_Set, pcap_obj,
                                        is_verbose=False, formatted_keys=()):
        """Filter the temp full capture down to application traffic and
        write the result at ``self.pcap_file_name`` in the user-requested
        format (pcap or pcapng+DSB).

        On any internal error (no sockets, no valid sockets, no BPF filter
        producible), falls back to ``finalize_full_capture`` so the user
        always gets a final file at the requested path with the right format.
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

        # Seed the manifest with destination ports from the traced sockets.
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
