"""The ``-f/--full_capture`` worker thread of a :class:`friTap.pcap.PCAP`.

Local captures sniff with scapy into the temp pcap; Android captures run
tcpdump on the device (pulled at teardown by ``PCAP.stop_device_capture``);
``--owner-capture`` hands either one to AppTap. The thread reads its owner's
config and teardown lock through ``self.pcap``, which may be a test stub.
"""
import atexit
import ntpath
import traceback
from threading import Event, Thread


def _pcap():
    """The ``friTap.pcap`` module, looked up at call time.

    Scapy names and capture helpers are read from it so tests that patch
    ``friTap.pcap.<name>`` (``conf``, ``sniff``, ``wrpcap``, ...) reach this code.
    """
    from . import pcap
    return pcap


class FullCaptureThread(Thread):
    """Daemon thread that runs the full capture for *pcap* until ``join``."""

    def __init__(self, pcap):
        super().__init__()
        self.pcap = pcap
        self.pcap_file_name = pcap.pcap_file_name
        self.daemon = True
        self.socket = None
        self.loopback_socket = None
        self.stop_capture = Event()
        self.tmp_pcap_name = self._get_tmp_pcap_name()
        self._file_linktype = None
        self._warned_linktype_drop = False

        self.mobile_subprocess = -1
        self.android_capture_process = -1
        self.is_Mobile = pcap.is_Mobile

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
        return _pcap().temp_capture_path(self.pcap_file_name)

    def write_packet_to_pcap(self, packet):
        """Append ``packet`` to the temp pcap, matching the file's linktype
        (see _normalize_to_linktype)."""
        pcap_module = _pcap()
        if self._file_linktype is None:
            existing = pcap_module._existing_pcap_linktype(self.tmp_pcap_name)
            self._file_linktype = (existing if existing is not None
                                   else pcap_module._packet_linktype(packet))
        normalized = pcap_module._normalize_to_linktype(packet, self._file_linktype)
        if normalized is None:
            self._warn_dropped_packet(packet)
            return
        pcap_module.wrpcap(self.tmp_pcap_name, normalized, append=True)  # appends packet to output file

    def _warn_dropped_packet(self, packet):
        if self._warned_linktype_drop:
            return
        self._warned_linktype_drop = True
        self.pcap.logger.warning(
            "full capture: dropping %s packets that cannot be stored in a "
            "linktype-%d pcap (mixed-interface capture via --loopback)",
            type(packet).__name__, self._file_linktype)

    def clean_up_and_exit(self):
        """Gracefully exit the FullCaptureThread"""
        pcap = self.pcap
        pcap.logger.info("Cleaning up FullCaptureThread resources.")

        if getattr(pcap, "apptap_session", None) is not None:
            pcap.stop_owner_capture()

        if self.socket:
            try:
                pcap.logger.info("Closing network socket.")
                self.socket.close()
            except Exception as e:
                pcap.logger.error(f"Error while closing the socket: {e}")
        if self.loopback_socket:
            try:
                self.loopback_socket.close()
            except Exception as e:
                pcap.logger.debug(f"Error while closing the loopback socket: {e}")
        if self.android_capture_process != -1:
            try:
                pcap.logger.info("Terminating android capture process.")
                self.android_capture_process.terminate()
                self.android_capture_process.wait(timeout=2)
            except Exception as e:
                pcap.logger.error(f"Error while terminating android capture process: {e}")

    def _open_loopback_socket(self):
        """Open an L2 listener on the loopback interface, or None on any failure.

        Windows needs Npcap's loopback adapter (``conf.loopback_name``); Linux and
        macOS use ``lo``/``lo0``. The primary capture proceeds regardless.
        """
        pcap_module = _pcap()
        conf = pcap_module.conf
        loop_name = getattr(conf, "loopback_name", None)
        if not loop_name:
            self.pcap.logger.debug(
                "loopback capture: scapy knows no loopback adapter; skipping "
                "(on Windows, install Npcap with loopback support).")
            return None
        try:
            sock = conf.L2listen(type=pcap_module.ETH_P_ALL, iface=loop_name)
            self.pcap.logger.info(
                "also capturing loopback traffic on %s (enabled via --loopback)",
                loop_name)
            return sock
        except Exception as e:
            self.pcap.logger.warning(
                "loopback capture unavailable on %s (%s); continuing with the "
                "primary interface. On Windows, install Npcap with loopback "
                "support to capture 127.0.0.1 traffic.", loop_name, e)
            return None

    def _start_owner_capture(self) -> bool:
        """Start an AppTap session into the temp pcap; True when AppTap now owns the capture.

        False when no session could be built or it failed to start (the caller
        falls back to whole-device capture).
        """
        pcap = self.pcap
        session = pcap._build_apptap_session(self.tmp_pcap_name)
        if session is None:
            return False
        try:
            session.start()
            pcap.apptap_session = session
            pcap.capture_tier = getattr(session, "_chosen", None)
            pcap.logger.info(
                "owner-capture: AppTap acquiring app-scoped pcap (tier=%s)",
                pcap.capture_tier)
            return True
        except Exception as exc:
            pcap.logger.error(
                "owner-capture: AppTap failed to start (%s); falling back "
                "to whole-device capture", exc)
            try:
                session.teardown()
            except Exception:
                pass
            return False

    def full_local_capture(self):
        pcap = self.pcap
        if getattr(pcap, "owner_capture", False) and self._start_owner_capture():
            return
        # Otherwise fall through to the scapy capture below.
        pcap_module = _pcap()
        try:
            self._sniff_until_stopped(pcap_module)
        except (PermissionError, RuntimeError, pcap_module.Scapy_Exception) as e:
            # RuntimeError: Windows without Npcap, where conf.L2listen is scapy's
            # _NotAvailableSocket raising RuntimeError("winpcap is not installed").
            # Caught before the generic handler so the user gets the Npcap hint.
            pcap.logger.error(f"Full capture (-f) failed: {e}")
            pcap.logger.error(pcap_module._libpcap_hint())
            self.clean_up_and_exit()
        except TypeError as e:
            # Shutdown race: the stop path closes the sockets while sniff() is
            # blocked in select_objects. A closed Windows pcap socket's fileno()
            # is None, so scapy's `i.fileno() < 0` raises TypeError. Benign
            # teardown artifact: end cleanly without the Npcap hint.
            if self._is_tearing_down():
                pcap.logger.debug(f"Full capture stopped during teardown ({e}).")
            else:
                self._log_unexpected_failure(e)
            self.clean_up_and_exit()
        except Exception as e:
            self._log_unexpected_failure(e)
            self.clean_up_and_exit()

    def _sniff_until_stopped(self, pcap_module):
        """Sniff the primary (and opt-in loopback) interface into the temp pcap until stopped."""
        pcap = self.pcap
        conf = pcap_module.conf
        self.socket = conf.L2listen(
            type=pcap_module.ETH_P_ALL
        )

        # Opt-in loopback sniffing; failure degrades to primary-only.
        sockets = [self.socket]
        if getattr(pcap, "include_loopback", False):
            self.loopback_socket = self._open_loopback_socket()
            if self.loopback_socket is not None:
                sockets.append(self.loopback_socket)

        pcap.logger.info("doing full local capture")

        capture_bpf = pcap_module.build_capture_bpf(
            filter_infrastructure=getattr(pcap, "filter_infrastructure", True),
            include_loopback=getattr(pcap, "include_loopback", False),
        )
        pcap_module.sniff(
            opened_socket=sockets if len(sockets) > 1 else self.socket,
            filter=capture_bpf or None,
            prn=self.write_packet_to_pcap,
            stop_filter=self.stop_capture_thread
        )

    def _is_tearing_down(self) -> bool:
        """Whether a sniff() TypeError comes from the stop path closing the sockets."""
        sc = getattr(self, "stop_capture", None)
        if sc is not None:
            try:
                if sc.is_set() if hasattr(sc, "is_set") else sc.isSet():
                    return True
            except Exception:
                pass
        for s in (self.socket, getattr(self, "loopback_socket", None)):
            if s is None:
                continue
            try:
                if s.fileno() is None:   # closed pcap handle -> teardown race
                    return True
            except Exception:
                return True   # fileno() on a dead socket -> teardown
        return False

    def _log_unexpected_failure(self, e):
        logger = self.pcap.logger
        logger.error(f"Full capture (-f) failed with an unexpected error: {e}")
        logger.error(_pcap()._libpcap_hint())
        logger.debug("Full traceback for debugging:")
        logger.debug(traceback.format_exc())

    def run(self):
        if self.is_Mobile:
            try:
                self.mobile_subprocess = self.full_mobile_capture()
            except Exception as e:
                self.pcap.logger.error(f"Full mobile capture unavailable: {e}")
                self.pcap.logger.debug(traceback.format_exc())
                self.mobile_subprocess = -1
        else:
            self.full_local_capture()

    def join(self, timeout=None):
        pcap = self.pcap
        self.stop_capture.set()

        # AppTap owns its capture process and teardown.
        if getattr(pcap, "apptap_session", None) is not None:
            pcap.stop_owner_capture()
            super().join(timeout)
            return

        if self.is_Mobile and pcap.android_Instance.is_Android:
            if self.android_capture_process != -1 and self.android_capture_process.poll() is None:
                # Stop tcpdump by pid (killing the local adb client alone
                # leaves it running), pull the pcap, delete the device file.
                pcap.stop_device_capture()

        super().join(timeout)

    def stop_capture_thread(self, packet):
        if hasattr(self.stop_capture, "is_set"):
            status = self.stop_capture.is_set()
        else:
            status = self.stop_capture.isSet()
        return status

    def full_mobile_capture(self):
        pcap = self.pcap
        if not pcap.android_Instance.is_Android:
            pcap.logger.error("currently a full capture on iOS is not supported\nAbborting...")
            exit(2)
        if not pcap.android_Instance.adb_check_root():
            pcap._log_root_unavailable()
            return -1

        if getattr(pcap, "owner_capture", False) and self._start_owner_capture():
            # AppTap owns capture and teardown; tcpdump is skipped.
            return -1
        # Otherwise fall through to the tcpdump capture below.
        return self._start_device_tcpdump()

    def _start_device_tcpdump(self):
        """Launch tcpdump on the device; its process, or -1 when the session already ended."""
        pcap = self.pcap
        pcap_module = _pcap()
        if not pcap.android_Instance.is_tcpdump_available:
            pcap.android_Instance.install_tcpdump()
        # Start under the teardown lock: either tcpdump runs before
        # stop_device_capture() looks, or it must not start (it would leak).
        with pcap._device_capture_lock:
            if pcap._device_capture_stopped:
                pcap.logger.info(
                    "full capture: session already ending; not starting tcpdump")
                return -1
            self.android_capture_process = pcap.android_Instance.run_tcpdump_capture(
                pcap_module.device_capture_basename(self.pcap_file_name),
                include_loopback=getattr(pcap, "include_loopback", False),
                filter_infrastructure=getattr(pcap, "filter_infrastructure", True))
        # Net for exits that bypass friTap's own teardown.
        atexit.register(pcap.stop_device_capture)

        pcap.logger.info("doing full capture on Android")
        return self.android_capture_process
