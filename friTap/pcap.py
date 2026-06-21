#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import ntpath
import os
import subprocess
from threading import Thread, Event
import random
import logging
import time
import psutil
import struct
import traceback
import warnings

from friTap.constants import build_infrastructure_bpf
from .pcap_utility import is_pcapng_filename

try:
    from scapy.all import wrpcap, conf, ETH_P_ALL, sniff, Scapy_Exception
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

from .android import Android
 
INVALID_IPV4 = "0.0.0.0"
INVALID_IPV6 = "::"

# Configure logging to suppress scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
warnings.simplefilter("ignore", ResourceWarning)


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

class PCAP:

    def __init__(self,pcap_file_name,SSL_READ,SSL_WRITE, doFullCapture, isMobile, print_debug_infos=False):
        self.pcap_file_name = pcap_file_name
        self.logger = logging.getLogger('friTap')
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
            
    

    def get_instance_of_FullCaptureThread(self):
        
        pcap_class = self
        
        class FullCaptureThread(Thread):
            
            def __init__(self):
                super(FullCaptureThread,self).__init__()
                self.pcap_file_name = pcap_class.pcap_file_name
                self.daemon = True
                self.socket = None
                self.stop_capture = Event()
                self.tmp_pcap_name = self._get_tmp_pcap_name()
                
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
                wrpcap(self.tmp_pcap_name, packet, append=True)  #appends packet to output file
            
            
            def clean_up_and_exit(self):
                """Gracefully exit the FullCaptureThread"""
                pcap_class.logger.info("Cleaning up FullCaptureThread resources.")
                if self.socket:
                    try:
                        pcap_class.logger.info("Closing network socket.")
                        self.socket.close()
                    except Exception as e:
                        pcap_class.logger.error(f"Error while closing the socket: {e}")
                if self.android_capture_process != -1:
                    try:
                        pcap_class.logger.info("Terminating android capture process.")
                        self.android_capture_process.terminate()
                        self.android_capture_process.wait(timeout=2)
                    except Exception as e:
                        pcap_class.logger.error(f"Error while terminating android capture process: {e}")

            
            
            def full_local_capture(self):
                try:

                    self.socket = conf.L2listen(
                        type=ETH_P_ALL
                    )

                    pcap_class.logger.info("doing full local capture")

                    sniff(
                        opened_socket=self.socket,
                        filter=build_infrastructure_bpf(),
                        prn=self.write_packet_to_pcap,
                        stop_filter=self.stop_capture_thread
                    )
                except PermissionError as e:
                    pcap_class.logger.error(f"PermissionError: {e}")
                    pcap_class.logger.debug("It seems you do not have permissions to access /dev/bpf. Please run the script with 'sudo' or grant your user access to /dev/bpf* files.")
                    pcap_class.logger.debug("Exiting the program.")
                    self.clean_up_and_exit()
                except Scapy_Exception as e:
                    pcap_class.logger.error(f"Scapy_Exception: {e}")
                    pcap_class.logger.debug("Scapy could not open /dev/bpf for network capture. Ensure you have the correct permissions.")
                    pcap_class.logger.debug("Run the script with 'sudo' (not recommended for security reasons).")
                    self.clean_up_and_exit()
                except Exception as e:
                    pcap_class.logger.error(f"Unknown error: {e}")
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
        pcap_file = open(self.pcap_file_name, "wb", 0)
        pcap_file = self.write_pcap_header(pcap_file)
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
            for writes in (
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
                    (">H", 0)):                       # Urgent Pointer
                self.pcap_file.write(struct.pack(writes[0], writes[1]))

            self.pcap_file.write(data)

        elif ss_family == "AF_INET6":
            for writes in (
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
                (">16s", bytes.fromhex(src_addr)),
                # Destination Address
                (">16s", bytes.fromhex(dst_addr)),
                # TCP header
                (">H", src_port),                 # Source Port
                (">H", dst_port),                 # Destination Port
                (">I", seq),                      # Sequence Number
                (">I", ack),                      # Acknowledgment Number
                (">H", 0x5018),                   # Header Length and Flags
                (">H", 0xFFFF),                   # Window Size
                (">H", 0),                        # Checksum
                    (">H", 0)):                       # Urgent Pointer
                self.pcap_file.write(struct.pack(writes[0], writes[1]))

            self.pcap_file.write(data)

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
            for writes in (
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
                    (">H", 0)):                       # Checksum
                self.pcap_file.write(struct.pack(writes[0], writes[1]))

            self.pcap_file.write(data)

        elif ss_family == "AF_INET6":
            for writes in (
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
                (">16s", bytes.fromhex(src_addr)),
                # Destination Address
                (">16s", bytes.fromhex(dst_addr)),
                # UDP header
                (">H", src_port),                 # Source Port
                (">H", dst_port),                 # Destination Port
                (">H", 8 + len(data)),            # UDP Length
                    (">H", 0)):                       # Checksum
                self.pcap_file.write(struct.pack(writes[0], writes[1]))

            self.pcap_file.write(data)

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
        from .output.pcapng_blocks import build_shb, build_idb, build_dsb
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
        from .output.pcapng_blocks import build_shb, build_idb, build_dsb, build_epb

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

    def set_active_keylogs(self, mapping: dict) -> None:
        """Record the per-protocol split keylog paths for the manifest.

        Called externally when multiple protocol formatters are active and the
        single ``-k`` path has been split per protocol. Stored defensively (a
        shallow copy) and surfaced in the manifest under the "keylogs" field.
        """
        self.active_keylogs = dict(mapping or {})

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
            if self.keylog_path:
                manifest["keylog"] = str(self.keylog_path)
                # Also record the keylog under the active protocol's offline
                # decryptor field (its registry cli_dest, e.g. "mtproto_keylog" /
                # "signal_keylog") so the manifest-driven offline pipeline routes
                # the keys to friTap's own decryptor instead of treating them as a
                # generic TLS SSLKEYLOGFILE (which yields 0 flows for MTProto/Signal).
                # CRITICAL: use the per-protocol SPLIT path when one exists — for a
                # multi-protocol capture the base -k path holds the TLS keys, NOT
                # the protocol's keys, so writing it here would point e.g.
                # signal_keylog at the TLS log and decrypt 0 Signal messages.
                try:
                    from friTap.offline.registry import get_offline_decryptor_registry
                    for entry in get_offline_decryptor_registry().list():
                        if entry.protocol_name == self.capture_protocol:
                            proto_keylog = active_keylogs.get(
                                entry.protocol_name, self.keylog_path
                            )
                            manifest[entry.cli_dest] = str(proto_keylog)
                            break
                except Exception as e:
                    self.logger.debug(f"manifest protocol-keylog mapping skipped: {e}")
            # Record every per-protocol split path so the offline pipeline can
            # locate each keylog. The single "keylog" field above is preserved
            # for back-compat.
            if active_keylogs:
                manifest["keylogs"] = {
                    proto: str(path) for proto, path in active_keylogs.items()
                }
            manifest_path = f"{self.pcap_file_name}.fritap.json"
            with open(manifest_path, "w", encoding="utf-8") as fh:
                _json.dump(manifest, fh, indent=2)
            self.logger.debug(f"Wrote capture manifest {manifest_path}")
        except Exception as e:
            self.logger.debug(f"Could not write capture manifest: {e}")

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
