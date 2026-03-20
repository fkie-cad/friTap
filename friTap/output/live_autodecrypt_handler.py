#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Live auto-decrypt handler: raw capture + TLS keys → PCAPNG FIFO.

Combines raw network packet capture (tcpdump on Android, scapy/tcpdump
locally) with TLS key material from Frida hooks. Both are written to a
single PCAPNG FIFO that Wireshark reads and auto-decrypts.

Data flow:
    KeylogEvent (Frida) → DSB blocks ─┐
                                       ├─► PCAPNG FIFO → Wireshark
    Raw packets (tcpdump/scapy) → EPB ─┘
"""

from __future__ import annotations

import logging
import os
import struct
import subprocess
import tempfile
import threading
import time
from typing import IO, List, Optional, TYPE_CHECKING

from .base import OutputHandler

if TYPE_CHECKING:
    from ..events import EventBus, KeylogEvent

from .pcapng_handler import BT_SHB, BT_IDB, BT_EPB, BT_DSB, TLS_KEY_LOG, _pad4

# Link types
LINKTYPE_ETHERNET = 1

# Pcap magic for parsing tcpdump output
PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1


class LiveAutoDecryptHandler(OutputHandler):
    """Raw packet capture + TLS keys → PCAPNG FIFO for Wireshark auto-decrypt."""

    def __init__(self, is_mobile: bool = False, device_id: Optional[str] = None) -> None:
        self._is_mobile = is_mobile
        self._device_id = device_id
        self._tmpdir: Optional[str] = None
        self._fifo_path: Optional[str] = None
        self._file: Optional[IO] = None
        self._logger = logging.getLogger("friTap.output.live_autodecrypt")
        self._event_bus: Optional[EventBus] = None
        self._write_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._capture_thread: Optional[threading.Thread] = None
        self._idb_written = False
        self._dsb_buffer: List[str] = []
        self._dsb_buffer_lock = threading.Lock()
        self._subprocess: Optional[subprocess.Popen] = None

    @property
    def fifo_path(self) -> Optional[str]:
        return self._fifo_path

    @property
    def tmpdir(self) -> Optional[str]:
        return self._tmpdir

    def create_fifo(self) -> str:
        """Create the named pipe and return its path."""
        self._tmpdir = tempfile.mkdtemp()
        self._fifo_path = os.path.join(self._tmpdir, "fritap_autodecrypt.pcapng")
        os.mkfifo(self._fifo_path)
        return self._fifo_path

    def setup(self, event_bus: "EventBus") -> None:
        """Non-blocking: subscribe to KeylogEvent and buffer keys until connected."""
        if not self._fifo_path:
            raise RuntimeError("Call create_fifo() before setup()")
        from ..events import KeylogEvent
        self._event_bus = event_bus
        event_bus.subscribe(KeylogEvent, self._on_keylog)

    def _on_keylog(self, event: "KeylogEvent") -> None:
        """Handle TLS key material — write DSB or buffer if not yet ready."""
        if not event.key_data:
            return
        with self._dsb_buffer_lock:
            if self._idb_written and self._file:
                self._write_dsb(event.key_data)
            else:
                self._dsb_buffer.append(event.key_data)

    def connect(self, timeout: float = 30.0) -> bool:
        """Open the FIFO for writing (blocks until Wireshark connects or timeout).

        Writes SHB immediately, then starts the capture thread.
        Returns True if connected, False on timeout.
        """
        if not self._fifo_path or not self._event_bus:
            raise RuntimeError("Call create_fifo() and setup() before connect()")

        file_obj = [None]
        error = [None]

        def _open_fifo():
            try:
                file_obj[0] = open(self._fifo_path, "wb")
            except Exception as e:
                error[0] = e

        opener = threading.Thread(target=_open_fifo, daemon=True)
        opener.start()
        opener.join(timeout=timeout)

        if opener.is_alive():
            self._logger.error(
                "Wireshark did not connect within %ds — live auto-decrypt disabled",
                int(timeout),
            )
            return False

        if error[0] is not None:
            self._logger.error("Failed to open FIFO: %s", error[0])
            return False

        self._file = file_obj[0]
        self._write_shb()

        # Start capture thread
        self._capture_thread = threading.Thread(
            target=self._capture_loop, daemon=True, name="autodecrypt-capture"
        )
        self._capture_thread.start()

        self._logger.info("Wireshark connected — streaming auto-decrypt PCAPNG")
        return True

    # ------------------------------------------------------------------
    # PCAPNG block writers (all require self._write_lock)
    # ------------------------------------------------------------------

    def _write_shb(self) -> None:
        """Write Section Header Block."""
        if not self._file:
            return
        body = struct.pack("<I", 0x1A2B3C4D)  # Byte-Order Magic
        body += struct.pack("<HH", 1, 0)       # Version 1.0
        body += struct.pack("<q", -1)           # Section Length (unspecified)
        block_len = 12 + len(body)
        with self._write_lock:
            self._file.write(struct.pack("<I", BT_SHB))
            self._file.write(struct.pack("<I", block_len))
            self._file.write(body)
            self._file.write(struct.pack("<I", block_len))
            self._file.flush()

    def _write_idb(self, link_type: int) -> None:
        """Write Interface Description Block with the given link type."""
        if not self._file:
            return
        body = struct.pack("<HHI", link_type, 0, 65535)  # LinkType + Reserved + SnapLen
        padded = _pad4(len(body))
        block_len = 12 + padded
        # Hold dsb_buffer_lock while setting _idb_written to prevent
        # _on_keylog from writing a DSB before buffered ones are flushed.
        with self._dsb_buffer_lock:
            with self._write_lock:
                self._file.write(struct.pack("<I", BT_IDB))
                self._file.write(struct.pack("<I", block_len))
                self._file.write(body)
                self._file.write(b"\x00" * (padded - len(body)))
                self._file.write(struct.pack("<I", block_len))
                self._file.flush()
            self._idb_written = True
            for key_data in self._dsb_buffer:
                self._write_dsb(key_data)
            self._dsb_buffer.clear()

    def _write_dsb(self, key_data: str) -> None:
        """Write a Decryption Secrets Block. Caller must hold appropriate lock context."""
        if not self._file:
            return
        secrets_bytes = key_data.encode("utf-8")
        if not secrets_bytes.endswith(b"\n"):
            secrets_bytes += b"\n"
        body = struct.pack("<I", TLS_KEY_LOG)
        body += struct.pack("<I", len(secrets_bytes))
        body += secrets_bytes
        padded = _pad4(len(body))
        block_len = 12 + padded
        try:
            with self._write_lock:
                self._file.write(struct.pack("<I", BT_DSB))
                self._file.write(struct.pack("<I", block_len))
                self._file.write(body)
                self._file.write(b"\x00" * (padded - len(body)))
                self._file.write(struct.pack("<I", block_len))
                self._file.flush()
        except (BrokenPipeError, OSError) as e:
            self._logger.debug("DSB write failed (pipe closed?): %s", e)

    def _write_epb(self, packet_data: bytes, ts_us: Optional[int] = None) -> None:
        """Write an Enhanced Packet Block."""
        if not self._file or not packet_data:
            return
        if ts_us is None:
            ts_us = int(time.time() * 1_000_000)
        ts_high = (ts_us >> 32) & 0xFFFFFFFF
        ts_low = ts_us & 0xFFFFFFFF
        captured_len = len(packet_data)
        body = struct.pack("<IIIII", 0, ts_high, ts_low, captured_len, captured_len) + packet_data
        padded = _pad4(len(body))
        block_len = 12 + padded
        block = struct.pack("<II", BT_EPB, block_len) + body + b"\x00" * (padded - len(body)) + struct.pack("<I", block_len)
        try:
            with self._write_lock:
                self._file.write(block)
                self._file.flush()
        except (BrokenPipeError, OSError) as e:
            self._logger.debug("EPB write failed (pipe closed?): %s", e)
            self._stop_event.set()

    # ------------------------------------------------------------------
    # Capture loop
    # ------------------------------------------------------------------

    def _capture_loop(self) -> None:
        """Main capture thread: start tcpdump/scapy and stream packets."""
        try:
            if self._is_mobile:
                self._capture_mobile()
            else:
                self._capture_local()
        except (BrokenPipeError, OSError) as e:
            self._logger.info("Capture stopped (pipe closed): %s", e)
        except Exception as e:
            self._logger.error("Capture error: %s", e)
        finally:
            self._stop_event.set()

    # ------------------------------------------------------------------
    # Local capture (scapy → tcpdump fallback)
    # ------------------------------------------------------------------

    def _capture_local(self) -> None:
        """Capture on the local machine using scapy or tcpdump."""
        try:
            self._capture_local_scapy()
        except Exception as e:
            self._logger.info("Scapy capture unavailable (%s), falling back to tcpdump", e)
            self._capture_local_tcpdump()

    def _capture_local_scapy(self) -> None:
        """Capture using scapy L2listen + sniff."""
        from scapy.all import conf, ETH_P_ALL, sniff as scapy_sniff

        self._write_idb(LINKTYPE_ETHERNET)
        self._logger.info("Local capture started (scapy)")

        sock = conf.L2listen(type=ETH_P_ALL)
        try:
            scapy_sniff(
                opened_socket=sock,
                prn=self._on_scapy_packet,
                stop_filter=lambda _pkt: self._stop_event.is_set(),
            )
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _on_scapy_packet(self, packet) -> None:
        """Callback for each scapy packet — write as EPB."""
        raw_bytes = bytes(packet)
        self._write_epb(raw_bytes)

    def _capture_local_tcpdump(self) -> None:
        """Capture using local tcpdump subprocess writing pcap to stdout."""
        cmd = ["tcpdump", "-U", "-i", "any", "-s", "0", "-w", "-"]
        try:
            self._subprocess = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
            )
        except FileNotFoundError:
            self._logger.error(
                "Neither scapy nor tcpdump available. "
                "Install scapy (pip install scapy) or tcpdump, and ensure sufficient permissions."
            )
            return
        except PermissionError:
            self._logger.error(
                "Permission denied running tcpdump. Run with sudo or grant capture permissions."
            )
            return

        self._read_pcap_stream(self._subprocess.stdout)

    # ------------------------------------------------------------------
    # Mobile capture (adb exec-out tcpdump)
    # ------------------------------------------------------------------

    def _capture_mobile(self) -> None:
        """Capture on Android device via adb exec-out tcpdump."""
        # Ensure tcpdump is available
        from ..android import Android
        android = Android(device_id=self._device_id)
        if android.is_Android and not android.is_tcpdump_available:
            self._logger.info("Installing tcpdump on device...")
            android.install_tcpdump()

        # Build adb command for streaming pcap to stdout
        adb_cmd = self._build_adb_cmd()
        tcpdump_cmd = (
            f'{android.tcpdump_path} -U -i any -s 0 -w - '
            f'"not (tcp port 5555 or tcp port 27042)"'
        )
        full_cmd = adb_cmd + ["shell", tcpdump_cmd]

        self._logger.info("Starting mobile capture via adb exec-out tcpdump")
        try:
            self._subprocess = subprocess.Popen(
                full_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
            )
        except FileNotFoundError:
            self._logger.error("adb not found in PATH")
            return

        self._read_pcap_stream(self._subprocess.stdout)

    def _build_adb_cmd(self) -> list:
        """Build the base adb command with optional device specifier."""
        cmd = ["adb"]
        if self._device_id:
            cmd.extend(["-s", self._device_id])
        return cmd

    # ------------------------------------------------------------------
    # Pcap stream parser (shared by local tcpdump and mobile)
    # ------------------------------------------------------------------

    def _read_pcap_stream(self, stream: IO) -> None:
        """Read a pcap stream (global header + records) and write as PCAPNG EPBs."""
        # Read pcap global header (24 bytes)
        header = self._read_exact(stream, 24)
        if not header:
            self._logger.error("Failed to read pcap global header from capture source")
            return

        magic = struct.unpack("<I", header[0:4])[0]
        if magic == PCAP_MAGIC_LE:
            endian = "<"
        elif magic == PCAP_MAGIC_BE:
            endian = ">"
        else:
            self._logger.error("Invalid pcap magic: 0x%08X", magic)
            return

        link_type = struct.unpack(f"{endian}I", header[20:24])[0]
        self._write_idb(link_type)
        self._logger.info("Capture started (link type %d)", link_type)

        # Read pcap records
        while not self._stop_event.is_set():
            rec_header = self._read_exact(stream, 16)
            if not rec_header:
                break  # EOF

            ts_sec, ts_usec, incl_len, _orig_len = struct.unpack(
                f"{endian}IIII", rec_header
            )
            packet_data = self._read_exact(stream, incl_len)
            if not packet_data:
                break

            ts_us = ts_sec * 1_000_000 + ts_usec
            self._write_epb(packet_data, ts_us=ts_us)

    @staticmethod
    def _read_exact(stream: IO, n: int) -> Optional[bytes]:
        """Read exactly n bytes from stream, or return None on EOF."""
        buf = b""
        while len(buf) < n:
            chunk = stream.read(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Stop capture, clean up resources."""
        self._stop_event.set()

        # Stop subprocess
        if self._subprocess:
            try:
                self._subprocess.terminate()
                self._subprocess.wait(timeout=3)
            except Exception:
                try:
                    self._subprocess.kill()
                    self._subprocess.wait()
                except Exception:
                    pass
            self._subprocess = None

        # Wait for capture thread
        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=5)

        # Close FIFO
        if self._file:
            try:
                self._file.close()
            except (BrokenPipeError, OSError):
                pass
            self._file = None

        # Unsubscribe
        if self._event_bus:
            from ..events import KeylogEvent
            self._event_bus.unsubscribe(KeylogEvent, self._on_keylog)

        # Remove FIFO and tmpdir
        from ..sinks.live_pcapng import _cleanup_fifo
        _cleanup_fifo(self._fifo_path, self._tmpdir)
