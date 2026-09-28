#!/usr/bin/env python3
"""Generate a TLS 1.3 pcap + NSS keylog fixture WITHOUT capture privileges.

A userspace TCP proxy sits between a Python TLS 1.3 client and the local
``tls13_server.py`` oracle, forwarding the raw (encrypted) TLS records in both
directions and recording each chunk in wire order. Afterwards the recorded
byte stream is framed into a synthetic TCP/IP conversation with scapy, so tshark
can reassemble the records and — given the server's NSS keylog — decrypt both
directions. No BPF / sudo needed, so this reproduces in CI.
"""
from __future__ import annotations

import os
import socket
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path

from scapy.all import Ether, IP, TCP, wrpcap

REPO = Path(os.environ.get("FRITAP_REPO", Path(__file__).resolve().parents[1]))
SERVER = REPO / "research/memory_scan_lsass/tools/tls13_server.py"

CLIENT_IP, SERVER_IP = "10.13.0.1", "10.13.0.2"
CLIENT_PORT, SERVER_PORT = 54321, 443


def _pump(src, dst, direction, log, lock):
    """Forward src->dst, recording each chunk as (direction, bytes)."""
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            with lock:
                log.append((direction, data))
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def _proxy_once(listen_sock, server_addr, log, lock):
    client, _ = listen_sock.accept()
    upstream = socket.create_connection(server_addr)
    t1 = threading.Thread(target=_pump, args=(client, upstream, "c2s", log, lock))
    t2 = threading.Thread(target=_pump, args=(upstream, client, "s2c", log, lock))
    t1.start(); t2.start(); t1.join(); t2.join()
    client.close(); upstream.close()


def _frame_pcap(log, out_pcap):
    """Turn the ordered (direction, bytes) chunks into a TCP/IP pcap."""
    cseq, sseq = 1000, 5000  # initial sequence numbers per direction
    pkts = []
    t = time.time()

    cmac, smac = "02:00:00:00:00:01", "02:00:00:00:00:02"

    def add(sport, dport, src, dst, seq, ack, flags, payload=b""):
        nonlocal t
        emac = (cmac, smac) if src == CLIENT_IP else (smac, cmac)
        p = Ether(src=emac[0], dst=emac[1]) / IP(src=src, dst=dst) / TCP(
            sport=sport, dport=dport, seq=seq, ack=ack, flags=flags) / payload
        p.time = t
        t += 0.001
        pkts.append(p)

    # Handshake: SYN, SYN-ACK, ACK.
    add(CLIENT_PORT, SERVER_PORT, CLIENT_IP, SERVER_IP, cseq, 0, "S")
    add(SERVER_PORT, CLIENT_PORT, SERVER_IP, CLIENT_IP, sseq, cseq + 1, "SA")
    cseq += 1; sseq += 1
    add(CLIENT_PORT, SERVER_PORT, CLIENT_IP, SERVER_IP, cseq, sseq, "A")

    for direction, data in log:
        if direction == "c2s":
            add(CLIENT_PORT, SERVER_PORT, CLIENT_IP, SERVER_IP, cseq, sseq, "PA", data)
            cseq += len(data)
        else:
            add(SERVER_PORT, CLIENT_PORT, SERVER_IP, CLIENT_IP, sseq, cseq, "PA", data)
            sseq += len(data)

    # Teardown.
    add(CLIENT_PORT, SERVER_PORT, CLIENT_IP, SERVER_IP, cseq, sseq, "FA")
    add(SERVER_PORT, CLIENT_PORT, SERVER_IP, CLIENT_IP, sseq, cseq + 1, "FA")
    wrpcap(str(out_pcap), pkts)


def main() -> int:
    out_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO / "tests/fixtures"
    out_pcap = out_dir / "schannel_tls13.pcap"
    out_keylog = out_dir / "schannel_tls13.keylog"

    # 1. Start the TLS 1.3 oracle server (ephemeral port, its own keylog).
    proc = subprocess.Popen(
        [sys.executable, str(SERVER), "--port", "0", "--keylog", str(out_keylog),
         "--hold", "0", "--once"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    server_port = None
    for _ in range(50):
        line = proc.stdout.readline()
        if not line:
            break
        if line.startswith("PORT "):
            server_port = int(line.split()[1])
            break
    if server_port is None:
        sys.stderr.write("server failed to report PORT; stderr:\n")
        sys.stderr.write(proc.stderr.read())
        return 1

    # 2. Userspace proxy: client -> proxy -> server, recording wire bytes.
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    proxy_port = lsock.getsockname()[1]
    log, lock = [], threading.Lock()
    pt = threading.Thread(target=_proxy_once,
                          args=(lsock, ("127.0.0.1", server_port), log, lock))
    pt.start()

    # 3. TLS 1.3 client through the proxy: send a request, read the response
    #    (so BOTH directions carry application data -> both TRAFFIC_SECRET_0).
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    with socket.create_connection(("127.0.0.1", proxy_port)) as raw:
        with ctx.wrap_socket(raw, server_hostname="localhost") as tls:
            tls.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            _ = tls.recv(4096)
    pt.join(timeout=10)
    lsock.close()
    proc.wait(timeout=10)

    # 4. Frame the recorded bytes into a pcap.
    _frame_pcap(log, out_pcap)
    labels = sorted({ln.split()[0] for ln in
                     out_keylog.read_text().splitlines() if ln and not ln.startswith("#")})
    print(f"[+] wrote {out_pcap} ({sum(len(d) for _, d in log)} payload bytes, "
          f"{len(log)} chunks)")
    print(f"[+] wrote {out_keylog} labels={labels}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
