#!/usr/bin/env python3
import argparse
import frida
import sys
import signal
import time
import struct
import pprint
import os
import random

__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))


def speartrace(output, verbose, app_name=None, pid=None, enable_spawn_gating=False):

    # session[<SESSION id>] = (<bytes sent by client>,
    #                                  <bytes sent by server>)
    sessions = {}

    def log_pcap(pcap_file, ss_family, function, src_addr, src_port,
                 dst_addr, dst_port, data):
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
        """
        t = time.time()

        if function == "read":
            session_unique_key = str(src_addr) + str(src_port) + \
                str(dst_addr) + str(dst_port)
        else:
            session_unique_key = str(dst_addr) + str(dst_port) + \
                str(src_addr) + str(src_port)
        if session_unique_key not in sessions:

            sessions[session_unique_key] = (random.randint(0, 0xFFFFFFFF),
                                            random.randint(0, 0xFFFFFFFF))

        client_sent, server_sent = sessions[session_unique_key]

        if function == "read":
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
                pcap_file.write(struct.pack(writes[0], writes[1]))
            pcap_file.write(data)
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
                pcap_file.write(struct.pack(writes[0], writes[1]))
            pcap_file.write(data)
        else:
            print("Packet has unknown/unsupported family!")

        if function == "read":
            server_sent += len(data)
        else:
            client_sent += len(data)
        sessions[session_unique_key] = (client_sent, server_sent)

    def on_message(message, data):
        if message["type"] == "error":
            pprint.pprint(message)
            os.kill(os.getpid(), signal.SIGTERM)
            return
        if not data or len(data) == 0:
            return
        p = message["payload"]
        if verbose:
            print(f"[*] PID: {p['pid']}:  {p['function']}")
        if output:
            log_pcap(pcap_file, p["ss_family"], p["function"], p["src_addr"],
                     p["src_port"], p["dst_addr"], p["dst_port"], data)

    def on_child_added(child):
        print(f"[*] Attached to child process with pid {child.pid}")
        instrument(device.attach(child.pid))
        device.resume(child.pid)

    def on_spawn_added(spawn):
        print(
            f"[*] Process spawned with pid {spawn.pid}. Name: {spawn.identifier}")
        instrument(device.attach(spawn.pid))
        device.resume(spawn.pid)

    def instrument(process):
        process.enable_child_gating()
        with open(os.path.join(__location__, "_socket_trace.js")) as f:
            script = process.create_script(f.read())
        script.on("message", on_message)
        script.load()

    device = frida.get_usb_device()
    device.on("child_added", on_child_added)
    if enable_spawn_gating:
        device.enable_spawn_gating()
        device.on("spawn_added", on_spawn_added)
    if app_name:
        pid = device.spawn(app_name)
    process = device.attach(pid)
    print(f"[*] Attached to process with pid {pid}")
    if output:
        # prepare pcap
        pcap_file = open(output, "wb", 0)
        for writes in (
            ("=I", 0xa1b2c3d4),     # Magic number
            ("=H", 2),              # Major version number
            ("=H", 4),              # Minor version number
            ("=i", time.timezone),  # GMT to local correction
            ("=I", 0),              # Accuracy of timestamps
            ("=I", 65535),          # Max length of captured packets
                ("=I", 101)):           # Data link type (LINKTYPE_IPV4 = 228) CHANGED TO RAW
            pcap_file.write(struct.pack(writes[0], writes[1]))

    print("Press Ctrl+C to stop logging.")
    instrument(process)
    if app_name:
        device.resume(pid)
    try:
        signal.pause()
    except KeyboardInterrupt:
        pass

    process.detach()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Log network traffic of a single android application")
    ap.add_argument("-p", "--pid", metavar="<pid>",
                    required=False, help="The targets PID")
    ap.add_argument("-f", metavar="<app name>",
                    required=False, help="The name of the application to spawn")
    ap.add_argument("-o", "--output", metavar="<file>",
                    required=False, help="Path to pcap to write to")
    ap.add_argument("-v", "--verbose", required=False,
                    help="Print verbose output", action="store_true")
    ap.add_argument("-e", "--enable_spawn_gating", required=False,
                    action="store_true", help="Enable spawn gating")
    parsed = ap.parse_args()
    if not ((parsed.pid is None) ^ (parsed.f is None)):
        print("Exactly one of -p/-f has to specified!")
        sys.exit(1)
    if parsed.pid:
        speartrace(parsed.output, parsed.verbose, pid=parsed.pid,
                   enable_spawn_gating=parsed.enable_spawn_gating)
    else:
        speartrace(parsed.output, parsed.verbose, app_name=parsed.f,
                   enable_spawn_gating=parsed.enable_spawn_gating)
