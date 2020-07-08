import frida
import argparse
import signal
import struct
import time
import random
import pprint
import os
import socket


try:
    import hexdump  # pylint: disable=g-import-not-at-top
except ImportError:
    pass

__author__ = "Max Ufer"
__version__ = "0.01"

# ssl_session[<SSL_SESSION id>] = (<bytes sent by client>,
#                                  <bytes sent by server>)
ssl_sessions = {}


def ssl_log(app, pcap=None, verbose=False):

    def log_pcap(pcap_file, ss_family, ssl_session_id, function, src_addr, src_port,
                 dst_addr, dst_port, data):
        """Writes the captured data to a pcap file.
        Args:
        pcap_file: The opened pcap file.
        ss_family: The family of the connection, IPv4/IPv6
        ssl_session_id: The SSL session ID for the communication.
        function: The function that was intercepted ("SSL_read" or "SSL_write").
        src_addr: The source address of the logged packet.
        src_port: The source port of the logged packet.
        dst_addr: The destination address of the logged packet.
        dst_port: The destination port of the logged packet.
        data: The decrypted packet data.
        """
        t = time.time()

        if ssl_session_id not in ssl_sessions:
            ssl_sessions[ssl_session_id] = (random.randint(0, 0xFFFFFFFF),
                                            random.randint(0, 0xFFFFFFFF))
        client_sent, server_sent = ssl_sessions[ssl_session_id]

        if function == "SSL_read":
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

        if function == "SSL_read":
            server_sent += len(data)
        else:
            client_sent += len(data)
        ssl_sessions[ssl_session_id] = (client_sent, server_sent)

    def on_message(message, data):
        """Callback for errors and messages sent from Frida-injected JavaScript.
        Logs captured packet data received from JavaScript to the console and/or a
        pcap file. See https://www.frida.re/docs/messages/ for more detail on
        Frida's messages.
        Args:
        message: A dictionary containing the message "type" and other fields
            dependent on message type.
        data: The string of captured decrypted data.
        """
        if message["type"] == "error":
            pprint.pprint(message)
            os.kill(os.getpid(), signal.SIGTERM)
            return
        if not data or len(data) == 0:
            return
        p = message["payload"]
        if verbose:
            if(p["ss_family"] == "AF_INET"):
                src_addr = socket.inet_ntop(socket.AF_INET,
                                            struct.pack(">I", p["src_addr"]))
                dst_addr = socket.inet_ntop(socket.AF_INET,
                                            struct.pack(">I", p["dst_addr"]))
            elif(p["ss_family"] == "AF_INET6"):

                raw_src_addr = bytes.fromhex(p["src_addr"])
                src_addr = socket.inet_ntop(socket.AF_INET6,
                                            struct.pack(">16s", raw_src_addr))
                raw_dst_addr = bytes.fromhex(p["dst_addr"])
                dst_addr = socket.inet_ntop(socket.AF_INET6,
                                            struct.pack(">16s", raw_dst_addr))
            print("SSL Session: " + p["ssl_session_id"])
            print("[%s] %s:%d --> %s:%d" % (
                p["function"],
                src_addr,
                p["src_port"],
                dst_addr,
                p["dst_port"]))
            hexdump.hexdump(data)
            print()
        if pcap:
            log_pcap(pcap_file, p["ss_family"], p["ssl_session_id"], p["function"], p["src_addr"],
                     p["src_port"], p["dst_addr"], p["dst_port"], data)

    device = frida.get_usb_device()
    process = device.attach(app)
    if pcap:
        pcap_file = open(pcap, "wb", 0)
        for writes in (
            ("=I", 0xa1b2c3d4),     # Magic number
            ("=H", 2),              # Major version number
            ("=H", 4),              # Minor version number
            ("=i", time.timezone),  # GMT to local correction
            ("=I", 0),              # Accuracy of timestamps
            ("=I", 65535),          # Max length of captured packets
                ("=I", 101)):           # Data link type (LINKTYPE_IPV4 = 228) CHANGED TO RAW
            pcap_file.write(struct.pack(writes[0], writes[1]))
    with open("_ssl_log.js") as f:
        script = process.create_script(f.read())
    script.on("message", on_message)
    print("Press Ctrl+C to stop logging.")
    print('[*] Running Script')
    script.load()
    try:
        signal.pause()
    except KeyboardInterrupt:
        pass

    process.detach()


class ArgParser(argparse.ArgumentParser):
    def error(self, message):
        print("ssl_logger v" + __version__)
        print("by " + __author__)
        print()
        print("Error: " + message)
        print()
        print(self.format_help().replace("usage:", "Usage:"))
        self.exit(0)


if __name__ == "__main__":

    parser = ArgParser(
        add_help=False,
        description="Decrypts and logs a process's SSL traffic.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=r"""
Examples:
  %(prog)s -pcap ssl.pcap com.example.app
  %(prog)s -verbose com.example.app
  %(prog)s -pcap log.pcap -verbose com.example.app
""")

    args = parser.add_argument_group("Arguments")
    args.add_argument("-pcap", metavar="<path>", required=False,
                      help="Name of PCAP file to write")
    args.add_argument("-verbose", required=False, action="store_const",
                      const=True, help="Show verbose output")
    args.add_argument("app", metavar="<app name>",
                      help="APP whose SSL calls to log")
    parsed = parser.parse_args()

    ssl_log(parsed.app, parsed.pcap, parsed.verbose)
