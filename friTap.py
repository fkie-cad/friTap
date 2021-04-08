import frida
import argparse
import signal
import struct
import time
import random
import pprint
import os
import socket
import sys
import tempfile

try:
    import hexdump  # pylint: disable=g-import-not-at-top
except ImportError:
    print("Unable to import hexdump module!")
    pass

__author__ = "Max Ufer, Daniel Baier"
__version__ = "1.0"

# ssl_session[<SSL_SESSION id>] = (<bytes sent by client>,
#                                  <bytes sent by server>)
ssl_sessions = {}


filename = ""
tmpdir = ""

# Names of all supported read functions:
SSL_READ = ["SSL_read", "wolfSSL_read", "readApplicationData", "NSS_read"]
# Names of all supported write functions:
SSL_WRITE = ["SSL_write", "wolfSSL_write", "writeApplicationData", "NSS_write"]


def write_pcap_header(pcap_file):
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


def cleanup(live=False):
    if live:
        os.unlink(filename)  # Remove file
        os.rmdir(tmpdir)  # Remove directory
    print("\nThx for using friTap\nHave a nice day\n")
    os._exit(0)


def temp_fifo():
    global tmpdir
    global filename
    tmpdir = tempfile.mkdtemp()
    filename = os.path.join(tmpdir, 'fritap_sharkfin')  # Temporary filename
    os.mkfifo(filename)  # Create FIFO
    try:
        return filename
    except OSError as e:
        print(f'Failed to create FIFO: {e}')


def ssl_log(app, pcap=None, verbose=False, spawn=False, keylog=False, enable_spawn_gating=False, android=False, live=False):

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

        if function in SSL_READ:
            session_unique_key = str(src_addr) + str(src_port) + \
                str(dst_addr) + str(dst_port)
        else:
            session_unique_key = str(dst_addr) + str(dst_port) + \
                str(src_addr) + str(src_port)
        if session_unique_key not in ssl_sessions:

            ssl_sessions[session_unique_key] = (random.randint(0, 0xFFFFFFFF),
                                                random.randint(0, 0xFFFFFFFF))

        client_sent, server_sent = ssl_sessions[session_unique_key]

        if function in SSL_READ:
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

        if function in SSL_READ:
            server_sent += len(data)
        else:
            client_sent += len(data)
        ssl_sessions[session_unique_key] = (client_sent, server_sent)

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
        p = message["payload"]
        if not "contentType" in p:
            return
        if p["contentType"] == "console":
            print("[*] " + p["console"])
        if verbose:
            if(p["contentType"] == "keylog"):
                print(p["keylog"])
            elif not data or len(data) == 0:
                return
            else:
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
                print("SSL Session: " + str(p["ssl_session_id"]))
                print("[%s] %s:%d --> %s:%d" % (
                    p["function"],
                    src_addr,
                    p["src_port"],
                    dst_addr,
                    p["dst_port"]))
                hexdump.hexdump(data)
                print()
        if pcap and p["contentType"] == "datalog":
            log_pcap(pcap_file, p["ss_family"], p["ssl_session_id"], p["function"], p["src_addr"],
                     p["src_port"], p["dst_addr"], p["dst_port"], data)
        if live and p["contentType"] == "datalog":
            try:
                log_pcap(named_pipe, p["ss_family"], p["ssl_session_id"], p["function"], p["src_addr"],
                         p["src_port"], p["dst_addr"], p["dst_port"], data)
            except (BrokenPipeError, IOError):
                process.detach()
                cleanup(live)

        if keylog and p["contentType"] == "keylog":
            keylog_file.write(p["keylog"] + "\n")
            keylog_file.flush()

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
        with open("_ssl_log.js") as f:
            script = process.create_script(f.read())
        script.on("message", on_message)
        script.load()

    # Main code
    if android:
        device = frida.get_usb_device()
    else:
        device = frida.get_local_device()

    device.on("child_added", on_child_added)
    if enable_spawn_gating:
        device.enable_spawn_gating()
        device.on("spawn_added", on_spawn_added)
    if spawn:
        if android:
            pid = device.spawn(app)
        else:
            pid = device.spawn(app.split(" "))
        process = device.attach(pid)
    else:
        process = device.attach(int(app) if app.isnumeric() else app)

    if live:
        if pcap:
            print("[*] YOU ARE TRYING TO WRITE A PCAP AND HAVING A LIVE VIEW\nTHIS IS NOT SUPPORTED!\nWHEN YOU DO A LIVE VIEW YOU CAN SAFE YOUR CAPUTRE WIHT WIRESHARK.")
        fifo_file = temp_fifo()
        print(f'[*] friTap live view on Wireshark')
        print(f'[*] Created named pipe for Wireshark live view to {fifo_file}')
        print(
            f'[*] Now open this named pipe with Wireshark in another terminal: sudo wireshark -k -i {fifo_file}')
        print(f'[*] friTap will continue after the named pipe is ready....\n')
        # input()
        #named_pipe = os.open(fifo_file, os.O_WRONLY | os.O_CREAT | os.O_NONBLOCK)
        named_pipe = open(fifo_file, "wb", 0)
        named_pipe = write_pcap_header(named_pipe)
    elif pcap:
        pcap_file = open(pcap, "wb", 0)
        pcap_file = write_pcap_header(pcap_file)

    if keylog:
        keylog_file = open(keylog, "w")

    print("Press Ctrl+C to stop logging.")
    print('[*] Running Script')
    instrument(process)
    if pcap:
        print(f'[*] Logging pcap to {pcap}')
    if keylog:
        print(f'[*] Logging keylog file to {keylog}')

    if spawn:
        device.resume(pid)
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass

    process.detach()


class ArgParser(argparse.ArgumentParser):
    def error(self, message):
        print("friTap v" + __version__)
        print("by " + __author__)
        print()
        print("Error: " + message)
        print()
        print(self.format_help().replace("usage:", "Usage:"))
        self.exit(0)


if __name__ == "__main__":

    parser = ArgParser(
        add_help=False,
        description="Decrypts and logs an executables or android applications SSL/TLS traffic.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=r"""
Examples:
  %(prog)s -a -p ssl.pcap com.example.app
  %(prog)s -a --verbose com.example.app
  %(prog)s -a --pcap log.pcap --verbose com.example.app
  %(prog)s -a -k keys.log -v -s com.example.app
  %(prog)s --pcap log.pcap "$(which curl) https://www.google.com"
""")

    args = parser.add_argument_group("Arguments")
    args.add_argument("-a", "--android", required=False, action="store_const",
                      const=True, help="Attach to a process on android")
    args.add_argument("-k", "--keylog", metavar="<path>", required=False,
                      help="Log the keys used for tls traffic")
    args.add_argument("-l", "--live", required=False, action="store_const", const=True,
                      help="Creates a named pipe /tmp/sharkfin which can be read by Wireshark during the capturing process")
    args.add_argument("-p ", "--pcap", metavar="<path>", required=False,
                      help="Name of PCAP file to write")
    args.add_argument("-s", "--spawn", required=False, action="store_const", const=True,
                      help="Spawn the executable/app instead of attaching to a running process")
    args.add_argument("-v", "--verbose", required=False, action="store_const",
                      const=True, help="Show verbose output")
    args.add_argument("--enable_spawn_gating", required=False, action="store_const", const=True,
                      help="Catch newly spawned processes. ATTENTION: These could be unrelated to the current process!")
    args.add_argument("exec", metavar="<executable/app name/pid>",
                      help="executable/app whose SSL calls to log")
    parsed = parser.parse_args()

    try:
        print("Start logging")
        ssl_log(parsed.exec, parsed.pcap, parsed.verbose,
                parsed.spawn, parsed.keylog, parsed.enable_spawn_gating, parsed.android, parsed.live)
    except Exception as ar:
        print(ar)

    finally:
        cleanup(parsed.live)
