#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import frida
import argparse
import signal
import struct
import time
import pprint
import os
import socket
import sys
import tempfile
import json
import pcap

try:
    import hexdump  # pylint: disable=g-import-not-at-top
except ImportError:
    print("Unable to import hexdump module!")
    pass

__author__ = "Daniel Baier, Francois Egner, Max Ufer"
__version__ = "1.0.2"


keydump_Set = {*()}
traced_Socket_Set = {*()}
filename = ""
tmpdir = ""
pcap = None

# Names of all supported read functions:
SSL_READ = ["SSL_read", "wolfSSL_read", "readApplicationData", "NSS_read","Full_read"]
# Names of all supported write functions:
SSL_WRITE = ["SSL_write", "wolfSSL_write", "writeApplicationData", "NSS_write","Full_write"]



def cleanup(live=False, socket_trace=False):
    if live:
        os.unlink(filename)  # Remove file
        os.rmdir(tmpdir)  # Remove directory
    if type(socket_trace) is str:
        print(f"[*] Write traced sockets into {socket_trace}")
        write_socket_trace(socket_trace)
    if socket_trace == True:
        print("[*] Traced sockets")
        print(get_display_filter())
        
    print("\nThx for using friTap\nHave a nice day\n")
    os._exit(0)
    
    
def get_addr_string(socket_addr,ss_family):
    if ss_family == "AF_INET":
        return  socket.inet_ntop(socket.AF_INET, struct.pack(">I", socket_addr))
    else: # this should only be AF_INET6
        raw_addr = bytes.fromhex(socket_addr)
        return socket.inet_ntop(socket.AF_INET6, struct.pack(">16s", raw_addr))
    
def get_display_filter():
    display_filter = ""
    for length_of_socket_Set in range(len(traced_Socket_Set)):
        if length_of_socket_Set == 1:
            display_filter = traced_Socket_Set.pop()
            break
        display_filter = traced_Socket_Set.pop() + " or "
        length_of_socket_Set = length_of_socket_Set -1
    return display_filter
        

def write_socket_trace(socket_trace_name):
    with open(socket_trace_name, 'a') as trace_file:
        trace_file.write(get_display_filter() + '\n')
    
        

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


def ssl_log(app, pcap_name=None, verbose=False, spawn=False, keylog=False, enable_spawn_gating=False, mobile=False, live=False, environment_file=None, debug_output=False,full_capture=False, socket_trace=False):

    
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
        if debug_output:
            if p["contentType"] == "console_dev" and p["console_dev"]:
                print("[***] " + p["console_dev"])    
        if verbose:
            if(p["contentType"] == "keylog") and keylog:
                if p["keylog"] not in keydump_Set:
                    print(p["keylog"])
                    keydump_Set.add(p["keylog"])
                    keylog_file.write(p["keylog"] + "\n")
                    keylog_file.flush()    
            elif not data or len(data) == 0:
                return
            else:
                src_addr = get_addr_string(p["src_addr"], p["ss_family"])
                dst_addr = get_addr_string(p["dst_addr"], p["ss_family"])
                
                if socket_trace == False and full_capture  == False:
                    print("SSL Session: " + str(p["ssl_session_id"]))
                if  socket_trace:
                    display_filter = "ip.src == " +src_addr+  "and ip.dst =="+dst_addr
                    traced_Socket_Set.add(display_filter)
                    print("[socket_trace] %s:%d --> %s:%d" % (src_addr, p["src_port"], dst_addr, p["dst_port"]))
                else:
                    print("[%s] %s:%d --> %s:%d" % (p["function"], src_addr, p["src_port"], dst_addr, p["dst_port"]))
                    hexdump.hexdump(data)
                print()
        if pcap_name and p["contentType"] == "datalog":
            pcap_obj.log_plaintext_payload(p["ss_family"], p["function"], p["src_addr"],
                     p["src_port"], p["dst_addr"], p["dst_port"], data)
        if live and p["contentType"] == "datalog":
            try:
                pcap_obj.log_plaintext_payload(p["ss_family"], p["function"], p["src_addr"],
                         p["src_port"], p["dst_addr"], p["dst_port"], data)
            except (BrokenPipeError, IOError):
                process.detach()
                cleanup(live)

        if keylog and p["contentType"] == "keylog":
            if p["keylog"] not in keydump_Set:
                keylog_file.write(p["keylog"] + "\n")
                keylog_file.flush()
                keydump_Set.add(p["keylog"])
        
        if socket_trace:
            src_addr = get_addr_string(p["src_addr"], p["ss_family"])
            dst_addr = get_addr_string(p["dst_addr"], p["ss_family"])
            display_filter = "ip.src == " +src_addr+  "and ip.dst =="+dst_addr
            traced_Socket_Set.add(display_filter)

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
        with open("_ssl_log.js") as f:
            script = process.create_script(f.read())
        script.on("message", on_message)
        script.load()

    # Main code
    if mobile:
        device = frida.get_usb_device()
    else:
        device = frida.get_local_device()

    device.on("child_added", on_child_added)
    if enable_spawn_gating:
        device.enable_spawn_gating()
        device.on("spawn_added", on_spawn_added)
    if spawn:
        print("spawning "+ app)
        if mobile:
            pid = device.spawn(app)
        else:
            used_env = {}
            if environment_file:
                with open(environment_file) as json_env_file:
                    used_env = json.load(json_env_file)
            pid = device.spawn(app.split(" "),env=used_env)
            device.resume(pid)
            time.sleep(1) # without it Java.perform silently fails
        process = device.attach(pid)
    else:
        process = device.attach(int(app) if app.isnumeric() else app)

    if live:
        if pcap_name:
            print("[*] YOU ARE TRYING TO WRITE A PCAP AND HAVING A LIVE VIEW\nTHIS IS NOT SUPPORTED!\nWHEN YOU DO A LIVE VIEW YOU CAN SAFE YOUR CAPUTRE WIHT WIRESHARK.")
        fifo_file = temp_fifo()
        print(f'[*] friTap live view on Wireshark')
        print(f'[*] Created named pipe for Wireshark live view to {fifo_file}')
        print(
            f'[*] Now open this named pipe with Wireshark in another terminal: sudo wireshark -k -i {fifo_file}')
        print(f'[*] friTap will continue after the named pipe is ready....\n')
        pcap_obj =  pcap.PCAP(fifo_file,SSL_READ,SSL_WRITE,full_capture)

    elif pcap_name:
        pcap_obj =  pcap.PCAP(pcap_name,SSL_READ,SSL_WRITE,full_capture)
        

    if keylog:
        keylog_file = open(keylog, "w")

    print("Press Ctrl+C to stop logging.")
    print('[*] Running Script')
    instrument(process)
    if pcap_name and full_capture:
        print(f'[*] Logging pcap to {pcap_name}')
    if pcap_name and full_capture == False:
        print(f'[*] Logging TLS plaintext as pcap to {pcap_name}')
    if keylog:
        print(f'[*] Logging keylog file to {keylog}')
        

    if spawn:
        device.resume(pid)
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass

    process.detach()
    if full_capture:
        pcap_obj.create_application_traffic_pcap()


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
        description="Decrypts and logs an executables or mobile applications SSL/TLS traffic.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=r"""
Examples:
  %(prog)s -m -p ssl.pcap com.example.app
  %(prog)s -m --verbose com.example.app
  %(prog)s -m --pcap log.pcap --verbose com.example.app
  %(prog)s -m -k keys.log -v -s com.example.app
  %(prog)s --pcap log.pcap "$(which curl) https://www.google.com"
""")

    args = parser.add_argument_group("Arguments")
    args.add_argument("-m", "--mobile", required=False, action="store_const",
                      const=True, help="Attach to a process on android or iOS")
    args.add_argument("-d", "--debug", required=False, action="store_const", const=True,
                      help="Set the debug output of friTap")
    args.add_argument("-f", "--full_capture", required=False, action="store_const", const=True,
                      help="Do a full packet capture instead of logging only the decrypted TLS payload")
    args.add_argument("-k", "--keylog", metavar="<path>", required=False,
                      help="Log the keys used for tls traffic")
    args.add_argument("-l", "--live", required=False, action="store_const", const=True,
                      help="Creates a named pipe /tmp/sharkfin which can be read by Wireshark during the capturing process")
    args.add_argument("-p ", "--pcap", metavar="<path>", required=False,
                      help="Name of PCAP file to write")
    args.add_argument("-s", "--spawn", required=False, action="store_const", const=True,
                      help="Spawn the executable/app instead of attaching to a running process")
    args.add_argument("-sot", "--socket_tracing", metavar="<path>", required=False, nargs='?', const=True,
                      help="Traces all socket of the target application and provide a prepared wireshark display filter. If pathname is set, it will write the socket trace into a file-")
    args.add_argument("-env","--environment", metavar="<env.json>", required=False,
                      help="Provide the environment necessary for spawning as an JSON file. For instance: {\"ENV_VAR_NAME\": \"ENV_VAR_VALUE\" }")
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
                parsed.spawn, parsed.keylog, parsed.enable_spawn_gating, parsed.mobile, parsed.live, parsed.environment, parsed.debug, parsed.full_capture, parsed.socket_tracing)
    except Exception as ar:
        print(ar)

    finally:
        cleanup(parsed.live,parsed.socket_tracing)
        
