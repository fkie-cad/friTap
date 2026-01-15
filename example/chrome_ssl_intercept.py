#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Standalone script to intercept SSL/TLS traffic from Chrome on Android
using friTap's _ssl_log.js agent.

This script shows how to handle initialization messages 
from the friTap agent properly.

Usage:
    python chrome_ssl_intercept.py [PID or PACKAGE_NAME]
    python chrome_ssl_intercept.py -D <device_id> com.android.chrome
    python chrome_ssl_intercept.py --spawn com.android.chrome

    PID: Process ID of Chrome (e.g., 27913)
    PACKAGE_NAME: Android package name (e.g., com.android.chrome)

Examples:
    python chrome_ssl_intercept.py 27913
    python chrome_ssl_intercept.py com.android.chrome
    python chrome_ssl_intercept.py --spawn com.android.chrome
    python chrome_ssl_intercept.py -D emulator-5554 com.android.chrome

Requirements:
    - frida-server running on the Android device
    - frida Python package installed
    - USB debugging enabled and device connected
"""

import frida
import sys
import os
import struct
import socket
import signal
import time
import argparse

# Path to the friTap JavaScript agent (relative to this script)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FRITAP_JS_PATH = os.path.join(SCRIPT_DIR, "friTap", "_ssl_log.js")

# Default target
DEFAULT_TARGET = "com.android.chrome"

# Number of attach retries
MAX_RETRIES = 3

# Global script reference for message handler
script = None


def get_addr_string(socket_addr, ss_family):
    """Convert socket address to human-readable string representation."""
    try:
        if ss_family == "AF_INET":
            return socket.inet_ntop(socket.AF_INET, struct.pack(">I", socket_addr))
        else:  # AF_INET6
            raw_addr = bytes.fromhex(socket_addr)
            return socket.inet_ntop(socket.AF_INET6, struct.pack(">16s", raw_addr))
    except Exception as e:
        return f"<addr_error: {e}>"


def on_message(message, data):
    """
    Handle messages from the Frida script.

    The friTap agent sends initialization messages that MUST be responded to,
    otherwise the agent hangs waiting and Frida times out.
    """
    global script

    if message["type"] == "error":
        print(f"[ERROR] {message.get('description', message)}")
        if message.get("stack"):
            print(f"[STACK] {message['stack']}")
        return

    if message["type"] == "send":
        payload = message.get("payload", {})


        if payload == "experimental":
            script.post({"type": "experimental", "payload": False})
            return

        if payload == "defaultFD":
            script.post({"type": "defaultFD", "payload": False})
            return

        if payload == "socket_tracing":
            script.post({"type": "socket_tracing", "payload": False})
            return

        if payload == "pattern_hooking":
            script.post({"type": "pattern_hooking", "payload": None})
            return

        if payload == "offset_hooking":
            script.post({"type": "offset_hooking", "payload": None})
            return

        if payload == "install_lsass_hook":
            script.post({"type": "install_lsass_hook", "payload": False})
            return

        if payload == "anti":
            script.post({"type": "antiroot", "payload": False})
            return

        # ============================================================
        # Handle regular messages from the agent
        # ============================================================

        if not isinstance(payload, dict):
            return

        content_type = payload.get("contentType")

        # Console messages from the agent
        if content_type == "console":
            msg = payload.get("console", "")
            print(f"[*] {msg}")

        # Debug/development console messages
        elif content_type == "console_dev":
            msg = payload.get("console_dev", "")
            if msg and len(msg) > 3:
                print(f"[DEBUG] {msg}")

        # Captured SSL/TLS data
        elif content_type == "datalog" and data:
            try:
                src_addr = get_addr_string(payload["src_addr"], payload["ss_family"])
                dst_addr = get_addr_string(payload["dst_addr"], payload["ss_family"])
                func_name = payload.get("function", "unknown")
                src_port = payload.get("src_port", 0)
                dst_port = payload.get("dst_port", 0)
                ssl_session = payload.get("ssl_session_id", "N/A")

                print(f"\n{'='*60}")
                print(f"[{func_name}] SSL Session: {ssl_session}")
                print(f"  {src_addr}:{src_port} --> {dst_addr}:{dst_port}")
                print(f"  Data length: {len(data)} bytes")
                print("  Data (first 200 bytes):")

                # Print hex dump of the data
                hex_data = data[:200].hex()
                for i in range(0, len(hex_data), 32):
                    chunk = hex_data[i:i+32]
                    # Format as hex pairs with spaces
                    formatted = ' '.join(chunk[j:j+2] for j in range(0, len(chunk), 2))
                    print(f"    {formatted}")

                if len(data) > 200:
                    print(f"    ... ({len(data) - 200} more bytes)")
                print(f"{'='*60}\n")

            except Exception as e:
                print(f"[ERROR] Failed to parse datalog: {e}")

        # Key material (for TLS decryption in Wireshark)
        elif content_type == "keylog":
            keylog = payload.get("keylog", "")
            if keylog:
                print(f"[KEYLOG] {keylog}")


def attach_with_retry(device, target, is_pid=False, max_retries=MAX_RETRIES):
    """
    Attempt to attach to the target process with retries.
    Returns the process handle on success, exits on failure.
    """
    for attempt in range(1, max_retries + 1):
        try:
            print(f"[*] Attach attempt {attempt}/{max_retries}...")
            if is_pid:
                process = device.attach(int(target), persist_timeout=30)
            else:
                process = device.attach(target, persist_timeout=30)
            return process
        except frida.TimedOutError:
            if attempt < max_retries:
                print(f"[!] Timeout on attempt {attempt}, retrying in 2 seconds...")
                time.sleep(2)
            else:
                raise
        except frida.ProcessNotFoundError:
            raise
        except frida.PermissionDeniedError:
            raise
    return None


def main():
    global script

    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Intercept SSL/TLS traffic from Chrome on Android using friTap",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 27913                          # Attach by PID
  %(prog)s com.android.chrome             # Attach by package name
  %(prog)s --spawn com.android.chrome     # Spawn the app
  %(prog)s -D emulator-5554 27913         # Attach on specific device
  %(prog)s -D emulator-5554 --spawn com.android.chrome
        """
    )
    parser.add_argument("target", nargs="?", default=DEFAULT_TARGET,
                        help=f"PID or package name (default: {DEFAULT_TARGET})")
    parser.add_argument("-D", "--device", metavar="ID",
                        help="Connect to device with the given ID (use 'frida-ls-devices' to list)")
    parser.add_argument("--spawn", "-s", action="store_true",
                        help="Spawn the app instead of attaching to running process")
    parser.add_argument("--retries", "-r", type=int, default=MAX_RETRIES,
                        help=f"Number of attach retries (default: {MAX_RETRIES})")

    args = parser.parse_args()
    target = args.target
    spawn_mode = args.spawn
    device_id = args.device

    # Determine if target is a PID or package name
    is_pid = target.isdigit()

    print("[*] friTap Chrome SSL Interceptor")
    print(f"[*] Target: {target} ({'PID' if is_pid else 'package name'})")
    print(f"[*] Mode: {'spawn' if spawn_mode else 'attach'}")
    if device_id:
        print(f"[*] Device: {device_id}")
    print(f"[*] Agent path: {FRITAP_JS_PATH}")
    print()

    # Check if the agent file exists
    if not os.path.exists(FRITAP_JS_PATH):
        print(f"[!] Error: friTap agent not found at {FRITAP_JS_PATH}")
        sys.exit(1)

    # Connect to device
    if device_id:
        print(f"[*] Connecting to device '{device_id}'...")
        try:
            device = frida.get_device(device_id, timeout=10)
            print(f"[+] Connected to: {device.name}")
        except frida.InvalidArgumentError:
            print(f"[!] Error: Device '{device_id}' not found.")
            print("[!] List available devices with: frida-ls-devices")
            sys.exit(1)
        except frida.TimedOutError:
            print(f"[!] Error: Timeout connecting to device '{device_id}'.")
            sys.exit(1)
        except frida.ServerNotRunningError:
            print("[!] Error: frida-server is not running on the device.")
            print("[!] Start it with: adb shell 'su -c /data/local/tmp/frida-server &'")
            sys.exit(1)
    else:
        print("[*] Connecting to Android device via USB...")
        try:
            device = frida.get_usb_device(timeout=10)
            print(f"[+] Connected to: {device.name}")
        except frida.TimedOutError:
            print("[!] Error: Timeout connecting to device. Is the device connected?")
            sys.exit(1)
        except frida.ServerNotRunningError:
            print("[!] Error: frida-server is not running on the device.")
            print("[!] Start it with: adb shell 'su -c /data/local/tmp/frida-server &'")
            sys.exit(1)

    # Spawn or attach to the target process
    process = None
    pid = None

    if spawn_mode:
        # Spawn the application
        if is_pid:
            print("[!] Error: Cannot spawn with a PID. Use package name instead.")
            sys.exit(1)
        print(f"[*] Spawning {target}...")
        try:
            pid = device.spawn(target)
            print(f"[+] Spawned process with PID: {pid}")
            process = device.attach(pid)
            print("[+] Attached to spawned process")
        except frida.NotSupportedError as e:
            print(f"[!] Error spawning: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Error spawning {target}: {e}")
            sys.exit(1)
    else:
        # Attach to existing process
        print(f"[*] Attaching to {target}...")
        print("[*] This may take a while on emulators...")
        try:
            process = attach_with_retry(device, target, is_pid, args.retries)
            print("[+] Attached to process")
        except frida.TimedOutError:
            print(f"[!] Error: Timeout while attaching to {target}.")
            print("[!] Possible causes:")
            print("[!]   - Emulator/device is slow - increase --retries")
            print("[!]   - SELinux blocking attachment - check: adb shell getenforce")
            print("[!]   - Process is protected/hardened")
            if is_pid:
                print("[!] Try attaching by name instead:")
                print(f"[!]   python {sys.argv[0]} com.android.chrome")
            print("[!] Or try spawning the app:")
            print(f"[!]   python {sys.argv[0]} --spawn com.android.chrome")
            sys.exit(1)
        except frida.ProcessNotFoundError:
            print(f"[!] Error: Process '{target}' not found.")
            if is_pid:
                print("[!] Find Chrome PID with: adb shell pidof com.android.chrome")
            else:
                print("[!] Make sure the app is running or use --spawn to start it")
            sys.exit(1)
        except frida.PermissionDeniedError:
            print("[!] Error: Permission denied. Is frida-server running as root?")
            sys.exit(1)

    # Load the friTap JavaScript agent
    print("[*] Loading friTap agent...")
    try:
        with open(FRITAP_JS_PATH, encoding='utf-8', newline='\n') as f:
            script_code = f.read()
    except Exception as e:
        print(f"[!] Error reading agent file: {e}")
        sys.exit(1)

    # Create and load the Frida script
    # Using 'qjs' (QuickJS) runtime as recommended for production
    try:
        script = process.create_script(script_code, runtime="qjs")
        script.on("message", on_message)
        script.load()
        print("[+] Agent loaded successfully")
    except frida.TransportError as e:
        print(f"[!] Transport error: {e}")
        print("[!] This might be a timeout issue. Make sure frida-server is running.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error loading script: {e}")
        sys.exit(1)

    # Resume the process if we spawned it
    if spawn_mode and pid:
        print("[*] Resuming spawned process...")
        device.resume(pid)
        print("[+] Process resumed")
        time.sleep(1)  # Give the app time to initialize

    print()
    print("[*] SSL/TLS interception active!")
    print("[*] Browse to any HTTPS site in Chrome to see traffic.")
    print("[*] Press Ctrl+C to stop...")
    print()

    # Set up signal handler for clean exit
    def signal_handler(signum, frame):
        print("\n[*] Interrupt received, cleaning up...")
        try:
            script.unload()
        except Exception:
            pass
        try:
            process.detach()
        except Exception:
            pass
        print("[*] Detached. Goodbye!")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Keep the script running
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        signal_handler(None, None)


if __name__ == "__main__":
    main()
