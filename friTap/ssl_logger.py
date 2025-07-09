#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import frida
import tempfile
import os
import struct
import socket
import pprint
import signal
import time
import sys
import json
import threading
import logging
from datetime import datetime, timezone
from .pcap import PCAP
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class CustomFormatter(logging.Formatter):
    """Custom formatter that uses original friTap prefix format"""
    
    def format(self, record):
        # Map log levels to original prefixes
        prefix_map = {
            logging.INFO: '[*]',
            logging.DEBUG: '[!]',
            logging.WARNING: '[-]',
            logging.ERROR: '[-]',
            logging.CRITICAL: '[-]'
        }
        
        prefix = prefix_map.get(record.levelno, '[*]')
        return f"{prefix} {record.getMessage()}"

try:
    import hexdump  # pylint: disable=g-import-not-at-top
except ImportError:
    # Will be handled by logger later
    hexdump = None

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
except ImportError:
    Console = None


# here - where we are.
here = os.path.abspath(os.path.dirname(__file__))

# Names of all supported read functions:
SSL_READ = ["SSL_read", "wolfSSL_read", "readApplicationData", "NSS_read","Full_read"]
# Names of all supported write functions:
SSL_WRITE = ["SSL_write", "wolfSSL_write", "writeApplicationData", "NSS_write","Full_write"]

class SSL_Logger():

    def __init__(self, app, pcap_name=None, verbose=False, spawn=False, keylog=False, enable_spawn_gating=False, mobile=False, live=False, environment_file=None, debug_mode=False,full_capture=False, socket_trace=False, host=False, offsets=None, debug_output=False, experimental=False, anti_root=False, payload_modification=False,enable_default_fd=False, patterns=None, custom_hook_script=None, json_output=None):
        # Set up logging
        self.logger = logging.getLogger('friTap')
        if not self.logger.handlers:
            self._setup_logging(debug_mode, debug_output)
        
        # Create a special logger to print clean messages without prefixes (e.g. farewell line)
        self.special_logger = logging.getLogger('friTap.no_prefix')
        if not self.special_logger.handlers:
            self.special_logger.setLevel(logging.INFO)
            self.special_handler = logging.StreamHandler()
            self.special_handler.setFormatter(logging.Formatter("%(message)s"))
            self.special_logger.addHandler(self.special_handler)
            self.special_logger.propagate = False  # Prevent duplicate messages
        self.logger.propagate = False  # Prevent duplicate messages
        
        # Check for hexdump availability
        if hexdump is None:
            self.logger.warning("Unable to import hexdump module! Hexdump functionality will be disabled.")
        
        self.debug = debug_mode
        self.anti_root = anti_root
        self.pcap_name = pcap_name
        self.mobile = mobile
        self.debug_output = debug_output
        self.full_capture = full_capture
        self.target_app = app
        self.verbose = verbose
        self.spawn = spawn
        self.pcap_obj = None
        self.socket_trace = socket_trace
        self.keylog = keylog
        self.offsets = offsets
        self.offsets_data = None
        self.environment_file = environment_file
        self.host = host
        self.enable_spawn_gating = enable_spawn_gating
        self.live = live
        self.payload_modification = payload_modification
        self.enable_default_fd = enable_default_fd
        self.experimental = experimental
        self.custom_hook_script = custom_hook_script
        self.script = None
        self.running = True
        self.json_output = json_output

        self.tmpdir = None
        self.filename = ""
        self.startup = True

        self.process = None
        self.device = None
        self.keylog_file = None
        self.json_file = None

        self.patterns = patterns
        self.pattern_data = None        

        self.keydump_Set = {*()}
        self.traced_Socket_Set = {*()}
        self.traced_scapy_socket_Set = {*()}
        
        # JSON session data
        self.session_data = {
            "friTap_version": "1.3.4.2",  # Should be imported from about.py
            "session_info": {
                "start_time": datetime.now(timezone.utc).isoformat(),
                "target_app": app,
                "mobile": mobile,
                "spawn": spawn,
                "verbose": verbose,
                "live": live,
                "debug": debug_mode
            },
            "ssl_sessions": [],
            "connections": [],
            "key_extractions": [],
            "errors": [],
            "statistics": {
                "total_sessions": 0,
                "total_connections": 0,
                "total_bytes_captured": 0,
                "libraries_detected": []
            }
        }

        self.init_fritap()
        
    def _setup_logging(self, debug_mode, debug_output):
        """Set up logging configuration for friTap with original prefix format"""
        if debug_mode or debug_output:
            level = logging.DEBUG
        else:
            level = logging.INFO
            
        # Use custom formatter with original prefix format
        formatter = CustomFormatter()
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        console_handler.setLevel(level)
        
        self.logger.setLevel(level)
        self.logger.addHandler(console_handler)
        self.logger.propagate = False  # Prevent duplicate messages
    
    
    def init_fritap(self):
        if frida.__version__ < "17":
            self.frida_agent_script = "_ssl_log_legacy.js"
        else:
            self.frida_agent_script = "_ssl_log.js"

        if self.pcap_name:
            self.pcap_obj =  PCAP(self.pcap_name,SSL_READ,SSL_WRITE,self.full_capture, self.mobile,self.debug)

        if self.offsets is not None:
            if os.path.exists(self.offsets):
                offset_file = open(self.offsets, "r")
                self.offsets_data = offset_file.read()
                offset_file.close()
            else:
                try:
                    json.load(self.offsets)
                    self.offsets_data = self.offsets
                except ValueError as e:
                    self.logger.error(f"Log error, defaulting to auto-detection: {e}")

        if self.patterns is not None:
            self.load_patterns()

        if self.keylog:
            self.keylog_file = open(self.keylog, "w")
        
        if self.json_output:
            self.json_file = open(self.json_output, "w")
            self.logger.info(f"JSON output will be saved to {self.json_output}")

        if self.live:
            if self.pcap_name:
                self.logger.warning("YOU ARE TRYING TO WRITE A PCAP AND HAVING A LIVE VIEW\nTHIS IS NOT SUPPORTED!\nWHEN YOU DO A LIVE VIEW YOU CAN SAVE YOUR CAPTURE WITH WIRESHARK.")
            fifo_file = self.temp_fifo()
            self.logger.info('friTap live view on Wireshark')
            self.logger.info(f'Created named pipe for Wireshark live view to {fifo_file}')
            self.logger.info(f'Now open this named pipe with Wireshark in another terminal: sudo wireshark -k -i {fifo_file}')
            self.logger.info('friTap will continue after the named pipe is ready....')
            self.pcap_obj =  PCAP(fifo_file,SSL_READ,SSL_WRITE,self.full_capture, self.mobile,self.debug)

    
    def on_detach(self, reason):

        if reason == "application-requested":
            return
        
        self.logger.info(f"Target process stopped: {reason}")
        self._log_session_end(reason)
        self.pcap_cleanup(self.full_capture,self.mobile,self.pcap_name)
        self.cleanup(self.live,self.socket_trace,self.full_capture,self.debug)
        

    def handle_frida_script_error(self, message: dict):
        print("\n\n")
        error_msg = message.get("description", "Unknown error")
        stack = message.get("stack", "No stacktrace provided")
        file = message.get("fileName", "")
        line = message.get("lineNumber", "")
        column = message.get("columnNumber", "")

        # Log error to JSON if enabled
        if self.json_output:
            error_entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "frida_script_error",
                "description": error_msg,
                "file": file,
                "line": line,
                "column": column,
                "stack": stack
            }
            self.session_data["errors"].append(error_entry)
            
        if self.debug_output:
            if Console:
                console = Console()
                header = Text("✖ Frida Script Error", style="bold red")
                body = Text.from_markup(
                    f"[bold]Description:[/bold] {error_msg}\n"
                    f"[bold]File:[/bold] {file}:{line}:{column}\n\n"
                    f"[bold]Stacktrace:[/bold]\n{stack}"
                )
                panel = Panel(body, title=header, expand=False, border_style="red")
                console.print(panel)
            else:
                self.logger.error("✖ Frida Script Error:")
                self.logger.error(f"Description: {error_msg}")
                self.logger.error(f"File: {file}:{line}:{column}")
                self.logger.error(f"Stacktrace:\n{stack}")
        else:
            self.logger.error(f"Error from Frida script: {error_msg}")
        
        self.logger.critical("Exiting due to script error.")

        os.kill(os.getpid(), signal.SIGTERM)

    def temp_fifo(self):
        self.tmpdir = tempfile.mkdtemp()
        self.filename = os.path.join(self.tmpdir, 'fritap_sharkfin')  # Temporary filename
        os.mkfifo(self.filename)  # Create FIFO
        try:
            return self.filename
        except OSError as e:
            self.logger.error(f'Failed to create FIFO: {e}')
        

    def on_fritap_message(self, job, message, data):
        """Callback for errors and messages sent from Frida-injected JavaScript.
        Logs captured packet data received from JavaScript to the console and/or a
        pcap file. See https://www.frida.re/docs/messages/ for more detail on
        Frida's messages.
        Args:
        message: A dictionary containing the message "type" and other fields
            dependent on message type.
        data: The string of captured decrypted data or the caputured decryption keys
        """


        """
        This offers the possibility to work with the JobManger() from the AndroidFridaManager project.
        """
        if self.script is None:
            self.script = job.script

        #print("----- Debug message -----")
        #print(message)
        #print("-------------------------")
        msg_type = message.get('type')
        #print(f"[*] Received message of type: {msg_type}")

        if msg_type == 'send':
            payload = message.get('payload')

            if self.startup and payload == 'experimental':
                self.script.post({'type':'experimental', 'payload': self.experimental})

            if self.startup and payload == 'defaultFD':
                self.script.post({'type':'defaultFD', 'payload': self.enable_default_fd})

            if self.startup and payload == 'socket_tracing':
                self.script.post({'type':'socket_tracing', 'payload': self.socket_trace})

            if self.startup and payload == 'pattern_hooking':
                self.script.post({'type':'pattern_hooking', 'payload': self.pattern_data})

            if self.startup and payload == 'offset_hooking':
                self.script.post({'type':'offset_hooking', 'payload': self.offsets_data})
            
            if self.startup and payload == 'anti':
                self.script.post({'type':'antiroot', 'payload': self.anti_root})
                self.startup = False
            
        
        if message["type"] == "error":
            self.handle_frida_script_error(message)
            return
        
        if "contentType" not in payload:
            return
        if payload["contentType"] == "console":
            if payload["console"].startswith("[*]"):
                self.logger.info(payload["console"].replace("[*] ", ""))
            else:
                self.logger.info(payload["console"])
        if self.debug or self.debug_output:
            if payload["contentType"] == "console_dev" and payload["console_dev"]:
                if len(payload["console_dev"]) > 3:
                    self.logger.debug(payload["console_dev"])
            elif payload["contentType"] == "console_error" and payload["console_error"]:
                if len(payload["console_error"]) > 3:
                    self.logger.error(payload["console_error"])
        if self.verbose:
            if(payload["contentType"] == "keylog") and self.keylog:
                if payload["keylog"] not in self.keydump_Set:
                    self.logger.info(payload["keylog"])
                    self.keydump_Set.add(payload["keylog"])
                    self.keylog_file.write(payload["keylog"] + "\n")
                    self.keylog_file.flush()
                    # Log to JSON if enabled
                    if self.json_output:
                        key_entry = {
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "type": "key_extraction",
                            "key_data": payload["keylog"]
                        }
                        self.session_data["key_extractions"].append(key_entry)
            elif not data or len(data) == 0:
                return
            else:
                src_addr = get_addr_string(payload["src_addr"], payload["ss_family"])
                dst_addr = get_addr_string(payload["dst_addr"], payload["ss_family"])

                if not self.socket_trace and not self.full_capture:
                    self.logger.info("SSL Session: " + str(payload["ssl_session_id"]))

                if self.full_capture:
                    # Add to traced_scapy_socket_Set as a frozenset dictionary
                    scapy_filter_entry = {
                        "src_addr": src_addr,
                        "dst_addr": dst_addr,
                        "ss_family": payload["ss_family"]
                    }
                    self.traced_scapy_socket_Set.add(frozenset(scapy_filter_entry.items()))  # Use frozenset for uniqueness

                if self.socket_trace:
                    display_filter_entry = {
                        "src_addr": src_addr,
                        "dst_addr": dst_addr,
                        "src_port": payload["src_port"],
                        "dst_port": payload["dst_port"],
                        "ss_family": payload["ss_family"]
                    }
                    self.traced_Socket_Set.add(frozenset(display_filter_entry.items()))
                    scapy_filter_entry = {
                        "src_addr": src_addr,
                        "dst_addr": dst_addr,
                        "ss_family": payload["ss_family"]
                    }
                    self.traced_scapy_socket_Set.add(frozenset(scapy_filter_entry.items()))

                    # Use structured data for the debug print
                    self.logger.debug(f"[socket_trace] {src_addr}:{payload['src_port']} --> {dst_addr}:{payload['dst_port']}")

                else:
                    self.logger.info("[%s] %s:%d --> %s:%d" % (payload["function"], src_addr, payload["src_port"], dst_addr, payload["dst_port"]))
                    if hexdump:
                        hexdump.hexdump(data)
                    else:
                        self.logger.info(f"Data: {data.hex() if data else 'No data'}")
                
                # Log connection to JSON if enabled
                if self.json_output:
                    connection_entry = {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "function": payload["function"],
                        "ssl_session_id": payload.get("ssl_session_id"),
                        "src_addr": src_addr,
                        "src_port": payload["src_port"],
                        "dst_addr": dst_addr,
                        "dst_port": payload["dst_port"],
                        "ss_family": payload["ss_family"],
                        "data_length": len(data) if data else 0
                    }
                    self.session_data["connections"].append(connection_entry)
                    self.session_data["statistics"]["total_connections"] += 1
                    self.session_data["statistics"]["total_bytes_captured"] += len(data) if data else 0
        if self.pcap_name and payload["contentType"] == "datalog" and not self.full_capture:
            self.pcap_obj.log_plaintext_payload(payload["ss_family"], payload["function"], payload["src_addr"],
                     payload["src_port"], payload["dst_addr"], payload["dst_port"], data)
        if self.live and payload["contentType"] == "datalog" and not self.full_capture:
            try:
                self.pcap_obj.log_plaintext_payload(payload["ss_family"], payload["function"], payload["src_addr"],
                         payload["src_port"], payload["dst_addr"], payload["dst_port"], data)
            except (BrokenPipeError, IOError):
                self.detach_with_timeout(self.process)
                self.cleanup(self.live, self.socket_trace, self.full_capture, self.debug)

        if self.keylog and payload["contentType"] == "keylog":
            if payload["keylog"] not in self.keydump_Set:
                self.keylog_file.write(payload["keylog"] + "\n")
                self.keylog_file.flush()
                self.keydump_Set.add(payload["keylog"])
        
        if self.socket_trace or self.full_capture:
            if "src_addr" not in payload:
                return
            
            src_addr = get_addr_string(payload["src_addr"], payload["ss_family"])
            dst_addr = get_addr_string(payload["dst_addr"], payload["ss_family"])

            if self.socket_trace:
                # Add a structured dictionary to traced_Socket_Set
                display_filter_entry = {
                    "src_addr": src_addr,
                    "dst_addr": dst_addr,
                    "src_port": payload["src_port"],
                    "dst_port": payload["dst_port"],
                    "ss_family": payload["ss_family"]
                }
                self.traced_Socket_Set.add(frozenset(display_filter_entry.items()))  # Use frozenset for uniqueness
                # Add a structured dictionary to traced_scapy_socket_Set
                scapy_filter_entry = {
                    "src_addr": src_addr,
                    "dst_addr": dst_addr,
                    "ss_family": payload["ss_family"]
                }
                self.traced_scapy_socket_Set.add(frozenset(scapy_filter_entry.items()))  # Use frozenset for uniqueness

    

    
    def on_custom_hook_message(self, message, data):
        """
        This handler is used to print the messages from the provided custom hooks
        """

        if message["type"] == "error":
            pprint.pprint(message)
            os.kill(os.getpid(), signal.SIGTERM)
            return
        
        custom_hook_payload = message["payload"]
        if "custom" not in custom_hook_payload:
            return

        self.logger.info(f"custom hook: {custom_hook_payload['custom']}")

    
    
    def on_child_added(self, child):
        self.logger.info(f"Attached to child process with pid {child.pid}")
        self.instrument(self.device.attach(child.pid), self.own_message_handler)
        self.device.resume(child.pid)


    def on_spawn_added(self, spawn):
        self.logger.info(f"Process spawned with pid {spawn.pid}. Name: {spawn.identifier}")
        self.instrument(self.device.attach(spawn.pid), self.own_message_handler)
        self.device.resume(spawn.pid)
        

    def instrument(self, process, own_message_handler):
        runtime="qjs"
        debug_port = 1337
        if self.debug:
            if frida.__version__ < "16":
                process.enable_debugger(debug_port)
            self.logger.info("running in debug mode")
            self.logger.info(f"Chrome Inspector server listening on port {debug_port}")
            self.logger.info("Open Chrome with chrome://inspect for debugging")
            runtime="v8"
        
        if self.custom_hook_script is not None:
            custom_script_string = self.get_custom_frida_script()
            if self.debug_output:
                self.logger.debug(f"loading custom frida script: {self.custom_hook_script}")
        
        script_string = self.get_fritap_frida_script()
        if self.debug_output:
            self.logger.debug(f"loading friTap frida script: {self.frida_agent_script}")
        

        if self.offsets_data is not None:
            self.logger.info(f"applying hooks at offset {self.offsets_data}")

        if self.pattern_data is not None:
            self.logger.info("Using pattern provided by pattern.json for hooking")

        
        if self.custom_hook_script is not None:
            self.custom_script = process.create_script(custom_script_string, runtime=runtime)
            self.custom_script.on("message", self.on_custom_hook_message)
            self.custom_script.load()


        self.script = process.create_script(script_string, runtime=runtime)

        if self.debug and frida.__version__ >= "16":
            self.script.enable_debugger(debug_port)

        if own_message_handler is not None:
            self.script.on("message", self._provide_custom_hooking_handler(own_message_handler))
            return self.script
        else:
            self.script.on("message", self._internal_callback_wrapper())
        self.script.load()
        
        

        
        #script.post({'type':'readmod', 'payload': '0x440x410x53'})
        if self.payload_modification:
            class ModWatcher(FileSystemEventHandler):
                def __init__(self, process):
                    
                    self.process = process

                def on_any_event(self, event):
                    try:
                        if(event.event_type == "modified" and ("readmod" in event.src_path)):
                            with open("./readmod.bin", "rb") as f:
                                buffer = f.read()
                                self.script.post({'type':'readmod', 'payload': buffer.hex()})
                        elif(event.event_type == "modified" and ("writemod" in event.src_path)):
                            with open("./writemod.bin", "rb") as f:
                                buffer = f.read()
                                self.script.post({'type':'writemod', 'payload': buffer.hex()})
                    except RuntimeError as e:
                        self.logger.error(f"Watcher error: {e}")
                
                

            self.logger.debug("Init watcher")
            event_handler = ModWatcher(process)
            
            observer = Observer()
            observer.schedule(event_handler, os.getcwd())
            observer.start()

        return self.script
     
    
    def load_patterns(self):
        if os.path.exists(self.patterns):
            try:
                with open(self.patterns, "rb") as file:
                    raw_data = file.read()
                    pattern_file = raw_data.decode("utf-8")

                # Try parsing the JSON to verify it's valid
                json_data = json.loads(pattern_file)
                self.pattern_data = json.dumps(json_data, ensure_ascii=False).encode('utf-8').decode('utf-8')  # Ensure pattern_data is a JSON string in utf-8

            except (UnicodeDecodeError, json.JSONDecodeError) as e:
                self.logger.error(f"UnicodeDecodeError: {e}")
            except (ValueError, json.JSONDecodeError) as e:
                self.logger.error(f"Error loading JSON file, defaulting to auto-detection: {e}")
            except OSError as e:
                self.logger.error(f"Error reading the file: {e}")
        else:
            self.logger.error(f"Pattern file {self.patterns} does not exist.")
    
    
    def start_fritap_session_instrumentation(self, own_message_handler, process):
        self.process = process
        script = self.instrument(self.process, own_message_handler)
        return script

    
    def start_fritap_session(self, own_message_handler=None):

        if self.mobile:
            try:
                if self.mobile is True:  # No device ID provided
                    if self.debug_output or self.debug:
                        self.logger.debug("Attaching to the first available USB device...")
                    self.device = frida.get_usb_device()
                else:  # Device ID provided
                    if self.debug_output or self.debug:
                        self.logger.debug(f"Attaching to the device with ID: {self.mobile}")
                    self.device = frida.get_device(self.mobile)
                self.logger.info("Successfully attached to the mobile device.")
            except frida.ServerNotRunningError:
                self.logger.error("Frida server is not running. Please ensure it is started on the device.")
                sys.exit(1)
            except frida.DeviceNotFoundError:
                self.logger.error(f"Device with ID '{self.mobile}' not found. Please check the device ID or ensure it is connected.")
                sys.exit(1)
            except Exception as e:
                self.logger.error(f"Unexpected error while attaching to the device: {e}")
                sys.exit(1)
        elif self.host:
            self.device = frida.get_device_manager().add_remote_device(self.host)
        else:
            self.device = frida.get_local_device()

        self.device.on("child_added", self.on_child_added)
        if self.enable_spawn_gating:
            self.device.enable_spawn_gating()
            self.device.on("spawn_added", self.on_spawn_added)
        if self.spawn:
            self.logger.info(f"spawning {self.target_app}")
            
            if self.mobile or self.host:
                pid = self.device.spawn(self.target_app)
            else:
                used_env = {}
                if self.environment_file:
                    with open(self.environment_file) as json_env_file:
                        used_env = json.load(json_env_file)
                pid = self.device.spawn(self.target_app.split(" "),env=used_env)
                self.device.resume(pid)
                time.sleep(1) # without it Java.perform silently fails
            self.process = self.device.attach(pid)
        else:
            self.process = self.device.attach(int(self.target_app) if self.target_app.isnumeric() else self.target_app)


        script = self.instrument(self.process, own_message_handler)



        if self.pcap_name and self.full_capture:
            self.logger.info(f'Logging pcap to {self.pcap_name}')
        if self.pcap_name and not self.full_capture:
            self.logger.info(f'Logging TLS plaintext as pcap to {self.pcap_name}')
        if self.keylog:
            self.logger.info(f'Logging keylog file to {self.keylog}')
            
        #self.process.on('detached', self.on_detach)

        if self.spawn:
            self.device.resume(pid)

        return self.process, script


    def finish_fritap(self):
        if self.script:
            self.script.unload()


    def _provide_custom_hooking_handler(self, handler):
        def wrapped_handler(message, data):
            handler(message, data)

        return wrapped_handler


    def _internal_callback_wrapper(self):
        def wrapped_handler(message, data):
            self.on_fritap_message(None, message, data)
        
        return wrapped_handler


    def detach_with_timeout(self, timeout=5):
        """
        Attempt to detach from the Frida process with a timeout.

        Args:
            process: The Frida process to detach from.
            timeout: Time in seconds to wait before forcing detachment.
        """
        def detach():
            try:
                if self.debug_output or self.debug:
                    self.logger.debug("Attempting to detach from Frida process...")
                try:
                    self.script.unload()
                except Exception:
                    pass

                self.process.detach()
                if self.debug_output or self.debug:
                    self.logger.debug("Successfully detached from Frida process.")
            except Exception as e:
                self.logger.error(f"Error while detaching: {e}")

        # Create a thread to run the detach method
        detach_thread = threading.Thread(target=detach)
        detach_thread.start()

        # Wait for the thread to complete
        detach_thread.join(timeout=timeout)

        if detach_thread.is_alive():
            if self.debug_output:
                self.logger.warning(f"Detach process timed out after {timeout} seconds.")
            # Force cleanup if necessary
            # Note: Frida doesn't provide a "force detach," so handle gracefully
        else:
            if self.debug_output:
                self.logger.debug("Detached friTap from process successfully.")



    def set_keylog_file(self, keylog_name):
        self.keylog_file = open(keylog_name, "w")
    

    def pcap_cleanup(self, is_full_capture, is_mobile, pcap_name):
        if is_full_capture and self.pcap_obj is not None:
                capture_type = "local"
                self.pcap_obj.full_capture_thread.join(2.0)
                if self.pcap_obj.full_capture_thread.is_alive() and not is_mobile:
                    self.pcap_obj.full_capture_thread.socket.close()
                if self.pcap_obj.full_capture_thread.mobile_subprocess != -1:
                    capture_type = "mobile"
                    self.pcap_obj.android_Instance.send_ctrlC_over_adb()
                    time.sleep(1)
                    self.pcap_obj.full_capture_thread.mobile_subprocess.terminate()
                    self.pcap_obj.full_capture_thread.mobile_subprocess.wait()
                    if not self.pcap_obj.android_Instance.is_tcpdump_available():
                        self.logger.error("tcpdump is not available on the device.")
                        return
                    self.pcap_obj.android_Instance.pull_pcap_from_device()
                self.logger.info(f"full {capture_type} capture saved to _{pcap_name}")
                if self.keylog_file is None:
                    self.logger.info("remember that the full capture won't contain any decrypted TLS traffic.")
                else:
                    self.logger.info(f"remember that the full capture won't contain any decrypted TLS traffic. In order to decrypt it use the logged keys from {self.keylog_file.name}")
    

    def cleanup(self, live=False, socket_trace=False, full_capture=False, debug_output=False, debug=False):
        if self.pcap_obj is not None and full_capture:
            if self.pcap_obj.full_capture_thread.is_alive():
                self.pcap_obj.full_capture_thread.join()
                time.sleep(2)
        if live:
            os.unlink(self.filename)  # Remove file
            os.rmdir(self.tmpdir)  # Remove directory
        if type(socket_trace) is str:
            self.logger.info(f"Write traced sockets into {socket_trace}")
            self.write_socket_trace(socket_trace)
        if socket_trace:
            display_filter = PCAP.get_filter_from_traced_sockets(self.traced_Socket_Set, filter_type="display")
            self.logger.info(f"Generated Display Filter for Wireshark:\n{display_filter}")
        
        if full_capture and len(self.traced_scapy_socket_Set) > 0:
            if debug_output or debug:
                display_filter = PCAP.get_filter_from_traced_sockets(self.traced_Socket_Set, filter_type="display")
                self.logger.debug(f"Generated Display Filter for Wireshark:\n{display_filter}")

            try:
                self.pcap_obj.create_application_traffic_pcap(self.traced_scapy_socket_Set,self.pcap_obj)
            except Exception as e:
                self.logger.error(f"Error: {e}")

        elif full_capture and len(self.traced_scapy_socket_Set) < 1:
            if socket_trace:
                self.logger.warning(f"friTap was unable to identify the used sockets. The resulting PCAP _{self.pcap_obj.pcap_file_name} will contain all traffic from the device.")
            else:
                self.logger.info(f"friTap not trace the sockets in use (--socket_tracing option not enabled). The resulting PCAP _{self.pcap_obj.pcap_file_name} will contain all traffic from the device.")
            
        # Finalize JSON output if enabled
        if self.json_output:
            self._finalize_json_output()
            
        self.running = False
        if self.process:
            self.detach_with_timeout()  # Detach Frida process if applicable
        self.special_logger.info("\nThanks for using friTap. Have a great day!")
        os._exit(0)

    def get_fritap_frida_script(self):
        with open(os.path.join(here, self.frida_agent_script), encoding='utf-8', newline='\n') as f:
            script_string = f.read()
            return script_string
    
    def inspect_libraries(self):
        """Inspect loaded libraries using the SSL Library Inspector"""
        try:
            # Set up device connection like in start_fritap_session but simpler
            if self.mobile:
                try:
                    if self.mobile is True:  # No device ID provided
                        if self.debug_output or self.debug:
                            self.logger.debug("Attaching to the first available USB device...")
                        device = frida.get_usb_device()
                    else:  # Device ID provided
                        if self.debug_output or self.debug:
                            self.logger.debug(f"Attaching to the device with ID: {self.mobile}")
                        device = frida.get_device(self.mobile)
                    self.logger.info("Successfully attached to the mobile device.")
                except frida.ServerNotRunningError:
                    self.logger.error("Frida server is not running. Please ensure it is started on the device.")
                    return "Error: Frida server not running"
                except frida.DeviceNotFoundError:
                    self.logger.error(f"Device with ID '{self.mobile}' not found. Please check the device ID or ensure it is connected.")
                    return "Error: Device not found"
                except Exception as e:
                    self.logger.error(f"Unexpected error while attaching to the device: {e}")
                    return f"Error: {e}"
            elif self.host:
                device = frida.get_device_manager().add_remote_device(self.host)
            else:
                device = frida.get_local_device()

            # Attach to the process
            if self.spawn:
                self.logger.info(f"spawning {self.target_app}")
                if self.mobile or self.host:
                    pid = device.spawn(self.target_app)
                else:
                    used_env = {}
                    if self.environment_file:
                        with open(self.environment_file) as json_env_file:
                            used_env = json.load(json_env_file)
                    pid = device.spawn(self.target_app.split(" "), env=used_env)
                    device.resume(pid)
                    time.sleep(1)  # without it Java.perform silently fails
                process = device.attach(pid)
            else:
                process = device.attach(int(self.target_app) if self.target_app.isnumeric() else self.target_app)

            # Create a JavaScript implementation of the SSL Library Inspector
            ssl_inspector_script = """
            function inspectSSLLibraries() {
                const output = [];
                
                // Step 1: All loaded libraries
                output.push("=== [ Loaded Libraries ] ===");
                const modules = Process.enumerateModules();
                for (const mod of modules) {
                    output.push(`- ${mod.name} @ ${mod.base} (${mod.size} bytes)`);
                }
                
                output.push("\\n=== [ Libraries with 'ssl' in their name ] ===");
                const sslNameLibs = modules.filter(mod => mod.name.toLowerCase().includes("ssl"));
                for (const mod of sslNameLibs) {
                    output.push(`- ${mod.name}`);
                }
                
                output.push("\\n=== [ Libraries with TLS/SSL-related exports ] ===");
                const sslExportLibs = [];
                const sslPatterns = [
                    '_ssl', 'ssl_', 'SSL_', 'TLS_', 'tls_', 
                    'mbedtls_', 'wolfssl', 'wolfSSL', 'gnutls_',
                    'BIO_', 'X509_', 'EVP_', 'RAND_', 'RSA_',
                    'AES_', 'DES_', 'MD5_', 'SHA_', 'HMAC_',
                    'PKCS', 'ASN1_', 'PEM_', 'CRYPTO_'
                ];
                
                for (const mod of modules) {
                    try {
                        const exports = Process.getModuleByName(mod.name).enumerateExports();
                        const relevantExports = exports.filter(exp => 
                            sslPatterns.some(pattern => exp.name.includes(pattern))
                        );
                        
                        if (relevantExports.length > 0) {
                            sslExportLibs.push(mod.name);
                            output.push(`- ${mod.name} (${relevantExports.length} TLS/SSL exports)`);
                            
                            // Show some key exports for debugging
                            const keyExports = relevantExports.slice(0, 5);
                            for (const exp of keyExports) {
                                output.push(`  * ${exp.name} @ ${exp.address}`);
                            }
                            if (relevantExports.length > 5) {
                                output.push(`  ... and ${relevantExports.length - 5} more`);
                            }
                        }
                    } catch (err) {
                        output.push(`[!] Could not enumerate exports of ${mod.name}: ${err}`);
                    }
                }
                
                // Step 2: Check for common SSL/TLS libraries
                output.push("\\n=== [ Known SSL/TLS Library Detection ] ===");
                const knownLibraries = [
                    { name: 'OpenSSL', patterns: ['libssl', 'libcrypto', 'openssl'] },
                    { name: 'WolfSSL', patterns: ['libwolfssl', 'wolfssl'] },
                    { name: 'mbedTLS', patterns: ['libmbedtls', 'mbedtls'] },
                    { name: 'GnuTLS', patterns: ['libgnutls', 'gnutls'] },
                    { name: 'NSS', patterns: ['libnss', 'nss'] },
                    { name: 'Schannel', patterns: ['schannel', 'secur32'] },
                    { name: 'Secure Transport', patterns: ['Security', 'SecureTransport'] },
                    { name: 'BoringSSL', patterns: ['boringssl'] },
                    { name: 'LibreSSL', patterns: ['libressl'] }
                ];
                
                for (const lib of knownLibraries) {
                    const foundModules = modules.filter(mod => 
                        lib.patterns.some(pattern => 
                            mod.name.toLowerCase().includes(pattern.toLowerCase())
                        )
                    );
                    
                    if (foundModules.length > 0) {
                        output.push(`✓ ${lib.name} detected:`);
                        for (const mod of foundModules) {
                            output.push(`  - ${mod.name} @ ${mod.base}`);
                        }
                    }
                }
                
                return output.join("\\n");
            }
            
            rpc.exports.inspectssl = inspectSSLLibraries;
            """
            
            # Create and load the script
            script = process.create_script(ssl_inspector_script)
            script.load()
            
            # Call the SSL library inspector
            result = script.exports_sync.inspectssl()
            
            # Clean up
            script.unload()
            process.detach()
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error during library inspection: {e}")
            return f"Error: Failed to inspect libraries - {e}"
            
    
    def get_custom_frida_script(self):
        with open(os.path.join(here, self.custom_hook_script), encoding='utf-8', newline='\n') as f:
            script_string = f.read()
            return script_string
    
    
    def get_fritap_frida_script_path(self):
        return os.path.join(os.path.dirname(__file__), self.frida_agent_script)


    def install_signal_handler(self):
        def signal_handler(signum, frame):
            self.logger.info("Ctrl+C detected. Cleaning up...")
            self.pcap_cleanup(self.full_capture, self.mobile, self.pcap_name)
            self.cleanup(self.live, self.socket_trace, self.full_capture, self.debug_output, self.debug)  # Call the instance's cleanup method


        signal.signal(signal.SIGINT, signal_handler)
        
    def _log_session_end(self, reason):
        """Log session end information to JSON if enabled"""
        if self.json_output:
            self.session_data["session_info"]["end_time"] = datetime.now(timezone.utc).isoformat()
            self.session_data["session_info"]["end_reason"] = reason
            self.session_data["statistics"]["total_sessions"] = len(self.session_data["ssl_sessions"])
            
    def _finalize_json_output(self):
        """Write final JSON output to file"""
        if self.json_file:
            try:
                # Update statistics
                self.session_data["session_info"]["end_time"] = datetime.now(timezone.utc).isoformat()
                
                # Write JSON data
                json.dump(self.session_data, self.json_file, indent=2, ensure_ascii=False)
                self.json_file.close()
                self.logger.info(f"JSON output saved to {self.json_output}")
            except Exception as e:
                self.logger.error(f"Error writing JSON output: {e}")
                
    def add_ssl_session(self, session_info):
        """Add SSL session information to JSON output"""
        if self.json_output:
            session_entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "session_id": session_info.get("session_id"),
                "cipher_suite": session_info.get("cipher_suite"),
                "protocol_version": session_info.get("protocol_version"),
                "server_name": session_info.get("server_name"),
                "certificate_info": session_info.get("certificate_info")
            }
            self.session_data["ssl_sessions"].append(session_entry)
            
    def add_library_detection(self, library_name, library_path):
        """Add detected SSL library information to JSON output"""
        if self.json_output:
            library_info = {
                "name": library_name,
                "path": library_path,
                "detected_at": datetime.now(timezone.utc).isoformat()
            }
            if library_info not in self.session_data["statistics"]["libraries_detected"]:
                self.session_data["statistics"]["libraries_detected"].append(library_info)


    def write_socket_trace(self, socket_trace_name):
        with open(socket_trace_name, 'a') as trace_file:
            trace_file.write(PCAP.get_filter_from_traced_sockets(self.traced_Socket_Set, filter_type="display") + '\n')


  
def get_addr_string(socket_addr,ss_family):
    if ss_family == "AF_INET":
        return  socket.inet_ntop(socket.AF_INET, struct.pack(">I", socket_addr))
    else: # this should only be AF_INET6
        raw_addr = bytes.fromhex(socket_addr)
        return socket.inet_ntop(socket.AF_INET6, struct.pack(">16s", raw_addr))



