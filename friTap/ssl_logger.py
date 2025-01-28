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
from .pcap import PCAP
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, LoggingEventHandler

try:
    import hexdump  # pylint: disable=g-import-not-at-top
except ImportError:
    print("Unable to import hexdump module!")
    pass


# here - where we are.
here = os.path.abspath(os.path.dirname(__file__))

# Names of all supported read functions:
SSL_READ = ["SSL_read", "wolfSSL_read", "readApplicationData", "NSS_read","Full_read"]
# Names of all supported write functions:
SSL_WRITE = ["SSL_write", "wolfSSL_write", "writeApplicationData", "NSS_write","Full_write"]

class SSL_Logger():

    def __init__(self, app, pcap_name=None, verbose=False, spawn=False, keylog=False, enable_spawn_gating=False, mobile=False, live=False, environment_file=None, debug_mode=False,full_capture=False, socket_trace=False, host=False, offsets=None, debug_output=False, experimental=False, anti_root=False, payload_modification=False,enable_default_fd=False, patterns=None, custom_hook_script=None):
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

        self.tmpdir = None
        self.filename = ""
        self.startup = True

        self.process = None
        self.device = None
        self.keylog_file = None

        self.patterns = patterns
        self.pattern_data = None        

        self.keydump_Set = {*()}
        self.traced_Socket_Set = {*()}
        self.traced_scapy_socket_Set = {*()}

        self.init_fritap()
    
    
    def init_fritap(self):
        if frida.__version__ < "16":
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
                    print(f"Log error, defaulting to auto-detection: {e}")

        if self.patterns is not None:
            self.load_patterns()

        if self.keylog:
            self.keylog_file = open(self.keylog, "w")

        if self.live:
            if self.pcap_name:
                print("[*] YOU ARE TRYING TO WRITE A PCAP AND HAVING A LIVE VIEW\nTHIS IS NOT SUPPORTED!\nWHEN YOU DO A LIVE VIEW YOU CAN SAFE YOUR CAPUTRE WITH WIRESHARK.")
            fifo_file = self.temp_fifo()
            print(f'[*] friTap live view on Wireshark')
            print(f'[*] Created named pipe for Wireshark live view to {fifo_file}')
            print(
                f'[*] Now open this named pipe with Wireshark in another terminal: sudo wireshark -k -i {fifo_file}')
            print(f'[*] friTap will continue after the named pipe is ready....\n')
            self.pcap_obj =  PCAP(fifo_file,SSL_READ,SSL_WRITE,self.full_capture, self.mobile,self.debug)

    
    def on_detach(self, reason):

        if reason == "application-requested":
            return
        
        print(f"\n[*] Target process stopped: {reason}\n")            
        self.pcap_cleanup(self.full_capture,self.mobile,self.pcap_name)
        self.cleanup(self.live,self.socket_trace,self.full_capture,self.debug)
        


    def temp_fifo(self):
        self.tmpdir = tempfile.mkdtemp()
        self.filename = os.path.join(self.tmpdir, 'fritap_sharkfin')  # Temporary filename
        os.mkfifo(self.filename)  # Create FIFO
        try:
            return self.filename
        except OSError as e:
            print(f'Failed to create FIFO: {e}')
        

    def on_fritap_message(self,job, message, data):
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
        if self.script == None:
            self.script = job.script
            
        if self.startup and message['payload'] == 'experimental':
            self.script.post({'type':'experimental', 'payload': self.experimental})

        if self.startup and message['payload'] == 'defaultFD':
            self.script.post({'type':'defaultFD', 'payload': self.enable_default_fd})

        if self.startup and message['payload'] == 'socket_tracing':
            self.script.post({'type':'socket_tracing', 'payload': self.socket_trace})

        if self.startup and message['payload'] == 'pattern_hooking':
            self.script.post({'type':'pattern_hooking', 'payload': self.pattern_data})

        if self.startup and message['payload'] == 'offset_hooking':
            self.script.post({'type':'offset_hooking', 'payload': self.offsets_data})
        
        if self.startup and message['payload'] == 'anti':
            self.script.post({'type':'antiroot', 'payload': self.anti_root})
            self.startup = False
            
        
        if message["type"] == "error":
            pprint.pprint(message)
            os.kill(os.getpid(), signal.SIGTERM)
            return
        
        p = message["payload"]
        if not "contentType" in p:
            return
        if p["contentType"] == "console":
            if p["console"].startswith("[*]"):
                print(p["console"])
            else:
                print("[*] " + p["console"])
        if self.debug or self.debug_output:
            if p["contentType"] == "console_dev" and p["console_dev"]:
                if len(p["console_dev"]) > 3:
                    print("[***] " + p["console_dev"])
            elif p["contentType"] == "console_error" and p["console_error"]:
                if len(p["console_error"]) > 3:
                    print("[---] " + p["console_error"])
        if self.verbose:
            if(p["contentType"] == "keylog") and self.keylog:
                if p["keylog"] not in self.keydump_Set:
                    print(p["keylog"])
                    self.keydump_Set.add(p["keylog"])
                    self.keylog_file.write(p["keylog"] + "\n")
                    self.keylog_file.flush()    
            elif not data or len(data) == 0:
                return
            else:
                src_addr = get_addr_string(p["src_addr"], p["ss_family"])
                dst_addr = get_addr_string(p["dst_addr"], p["ss_family"])

                if self.socket_trace == False and self.full_capture == False:
                    print("SSL Session: " + str(p["ssl_session_id"]))

                if self.full_capture:
                    # Add to traced_scapy_socket_Set as a frozenset dictionary
                    scapy_filter_entry = {
                        "src_addr": src_addr,
                        "dst_addr": dst_addr,
                        "ss_family": p["ss_family"]
                    }
                    self.traced_scapy_socket_Set.add(frozenset(scapy_filter_entry.items()))  # Use frozenset for uniqueness

                if self.socket_trace:
                    display_filter_entry = {
                        "src_addr": src_addr,
                        "dst_addr": dst_addr,
                        "src_port": p["src_port"],
                        "dst_port": p["dst_port"],
                        "ss_family": p["ss_family"]
                    }
                    self.traced_Socket_Set.add(frozenset(display_filter_entry.items()))
                    scapy_filter_entry = {
                        "src_addr": src_addr,
                        "dst_addr": dst_addr,
                        "ss_family": p["ss_family"]
                    }
                    self.traced_scapy_socket_Set.add(frozenset(scapy_filter_entry.items()))

                    # Use structured data for the debug print
                    print(f"[socket_trace] {src_addr}:{p['src_port']} --> {dst_addr}:{p['dst_port']}")

                else:
                    print("[%s] %s:%d --> %s:%d" % (p["function"], src_addr, p["src_port"], dst_addr, p["dst_port"]))
                    hexdump.hexdump(data)
                print()
        if self.pcap_name and p["contentType"] == "datalog" and self.full_capture == False:
            self.pcap_obj.log_plaintext_payload(p["ss_family"], p["function"], p["src_addr"],
                     p["src_port"], p["dst_addr"], p["dst_port"], data)
        if self.live and p["contentType"] == "datalog" and self.full_capture == False:
            try:
                self.pcap_obj.log_plaintext_payload(p["ss_family"], p["function"], p["src_addr"],
                         p["src_port"], p["dst_addr"], p["dst_port"], data)
            except (BrokenPipeError, IOError):
                self.detach_with_timeout(self.process)
                self.cleanup(self.live, self.socket_trace, self.full_capture, self.debug)

        if self.keylog and p["contentType"] == "keylog":
            if p["keylog"] not in self.keydump_Set:
                self.keylog_file.write(p["keylog"] + "\n")
                self.keylog_file.flush()
                self.keydump_Set.add(p["keylog"])
        
        if self.socket_trace or self.full_capture:
            if "src_addr" not in p:
                return
            
            src_addr = get_addr_string(p["src_addr"], p["ss_family"])
            dst_addr = get_addr_string(p["dst_addr"], p["ss_family"])

            if self.socket_trace:
                # Add a structured dictionary to traced_Socket_Set
                display_filter_entry = {
                    "src_addr": src_addr,
                    "dst_addr": dst_addr,
                    "src_port": p["src_port"],
                    "dst_port": p["dst_port"],
                    "ss_family": p["ss_family"]
                }
                self.traced_Socket_Set.add(frozenset(display_filter_entry.items()))  # Use frozenset for uniqueness
                # Add a structured dictionary to traced_scapy_socket_Set
                scapy_filter_entry = {
                    "src_addr": src_addr,
                    "dst_addr": dst_addr,
                    "ss_family": p["ss_family"]
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
        if not "custom" in custom_hook_payload:
            return

        print("[+] custom hook: "+custom_hook_payload["custom"])

    
    
    def on_child_added(self, child):
        print(f"[*] Attached to child process with pid {child.pid}")
        self.instrument(self.device.attach(child.pid))
        self.device.resume(child.pid)


    def on_spawn_added(self, spawn):
        print(
            f"[*] Process spawned with pid {spawn.pid}. Name: {spawn.identifier}")
        self.instrument(self.device.attach(spawn.pid))
        self.device.resume(spawn.pid)
        

    def instrument(self, process, own_message_handler):
        runtime="qjs"
        debug_port = 1337
        if self.debug:
            if frida.__version__ < "16":
                process.enable_debugger(debug_port)
            print("\n[!] running in debug mode")
            print(f"[!] Chrome Inspector server listening on port {debug_port}")
            print("[!] Open Chrome with chrome://inspect for debugging\n")
            runtime="v8"
        
        if self.custom_hook_script is not None:
            custom_script_string = self.get_custom_frida_script()
            if self.debug_output:
                print("[***] loading custom frida script: " + self.custom_hook_script)
        
        script_string = self.get_fritap_frida_script()
        if self.debug_output:
            print("[***] loading friTap frida script: " + self.frida_agent_script)
        

        if self.offsets_data is not None:
            print(f"[*] applying hooks at offset {self.offsets_data}")


        if self.pattern_data is not None:
            print(f"[*] Using pattern provided by pattern.json for hooking")

        
        if self.custom_hook_script is not None:
            self.custom_script = process.create_script(custom_script_string, runtime=runtime)
            self.custom_script.on("message", self.on_custom_hook_message)
            self.custom_script.load()


        self.script = process.create_script(script_string, runtime=runtime)

        if self.debug and frida.__version__ >= "16":
            self.script.enable_debugger(debug_port)

        if own_message_handler != None:
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
                        print(e)
                
                

            print("Init watcher")
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
                print(f"[-] UnicodeDecodeError: {e}")
            except (ValueError, json.JSONDecodeError) as e:
                print(f"[-] Error loading JSON file, defaulting to auto-detection: {e}")
            except OSError as e:
                print(f"[-] Error reading the file: {e}")
        else:
            print(f"[-] Pattern file {self.patterns} does not exist.")
    
    
    def start_fritap_session_instrumentation(self, own_message_handler, process):
        self.process = process
        script = self.instrument(self.process, own_message_handler)
        return script

    
    def start_fritap_session(self, own_message_handler=None):

        if self.mobile:
            try:
                if self.mobile is True:  # No device ID provided
                    if self.debug_output or self.debug:
                        print("[*] Attaching to the first available USB device...")
                    self.device = frida.get_usb_device()
                else:  # Device ID provided
                    if self.debug_output or self.debug:
                        print(f"[*] Attaching to the device with ID: {self.mobile}")
                    self.device = frida.get_device(self.mobile)
                print("[*] Successfully attached to the mobile device.")
            except frida.ServerNotRunningError:
                print("[-] Frida server is not running. Please ensure it is started on the device.")
                sys.exit(1)
            except frida.DeviceNotFoundError:
                print(f"[-] Device with ID '{self.mobile}' not found. Please check the device ID or ensure it is connected.")
                sys.exit(1)
            except Exception as e:
                print(f"[-] Unexpected error while attaching to the device: {e}")
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
            print("spawning "+ self.target_app)
            
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
            print(f'[*] Logging pcap to {self.pcap_name}')
        if self.pcap_name and self.full_capture == False:
            print(f'[*] Logging TLS plaintext as pcap to {self.pcap_name}')
        if self.keylog:
            print(f'[*] Logging keylog file to {self.keylog}')
            
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
                    print("[*] Attempting to detach from Frida process...")
                try:
                    self.script.unload()
                except:
                    pass

                self.process.detach()
                if self.debug_output or self.debug:
                    print("[*] Successfully detached from Frida process.")
            except Exception as e:
                print(f"[-] Error while detaching: {e}")

        # Create a thread to run the detach method
        detach_thread = threading.Thread(target=detach)
        detach_thread.start()

        # Wait for the thread to complete
        detach_thread.join(timeout=timeout)

        if detach_thread.is_alive():
            if self.debug_output:
                print(f"[-] Detach process timed out after {timeout} seconds.")
            # Force cleanup if necessary
            # Note: Frida doesn't provide a "force detach," so handle gracefully
        else:
            if self.debug_output:
                print("[*] Detached friTap from process successfully.")



    def set_keylog_file(self, keylog_name):
        self.keylog_file = open(keylog_name, "w")
    

    def pcap_cleanup(self, is_full_capture, is_mobile, pcap_name):
        if is_full_capture and self.pcap_obj is not None:
                capture_type = "local"
                self.pcap_obj.full_capture_thread.join(2.0)
                if self.pcap_obj.full_capture_thread.is_alive() and is_mobile == False:
                    self.pcap_obj.full_capture_thread.socket.close()
                if self.pcap_obj.full_capture_thread.mobile_subprocess != -1:
                    capture_type = "mobile"
                    self.pcap_obj.android_Instance.send_ctrlC_over_adb()
                    time.sleep(1)
                    self.pcap_obj.full_capture_thread.mobile_subprocess.terminate()
                    self.pcap_obj.full_capture_thread.mobile_subprocess.wait()
                    self.pcap_obj.android_Instance.pull_pcap_from_device()
                print(f"[*] full {capture_type} capture safed to _{pcap_name}")
                if self.keylog_file is None:
                    print(f"[*] remember that the full capture won't contain any decrypted TLS traffic.")
                else:
                    print(f"[*] remember that the full capture won't contain any decrypted TLS traffic. In order to decrypt it use the logged keys from {self.keylog_file.name}")
    

    def cleanup(self, live=False, socket_trace=False, full_capture=False, debug_output=False, debug=False):
        if self.pcap_obj is not None and full_capture:
            if self.pcap_obj.full_capture_thread.is_alive():
                self.pcap_obj.full_capture_thread.join()
                time.sleep(2)
        if live:
            os.unlink(self.filename)  # Remove file
            os.rmdir(self.tmpdir)  # Remove directory
        if type(socket_trace) is str:
            print(f"[*] Write traced sockets into {socket_trace}")
            self.write_socket_trace(socket_trace)
        if socket_trace == True:
            display_filter = PCAP.get_filter_from_traced_sockets(self.traced_Socket_Set, filter_type="display")
            print(f"[*] Generated Display Filter for Wireshark:\n{display_filter}")
        
        if full_capture and len(self.traced_scapy_socket_Set) > 0:
            if debug_output or debug:
                display_filter = PCAP.get_filter_from_traced_sockets(self.traced_Socket_Set, filter_type="display")
                print(f"[*] Generated Display Filter for Wireshark:\n{display_filter}")

            try:
                self.pcap_obj.create_application_traffic_pcap(self.traced_scapy_socket_Set,self.pcap_obj)
            except Exception as e:
                print(f"Error: {e}")

        elif full_capture and len(self.traced_scapy_socket_Set) < 1:
            if socket_trace == True:
                print(f"[-] friTap was unable to indentify the used sockets. \n[*] The resulting PCAP _{self.pcap_obj.pcap_file_name} will contain all trafic from the device.")
            else:
                print(f"[*] friTap not trace the sockets in use (--socket_tracing option not enabled)\n[*] The resulting PCAP _{self.pcap_obj.pcap_file_name} will contain all trafic from the device.")
            
        self.running = False
        if self.process:
            self.detach_with_timeout()  # Detach Frida process if applicable
        print("\n\nThx for using friTap\nHave a great day\n")
        os._exit(0)

    def get_fritap_frida_script(self):
        with open(os.path.join(here, self.frida_agent_script), encoding='utf-8', newline='\n') as f:
            script_string = f.read()
            return script_string
            
    
    def get_custom_frida_script(self):
        with open(os.path.join(here, self.custom_hook_script), encoding='utf-8', newline='\n') as f:
            script_string = f.read()
            return script_string
    
    
    def get_fritap_frida_script_path(self):
        return os.path.join(os.path.dirname(__file__), self.frida_agent_script)


    def install_signal_handler(self):
        def signal_handler(signum, frame):
            print("\n[*] Ctrl+C detected. Cleaning up...")
            self.pcap_cleanup(self.full_capture, self.mobile, self.pcap_name)
            self.cleanup(self.live, self.socket_trace, self.full_capture, self.debug_output, self.debug)  # Call the instance's cleanup method


        signal.signal(signal.SIGINT, signal_handler)


    def write_socket_trace(self, socket_trace_name):
        with open(socket_trace_name, 'a') as trace_file:
            trace_file.write(PCAP.get_filter_from_traced_sockets(self.traced_Socket_Set, filter_type="display") + '\n')


  
def get_addr_string(socket_addr,ss_family):
    if ss_family == "AF_INET":
        return  socket.inet_ntop(socket.AF_INET, struct.pack(">I", socket_addr))
    else: # this should only be AF_INET6
        raw_addr = bytes.fromhex(socket_addr)
        return socket.inet_ntop(socket.AF_INET6, struct.pack(">16s", raw_addr))
            


   