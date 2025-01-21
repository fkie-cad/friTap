#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import ntpath
from threading import Thread, Event
import random
import logging
import time
import psutil
import struct
import traceback
# ensure that we only see errors from scapy 
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import warnings
warnings.simplefilter("ignore", ResourceWarning)

try:
    from scapy.error import Scapy_Exception
    from scapy.all import *
except ImportError:
	print('[-]: scapy is not installed, please install it by running: pip3 install scapy')
	exit(2)

from .android import Android
 
INVALID_IPV4 = "0.0.0.0"
INVALID_IPV6 = "::"

def terminate_lingering_processes(parent_pid):
    parent = psutil.Process(parent_pid)
    for child in parent.children(recursive=True):
        print(f"Terminating child process: {child.pid} ({child.name()})")
        child.terminate()
        try:
            child.wait(timeout=2)
        except psutil.TimeoutExpired:
            print(f"Forcing kill of child process: {child.pid}")
            child.kill()

class PCAP:
    
    def __init__(self,pcap_file_name,SSL_READ,SSL_WRITE, doFullCapture, isMobile, print_debug_infos=False):
        self.pcap_file_name = pcap_file_name
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
        
        if doFullCapture:
            if isMobile:
                self.android_Instance = Android(self.print_debug_infos,device_id=self.device_id)
            self.full_capture_thread = self.get_instance_of_FullCaptureThread()
            self.full_capture_thread.start()
            if self.full_capture_thread.is_alive():
                print("[*] capturing whole traffic of target app")
        else:
            print("[*] capturing only plaintext data")
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
                print("[*] Cleaning up FullCaptureThread resources.")
                if self.socket:
                    try:
                        print("[*] Closing network socket.")
                        self.socket.close()
                    except Exception as e:
                        print(f"[-] Error while closing the socket: {e}")
                if self.android_capture_process != -1:
                    try:
                        print("[*] Terminating android capture process.")
                        self.android_capture_process.terminate()
                        self.android_capture_process.wait(timeout=2)
                    except Exception as e:
                        print(f"[-] Error while terminating android capture process: {e}")

            
            
            def full_local_capture(self):
                try:
                        
                    self.socket = conf.L2listen(
                        type=ETH_P_ALL
                    )
                    
                    print("[*] doing full local capture")
                    
                    sniff(
                        opened_socket=self.socket,
                        prn=self.write_packet_to_pcap,
                        stop_filter=self.stop_capture_thread
                    )
                except PermissionError as e:
                    print(f"[-] PermissionError: {e}")
                    print("[!] It seems you do not have permissions to access /dev/bpf. Please run the script with 'sudo' or grant your user access to /dev/bpf* files.")
                    print("[!] Exiting the program.")
                    self.clean_up_and_exit()
                except Scapy_Exception as e:
                    print(f"[-] Scapy_Exception: {e}")
                    print("[!] Scapy could not open /dev/bpf for network capture. Ensure you have the correct permissions.")
                    print("[!] Run the script with 'sudo' (not recommended for security reasons).")
                    self.clean_up_and_exit()
                except Exception as e:
                    print(f"[-] Unknown error: {e}")
                    print("[!] Full traceback for debugging:")
                    traceback.print_exc()
                    self.clean_up_and_exit()
                
                
            def run(self):
                if self.is_Mobile:
                    self.mobile_subprocess = self.full_mobile_capture()
                else:
                    self.full_local_capture()
            
            
            def join(self, timeout=None):
                self.stop_capture.set()

                # Terminate the tcpdump process if running
                #if self.android_capture_process and self.android_capture_process.poll() in {None, -2, -15}:
                if self.is_Mobile and pcap_class.android_Instance.is_Android():
                    if self.android_capture_process != -1 and self.android_capture_process.poll() is None:
                        pcap_class.android_Instance.send_ctrlC_over_adb()
                        self.android_capture_process.terminate()
                        try:
                            self.android_capture_process.wait(timeout=2)  # Wait for graceful termination
                        except subprocess.TimeoutExpired:
                            print(f"[-] Android capture thread did not terminate. Forcing kill.")
                            self.android_capture_process.kill()

                super().join(timeout)
            
            
            def stop_capture_thread(self, packet):
                if hasattr(self.stop_capture, "is_set"):
                    status = self.stop_capture.is_set()
                else:
                    status = self.stop_capture.isSet()
                return status
                
                
            def full_mobile_capture(self):
                if pcap_class.android_Instance.is_Android():
                    if pcap_class.android_Instance.is_tcpdump_available == False:
                        pcap_class.android_Instance.push_tcpdump_to_device()
                    self.android_capture_process = pcap_class.android_Instance.run_tcpdump_capture("_"+self._get_pcap_base_name())
                    
                    print(f"[*] doing full capture on Android")
                    return self.android_capture_process
                else:
                    print("[-] currently a full capture on iOS is not supported\nAbborting...")
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
            print("Packet has unknown/unsupported family!")

        if function in self.SSL_READ:
            server_sent += len(data)
        else:
            client_sent += len(data)
        self.ssl_sessions[session_unique_key] = (client_sent, server_sent)
        
    
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



        
    # this function is able to reduce a capture to the traffic from the traced target application by using the information from the socket trace and applying a bpf filter of those traced packets
    def create_application_traffic_pcap(self, traced_Socket_Set,pcap_obj,  is_verbose=False):
        def is_valid_socket(socket_info):
            return (
                socket_info.get("src_addr") and socket_info.get("dst_addr")
                and socket_info.get("src_addr") != INVALID_IPV4
                and socket_info.get("dst_addr") != INVALID_IPV4
                and socket_info.get("src_addr") != INVALID_IPV6
                and socket_info.get("dst_addr") != INVALID_IPV6
            )

        if not traced_Socket_Set:
            print("[-] No sockets traced. The resulting PCAP will contain all traffic from the device.")
            return

        # Convert each frozenset in the traced_Socket_Set back to a dictionary
        socket_dicts = [dict(frozenset_entry) for frozenset_entry in traced_Socket_Set]

        valid_sockets = [socket for socket in socket_dicts if is_valid_socket(socket)]
        if not valid_sockets:
            print("[-] No valid sockets found. The resulting PCAP will contain all traffic.")
            return

        bpf_filter = PCAP.get_filter_from_traced_sockets(valid_sockets, filter_type="bpf")
        if not bpf_filter:
            print("[-] Failed to generate a valid BPF filter.")
            return

        if is_verbose:
            print(f"[*] Filtering with BPF filter:\n{bpf_filter}")
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
            filtered_capture = sniff(offline="_" + self.pcap_file_name, filter=bpf_filter) 
            wrpcap(self.pcap_file_name, filtered_capture)
        except Exception as e:
            print(f"[-] Error during PCAP filtering: {e}")
        else:
            print(f"[*] Successfully filtered. Output written to {self.pcap_file_name}")

    
    
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
    
        

