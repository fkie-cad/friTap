#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import ntpath
from threading import Thread, Event
import random
import logging
# ensure that we only see errors from scapy 
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
	from scapy.all import *
except ImportError:
	print('[-]: scapy is not installed, please install it by running: pip3 install scapy')
	exit(2)

import friTap.android as android
 

class PCAP:
    
    def __init__(self,pcap_file_name,SSL_READ,SSL_WRITE, doFullCapture, isMobile, print_debug_infos=False):
        self.pcap_file_name = pcap_file_name
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
                self.android_Instance = android.Android(self.print_debug_infos)
            self.full_capture_thread = self.get_instance_of_FullCaptureThread()
            self.full_capture_thread.start()
        else:
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
                
                self.mobile_pid = -1    
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
            
            
            def full_local_capture(self):
                self.socket = conf.L2listen(
                    type=ETH_P_ALL
                )
                
                print("[*] doing full capture")
                
                sniff(
                    opened_socket=self.socket,
                    prn=self.write_packet_to_pcap,
                    stop_filter=self.stop_capture_thread
                )
                
                
            def run(self):
                if self.is_Mobile:
                    self.mobile_pid = self.full_mobile_capture()
                else:
                    self.full_local_capture()
            
            
            def join(self, timeout=None):
                self.stop_capture.set()
                super().join(timeout)
            
            
            def stop_capture_thread(self, packet):
                return self.stop_capture.isSet()
                
                
            def full_mobile_capture(self):
                if pcap_class.android_Instance.is_Android():
                    pcap_class.android_Instance.push_tcpdump_to_device()
                    android_capture_process = pcap_class.android_Instance.run_tcpdump_capture("_"+self._get_pcap_base_name())
                    print("[*] doing full capture on Android")
                    return android_capture_process
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
    def get_filter_from_traced_sockets(socket_trace_set):
        filter = ""
        first_element = True
        for length_of_socket_Set in range(len(socket_trace_set)):
            if len(socket_trace_set) == 1:
                filter = socket_trace_set.pop() + " or "  + filter
                break
            if first_element:
                first_element = False
                filter = socket_trace_set.pop()
            else:
                filter = socket_trace_set.pop() + " or " + filter
                
            length_of_socket_Set = length_of_socket_Set - 1
            
        return filter

        
    # this function is able to reduce a capture to the traffic from the traced target application by using the information from the socket trace and applying a bpf filter of those traced packets
    def create_application_traffic_pcap(self,traced_Socket_Set):        
        bpf_filter = PCAP.get_filter_from_traced_sockets(traced_Socket_Set)
        print("[*] filtering the capture for the target application this might take a while...")
        try:
            filtered_capture = sniff(offline="_"+self.pcap_file_name,filter=bpf_filter)
            wrpcap(self.pcap_file_name,filtered_capture)
        except Exception as ar:
            print(ar)
        print(f"[*] finished and written to {self.pcap_file_name}")
    
    
    
    @staticmethod
    def get_display_filter(src_addr,dst_addr):
        return "ip.src == " +src_addr+  "and ip.dst =="+dst_addr
    
    
    @staticmethod
    def get_bpf_filter(src_addr,dst_addr):
        return "(src host " +src_addr+  " and dst host "+dst_addr+")"
    
        

