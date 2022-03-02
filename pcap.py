#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
try:
	from scapy.all import *
except ImportError:
	print('[-]: scapy is not installed, please install it by running: pip3 install scapy')
	exit(2)
 
 
 
a =  """
 # ip.dst == 142.250.186.164 and ip.src == 192.168.0.170 --> 19% --> 114 pakete
pkts = rdpcap("test.pcapng")

filter = "src host 142.250.186.164 and dst host 192.168.0.170"
filtered = (pkt for pkt in pkts if IP in pkt and (pkt[IP].src == "192.168.0.170" and pkt[IP].dst == "142.250.186.164"))
wrpcap("filtered.pcap",filtered)

 
 """
 

class PCAP:
    
    def __init__(self,pcap_file_name,SSL_READ,SSL_WRITE, doFullCapture):
        self.pcap_file_name = pcap_file_name
        self.pkt ={}
        
        # ssl_session[<SSL_SESSION id>] = (<bytes sent by client>,
        #                                  <bytes sent by server>)
        self.ssl_sessions = {}
        self.SSL_READ = SSL_READ
        self.SSL_WRITE = SSL_WRITE
        if doFullCapture:
            self.full_local_capture()
            self.create_application_traffic_pcap()
        else:
            self.pcap_file = self.__create_plaintext_pcap()
    
    
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
        
        
    def create_application_traffic_pcap(self,filter):
        pkts = rdpcap(self.pcap_file_name)
        filtered = (pkt for pkt in pkts if IP in pkt and (filter))
        wrpcap(self.pcap_file_name,filtered)
        # pkt[IP].src == "192.168.0.170" and pkt[IP].dst == "142.250.186.164"
        
        
    def write_pcap(self):
        wrpcap("_"+self.pcap_file_name, self.pkt, append=True)  #appends packet to output file
    
    
    def full_local_capture(self):
        try:
            print("[*] doing full capture")
            self.pkt = sniff()
        except KeyboardInterrupt:
            pass
        finally:
            self.write_pcap(self.pkt)
            print(f"safed to _{self.pcap_file_name}")