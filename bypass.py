#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

import socket
import struct
import time

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        print 'bypass mode!'
        
    def handle_packet(self, pkt_dir, pkt):
        # The example code here prints out the source/destination IP addresses,
        # which is unnecessary for your submission.
        src_ip = pkt[12:16]
        dst_ip = pkt[16:20]
        ipid, = struct.unpack('!H', pkt[4:6])    # IP identifier (big endian)
        transport_header_offset = ord(pkt[0]) & 0x0f
        dst_port = pkt[transport_header_offset*4 + 2 : transport_header_offset*4 +4]
        src_port = pkt[transport_header_offset*4 : transport_header_offset*4 +2]
        dst_port, = struct.unpack('!H', dst_port)
        src_port, = struct.unpack('!H', src_port)
        pkt_type, = struct.unpack('!B', pkt[9:10])
        types = {17:'UDP', 1:"ICMP", 6:"TCP"}
        
        if pkt_dir == PKT_DIR_INCOMING:
            dir_str = 'incoming'
        else:
            dir_str = 'outgoing'
        
        print 'packet type: %d ' % (types[pkt_type])
        print '%s len=%4dB, IPID=%5d  %15s -> %15s src_port: %s dst_port: %s' % (dir_str, len(pkt), ipid,
                socket.inet_ntoa(src_ip), socket.inet_ntoa(dst_ip), src_port, dst_port)

        # ... and simply allow the packet.
        if pkt_dir == PKT_DIR_INCOMING:
            self.iface_int.send_ip_packet(pkt)
        elif pkt_dir == PKT_DIR_OUTGOING:
            self.iface_ext.send_ip_packet(pkt)
