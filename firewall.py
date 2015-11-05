#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries.

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        # TODO: Load the firewall rules (from rule_filename) here.
        print 'I am supposed to load rules from %s, but I am feeling lazy.' % \
                config['rule']
        rules = open(config['rule'], 'r')
        geoipdb = open('geoipdb.txt', 'r')
        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
        # TODO: Also do some initialization if needed.
        types = {17:'UDP', 1:"ICMP", 6:"TCP"}
        
        rules_dict = {
                'UDP' : [],
                'TCP' : [], 
                'ICMP': [],
                'DNS' : []
        }
        rule = rules.readline()
        while rule:
            rule = rule.split()
            rules_dict[rule[1]].append(rule)
            rule = rules.readline()
    
    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        src_ip = pkt[12:16]
        dst_ip = pkt[16:20]
        pkt_type = pkt[9:10]
        transport_header_offset = pkt[0]&15
        dst_port = pkt[transport_header_offset +2:transport_header_offset +4]
        ipid, = struct.unpack('!H', pkt[4:6])    # IP identifier (big endian)
        print '%s len=%4dB, IPID=%5d  %15s -> %15s' % (dir_str, len(pkt), ipid, socket.inet_ntoa(src_ip), socket.inet_ntoa(dst_ip))
        if pkt_dir == PKT_DIR_INCOMING:
            dir_str = 'incoming'
        else:
            dir_str = 'outgoing'
        
        if pkt_type == 17 and : 
      

    # TODO: You can add more methods as you want.

# TODO: You may want to add more classes/functions as well.
