#!/usr/bin/env python
import socket, struct
from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries.


class Firewall:
    UDP = 17
    TCP = 6
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        self.geo_dict = {}
        self.rules_dict = {'tcp' : [], 'dns' : [], 'http' : []}
        self.types = {Firewall.UDP: 'udp', Firewall.TCP: 'tcp'}
        self.log = open('http.log', 'a')

        #initialize dicts
        self.init_geo('geoipdb.txt')
        self.init_rules(config['rule'])

    def init_geo(self, f):
        geoipdb = open(f, 'r')
        line = geoipdb.readline()
        while line:
            line = line.split()
            if line:
                country_code = line[2].upper()
                if country_code in self.geo_dict.keys():
                    self.geo_dict[country_code].append([line[0], line[1]])
                else:
                    self.geo_dict[country_code] = [[line[0], line[1]]]
            line = geoipdb.readline()

    def init_rules(self, f):
        rules = open(f, 'r')
        line = rules.readline()
        while line:
            line = line.lower().split()
            if line and (line[0] in ['deny', 'log']):
                self.rules_dict[line[1]].append(line)
            line = rules.readline()


    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        src_ip = socket.inet_ntoa(pkt[12:16])
        dst_ip = socket.inet_ntoa(pkt[16:20])
        pkt_type, = struct.unpack('!B', pkt[9])

        transport_offset = (ord(pkt[0]) & 0x0f) * 4
        src_port = pkt[transport_offset:transport_offset + 2]
        src_port, = struct.unpack('!H', src_port)
        dst_port = pkt[transport_offset + 2: transport_offset + 4]
        dst_port, = struct.unpack('!H', dst_port)
        ipid, = struct.unpack('!H', pkt[4:6])

        if pkt_dir == PKT_DIR_INCOMING:
            dir_str = 'incoming'
            ext_addr = src_ip
            ext_port = src_port
            self.send_interface = self.iface_int
        if pkt_dir == PKT_DIR_OUTGOING:
            dir_str = 'outgoing'
            ext_addr = dst_ip
            ext_port = dst_port
            self.send_interface = self.iface_ext

        # If TCP or DNS(UDP), apply rules, otherwise pass packet
        protocol = self.types[pkt_type]

        #check for dns here
        if dir_str == 'outgoing' and pkt_type == Firewall.UDP and dst_port == 53:
            dns, qname = self.dns_check(pkt, transport_offset)
        else:
            dns = False
        

        if dns:
            print "Matching to DNS"
            for rule in reversed(self.rules_dict['dns']):
                rule = rule.split()
                if self.compare_domains(qname, rule[2]):
                    print "Win!"
                    self.deny_dns(pkt, transport_offset)
                    return
        elif pkt_type == Firewall.TCP:
            #first run through deny rules. Otherwise log and match connection
            for rule in reversed(self.rules_dict['tcp']):
                v = self.apply_rule(rule, ext_addr, ext_port)
                if v:
                    print "MATCH!"
                    rst_packet = self.deny_tcp(pkt, transport_offset)
                    self.send_interface.send_ip_packet(rst_packet)
                    return

        self.send_interface.send_ip_packet(pkt)
        return

        # For applying rules, we can be smart and apply them in
        # reverse order, since the last matching rule in forward
        # order is applied, the FIRST matching rule in reverse order
        # is applied.

        # Apply rule -> Match -> send to handler

    def apply_rule(self, r, ad, port):
        verdict = None
        if self.check_address(ad, r[2]) and self.check_port(port, r[3]):
            verdict = r[0]
        return verdict

    def check_address(self, a, r):
        if r == 'any' or r == '0.0.0.0/0' or a == r:
            return True
        if '/' in r:
            return addr_in_subnet(a, r)

    def check_port(self, p, r):
        if '-' in r:
            low_bound, high_bound = r.split('-')
            low_bound = int(low_bound)
            high_bound = int(high_bound)
            if low_bound <= p and p <= high_bound:
                return True
            else: 
                return False
        if r == 'any' or p == int(r):
            return True
        return False


    def dns_check(self, pkt, transport_offset):
        dns_pkt_offset = transport_offset + 8
        qdcount = pkt[dns_pkt_offset + 4: dns_pkt_offset + 6]
        qdcount, = struct.unpack('!H', qdcount)
        if qdcount == 1:
            query_offset = dns_pkt_offset + 12
            dns_pkt = pkt[query_offset:]
            rr_type_offset = dns_pkt.index('\0') + 1
            qtype = dns_pkt[rr_type_offset: rr_type_offset + 2]
            qtype, = struct.unpack('!H', qtype)
            qclass = dns_pkt[rr_type_offset + 2: rr_type_offset + 4]
            qclass, = struct.unpack('!H', qclass)
            if (qtype == 1 or qtype == 28) and qclass == 1:
                qname = dns_pkt[: rr_type_offset]
                return True, qname
        return False, None

    # def deny_tcp(self, pkt, transport_offset):
    #     # Set flags in header, compute TCP checksum
    #     # Switch dst and src ip, compute ipv4 checksum

    #     # TCP steps: switch src and dst ports, copy seqno
    #     # copy ackno + 1, set header length to 20, set RST flag
    #     # copy all other fields, then compute checksum

    #     ip_header = self.build_IP_packet(pkt, pkt[transport_offset: transport_offset + 20]) #hack to get len(payload) = 40

    #     src_port = pkt[transport_offset: transport_offset + 2]
    #     dst_port = pkt[transport_offset + 2: transport_offset + 4]
    #     src_port, = struct.unpack('!H', src_port)
    #     dst_port, = struct.unpack('!H', dst_port)
    #     src_port, dst_port = dst_port, src_port
    #     print "Source Port: ", src_port
    #     print "Dest Port: ", dst_port
    #     src_port = struct.pack('!H', src_port)
    #     dst_port = struct.pack('!H', dst_port)     
    #     seqno, = struct.unpack('!L', pkt[transport_offset + 4: transport_offset + 8])
    #     ackno, = struct.unpack('!L', pkt[transport_offset+8:transport_offset+12])
    #     ackno = seqno + 1
    #     print "Sequence Number: ", seqno
    #     print "Ackno: ", ackno
    #     seqno = struct.pack('!L', seqno)
    #     ackno = struct.pack('!L', ackno)
    #     header_length, = struct.unpack('!B', pkt[transport_offset + 12])
    #     header_length = 0x50
    #     print "Header Length: ", header_length
    #     header_length = struct.pack('!B', header_length)
    #     ack_flag = 0x10
    #     rst_flag = 0x04
    #     flags, = struct.unpack('!B', pkt[transport_offset + 13])
    #     flags = rst_flag + ack_flag
    #     print "Flags: ", hex(flags)
    #     flags = struct.pack('!B', flags)
    #     zero_checksum = struct.pack('!H', 0)

    #     tcp_header = src_port + dst_port + seqno + ackno + header_length + flags + struct.pack('!H', 0) + \
    #                  zero_checksum + struct.pack('!H', 0)

    #     src_addr = ip_header[12:16]
    #     dst_addr = ip_header[16:20]
    #     print "Source Address: ", socket.inet_ntoa(src_addr)
    #     print "Dest Address: ", socket.inet_ntoa(dst_addr)
    #     zero_bits = struct.pack('!B', 0)
    #     protocol = struct.pack('!B', 6)
    #     tcp_length = struct.pack('!H', 20)
    #     pseudo_header = src_addr + dst_addr + zero_bits + protocol + tcp_length    

    #     rst_checksum = checksum(pseudo_header + tcp_header)
    #     rst_checksum = struct.pack('!H', rst_checksum)

    #     rst_tcp_header = src_port + dst_port + seqno + ackno + header_length + flags + struct.pack('!H', 0)+ \
    #                      rst_checksum + struct.pack('!H', 0)
    #     return ip_header + rst_tcp_header

    def deny_tcp(self, pkt, transport_offset):
        ip_header = self.build_IP_packet(pkt, None)

        """
        Pseudo Header
        ---------------

        Source Address (32)
        Destination Address (32)
        Reserved (8) | Protocol (8) | TCP Segment Length (16)

        """
        src_addr = ip_header[12:16]
        dst_addr = ip_header[16:20]
        reserved = struct.pack('!B', 0)
        protocol = struct.pack('!B', 6)
        tcp_length = struct.pack('!H', 20)
        pseudo_header = src_addr + dst_addr + reserved + protocol + tcp_length

        """
        TCP packet
        Src port (16) | Dst Port (16)
        Seqno (32)
        Ackno (32)
        Data offset(4) | Reserved (6) | Flags (6) | Window (16)
        Checksum (16) | Urgent Pointer (16)
        """
        src_port = pkt[transport_offset + 2 : transport_offset + 4]
        dst_port = pkt[transport_offset : transport_offset + 2]
        seqno, = struct.unpack('!L', pkt[transport_offset + 4: transport_offset + 8])
        ackno = seqno + 1
        offset_reserved_flags = 0x5014
        seqno = struct.pack('!L', seqno)
        ackno = struct.pack('!L', ackno)
        offset_reserved_flags = struct.pack('!H', offset_reserved_flags)
        window = struct.pack('!H', 0)
        zero_checksum = struct.pack('!H', 0)
        urgent_pointer = struct.pack('!H', 0)

        tcp_header = src_port + dst_port + seqno + ackno + offset_reserved_flags + window + zero_checksum + urgent_pointer
        rst_checksum = checksum(pseudo_header + tcp_header)
        rst_checksum = struct.pack('!H', rst_checksum)

        rst_tcp_header = src_port + dst_port + seqno + ackno + offset_reserved_flags + window + \
                         rst_checksum + urgent_pointer
        return ip_header + rst_tcp_header





    def deny_dns(self, pkt, transport_offset):

        pass

    def compare_domains(self, qname, domain):
        a = self.parse_name(qname)
        r = domain.split('.')
        if len(a) < len(r):
            return False
        i = 0
        while i < len(r) and r != '*':
            if a[i] != r[i] and r[i] != '*':
                return False
            i += 1
        return True

    def parse_name(self, qname):
        ret = []
        le = ord(qname[0])
        beg = 0
        while le != 0:
            ret.append(a[beg + 1: beg + le + 1])
            beg = beg + le + 1
            le = ord(qname[beg])
        return ret

    def build_IP_packet(self, pkt, payload):
        packet = struct.pack('!B', 0x45) + pkt[1]
        packet += struct.pack('!H', 40)
        packet += pkt[4:6]
        packet += pkt[6:8]
        packet += pkt[8:10]
        packet += struct.pack('!H', 0)
        packet += pkt[16:20]
        packet += pkt[12:16]
        packet = packet[:10] + struct.pack('!H', checksum(packet)) + packet[12:]
        return packet


def dotted_quad_to_num(ip):
    return struct.unpack('>L', socket.inet_aton(ip))[0]


def addr_in_subnet(ip, subnet):
    ip = dotted_quad_to_num(ip)
    netaddr, bits = subnet.split('/')
    netaddr = dotted_quad_to_num(netaddr)
    netmask = 0xffffffff << (32-int(bits))
    return (ip & netmask) == (netaddr & netmask)

def checksum(buf, total=0):
    i = 0
    while i + 1 < len(buf):
         w = ((ord(buf[i]) << 8) & 0xFF00) + (ord(buf[i+1]) & 0xFF)
         total, i = total + w, i + 2
    if len(buf) % 2 == 1:
        total += ord(buf[i]) & 0xFF

    while (total >> 16) > 0:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF

def ipv4_checksum():
    pass
    




    # TODO: You can add more methods as you want.

# TODO: You may want to add more classes/functions as well.

class Connection:

    def __init__(self, ext_addr, in_addr, ext_port, in_port):
        self.ext_addr = ext_addr
        self.in_addr = in_addr
        self.ext_port = ext_port
        self.in_port = in_port

        self.request_data = ''
        self.response_data  = ''

        self.sender_seqno = None
        self.receiver_seqno = None
