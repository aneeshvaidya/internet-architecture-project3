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
        

        # if pkt_type == Firewall.TCP or dns:
        #     if dns:
        #         protocol = 'dns'
        #     else:
        #         protocol = self.types[pkt_type]
        #     for rule in reversed(self.rules_dict[protocol]):
        #         if self.match_rule(rule, ext_addr, ext_port)
        #             self.handle_rule_match(rule, pkt)
        # else:
        #     self.send_interface.send_ip_packet(pkt)
        #     return

        if dns:
            for rule in reversed(self.rules_dict['dns']):
                rule = rule.split()
                if self.compare_domains(qname, rule[2]):
                    self.deny_dns(pkt, transport_offset)
        elif pkt_type == Firewall.TCP:
            #first run through deny rules. Otherwise log and match connection
            pass
        else:
            self.send_interface.send_ip_packet(pkt)

        # For applying rules, we can be smart and apply them in
        # reverse order, since the last matching rule in forward
        # order is applied, the FIRST matching rule in reverse order
        # is applied.

        # Apply rule -> Match -> send to handler


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

    def deny_tcp(self, pkt):
        # Set flags in header, compute TCP checksum
        # Switch dst and src ip, compute ipv4 checksum
        pass

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



def dotted_quad_to_num(ip):
    return struct.unpack('>L', socket.inet_aton(ip))[0]


def addr_in_subnet(ip, subnet):
    ip = dotted_quad_to_num(ip)
    netaddr, bits = subnet.split('/')
    netaddr = dotted_quad_to_num(netaddr)
    netmask = 0xffffffff << (32-int(bits))
    return (ip & netmask) == (netaddr & netmask)

def tcp_checksum(buf, total=0):
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
