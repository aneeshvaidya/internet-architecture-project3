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
        self.rules_dict = {'TCP' : [], 'DNS' : [], 'HTTP' : []}
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
        pkt_type = struct.unpack('!B', pkt[9])

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
        if pkt_type == Firewall.TCP or self.dns_check(pkt, pkt_type):
            protocol = self.types[pkt_type]
            for rule in reversed(self.rules_dict[protocol]):
                verdict = self.apply_rule(rule, ext_addr, ext_port)
                if verdict:
                    return
        else:
            self.send_interface.send_ip_packet(pkt)
            return

        # For applying rules, we can be smart and apply them in
        # reverse order, since the last matching rule in forward
        # order is applied, the FIRST matching rule in reverse order
        # is applied.

        # Apply rule -> Match -> send to handler

    def apply_rule(self, rule, addr, port):
        pass

    def dns_check(self, pkt, pkt_type):
        pass


def dotted_quad_to_num(ip):
    return struct.unpack('>L', socket.inet_aton(ip))[0]


def addr_in_subnet(ip, subnet):
    ip = dotted_quad_to_num(ip)
    netaddr, bits = subnet.split('/')
    netaddr = dotted_quad_to_num(netaddr)
    netmask = 0xffffffff << (32-int(bits))
    return (ip & netmask) == (netaddr & netmask)





    # TODO: You can add more methods as you want.

# TODO: You may want to add more classes/functions as well.
