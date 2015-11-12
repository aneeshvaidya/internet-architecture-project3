#!/usr/bin/env python
import socket,struct
from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries.

UDP = 17
ICMP = 1
TCP = 6

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        self.geo_dict = {}          #{"US":[[start,end],[start1, end1],...],"CA"[...]}
        self.rules_dict = {'UDP' : [],'TCP' : [],'ICMP': [],'DNS' : []   }

        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
        geoipdb = open('geoipdb.txt', 'r')
        geo_line = geoipdb.readline()
        while geo_line:
            geo_line = geo_line.split()
            country_code = geo_line[2].upper()
            if country_code in self.geo_dict.keys(): #why?
                self.geo_dict[country_code].append([geo_line[0],geo_line[1]])
            else:
                self.geo_dict[country_code]=[geo_line[0],geo_line[1]]
            geo_line = geoipdb.readline()

        # TODO: Also do some initialization if needed.
        self.types = {17:'UDP', 1:"ICMP", 6:"TCP"}
        
        # Load the firewall rules (from rule_filename) here.
        rules = open(config['rule'], 'r')        
        rule = rules.readline()
        while rule:
            rule = rule.split()
            if rule:
                if rule[0] == 'pass' or rule[0] == 'drop':
                    self.rules_dict[rule[1].upper()].append(rule)
            rule = rules.readline()
            
    
    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    """
    1) Find out the src and dst IPs
    2) Determine packet type and extract relevant fields
    3) Apply all rules, make a verdict
    """
    def handle_packet(self, pkt_dir, pkt):
        src_ip = socket.inet_ntoa(pkt[12:16])
        dst_ip = socket.inet_ntoa(pkt[16:20])
        pkt_type, = struct.unpack('!B', pkt[9:10])                          # what protocol use for rules check?

        
        transport_header_offset = ord(pkt[0]) & 0x0f
        dst_port = pkt[transport_header_offset + 2 : transport_header_offset +4]
        src_port = pkt[transport_header_offset : transport_header_offset +2]
        dst_port, = struct.unpack('!H', dst_port)
        src_port, = struct.unpack('!H', src_port)
        
        ipid, = struct.unpack('!H', pkt[4:6])       # IP identifier (big endian)
        DNS_flag = False

        if pkt_dir == PKT_DIR_INCOMING:
            dir_str = 'incoming'
            ext_addr = src_ip
            ext_port = src_port
        else:
            dir_str = 'outgoing'
            ext_addr = dst_ip
            ext_port = dst_port

        print '%d packet: %s len=%4dB, IPID=%5d port=%s  %15s -> %15s' % (pkt_type, dir_str, len(pkt), ipid, ext_port, src_ip, dst_ip)
        
        #Logic for transport protocol
        
        if pkt_type == UDP and dst_port == '53':  
            DNS_flag = True
            protocol = 'DNS'
        else:
            protocol = self.types[pkt_type]
            
        last_verdict = ''                       # check rules
        for rule in self.rules_dict[protocol]:
            print rule
            print ext_addr
            print ext_port
            v = self.apply_rule(rule, ext_addr, ext_port);
            if v:
                last_verdict = v;
            
        if last_verdict == 'pass':                  # allow the packet.
            if pkt_dir == PKT_DIR_INCOMING:
                self.iface_int.send_ip_packet(pkt)
            elif pkt_dir == PKT_DIR_OUTGOING:
                self.iface_ext.send_ip_packet(pkt)        
            
            
    def apply_rule(self, r, ad, port):
        last_verdict = None
        print "-----------"
        print r, ad, port
        if self.check_address(ad, r[2]) and self.check_port(port, r[3]):
                last_verdict = r[0]
        return last_verdict
        
        
    def check_address(self, a, r):    #check if address satisfy rule, both args in string format
        if r == 'any' or r == '0.0.0.0/0' or a == r:
            return True
        if '/' in r:                                        #subnet
            ip, mask = r.split('/')
            network = networkMask(ip,int(mask))
            return addressInNetwork(a, network)
            
        if len(r) == 2:                                      #GeoDB
            for network in self.geo_dict[r]:
                low_bound = dottedQuadToNum(network[0])
                high_bound = dottedQuadToNum(network[1])
                address = dottedQuadToNum(a)
                if low_bound < address and address < high_bound:
                    return True
        
        return False
        
    def check_port(self, p, r):       #check if port satisfy rule, both args in string format
        if r == 'any' or p == r:
            return True
        if '-' in r:                                        #subnet
            low_bound, high_bound = r.split('-')
            low_bound = int(low_bound)
            high_bound = int(high_bound)
            port = int(p)
            if low_bound < port and port < high_bound:
                return True
        return False
            
      

    # TODO: You can add more methods as you want.

def dottedQuadToNum(ip):
    "convert decimal dotted quad string to long integer"
    return struct.unpack('L',socket.inet_aton(ip))[0]

def numToDottedQuad(n):
    "convert long int to dotted quad string"
    return socket.inet_ntoa(struct.pack('L',n))
      
def makeMask(n):
    "return a mask of n bits as a long integer"
    return (2L<<n-1)-1
    
def networkMask(ip,bits):
    "Convert a network address to a long integer" 
    return dottedQuadToNum(ip) & makeMask(bits)

def addressInNetwork(ip,net):
   "Is an address in a network"
   return dottedQuadToNum(ip) & net == net



   
    # TODO: You may want to add more classes/functions as well.
