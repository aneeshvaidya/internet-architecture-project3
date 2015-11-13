#!/usr/bin/env python
import socket,struct
import pdb
from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

UDP = 17
ICMP = 1
TCP = 6

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        self.geo_dict = {}          #{"US":[[start,end],[start1, end1],...],"CA"[...]}
        self.rules_dict = {'UDP' : [],'TCP' : [],'ICMP': [],'DNS' : []   }

        # Load the GeoIP DB ('geoipdb.txt') as well.
        geoipdb = open('g.txt', 'r')
        geo_line = geoipdb.readline()
        while geo_line:
            geo_line = geo_line.split()
            if geo_line:
                country_code = geo_line[2].upper()
                if country_code in self.geo_dict.keys(): 
                    self.geo_dict[country_code].append([geo_line[0],geo_line[1]])
                else:
                    self.geo_dict[country_code]=[[geo_line[0],geo_line[1]]]
            geo_line = geoipdb.readline()

        self.types = {17:'UDP', 1:"ICMP", 6:"TCP"}
        
        # Load the firewall rules (from rule_filename) here.
        rules = open(config['rule'], 'r')        
        rule_line = rules.readline()
        while rule_line:
            rule_line = rule_line.lower().split()
            if rule_line and (rule_line[0] == 'pass' or rule_line[0] == 'drop'):
                self.rules_dict[rule_line[1].upper()].append(rule_line)
                # hack to DNS/UDP order logic - store UDP rule to DNS rules also
                if rule_line[1].upper() == "UDP":
                    self.rules_dict["DNS"].append(rule_line)
            rule_line = rules.readline()
        print self.rules_dict
            
    
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
        pkt_type, = struct.unpack('!B', pkt[9:10])        #  protocol used for rules check
        
        transport_header_offset = (ord(pkt[0]) & 0x0f) *4
        dst_port = pkt[transport_header_offset + 2 : transport_header_offset +4]
        src_port = pkt[transport_header_offset : transport_header_offset +2]
        dst_port, = struct.unpack('!H', dst_port)
        src_port, = struct.unpack('!H', src_port)

        
        ipid, = struct.unpack('!H', pkt[4:6])       # IP identifier (big endian). why do we need it?

        if pkt_dir == PKT_DIR_INCOMING:
            dir_str = 'incoming'
            ext_addr = src_ip
            ext_port = src_port
            self.send_interface = self.iface_int
        elif pkt_dir == PKT_DIR_OUTGOING:
            dir_str = 'outgoing'
            ext_addr = dst_ip
            ext_port = dst_port
            self.send_interface = self.iface_ext
        else:
            return

        if pkt_type == ICMP:
            ext_port, = struct.unpack('!B', pkt[transport_header_offset])

        print '%s packet: %s len=%4dB, IPID=%5d port=%s  %15s -> %15s' \
        % (self.types[pkt_type], dir_str, len(pkt), ipid, ext_port, src_ip, dst_ip)
        
        #Thus you should always pass nonTCP/UDP/ICMP packets
        if pkt_type in self.types.keys():
            protocol = self.types[pkt_type]
        else:
            self.send_interface.send_ip_packet(pkt)  
            return
      
        last_verdict = 'pass'

        #DNS packet processing
        is_valid_dns = False        
        if dir_str == 'outgoing' and pkt_type == UDP and dst_port == 53:    
            dns_pkt_offset = transport_header_offset + 8
            qdcount = pkt[dns_pkt_offset + 4: dns_pkt_offset + 6]
            qdcount, = struct.unpack('!H', qdcount)
            if qdcount == 1:                                    # only one question
                querry_offset = dns_pkt_offset + 12
                dns_pkt = pkt[querry_offset : ]
                rr_type_offset = dns_pkt.index('\0') + 1
                qtype = dns_pkt[rr_type_offset : rr_type_offset + 2]
                qtype, = struct.unpack('!H', qtype)
                qclass = dns_pkt[rr_type_offset +2 : rr_type_offset +4]
                qclass, = struct.unpack('!H', qclass)
                if (qtype == 1 or qtype == 28) and qclass == 1:
                    is_valid_dns = True                
                    qname = dns_pkt[ : rr_type_offset ]
                    for dns_rule in self.rules_dict["DNS"]:
                        #print dns_rule
                        if dns_rule[1] == 'dns':
                            if dns_rule[2] == '*':
                                last_verdict = dns_rule[0]
                                continue
                            if self.compare_domains(qname, dns_rule[2]):
                                last_verdict = dns_rule[0]
                                #print last_verdict
                        if dns_rule[1] == 'udp': 
                            v = self.apply_rule(dns_rule, ext_addr, ext_port);
                            if v:
                                #print v
                                last_verdict = v;
                                
            if is_valid_dns and last_verdict == 'pass':
                self.send_interface.send_ip_packet(pkt)
                return
                
        for rule in self.rules_dict[protocol]:       # check rules no DNS
            v = self.apply_rule(rule, ext_addr, ext_port);
            if v:
                last_verdict = v;                

        if last_verdict == 'pass':                  # allow the packet.
                self.send_interface.send_ip_packet(pkt)
                return
      
            
            
    def apply_rule(self, r, ad, port):
        last_verdict = None
        if self.check_address(ad, r[2]) and self.check_port(port, r[3]):
                last_verdict = r[0]
        return last_verdict
        
        
    def check_address(self, a, r):    #check if address satisfy rule, both args in string format
        if r == 'any' or r == '0.0.0.0/0' or a == r:
            return True
        if '/' in r:                                        #subnet
            return aInNet(a, r)
            
        if len(r) == 2:                                      #GeoDB
            r = r.upper()
            if not self.geo_dict.get(r):
                return False
            l = self.geo_dict[r]
            start = 0                                      #bin search
            end = len(l) - 1
            while start <= end:
                middle = (start + end) / 2
                lower_bound, upper_bound = l[middle]
                lower_bound, upper_bound = dottedQuadToNum(lower_bound), dottedQuadToNum(upper_bound)
                address = dottedQuadToNum(a)
                if lower_bound <= address and address <= upper_bound:
                    return True
                elif address > upper_bound:
                    start = middle + 1
                elif address < lower_bound:
                    end = middle - 1

        return False
        
    def check_port(self, p, r):       #check if port satisfy rule,  p int, r str
 
        if '-' in r:                                        #subnet
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
            
    #03 77 77 77 06 67 6f 6f 67 6c 65 03 63 6f 6d 00
    #   w  w  w     g  o  o  g  l  e     c  o  m
    def parse_name(self, a):
        ret = []
        le = ord(a[0])
        beg = 0
        while le != 0:
            ret.append(a[ beg +1 : beg + le +1].lower())
            beg = beg + le +1
            le = ord(a[beg])
        return ret
        
    
    
    # www.cafe3.peets.com
    # *.peets.com
    # qname in dns name format, domains is line from rules file (string)
    def compare_domains(self, qname, domains):
        a = self.parse_name(qname)
        r = domains.split('.')
        if len(a) < len(r):
            return False
        #print "query name: ", a
        #print "rules name: ", r
        i = 0
        while i < len(r) and r != '*':
            if a[i] != r[i] and r[i] != '*':
                return False
            i += 1

        return True
            
      


def dottedQuadToNum(ip):
    "convert decimal dotted quad string to long integer"
    return struct.unpack('>L',socket.inet_aton(ip))[0]

   
def aInNet(ip,net):
    ip = dottedQuadToNum(ip)
    netaddr,bits = net.split('/')
    netaddr = dottedQuadToNum(netaddr)
    # Must shift left an all ones value, /32 = zero shift, /0 = 32 shift left
    netmask = 0xffffffff << (32-int(bits))
    return (ip & netmask) == (netaddr & netmask)

