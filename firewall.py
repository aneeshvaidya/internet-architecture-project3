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
        self.rules_dict = {'udp' : [],'tcp' : [],'icmp': [],'dns' : [], 'http' : []  }
        self.types = {UDP :'udp', ICMP :"icmp", TCP :"tcp"}  
        self.TCPconnections = []    # established connections
        self.TCPrequests = []       # 1st handshake
        self.TCPresponses = []       # 2nd handshake

        # Load the GeoIP DB ('geoipdb.txt')
        self.init_geo('geoipdb.txt')
        # Load the firewall rules (from rule_filename) here.
        self.init_rules(config['rule'])
        
        self.log = open('http.log', 'a')
            
    
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
        if transport_header_offset < 20 : return            # supplemental page 4
        dst_port = pkt[transport_header_offset + 2 : transport_header_offset +4]
        src_port = pkt[transport_header_offset : transport_header_offset +2]
        dst_port, = struct.unpack('!H', dst_port)
        src_port, = struct.unpack('!H', src_port)
       
        ipid, = struct.unpack('!H', pkt[4:6])       # IP identifier (big endian).
        
        tcp_payload_offset = ((ord(pkt[transport_header_offset + 12])) & 0xf0) >> 2 #already multyplied by 4
        tcp_flags = ord(pkt[transport_header_offset + 13])
        is_syn_flag = tcp_flags & 0x2 > 0
        is_ack_flag = tcp_flags & 0x10 > 0
        is_fin_flag = tcp_flags & 0x1 > 0

        
        if pkt_dir == PKT_DIR_INCOMING:
            dir_str = 'incoming'
            ext_addr = src_ip
            ext_port = src_port
            self.send_interface = self.iface_int
            in_addr = dst_ip
            in_port = dst_port
        elif pkt_dir == PKT_DIR_OUTGOING:
            dir_str = 'outgoing'
            ext_addr = dst_ip
            ext_port = dst_port
            self.send_interface = self.iface_ext
            in_addr = src_ip
            in_port = src_port

        if pkt_type == ICMP:                    #handle type instead of port for ICMP
            ext_port, = struct.unpack('!B', pkt[transport_header_offset])

        #print '%s packet: %s len=%4dB, IPID=%5d port=%s  %15s -> %15s' \
        #% (self.types[pkt_type], dir_str, len(pkt), ipid, ext_port, src_ip, dst_ip)
        
        last_verdict = 'pass'        
        #Thus you should always pass nonTCP/UDP/ICMP packets
        if pkt_type in self.types.keys():
            protocol = self.types[pkt_type]

            #DNS packet processing     
            if dir_str == 'outgoing' and pkt_type == UDP and dst_port == 53:
                is_valid_dns, last_verdict, qtype = self.handle_DNS(pkt[transport_header_offset:])
                #print is_valid_dns, last_verdict
                if is_valid_dns and last_verdict == 'pass':
                    self.send_interface.send_ip_packet(pkt)
                    return
                if is_valid_dns and last_verdict == 'deny':
                    if qtype == 1:
                        kitties = self.build_IP_packet(pkt, self.build_UDP_packet(pkt[20:]))
                        self.iface_int.send_ip_packet(kitties)
                    return
                    
            #TCP packets processing
            if pkt_type == TCP:
                pass




            #HTTP packets processing
            if pkt_type == TCP and ext_port == 80:                   # only ext HTTP server 
                # store outgoing from VM syn requests   1 handshake
                if (not is_ack_flag) and is_syn_flag and pkt_dir == PKT_DIR_OUTGOING: 
                    TCPrequest = Connection(dst_ip, src_ip, dst_port, src_port)
                    TCPrequest.sender_seqno, = struct.unpack('!L', pkt[transport_header_offset + 4: transport_header_offset + 8]) #1000
                    self.TCPrequests.append(TCPrequest)
                    #print 'SYN ', TCPrequest
                    
                # establish TCP connections             2 handshake
                if is_ack_flag and is_syn_flag and pkt_dir == PKT_DIR_INCOMING:
                    TCPresponse = Connection(src_ip, dst_ip, src_port, dst_port)
                    if TCPresponse in self.TCPrequests:
                        i = self.TCPrequests.index(TCPresponse)
                        TCPresponse.receiver_seqno, = struct.unpack('!L', pkt[transport_header_offset + 4: transport_header_offset + 8])#2000
                        TCPresponse.sender_seqno, = struct.unpack('!L', pkt[transport_header_offset + 8: transport_header_offset + 12]) #1001
                        #print 'SYN + ACK ', TCPresponse
                        if self.TCPrequests[i].sender_seqno + 1 == TCPresponse.sender_seqno: 
                            self.TCPresponses.append(TCPresponse)
                            self.TCPrequests.remove(TCPresponse)
                            
                        
                            
                # process data           
                if is_ack_flag and not is_syn_flag and pkt_dir == PKT_DIR_OUTGOING: 
                    TCP_pkt = Connection(dst_ip, src_ip, dst_port, src_port)
                    TCP_pkt.sender_seqno, = struct.unpack('!L', pkt[transport_header_offset + 4: transport_header_offset + 8])   #1001
                    TCP_pkt.receiver_seqno, = struct.unpack('!L', pkt[transport_header_offset + 8: transport_header_offset + 12])#2001
                    
                    if TCP_pkt in self.TCPresponses:
                        i = self.TCPresponses.index(TCP_pkt)
                        if self.TCPresponses[i].sender_seqno == TCP_pkt.sender_seqno and self.TCPresponses[i].receiver_seqno + 1 == TCP_pkt.receiver_seqno:
                            self.TCPconnections.append(TCP_pkt)
                            self.TCPresponses.remove(TCP_pkt)
                            print "\n####   connection established    ####", TCP_pkt
                    if TCP_pkt in self.TCPconnections:
                        i = self.TCPconnections.index(TCP_pkt)
                        #print 'TCP outgoing ', TCP_pkt
                        #print "Dic ", self.TCPconnections, self.TCPconnections[0].stream
                        
                        if self.TCPconnections[i].sender_seqno == TCP_pkt.sender_seqno and self.TCPconnections[i].receiver_seqno == TCP_pkt.receiver_seqno:
                            
                            payload = pkt[transport_header_offset + tcp_payload_offset:]
                            self.TCPconnections[i].stream += payload.lower()
                            
                            self.TCPconnections[i].sender_seqno += len(payload)     #1006
                            #print "payload = ", payload
                        if is_fin_flag:                                     # dirty early termination
                            #print self.TCPconnections[0].stream
                            self.process_stream(self.TCPconnections[i])
                            self.TCPconnections.remove(TCP_pkt)
                        
                if is_ack_flag and not is_syn_flag and pkt_dir == PKT_DIR_INCOMING: 
                    TCP_pkt = Connection(src_ip, dst_ip, src_port, dst_port)
                    TCP_pkt.receiver_seqno, = struct.unpack('!L', pkt[transport_header_offset + 4: transport_header_offset + 8]) #2001
                    TCP_pkt.sender_seqno, = struct.unpack('!L', pkt[transport_header_offset + 8: transport_header_offset + 12])#1006
                    #print 'TCP incoming ', TCP_pkt
                    if TCP_pkt in self.TCPconnections:
                        i = self.TCPconnections.index(TCP_pkt)
                        if self.TCPconnections[i].sender_seqno == TCP_pkt.sender_seqno and self.TCPconnections[i].receiver_seqno == TCP_pkt.receiver_seqno:
                            payload = pkt[transport_header_offset + tcp_payload_offset:]
                            self.TCPconnections[i].stream += payload.lower()
                            #print "payload = ", payload
                            
                            self.TCPconnections[i].receiver_seqno += len(payload)     #1006                        
                        if is_fin_flag:                                         # dirty early termination
                            #print self.TCPconnections[0].stream
                            self.process_stream(self.TCPconnections[i])
                            self.TCPconnections.remove(TCP_pkt)
            
            
            
            
            
            
            
            # check rules no DNS        
            for rule in self.rules_dict[protocol]:       
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
    # qname list, domains is line from rules file (string)
    def compare_domains(self, qname, domains):
        a = qname
        r = domains.split('.')
        a.reverse()
        r.reverse()
        if len(a) < len(r):
            return False
        i = 0
        while i < len(r) and r != '*':
            if a[i] != r[i] and r[i] != '*':
                return False
            i += 1

        return True
        
    def init_geo(self,geo_file):    
        geoipdb = open(geo_file, 'r')
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
            
            
    def init_rules(self,rules_file): 
        rules = open(rules_file, 'r')        
        rule_line = rules.readline()
        while rule_line:
            rule_line = rule_line.lower().split()
            if rule_line and (rule_line[0] in ['pass', 'drop', 'deny', 'log']):
                self.rules_dict[rule_line[1]].append(rule_line)
                # hack to DNS/UDP order logic - store UDP rule to DNS rules also
                if rule_line[1] == "udp":
                    self.rules_dict["dns"].append(rule_line)
            rule_line = rules.readline()
        print self.rules_dict  

    def handle_DNS(self, pkt):
        is_valid_dns = False
        verdict = 'pass'
        dns_pkt_offset = 8
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
                for dns_rule in self.rules_dict["dns"]:
                    if dns_rule[1] == 'dns':
                        if self.compare_domains(self.parse_name(qname), dns_rule[2]):
                            verdict = dns_rule[0]
                    if dns_rule[1] == 'udp': 
                        v = self.apply_rule(dns_rule, ext_addr, ext_port);
                        if v:
                            verdict = v;
        return is_valid_dns, verdict, qtype
        
    def process_stream(self, con):
        stream = con.stream.split("\r\n")
        for line in stream:
            print line
            if "host:" in line:
                host = line.split()
                host = host[1]
            if "content-length:" in line:
                cont_len = line.split()
                cont_len = cont_len[1]
            if "http/1.1" in line:
                req = line.split()
                if req[0] == "http/1.1":
                    status = req[1]
        if host:
            for rule in self.rules_dict["http"]:
                if self.compare_domains(host, rule[2]):
                    req = stream[0].split()
                    method = req[0]
                    path = req[1]
                    version = req[2]
                    

                    log.write(host, method, path, version, status, cont_len)
        print host, method, path, version, status, cont_len              
            

        
        
        
                            
    # build DNS response based on DNS query packet - pkt
    def build_DNS_packet(self, pkt):
        packet = pkt[:2] # ID
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        #  1      copy     1   0  0  0  0         0
        opcode = ord(pkt[2]) & 0x78
        opcode = ((0x80 + opcode + 0x04) << 8) & 0xFF00
        packet += struct.pack("!H", opcode)  # Flags
        packet += struct.pack("!H", 1)  # Questions
        packet += struct.pack("!H", 1)  # Answers
        packet += struct.pack("!H", 0)  # Authorities
        packet += struct.pack("!H", 0)  # Additional
        # Questions
        query = pkt[12: ]
        query = query[ :query.index('\0') +5] # query
        packet += query
        packet += query

        #packet += struct.pack("!H", 0xC00C)  # pointer to name
        #packet += struct.pack("!H", 1)  # Type
        #packet += struct.pack("!H", 1)  # Class
        packet += struct.pack("!L", 15)  # TTL
        packet += struct.pack("!H", 4)  # RDLENGTH
        packet += socket.inet_aton('169.229.49.130') # RDATA
        return packet
    
    # build UDP packet with DNS response based on UDP DNS query packet - pkt    
    def build_UDP_packet(self, pkt):
        packet = pkt[2 : 4]             # dst_port
        packet += pkt[ : 2]             # src_port 
        dns_packet = self.build_DNS_packet(pkt[8:])
        packet += struct.pack("!H", len(dns_packet)+8)  # LENGTH
        packet += struct.pack("!H", 0)  # checksum
        packet += dns_packet 
        return packet
        
    # build IP response packet based on incoming IP packet - pkt and payload
    def build_IP_packet(self, pkt, payload):
        
        packet = pkt[ :2]             # version, IHL, TOS
        packet += struct.pack("!H", len(payload) +20)   # Total length
        packet += pkt[4:6]              # ID
        packet += pkt[6:8]              # flags magic
        packet += pkt[8:10]             # TTL, protocol
        packet += struct.pack("!H", 0)  # checksum
        packet += pkt[16 : 20]             # dst_addr
        packet += pkt[12 : 16]             # src_addr

        packet = packet[:10] + struct.pack("!H", my_checksum(packet)) + packet[12:] + payload
        return packet

        
        



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

    
def my_checksum(buf, sum=0):
    i = 0;
    while i + 1 < len(buf):        # Accumulate checksum
        w = ((ord(buf[i]) << 8) & 0xFF00) + (ord(buf[i+1]) & 0xFF)
        sum, i = sum + w, i + 2
    if len(buf)%2 == 1:          # Handle odd-sized case
        sum += ord(buf[i]) & 0xFF
    
    # take only 16 bits out of the 32 bit sum and add up the carries
    while (sum >> 16) > 0:
        sum = (sum & 0xFFFF) + (sum >> 16)        
    return ~sum & 0xFFFF            # one's complement the result

class Connection:
    def __init__(self, ext_addr, in_addr, ext_port, in_port):
        self.ext_addr = ext_addr
        self.in_addr = in_addr
        self.ext_port = ext_port
        self.in_port = in_port

        self.request_data = ''
        self.response_data  = ''
        self.stream = ''

        self.sender_seqno = None
        self.receiver_seqno = None
        
    def __eq__(self, other):
        if self.ext_addr == other.ext_addr and self.in_addr == other.in_addr \
            and self.ext_port == other.ext_port and self.in_port == other.in_port:
            return True
        else:
            return False
            
    def __str__(self):
        # return "Connection: ext " + str(self.ext_addr) + ":" + str(self.ext_port) + " int " + str(self.in_addr) +\
        # ":" + str(self.in_port) + 
        return " sender # " + str(self.sender_seqno) + " rec # " + str(self.receiver_seqno) 
        #"\n Stream: " + self.stream
        
    __repr__ = __str__
        