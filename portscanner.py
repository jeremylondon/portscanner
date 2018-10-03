"""
A port scanner written for BYU IT 567 by Jeremy London. Based on tutorials and examples from:
https://securitylair.wordpress.com/2014/02/21/simple-port-scanner-in-python-with-scapy-2/

"""

import argparse
import socket
import subprocess
import sys
import re
import logging
from netaddr import *
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import*
from datetime import datetime
from argparse import ArgumentParser, ArgumentTypeError

def parseNumList(string):
    """Parses a range of ports through the use of argparse

    :param string: The string to parse. 1-10 or just 1 will succeed. Others will raise ArgumentTypeError

    returns the list of numbers gathered from the string.
    """
    m = re.match(r'(\d+)(?:-(\d+))?$', string)
    if not m:
        raise ArgumentTypeError("'" + string + "' is not a range of numbers. Expected forms like '0-5' or '2'.")
    start = m.group(1)
    end = m.group(2) or start
    return list(range(int(start,10), int(end,10)+1))

def parseIPList(hostarg):
    """Parses a range of IPs. 

    :param hostarg: The string to parse the IPS from. Can be a single IP, a range or a submask.

    returns the list of IP addresses from the given string.
    """
    iplist = []
    if "/" in hostarg:
        ip = IPNetwork(hostarg)
        for ipnetwork in ip:
            iplist.append(str(ipnetwork))
    elif "-" in hostarg:
        split = hostarg.split("-")
        start = IPAddress(split[0])
        end = IPAddress(split[1])
        while start <= end:
            iplist.append(str(start))
            start += 1
    else:
        iplist.append(hostarg)
    return iplist

def printBanner(string, clearScreen=False):
    """Prints a header surrounded by lines of 60 '-'. If clear screen is set will clear original content in terminal.

    :param string: The header string to print.
    :param clearScreen: Should function clear screen of output (Default value = False)

    """
    if clearScreen:
        subprocess.call('clear', shell=True)
    print "-" * 60
    print string
    print "-" * 60

def traceRoute(destip):
    """Performs a traceroute with max depth of 28 using ICMP.

    :param destip: The destination IP to perform the traceroute to.

    """
    for i in range(1, 28):
        resp = sr1(IP(dst=destip,ttl=i)/ICMP(),timeout=3)
        if resp is None:
            print "Hop {0}: {1}".format(i, "*.*.*.*")
        elif resp.src == destip:
            print "Finished", resp.src
            break
        else:
            print "Hop {0}: {1}".format(i, resp.src)

def tcpScan(host, ports):
    """Performs a tcp scan on the host with the given ports

    :param host: The host address to scan
    :param ports: The ports to scan on that host

    returns a list of open ports as well as the number of closed ports found
    """
    closed_ports = 0
    open_ports = []

    for port in ports:  
        src_port = RandShort()
        p = IP(dst=host)/TCP(sport=src_port, dport=port, flags='S')
        resp = sr1(p, timeout=2)
        if resp is None:
            closed_ports += 1
        elif resp.haslayer(TCP):
            if resp.getlayer(TCP).flags == 0x12:
                send_rst = sr1(IP(dst=ip)/TCP(sport=src_port, dport=port, flags='AR'), timeout=1)
                open_ports.append(port)
            elif resp.getlayer(TCP).flags == 0x14:
                closed_ports += 1
    return open_ports, closed_ports
    

def udpScan(host, ports):
    """Performs a udp scan on the host with the given ports

    :param host: The host address to scan
    :param ports: The ports to scan on that host

    returns a list of open ports, number of closed ports, and a list of filtered ports.
    """
    closed_ports = 0
    open_ports = []
    filtered_ports = []

    for port in ports:  
        p = IP(dst=host)/UDP(dport=port)
        resp = sr1(p, timeout=5)
        if resp is None:
            open_ports.append(port)
        elif(response.haslayer(scapy.ICMP)):
			if(int(response.getlayer(scapy.ICMP).type)==3 and int(response.getlayer(scapy.ICMP).code)==3):
				closed_ports += 1
			
			elif(int(response.getlayer(scapy.ICMP).type)==3 and int(response.getlayer(scapy.ICMP).code) in [1,2,9,10,13]):
				filtered_ports = []
        else:
			closed_ports += 1

    return open_ports, closed_ports, filtered_ports

def scanPorts(host, ports, udp=False, pdf=False):
    """Scans the host on the given ports

    :param host: The host the scan
    :param ports: The ports to scan given as list
    :param udp:  If set will perform a UDP scan(Default value = False)
    :param pdf:  Not used(Default value = False)

    """
    if len(ports) > 1:
        portString = "{0}-{1}".format(ports[0],ports[len(ports)-1])
    else:
        portString = ports[0]
    printBanner("Performing {0} port scan on host {1} over ports {2}".format("TCP" if not udp else "UDP", host, portString))
    startTime = datetime.now()
    
    if udp:
        openp, closedp, filteredp = udpScan(host, ports)
    else:
        openp, closedp = tcpScan(host, ports)

    endTime = datetime.now()
    total =  endTime - startTime
    print 'Scanning Completed in: {0} seconds'.format(total)  
    for openport in openp:
        print "\tPort {0}: Open".format(openport) 
    if udp:
        for filtered in filteredp:
            print "\tPort {0}: Filtered".format(filtered)  
    print 'Found a total of {0} closed ports in {1} total ports scanned'.format(closedp, len(ports))
 
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='A simple port scanner using TCP. Allows ports to switch between UDP and the defaulted TCP. \
        Hosts and Ports can be in ranges.', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('host', metavar='XXX.XXX.XXX.XXX', type=str, help='The host to run the port scan on. Can be a single host, a range or a mask. Examples:\n\
            portscanner.py 192.167.207.0-192.167.207.256\n\
            portscanner.py 192.167.207.0/24')
    parser.add_argument('-p', '--port', dest='port',type=parseNumList, default=range(1,1025),\
        help='Specifies the ports to run the port scan on. Can be either a single number or range of ports i.e. 1-1025. Default 1-1025. Examples:\n\
            portscanner.py 192.192.192.192 -p 8\n\
            portscanner.py 192.192.192.192 -p 8-100')
    parser.add_argument('-u', '--udp', dest='udp',action='store_true', \
        help='Specifies the program to run a UDP port scan. Default = False.')
    parser.add_argument('-t', '--traceroute', dest='trace',action='store_true', \
        help='Specifies the program to run a traceroute on the IP. Default = False.')

    args = parser.parse_args()

    conf.verb = 0
    printBanner("Starting Port Scanner", True)
    iplist = parseIPList(args.host)
    for host in iplist:
        if args.trace:
            printBanner("Performing Trace Route")
            traceRoute(host)
        scanPorts(host, args.port, args.udp)