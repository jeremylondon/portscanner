# Simple Port Scanner
A simple port scanner made in requirements of a lab for IT567 at BYU by Jeremy London. Based on tutorials and examples from:
https://securitylair.wordpress.com/2014/02/21/simple-port-scanner-in-python-with-scapy-2/

## Running the Program
This port scanner has the following capabilities:
* Single, Range and Subnet mask of Hosts to scan (ex :123.456.789.0, 123.456.789.0-123.456.789.256 and 123.456.789.0/24)
* Single or Range Ports (ex: 1, or 1-1000)
* TCP And UDP port scanning (Defaulted to TCP use -u/--udp for a UDP scan)
* Tracerouting the given IP (-t)

If help is needed refer to -h command.
```usage: portscanner.py [-h] [-p PORT] [-u] [-t] XXX.XXX.XXX.XXX

A simple port scanner using TCP. Allows ports to switch between UDP and the defaulted TCP. Hosts and Ports can be in ranges.

positional arguments:
  XXX.XXX.XXX.XXX       The host to run the port scan on. Can be a single host, a range or a mask. Examples:
                                    portscanner.py 192.167.207.0-192.167.207.256
                                    portscanner.py 192.167.207.0/24

optional arguments:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  Specifies the ports to run the port scan on. Can be either a single number or range of ports i.e. 1-1025. Default 1-1025. Examples:
                                    portscanner.py 192.192.192.192 -p 8
                                    portscanner.py 192.192.192.192 -p 8-100
  -u, --udp             Specifies the program to run a UDP port scan. Default = False.
  -t, --traceroute      Specifies the program to run a traceroute on the IP. Default = False.```
