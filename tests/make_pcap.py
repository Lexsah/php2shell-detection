#!/usr/bin/env python3
"""Wrap a raw HTTP request fixture into a synthetic TCP session pcap (handshake + request + 200 reply)."""
import sys
from scapy.all import IP, TCP, Raw, wrpcap
req = open(sys.argv[1], "rb").read()
cli, srv, sp, dp = "192.0.2.100", "192.0.2.1", 40000, 80
resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nok"
c, s = 1000, 5000
pk = [IP(src=cli, dst=srv)/TCP(sport=sp, dport=dp, flags="S", seq=c),
      IP(src=srv, dst=cli)/TCP(sport=dp, dport=sp, flags="SA", seq=s, ack=c+1),
      IP(src=cli, dst=srv)/TCP(sport=sp, dport=dp, flags="A", seq=c+1, ack=s+1),
      IP(src=cli, dst=srv)/TCP(sport=sp, dport=dp, flags="PA", seq=c+1, ack=s+1)/Raw(req),
      IP(src=srv, dst=cli)/TCP(sport=dp, dport=sp, flags="A", seq=s+1, ack=c+1+len(req)),
      IP(src=srv, dst=cli)/TCP(sport=dp, dport=sp, flags="PA", seq=s+1, ack=c+1+len(req))/Raw(resp),
      IP(src=cli, dst=srv)/TCP(sport=sp, dport=dp, flags="A", seq=c+1+len(req), ack=s+1+len(resp)),
      IP(src=cli, dst=srv)/TCP(sport=sp, dport=dp, flags="FA", seq=c+1+len(req), ack=s+1+len(resp)),
      IP(src=srv, dst=cli)/TCP(sport=dp, dport=sp, flags="FA", seq=s+1+len(resp), ack=c+2+len(req)),
      IP(src=cli, dst=srv)/TCP(sport=sp, dport=dp, flags="A", seq=c+2+len(req), ack=s+2+len(resp))]
wrpcap(sys.argv[2], pk)
