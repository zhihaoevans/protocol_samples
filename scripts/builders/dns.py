#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, UDP, DNS, DNSQR, DNSRR, wrpcap

PROTO = "dns"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "dns_example_com.pcap"
    packets = []
    sessions = [
        ("192.168.0.10", "192.168.0.1", 53010, "example.com"),
        ("192.168.0.11", "192.168.0.1", 53011, "example.org"),
        ("192.168.0.12", "192.168.0.1", 53012, "example.net"),
        ("192.168.0.13", "192.168.0.1", 53013, "example.edu"),
    ]
    for src, dst, sport, name in sessions:
        for i in range(4):
            tid = 0x1200 + i
            q = Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=53) / DNS(rd=1, qd=DNSQR(qname=name), id=tid)
            a = Ether() / IP(src=dst, dst=src) / UDP(sport=53, dport=sport) / DNS(id=tid, qr=1, aa=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, ttl=60, rdata="93.184.216.34"))
            packets.extend([q, a])
    wrpcap(str(out_path), packets)
    return str(out_path)