#!/usr/bin/env python
from pathlib import Path

from scapy.all import Ether, IP, UDP, DNS, DNSQR, DNSRR, wrpcap

PROTO = "llmnr"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "llmnr_query.pcap"
    packets = []
    names = ["alpha.local", "beta.local", "gamma.local", "delta.local"]
    # LLMNR 多播地址与 MAC
    m_ip = "224.0.0.252"
    m_mac = "01:00:5e:00:00:fc"
    for i, name in enumerate(names):
        sport = 5355 + i
        src = f"192.168.0.{70+i}"
        for j in range(4):
            q = Ether(src="02:00:00:00:70:01", dst=m_mac) / IP(src=src, dst=m_ip) / UDP(sport=sport, dport=5355) / DNS(rd=1, qd=DNSQR(qname=name), id=0x1500 + j)
            a = Ether(src="02:00:00:00:70:ff", dst="02:00:00:00:70:01") / IP(src="192.168.0.1", dst=src) / UDP(sport=5355, dport=sport) / DNS(id=0x1500 + j, qr=1, aa=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, ttl=30, rdata="192.168.0.200"))
            packets.extend([q, a])
    wrpcap(str(out_path), packets)
    return str(out_path)