#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, UDP, DNS, DNSQR, DNSRR, wrpcap

PROTO = "mdns"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "mdns_query.pcap"
    packets = []
    names = ["a.local", "b.local", "c.local", "d.local"]
    for i, name in enumerate(names):
        sport = 5353 + i
        for j in range(4):
            q = (
                Ether(src="02:00:00:00:00:01", dst="01:00:5e:00:00:fb")
                / IP(src=f"192.168.0.{10+i}", dst="224.0.0.251")
                / UDP(sport=sport, dport=5353)
                / DNS(rd=1, qd=DNSQR(qname=name), id=0x1300 + j)
            )
            # 模拟响应（单播返回）
            a = (
                Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
                / IP(src="192.168.0.1", dst=f"192.168.0.{10+i}")
                / UDP(sport=5353, dport=sport)
                / DNS(id=0x1300 + j, qr=1, aa=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, ttl=60, rdata="192.168.0.100"))
            )
            packets.extend([q, a])
    wrpcap(str(out_path), packets)
    return str(out_path)