#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, UDP, Raw, wrpcap

PROTO = "kerberos"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "kerberos_udp88.pcap"
    packets = []
    # Kerberos 使用 UDP 88，占位 AS-REQ/AS-REP；4 会话 × 4 轮 × 双向 = 32 包
    for i in range(4):
        src = f"203.0.113.{10+i}"
        sport = 63000 + i
        for j in range(4):
            req = Ether() / IP(src=src, dst="203.0.113.1") / UDP(sport=sport, dport=88) / Raw(load=b"KRB_REQ_" + bytes([i, j]))
            rep = Ether() / IP(src="203.0.113.1", dst=src) / UDP(sport=88, dport=sport) / Raw(load=b"KRB_REP_" + bytes([i, j]))
            packets.extend([req, rep])
    wrpcap(str(out_path), packets)
    return str(out_path)