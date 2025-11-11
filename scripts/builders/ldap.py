#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, TCP, Raw, wrpcap

PROTO = "ldap"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "ldap_tcp389.pcap"
    packets = []
    # LDAP 使用 TCP 389，占位 Bind/Search/Result；4 会话 × 4 轮 × 双向 = 32 包
    for i in range(4):
        src = f"198.51.100.{10+i}"
        sport = 62000 + i
        for j in range(4):
            req = Ether() / IP(src=src, dst="198.51.100.1") / TCP(sport=sport, dport=389, flags="PA") / Raw(load=b"LDAP_REQ_" + bytes([i, j]))
            resp = Ether() / IP(src="198.51.100.1", dst=src) / TCP(sport=389, dport=sport, flags="PA") / Raw(load=b"LDAP_RESP_" + bytes([i, j]))
            packets.extend([req, resp])
    wrpcap(str(out_path), packets)
    return str(out_path)