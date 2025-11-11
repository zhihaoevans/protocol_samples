#!/usr/bin/env python
from pathlib import Path

from scapy.all import Ether, IP, UDP, Raw, wrpcap

PROTO = "mpls"

try:
    from scapy.layers.inet import MPLS
except Exception:
    MPLS = None


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "mpls_labeled_udp.pcap"
    packets = []
    sessions = [
        (100, "192.168.20.10", "192.168.20.1", 52010, 42010),
        (200, "192.168.21.10", "192.168.21.1", 52011, 42011),
        (300, "192.168.22.10", "192.168.22.1", 52012, 42012),
        (400, "192.168.23.10", "192.168.23.1", 52013, 42013),
    ]
    for label, src, dst, sport, dport in sessions:
        for i in range(4):
            if MPLS:
                fwd = Ether() / MPLS(label=label, s=1, ttl=64) / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(load=f"payload-{i}".encode())
                rev = Ether() / MPLS(label=label + 1, s=1, ttl=64) / IP(src=dst, dst=src) / UDP(sport=dport, dport=sport) / Raw(load=f"resp-{i}".encode())
            else:
                # 回退：以太类型 0x8847 + Raw，占位 MPLS 头部
                fwd = Ether(type=0x8847) / Raw(load=b"MPLS" + bytes([label & 0xFF, i])) / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(load=f"payload-{i}".encode())
                rev = Ether(type=0x8847) / Raw(load=b"MPLS" + bytes([(label + 1) & 0xFF, i])) / IP(src=dst, dst=src) / UDP(sport=dport, dport=sport) / Raw(load=f"resp-{i}".encode())
            packets.extend([fwd, rev])
    wrpcap(str(out_path), packets)
    return str(out_path)