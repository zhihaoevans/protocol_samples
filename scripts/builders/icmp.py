#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, ICMP, wrpcap

PROTO = "icmp"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "icmp_echo.pcap"
    packets = []
    pairs = [
        ("192.168.0.10", "192.168.0.1"),
        ("192.168.0.11", "192.168.0.1"),
        ("192.168.0.12", "192.168.0.1"),
        ("192.168.0.13", "192.168.0.1"),
    ]
    for src, dst in pairs:
        for _ in range(4):
            req = Ether() / IP(src=src, dst=dst) / ICMP(type=8)
            rep = Ether() / IP(src=dst, dst=src) / ICMP(type=0)
            packets.extend([req, rep])
    wrpcap(str(out_path), packets)
    return str(out_path)