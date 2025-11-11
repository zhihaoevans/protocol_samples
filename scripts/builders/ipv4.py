#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, Raw, wrpcap

PROTO = "ipv4"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "ipv4_payload.pcap"
    packets = []
    pairs = [
        ("192.168.0.10", "192.168.0.1"),
        ("192.168.0.11", "192.168.0.1"),
        ("192.168.0.12", "192.168.0.1"),
        ("192.168.0.13", "192.168.0.1"),
    ]
    # 每会话 4 次双向负载，共 8 包 × 4 会话 ≈ 32 包
    for src, dst in pairs:
        for i in range(4):
            fwd = Ether() / IP(src=src, dst=dst) / Raw(load=f"payload-{i}".encode())
            rev = Ether() / IP(src=dst, dst=src) / Raw(load=f"resp-{i}".encode())
            packets.extend([fwd, rev])
    wrpcap(str(out_path), packets)
    return str(out_path)