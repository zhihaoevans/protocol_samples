#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, UDP, Raw, wrpcap

PROTO = "udp"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "udp_payload.pcap"
    packets = []
    flows = [
        ("192.168.0.10", "192.168.0.1", 55510, 44410),
        ("192.168.0.11", "192.168.0.1", 55511, 44411),
        ("192.168.0.12", "192.168.0.1", 55512, 44412),
        ("192.168.0.13", "192.168.0.1", 55513, 44413),
    ]
    for src, dst, sport, dport in flows:
        for i in range(4):
            fwd = Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(load=f"payload-{i}".encode())
            rev = Ether() / IP(src=dst, dst=src) / UDP(sport=dport, dport=sport) / Raw(load=f"resp-{i}".encode())
            packets.extend([fwd, rev])
    wrpcap(str(out_path), packets)
    return str(out_path)