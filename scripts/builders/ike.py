#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, UDP, Raw, wrpcap

PROTO = "ike"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "ike_isakmp.pcap"
    packets = []
    pairs = [
        ("192.168.0.84", "192.168.0.1"),
        ("192.168.0.85", "192.168.0.1"),
        ("192.168.0.86", "192.168.0.1"),
        ("192.168.0.87", "192.168.0.1"),
    ]
    for i, (src, dst) in enumerate(pairs):
        sport = 50000 + i
        for j in range(4):
            init = Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=500) / Raw(load=b"IKE_SA_INIT_" + bytes([i, j]))
            resp = Ether() / IP(src=dst, dst=src) / UDP(sport=500, dport=sport) / Raw(load=b"IKE_RESP_" + bytes([i, j]))
            packets.extend([init, resp])
    wrpcap(str(out_path), packets)
    return str(out_path)