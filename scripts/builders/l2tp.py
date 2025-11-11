#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, UDP, Raw, wrpcap

PROTO = "l2tp"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "l2tp_tunnel.pcap"
    packets = []
    pairs = [
        ("192.168.0.94", "192.168.0.1"),
        ("192.168.0.95", "192.168.0.1"),
        ("192.168.0.96", "192.168.0.1"),
        ("192.168.0.97", "192.168.0.1"),
    ]
    for i, (src, dst) in enumerate(pairs):
        sport = 17010 + i
        for j in range(4):
            req = Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=1701) / Raw(load=b"L2TP_CTRL_" + bytes([i, j]))
            rep = Ether() / IP(src=dst, dst=src) / UDP(sport=1701, dport=sport) / Raw(load=b"L2TP_RESP_" + bytes([i, j]))
            packets.extend([req, rep])
    wrpcap(str(out_path), packets)
    return str(out_path)