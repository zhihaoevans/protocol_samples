#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, UDP, Raw, wrpcap

PROTO = "radius"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "radius_access.pcap"
    packets = []
    users = [
        ("192.168.0.50", "userA"),
        ("192.168.0.51", "userB"),
        ("192.168.0.52", "userC"),
        ("192.168.0.53", "userD"),
    ]
    for i, (src, uname) in enumerate(users):
        sport = 18120 + i
        for j in range(4):
            req = Ether() / IP(src=src, dst="192.168.0.1") / UDP(sport=sport, dport=1812) / Raw(load=b"ACCESS-REQUEST " + uname.encode() + b" #" + bytes([j]))
            acc = Ether() / IP(src="192.168.0.1", dst=src) / UDP(sport=1812, dport=sport) / Raw(load=b"ACCESS-ACCEPT " + uname.encode() + b" #" + bytes([j]))
            packets.extend([req, acc])
    wrpcap(str(out_path), packets)
    return str(out_path)