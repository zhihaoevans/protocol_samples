#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, Dot1Q, IP, UDP, Raw, wrpcap

PROTO = "vlan"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "vlan_dot1q.pcap"
    packets = []
    sessions = [
        (10, "192.168.10.10", "192.168.10.1", 55010, 44010),
        (11, "192.168.11.10", "192.168.11.1", 55011, 44011),
        (12, "192.168.12.10", "192.168.12.1", 55012, 44012),
        (13, "192.168.13.10", "192.168.13.1", 55013, 44013),
    ]
    for vlan_id, src, dst, sport, dport in sessions:
        for i in range(4):
            fwd = Ether() / Dot1Q(vlan=vlan_id) / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(load=f"payload-{i}".encode())
            rev = Ether() / Dot1Q(vlan=vlan_id) / IP(src=dst, dst=src) / UDP(sport=dport, dport=sport) / Raw(load=f"resp-{i}".encode())
            packets.extend([fwd, rev])
    wrpcap(str(out_path), packets)
    return str(out_path)