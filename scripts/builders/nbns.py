#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, UDP, Raw, wrpcap

PROTO = "nbns"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "nbns_udp137.pcap"
    packets = []
    # NetBIOS Name Service 使用 UDP 137，占位查询/响应；4 会话 × 4 轮 × 双向 = 32 包
    for i in range(4):
        src = f"192.168.201.{10+i}"
        sport = 61000 + i
        for j in range(4):
            q = Ether() / IP(src=src, dst="192.168.201.1") / UDP(sport=sport, dport=137) / Raw(load=b"NBNS_Q_" + bytes([i, j]))
            a = Ether() / IP(src="192.168.201.1", dst=src) / UDP(sport=137, dport=sport) / Raw(load=b"NBNS_A_" + bytes([i, j]))
            packets.extend([q, a])
    wrpcap(str(out_path), packets)
    return str(out_path)