#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, TCP, Raw, wrpcap

PROTO = "ldp"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "ldp_tcp646.pcap"
    packets = []

    # LDP 使用 TCP 646，简化为数据/响应对话；4 会话 × 4 轮 × 双向（每会话约 8 包）
    for i in range(4):
        src = f"192.0.2.{10+i}"
        sport = 46000 + i
        for j in range(4):
            req = Ether() / IP(src=src, dst="192.0.2.1") / TCP(sport=sport, dport=646, flags="PA") / Raw(load=b"LDP_MSG_" + bytes([i, j]))
            resp = Ether() / IP(src="192.0.2.1", dst=src) / TCP(sport=646, dport=sport, flags="PA") / Raw(load=b"LDP_ACK_" + bytes([i, j]))
            packets.extend([req, resp])

    wrpcap(str(out_path), packets)
    return str(out_path)