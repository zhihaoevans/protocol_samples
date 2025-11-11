#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, TCP, Raw, wrpcap

PROTO = "rdp"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "rdp_tcp3389.pcap"
    packets = []
    # RDP 使用 TCP 3389，占位握手/显示数据；4 会话 × 4 轮 × 双向 = 32 包
    for i in range(4):
        src = f"203.0.114.{10+i}"
        sport = 55040 + i
        for j in range(4):
            syn = Ether() / IP(src=src, dst="203.0.114.1") / TCP(sport=sport, dport=3389, flags="PA") / Raw(load=b"RDP_REQ_" + bytes([i, j]))
            ack = Ether() / IP(src="203.0.114.1", dst=src) / TCP(sport=3389, dport=sport, flags="PA") / Raw(load=b"RDP_RESP_" + bytes([i, j]))
            packets.extend([syn, ack])
    wrpcap(str(out_path), packets)
    return str(out_path)