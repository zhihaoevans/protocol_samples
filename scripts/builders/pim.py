#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, Raw, wrpcap

PROTO = "pim"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "pim_join_prune.pcap"
    packets = []

    # 使用 IP 协议号 103（PIM），简化为 Raw 负载，4 会话 × 4 轮 × 双向
    for i in range(4):
        src = f"192.168.0.{10+i}"
        dst = f"192.168.0.{1+i}"
        for j in range(4):
            fwd = Ether() / IP(src=src, dst=dst, proto=103) / Raw(load=b"PIM_JOIN_PRUNE_" + bytes([i, j]))
            rev = Ether() / IP(src=dst, dst=src, proto=103) / Raw(load=b"PIM_ACK_" + bytes([i, j]))
            packets.extend([fwd, rev])

    wrpcap(str(out_path), packets)
    return str(out_path)