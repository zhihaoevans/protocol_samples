#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, Raw, wrpcap

PROTO = "isis"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "isis_over_ip.pcap"
    packets = []
    # 使用 IP 协议号 124 的占位 IS-IS（简化为 Raw），4 会话 × 4 轮 × 双向 = 32 包
    for i in range(4):
        a = f"192.0.2.{10+i}"
        b = f"192.0.2.{1+i}"
        for j in range(4):
            fwd = Ether() / IP(src=a, dst=b, proto=124) / Raw(load=b"ISIS_CTRL_" + bytes([i, j]))
            rev = Ether() / IP(src=b, dst=a, proto=124) / Raw(load=b"ISIS_ACK_" + bytes([i, j]))
            packets.extend([fwd, rev])
    wrpcap(str(out_path), packets)
    return str(out_path)