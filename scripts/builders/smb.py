#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, TCP, Raw, wrpcap

PROTO = "smb"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "smb_tcp445.pcap"
    packets = []
    # SMB 使用 TCP 445，简化为请求/响应；4 会话 × 4 轮 × 双向 = 32 包
    for i in range(4):
        src = f"192.168.200.{10+i}"
        sport = 60000 + i
        for j in range(4):
            req = Ether() / IP(src=src, dst="192.168.200.1") / TCP(sport=sport, dport=445, flags="PA") / Raw(load=b"SMB_REQ_" + bytes([i, j]))
            resp = Ether() / IP(src="192.168.200.1", dst=src) / TCP(sport=445, dport=sport, flags="PA") / Raw(load=b"SMB_RESP_" + bytes([i, j]))
            packets.extend([req, resp])
    wrpcap(str(out_path), packets)
    return str(out_path)