#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, UDP, Raw, wrpcap

PROTO = "gtpc"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "gtpc_messages.pcap"
    packets = []
    # GTP-C 控制面端口 2123，4 会话 × 4 轮 × 双向 = 32 包
    for i in range(4):
        src = f"10.10.{i}.2"
        dst = f"10.10.{i}.1"
        sport = 31000 + i
        for j in range(4):
            req = Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=2123) / Raw(load=b"GTPC_REQ_" + bytes([i, j]))
            resp = Ether() / IP(src=dst, dst=src) / UDP(sport=2123, dport=sport) / Raw(load=b"GTPC_RESP_" + bytes([i, j]))
            packets.extend([req, resp])
    wrpcap(str(out_path), packets)
    return str(out_path)