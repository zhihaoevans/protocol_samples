#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, UDP, Raw, wrpcap

PROTO = "gtp"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "gtpu_sessions.pcap"
    packets = []

    # GTP-U 默认端口 2152，4 会话 × 4 轮 × 双向
    for i in range(4):
        ue = f"10.0.{i}.2"
        enb = f"10.0.{i}.1"
        sport = 30000 + i
        for j in range(4):
            uplink = Ether() / IP(src=ue, dst=enb) / UDP(sport=sport, dport=2152) / Raw(load=b"GTPU_UL_" + bytes([i, j]))
            downlink = Ether() / IP(src=enb, dst=ue) / UDP(sport=2152, dport=sport) / Raw(load=b"GTPU_DL_" + bytes([i, j]))
            packets.extend([uplink, downlink])

    wrpcap(str(out_path), packets)
    return str(out_path)