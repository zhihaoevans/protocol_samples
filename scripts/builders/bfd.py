#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, UDP, Raw, wrpcap

PROTO = "bfd"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "bfd_udp_multi.pcap"
    packets = []
    # BFD 单跳 UDP 3784（多跳 4784），此处用 3784，4 会话 × 4 轮 × 双向 = 32 包
    for i in range(4):
        a = f"172.20.{i}.10"
        b = f"172.20.{i}.1"
        sport = 36000 + i
        for j in range(4):
            ctrl = Ether() / IP(src=a, dst=b) / UDP(sport=sport, dport=3784) / Raw(load=b"BFD_CTRL_" + bytes([i, j]))
            echo = Ether() / IP(src=b, dst=a) / UDP(sport=3784, dport=sport) / Raw(load=b"BFD_ECHO_" + bytes([i, j]))
            packets.extend([ctrl, echo])
    wrpcap(str(out_path), packets)
    return str(out_path)