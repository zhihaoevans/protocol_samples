#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, UDP, Raw, wrpcap

PROTO = "openvpn"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "openvpn_udp1194.pcap"
    packets = []
    # OpenVPN 使用 UDP 1194，占位握手/数据；4 会话 × 4 轮 × 双向 = 32 包
    for i in range(4):
        a = f"10.210.{i}.2"
        b = f"10.210.{i}.1"
        sport = 65000 + i
        for j in range(4):
            hs = Ether() / IP(src=a, dst=b) / UDP(sport=sport, dport=1194) / Raw(load=b"OVPN_HS_" + bytes([i, j]))
            ack = Ether() / IP(src=b, dst=a) / UDP(sport=1194, dport=sport) / Raw(load=b"OVPN_ACK_" + bytes([i, j]))
            packets.extend([hs, ack])
    wrpcap(str(out_path), packets)
    return str(out_path)