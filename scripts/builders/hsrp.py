#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, UDP, Raw, wrpcap

PROTO = "hsrp"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "hsrp_hello.pcap"
    packets = []
    # HSRP 使用 UDP 1985，简化为 hello/ack 对话；4 会话 × 4 轮 × 双向 = 32 包
    for i in range(4):
        a = f"192.168.100.{10+i}"
        b = f"192.168.100.1"
        sport = 58000 + i
        for j in range(4):
            hello = Ether() / IP(src=a, dst=b) / UDP(sport=sport, dport=1985) / Raw(load=b"HSRP_HELLO_" + bytes([i, j]))
            ack = Ether() / IP(src=b, dst=a) / UDP(sport=1985, dport=sport) / Raw(load=b"HSRP_ACK_" + bytes([i, j]))
            packets.extend([hello, ack])
    wrpcap(str(out_path), packets)
    return str(out_path)