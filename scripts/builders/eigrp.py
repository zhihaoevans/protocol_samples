#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, Raw, wrpcap

PROTO = "eigrp"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "eigrp_hello_update.pcap"
    packets = []
    # 使用 IP 协议号 88 模拟 EIGRP，双向 Raw 负载
    routers = [
        ("192.168.0.80", "192.168.0.1"),
        ("192.168.0.81", "192.168.0.1"),
        ("192.168.0.82", "192.168.0.1"),
        ("192.168.0.83", "192.168.0.1"),
    ]
    for i, (src, dst) in enumerate(routers):
        for j in range(4):
            hello = Ether() / IP(src=src, dst=dst, proto=88) / Raw(load=b"EIGRP_HELLO_" + bytes([i, j]))
            ack = Ether() / IP(src=dst, dst=src, proto=88) / Raw(load=b"EIGRP_ACK_" + bytes([i, j]))
            packets.extend([hello, ack])
    wrpcap(str(out_path), packets)
    return str(out_path)