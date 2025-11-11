#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, Raw, wrpcap

PROTO = "vrrp"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "vrrp_advertisements.pcap"
    packets = []
    # 使用 IP(proto=112) 模拟 VRRP 通告，双向以保持 32 包结构
    routers = [
        ("192.168.0.40", "192.168.0.1"),
        ("192.168.0.41", "192.168.0.1"),
        ("192.168.0.42", "192.168.0.1"),
        ("192.168.0.43", "192.168.0.1"),
    ]
    for i, (src, dst) in enumerate(routers):
        for j in range(4):
            adv = Ether() / IP(src=src, dst=dst, proto=112) / Raw(load=b"VRRP_ADV_" + bytes([i, j]))
            ack = Ether() / IP(src=dst, dst=src, proto=112) / Raw(load=b"VRRP_ACK_" + bytes([i, j]))
            packets.extend([adv, ack])
    wrpcap(str(out_path), packets)
    return str(out_path)