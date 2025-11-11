#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IPv6, Raw, wrpcap

PROTO = "vrrpv3"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "vrrpv3_advertisements.pcap"
    packets = []
    # 使用 IPv6 下一头部 nh=112 模拟 VRRPv3 广告与响应
    routers = [
        ("fe80::8000", "fe80::1"),
        ("fe80::8001", "fe80::1"),
        ("fe80::8002", "fe80::1"),
        ("fe80::8003", "fe80::1"),
    ]
    for i, (src, dst) in enumerate(routers):
        for j in range(4):
            adv = Ether() / IPv6(src=src, dst=dst, nh=112) / Raw(load=b"VRRPv3_ADV_" + bytes([i, j]))
            ack = Ether() / IPv6(src=dst, dst=src, nh=112) / Raw(load=b"VRRPv3_ACK_" + bytes([i, j]))
            packets.extend([adv, ack])
    wrpcap(str(out_path), packets)
    return str(out_path)