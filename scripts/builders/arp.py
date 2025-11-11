#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, ARP, wrpcap

PROTO = "arp"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "arp_request_reply.pcap"
    packets = []
    pairs = [
        ("192.168.0.10", "192.168.0.1", "02:00:00:00:00:01", "02:00:00:00:00:02"),
        ("192.168.0.11", "192.168.0.1", "02:00:00:00:00:03", "02:00:00:00:00:02"),
        ("192.168.0.12", "192.168.0.1", "02:00:00:00:00:04", "02:00:00:00:00:02"),
        ("192.168.0.13", "192.168.0.1", "02:00:00:00:00:05", "02:00:00:00:00:02"),
    ]
    # 每个会话 4 次请求/应答，共 8 包 × 4 会话 ≈ 32 包
    for psrc, pdst, mac_src, mac_dst in pairs:
        for _ in range(4):
            req = Ether(src=mac_src, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc=psrc, pdst=pdst)
            rep = Ether(src=mac_dst, dst=mac_src) / ARP(op=2, psrc=pdst, pdst=psrc)
            packets.extend([req, rep])
    wrpcap(str(out_path), packets)
    return str(out_path)