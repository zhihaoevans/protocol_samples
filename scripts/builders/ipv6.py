#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, wrpcap

PROTO = "ipv6"

try:
    from scapy.layers.inet6 import IPv6
except Exception:
    IPv6 = None


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "ipv6_payload.pcap"

    packets = []
    if IPv6:
        from scapy.all import Raw
        # 4 会话，每会话 4 次双向 Raw 负载
        pairs = [
            ("fe80::10", "fe80::1"),
            ("fe80::11", "fe80::1"),
            ("fe80::12", "fe80::1"),
            ("fe80::13", "fe80::1"),
        ]
        for src, dst in pairs:
            for i in range(4):
                fwd = Ether() / IPv6(src=src, dst=dst) / Raw(load=f"v6-{i}".encode())
                rev = Ether() / IPv6(src=dst, dst=src) / Raw(load=f"v6-rev-{i}".encode())
                packets.extend([fwd, rev])
    else:
        # 回退为 IPv4 + Raw，按相同模式
        from scapy.all import IP, Raw
        pairs = [
            ("192.168.0.10", "192.168.0.1"),
            ("192.168.0.11", "192.168.0.1"),
            ("192.168.0.12", "192.168.0.1"),
            ("192.168.0.13", "192.168.0.1"),
        ]
        for src, dst in pairs:
            for i in range(4):
                fwd = Ether() / IP(src=src, dst=dst) / Raw(load=f"v6-fallback-{i}".encode())
                rev = Ether() / IP(src=dst, dst=src) / Raw(load=f"v6-fallback-rev-{i}".encode())
                packets.extend([fwd, rev])

    wrpcap(str(out_path), packets)
    return str(out_path)