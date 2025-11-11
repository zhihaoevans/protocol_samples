#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, wrpcap

PROTO = "icmpv6"

try:
    from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
except Exception:  # 回退
    IPv6 = None
    ICMPv6EchoRequest = None
    ICMPv6EchoReply = None


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    if IPv6 and ICMPv6EchoRequest and ICMPv6EchoReply:
        out_path = out_dir / "icmpv6_echo.pcap"
        packets = []
        pairs = [("fe80::1", "fe80::2"), ("fe80::3", "fe80::2"), ("fe80::4", "fe80::2"), ("fe80::5", "fe80::2")]
        for src, dst in pairs:
            for _ in range(4):
                req = Ether() / IPv6(src=src, dst=dst) / ICMPv6EchoRequest()
                rep = Ether() / IPv6(src=dst, dst=src) / ICMPv6EchoReply()
                packets.extend([req, rep])
        wrpcap(str(out_path), packets)
        return str(out_path)
    else:
        out_path = out_dir / "icmpv6_fallback.pcap"
        from scapy.all import IP, Raw

        packets = []
        pairs = [("192.168.0.10", "192.168.0.1"), ("192.168.0.11", "192.168.0.1"), ("192.168.0.12", "192.168.0.1"), ("192.168.0.13", "192.168.0.1")]
        for src, dst in pairs:
            for i in range(4):
                fwd = Ether() / IP(src=src, dst=dst) / Raw(load=f"icmpv6_unavailable_{i}".encode())
                rev = Ether() / IP(src=dst, dst=src) / Raw(load=f"resp_{i}".encode())
                packets.extend([fwd, rev])
        wrpcap(str(out_path), packets)
        return str(out_path)