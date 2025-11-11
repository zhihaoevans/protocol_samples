#!/usr/bin/env python
from pathlib import Path

from scapy.all import Ether, IP, UDP, Raw, wrpcap

PROTO = "coap"

try:
    from scapy.contrib.coap import CoAP
except Exception:
    CoAP = None


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "coap_requests.pcap"
    packets = []
    # 4 会话，每会话 4 次请求/响应，合计 8 包 × 4 = 32
    base_sports = [56831, 56832, 56833, 56834]
    for i, sport in enumerate(base_sports):
        src = f"192.168.0.{60+i}"
        for j in range(4):
            if CoAP:
                req = Ether() / IP(src=src, dst="192.168.0.1") / UDP(sport=sport, dport=5683) / CoAP()
                resp = Ether() / IP(src="192.168.0.1", dst=src) / UDP(sport=5683, dport=sport) / CoAP()
            else:
                req = Ether() / IP(src=src, dst="192.168.0.1") / UDP(sport=sport, dport=5683) / Raw(load=f"GET /r{j}".encode())
                resp = Ether() / IP(src="192.168.0.1", dst=src) / UDP(sport=5683, dport=sport) / Raw(load=f"2.05 Content r{j}".encode())
            packets.extend([req, resp])
    wrpcap(str(out_path), packets)
    return str(out_path)