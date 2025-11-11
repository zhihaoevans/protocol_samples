#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, TCP, Raw, wrpcap

PROTO = "http"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "http_get.pcap"
    packets = []
    base_ports = [12345, 12346, 12347, 12348]
    for i, sport in enumerate(base_ports):
        src = f"192.168.0.{10+i}"
        # 三次握手
        syn = Ether() / IP(src=src, dst="192.168.0.1") / TCP(sport=sport, dport=80, flags="S", seq=1000 + i)
        synack = Ether() / IP(src="192.168.0.1", dst=src) / TCP(sport=80, dport=sport, flags="SA", seq=2000 + i, ack=1001 + i)
        ack = Ether() / IP(src=src, dst="192.168.0.1") / TCP(sport=sport, dport=80, flags="A", seq=1001 + i, ack=2001 + i)
        # 请求/响应
        req = Ether() / IP(src=src, dst="192.168.0.1") / TCP(sport=sport, dport=80, flags="PA", seq=1001 + i, ack=2001 + i) / Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        resp = Ether() / IP(src="192.168.0.1", dst=src) / TCP(sport=80, dport=sport, flags="PA", seq=2001 + i, ack=1001 + i) / Raw(load=b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
        client_ack = Ether() / IP(src=src, dst="192.168.0.1") / TCP(sport=sport, dport=80, flags="A", seq=1002 + i, ack=2002 + i)
        # 关闭
        fin = Ether() / IP(src=src, dst="192.168.0.1") / TCP(sport=sport, dport=80, flags="FA", seq=1003 + i, ack=2002 + i)
        finack = Ether() / IP(src="192.168.0.1", dst=src) / TCP(sport=80, dport=sport, flags="FA", seq=2002 + i, ack=1004 + i)
        packets.extend([syn, synack, ack, req, resp, client_ack, fin, finack])
    wrpcap(str(out_path), packets)
    return str(out_path)