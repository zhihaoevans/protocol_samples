#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, TCP, wrpcap

PROTO = "tcp"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "tcp_handshake.pcap"
    packets = []
    base_ports = [12345, 12346, 12347, 12348]
    for i, sport in enumerate(base_ports):
        # 三次握手
        syn = Ether() / IP(src=f"192.168.0.{10+i}", dst="192.168.0.1") / TCP(sport=sport, dport=80, flags="S", seq=1000 + i)
        synack = Ether() / IP(src="192.168.0.1", dst=f"192.168.0.{10+i}") / TCP(sport=80, dport=sport, flags="SA", seq=2000 + i, ack=1001 + i)
        ack = Ether() / IP(src=f"192.168.0.{10+i}", dst="192.168.0.1") / TCP(sport=sport, dport=80, flags="A", seq=1001 + i, ack=2001 + i)
        # 数据交互与关闭，保证每会话 8 包
        client_psh = Ether() / IP(src=f"192.168.0.{10+i}", dst="192.168.0.1") / TCP(sport=sport, dport=80, flags="PA", seq=1001 + i, ack=2001 + i)
        server_psh = Ether() / IP(src="192.168.0.1", dst=f"192.168.0.{10+i}") / TCP(sport=80, dport=sport, flags="PA", seq=2001 + i, ack=1001 + i)
        client_ack = Ether() / IP(src=f"192.168.0.{10+i}", dst="192.168.0.1") / TCP(sport=sport, dport=80, flags="A", seq=1002 + i, ack=2002 + i)
        fin = Ether() / IP(src=f"192.168.0.{10+i}", dst="192.168.0.1") / TCP(sport=sport, dport=80, flags="FA", seq=1003 + i, ack=2002 + i)
        finack = Ether() / IP(src="192.168.0.1", dst=f"192.168.0.{10+i}") / TCP(sport=80, dport=sport, flags="FA", seq=2002 + i, ack=1004 + i)
        packets.extend([syn, synack, ack, client_psh, server_psh, client_ack, fin, finack])
    wrpcap(str(out_path), packets)
    return str(out_path)