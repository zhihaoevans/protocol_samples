#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, TCP, Raw, wrpcap

PROTO = "smtp"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "smtp_simple.pcap"
    packets = []
    base_ports = [25252, 25253, 25254, 25255]
    for i, sport in enumerate(base_ports):
        src = f"192.168.0.{10+i}"
        # 三次握手
        syn = Ether() / IP(src=src, dst="192.168.0.1") / TCP(sport=sport, dport=25, flags="S", seq=1000 + i)
        synack = Ether() / IP(src="192.168.0.1", dst=src) / TCP(sport=25, dport=sport, flags="SA", seq=2000 + i, ack=1001 + i)
        ack = Ether() / IP(src=src, dst="192.168.0.1") / TCP(sport=sport, dport=25, flags="A", seq=1001 + i, ack=2001 + i)
        # 简化 SMTP 交换：HELO/250，QUIT/221
        helo = Ether() / IP(src=src, dst="192.168.0.1") / TCP(sport=sport, dport=25, flags="PA", seq=1001 + i, ack=2001 + i) / Raw(load=b"HELO example.com\r\n")
        ok = Ether() / IP(src="192.168.0.1", dst=src) / TCP(sport=25, dport=sport, flags="PA", seq=2001 + i, ack=1001 + i) / Raw(load=b"250 Hello\r\n")
        quitc = Ether() / IP(src=src, dst="192.168.0.1") / TCP(sport=sport, dport=25, flags="PA", seq=1002 + i, ack=2002 + i) / Raw(load=b"QUIT\r\n")
        bye = Ether() / IP(src="192.168.0.1", dst=src) / TCP(sport=25, dport=sport, flags="PA", seq=2002 + i, ack=1002 + i) / Raw(load=b"221 Bye\r\n")
        # 关闭
        fin = Ether() / IP(src=src, dst="192.168.0.1") / TCP(sport=sport, dport=25, flags="FA", seq=1003 + i, ack=2003 + i)
        # 为保证每会话 8 包，移除服务器 FINACK，仅保留客户端 FIN
        packets.extend([syn, synack, ack, helo, ok, quitc, bye, fin])
    wrpcap(str(out_path), packets)
    return str(out_path)