#!/usr/bin/env python
from pathlib import Path

from scapy.all import Ether, IP, TCP, Raw, wrpcap

PROTO = "tls"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "tls_handshake_simplified.pcap"
    packets = []
    base_ports = [44431, 44432, 44433, 44434]
    for i, sport in enumerate(base_ports):
        src = f"192.168.0.{80+i}"
        # 三次握手
        syn = Ether() / IP(src=src, dst="192.168.0.1") / TCP(sport=sport, dport=443, flags="S", seq=1000 + i)
        synack = Ether() / IP(src="192.168.0.1", dst=src) / TCP(sport=443, dport=sport, flags="SA", seq=2000 + i, ack=1001 + i)
        ack = Ether() / IP(src=src, dst="192.168.0.1") / TCP(sport=sport, dport=443, flags="A", seq=1001 + i, ack=2001 + i)
        # 简化 TLS 交换：CH/SH、CKE/FIN（占位 Raw），保证每会话 8 包
        ch = Ether() / IP(src=src, dst="192.168.0.1") / TCP(sport=sport, dport=443, flags="PA", seq=1001 + i, ack=2001 + i) / Raw(load=b"TLS ClientHello")
        sh = Ether() / IP(src="192.168.0.1", dst=src) / TCP(sport=443, dport=sport, flags="PA", seq=2001 + i, ack=1001 + i) / Raw(load=b"TLS ServerHello")
        cke = Ether() / IP(src=src, dst="192.168.0.1") / TCP(sport=sport, dport=443, flags="PA", seq=1002 + i, ack=2002 + i) / Raw(load=b"TLS ClientKeyExchange")
        sf = Ether() / IP(src="192.168.0.1", dst=src) / TCP(sport=443, dport=sport, flags="PA", seq=2002 + i, ack=1002 + i) / Raw(load=b"TLS ServerFinished")
        # 关闭：仅客户端 FIN，使每会话恰好 8 包
        fin = Ether() / IP(src=src, dst="192.168.0.1") / TCP(sport=sport, dport=443, flags="FA", seq=1003 + i, ack=2003 + i)
        packets.extend([syn, synack, ack, ch, sh, cke, sf, fin])
    wrpcap(str(out_path), packets)
    return str(out_path)