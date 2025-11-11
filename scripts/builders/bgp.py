#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, TCP, wrpcap, Raw
try:
    from scapy.contrib.bgp import BGPHeader, BGPOpen, BGPKeepAlive
except Exception:
    BGPHeader = None
    BGPOpen = None
    BGPKeepAlive = None

PROTO = "bgp"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "bgp_open_keepalive.pcap"
    packets = []
    base_ports = [40179, 40180, 40181, 40182]
    for i, sport in enumerate(base_ports):
        src = f"192.168.0.{40+i}"
        # 三次握手
        syn = Ether() / IP(src=src, dst="192.168.0.1") / TCP(sport=sport, dport=179, flags="S", seq=1000 + i)
        synack = Ether() / IP(src="192.168.0.1", dst=src) / TCP(sport=179, dport=sport, flags="SA", seq=2000 + i, ack=1001 + i)
        ack = Ether() / IP(src=src, dst="192.168.0.1") / TCP(sport=sport, dport=179, flags="A", seq=1001 + i, ack=2001 + i)
        # Open 与 KeepAlive 交换
        if BGPHeader:
            # 为避免字段不兼容导致异常，这里仅用 BGPHeader 与原始负载占位
            open_cli = Ether() / IP(src=src, dst="192.168.0.1") / TCP(sport=sport, dport=179, flags="PA", seq=1001 + i, ack=2001 + i) / BGPHeader(type=1) / Raw(load=b"BGP-OPEN")
            open_srv = Ether() / IP(src="192.168.0.1", dst=src) / TCP(sport=179, dport=sport, flags="PA", seq=2001 + i, ack=1001 + i) / BGPHeader(type=1) / Raw(load=b"BGP-OPEN")
            ka_cli = Ether() / IP(src=src, dst="192.168.0.1") / TCP(sport=sport, dport=179, flags="PA", seq=1002 + i, ack=2002 + i) / BGPHeader(type=4) / Raw(load=b"BGP-KA")
            ka_srv = Ether() / IP(src="192.168.0.1", dst=src) / TCP(sport=179, dport=sport, flags="PA", seq=2002 + i, ack=1002 + i) / BGPHeader(type=4) / Raw(load=b"BGP-KA")
        else:
            open_cli = Ether() / IP(src=src, dst="192.168.0.1") / TCP(sport=sport, dport=179, flags="PA", seq=1001 + i, ack=2001 + i) / Raw(load=b"BGP-OPEN")
            open_srv = Ether() / IP(src="192.168.0.1", dst=src) / TCP(sport=179, dport=sport, flags="PA", seq=2001 + i, ack=1001 + i) / Raw(load=b"BGP-OPEN")
            ka_cli = Ether() / IP(src=src, dst="192.168.0.1") / TCP(sport=sport, dport=179, flags="PA", seq=1002 + i, ack=2002 + i) / Raw(load=b"BGP-KA")
            ka_srv = Ether() / IP(src="192.168.0.1", dst=src) / TCP(sport=179, dport=sport, flags="PA", seq=2002 + i, ack=1002 + i) / Raw(load=b"BGP-KA")
        # 关闭
        fin = Ether() / IP(src=src, dst="192.168.0.1") / TCP(sport=sport, dport=179, flags="FA", seq=1003 + i, ack=2003 + i)
        # 为保证每会话 8 包，移除服务器 FINACK，仅保留客户端 FIN
        packets.extend([syn, synack, ack, open_cli, open_srv, ka_cli, ka_srv, fin])
    wrpcap(str(out_path), packets)
    return str(out_path)