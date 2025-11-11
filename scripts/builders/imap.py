#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, TCP, Raw, wrpcap

PROTO = "imap"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "imap_multi_sessions.pcap"
    packets = []
    base_ports = [40143, 40144, 40145, 40146]
    for i, sport in enumerate(base_ports):
        src = f"192.168.0.{10+i}"
        # 三次握手
        syn = Ether() / IP(src=src, dst="192.168.0.1") / TCP(sport=sport, dport=143, flags="S", seq=1000 + i)
        synack = Ether() / IP(src="192.168.0.1", dst=src) / TCP(sport=143, dport=sport, flags="SA", seq=2000 + i, ack=1001 + i)
        ack = Ether() / IP(src=src, dst="192.168.0.1") / TCP(sport=sport, dport=143, flags="A", seq=1001 + i, ack=2001 + i)
        # 精简命令/响应：仅 LOGIN/OK
        login_cmd = f"A001 LOGIN user{i} pass{i}\r\n".encode()
        login = Ether() / IP(src=src, dst="192.168.0.1") / TCP(sport=sport, dport=143, flags="PA", seq=1001 + i, ack=2001 + i) / Raw(load=login_cmd)
        ok = Ether() / IP(src="192.168.0.1", dst=src) / TCP(sport=143, dport=sport, flags="PA", seq=2001 + i, ack=1001 + i) / Raw(load=b"A001 OK\r\n")
        # 前两会话增加 NOOP/OK，以使总包数达 32（9+9+7+7）
        extra = []
        if i < 2:
            noop = Ether() / IP(src=src, dst="192.168.0.1") / TCP(sport=sport, dport=143, flags="PA", seq=1002 + i, ack=2002 + i) / Raw(load=b"A002 NOOP\r\n")
            ok2 = Ether() / IP(src="192.168.0.1", dst=src) / TCP(sport=143, dport=sport, flags="PA", seq=2002 + i, ack=1002 + i) / Raw(load=b"A002 OK\r\n")
            extra = [noop, ok2]
        # 关闭
        fin = Ether() / IP(src=src, dst="192.168.0.1") / TCP(sport=sport, dport=143, flags="FA", seq=1002 + i, ack=2002 + i)
        finack = Ether() / IP(src="192.168.0.1", dst=src) / TCP(sport=143, dport=sport, flags="FA", seq=2002 + i, ack=1003 + i)
        packets.extend([syn, synack, ack, login, ok] + extra + [fin, finack])
    wrpcap(str(out_path), packets)
    return str(out_path)