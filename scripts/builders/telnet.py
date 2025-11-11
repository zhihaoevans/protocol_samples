#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, TCP, Raw, wrpcap

PROTO = "telnet"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "telnet_multi_sessions.pcap"
    packets = []
    base_ports = [40230, 40231, 40232, 40233]
    for i, sport in enumerate(base_ports):
        src = f"192.168.0.{10+i}"
        # 三次握手
        syn = Ether() / IP(src=src, dst="192.168.0.1") / TCP(sport=sport, dport=23, flags="S", seq=1000 + i)
        synack = Ether() / IP(src="192.168.0.1", dst=src) / TCP(sport=23, dport=sport, flags="SA", seq=2000 + i, ack=1001 + i)
        ack = Ether() / IP(src=src, dst="192.168.0.1") / TCP(sport=sport, dport=23, flags="A", seq=1001 + i, ack=2001 + i)
        # 简化命令/响应：用户输入与提示
        login = Ether() / IP(src=src, dst="192.168.0.1") / TCP(sport=sport, dport=23, flags="PA", seq=1001 + i, ack=2001 + i) / Raw(load=b"alice\r\n")
        prompt = Ether() / IP(src="192.168.0.1", dst=src) / TCP(sport=23, dport=sport, flags="PA", seq=2001 + i, ack=1001 + i) / Raw(load=b"login: ")
        # 前两会话增加一轮交互以使总计 32 包（9+9+7+7）
        extra = []
        if i < 2:
            cmd = Ether() / IP(src=src, dst="192.168.0.1") / TCP(sport=sport, dport=23, flags="PA", seq=1002 + i, ack=2002 + i) / Raw(load=b"help\r\n")
            reply = Ether() / IP(src="192.168.0.1", dst=src) / TCP(sport=23, dport=sport, flags="PA", seq=2002 + i, ack=1002 + i) / Raw(load=b"OK\r\n")
            extra = [cmd, reply]
        # 关闭
        fin = Ether() / IP(src=src, dst="192.168.0.1") / TCP(sport=sport, dport=23, flags="FA", seq=1002 + i, ack=2002 + i)
        finack = Ether() / IP(src="192.168.0.1", dst=src) / TCP(sport=23, dport=sport, flags="FA", seq=2002 + i, ack=1003 + i)
        packets.extend([syn, synack, ack, login, prompt] + extra + [fin, finack])
    wrpcap(str(out_path), packets)
    return str(out_path)