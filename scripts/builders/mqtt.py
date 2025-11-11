#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, TCP, Raw, wrpcap

PROTO = "mqtt"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "mqtt_connect.pcap"
    packets = []
    base_ports = [41883, 41884, 41885, 41886]
    for i, sport in enumerate(base_ports):
        src = f"192.168.0.{10+i}"
        # TCP 握手
        syn = Ether() / IP(src=src, dst="192.168.0.1") / TCP(sport=sport, dport=1883, flags="S", seq=1000 + i)
        synack = Ether() / IP(src="192.168.0.1", dst=src) / TCP(sport=1883, dport=sport, flags="SA", seq=2000 + i, ack=1001 + i)
        ack = Ether() / IP(src=src, dst="192.168.0.1") / TCP(sport=sport, dport=1883, flags="A", seq=1001 + i, ack=2001 + i)
        # MQTT CONNECT / CONNACK（简化 Raw）
        connect = Ether() / IP(src=src, dst="192.168.0.1") / TCP(sport=sport, dport=1883, flags="PA", seq=1001 + i, ack=2001 + i) / Raw(load=b"\x10\x10\x00\x04MQTT\x04\x02\x00<\x00\x04cli" + bytes([48+i]))
        connack = Ether() / IP(src="192.168.0.1", dst=src) / TCP(sport=1883, dport=sport, flags="PA", seq=2001 + i, ack=1001 + i) / Raw(load=b"\x20\x02\x00\x00")
        # 前两会话额外增加 PINGREQ/PINGRESP 以达总 32 包（9+9+7+7）
        extra = []
        if i < 2:
            pingreq = Ether() / IP(src=src, dst="192.168.0.1") / TCP(sport=sport, dport=1883, flags="PA", seq=1002 + i, ack=2002 + i) / Raw(load=b"\xc0\x00")
            pingresp = Ether() / IP(src="192.168.0.1", dst=src) / TCP(sport=1883, dport=sport, flags="PA", seq=2002 + i, ack=1002 + i) / Raw(load=b"\xd0\x00")
            extra = [pingreq, pingresp]
        # 关闭
        fin = Ether() / IP(src=src, dst="192.168.0.1") / TCP(sport=sport, dport=1883, flags="FA", seq=1002 + i, ack=2002 + i)
        finack = Ether() / IP(src="192.168.0.1", dst=src) / TCP(sport=1883, dport=sport, flags="FA", seq=2002 + i, ack=1003 + i)
        packets.extend([syn, synack, ack, connect, connack] + extra + [fin, finack])
    wrpcap(str(out_path), packets)
    return str(out_path)