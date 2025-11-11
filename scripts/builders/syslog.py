#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, UDP, Raw, wrpcap

PROTO = "syslog"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "syslog_udp.pcap"
    packets = []
    for i in range(4):
        src = f"192.168.0.{10+i}"
        for j in range(4):
            msg = f"<34>1 2025-01-01T00:00:{j:02d}Z host{i} app 123 - - Test {j}".encode()
            client = Ether() / IP(src=src, dst="192.168.0.1") / UDP(sport=55000 + i, dport=514) / Raw(load=msg)
            # 伪造服务端回送确认（非标准，但满足双向要求）
            server = Ether() / IP(src="192.168.0.1", dst=src) / UDP(sport=514, dport=55000 + i) / Raw(load=b"OK")
            packets.extend([client, server])
    wrpcap(str(out_path), packets)
    return str(out_path)