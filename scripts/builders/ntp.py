#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, UDP, Raw, wrpcap

PROTO = "ntp"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "ntp_requests.pcap"
    packets = []
    base_sports = [12345, 12346, 12347, 12348]
    for i, sport in enumerate(base_sports):
        src = f"192.168.0.{10+i}"
        for j in range(4):
            # NTP client request: LI=0, VN=3, Mode=3
            req = Ether() / IP(src=src, dst="192.168.0.1") / UDP(sport=sport, dport=123) / Raw(load=b"\x1b" + bytes([j]) + b"\x00" * 46)
            # NTP server response: LI=0, VN=3, Mode=4（简化）
            resp = Ether() / IP(src="192.168.0.1", dst=src) / UDP(sport=123, dport=sport) / Raw(load=b"\x1c" + bytes([j]) + b"\x00" * 46)
            packets.extend([req, resp])
    wrpcap(str(out_path), packets)
    return str(out_path)