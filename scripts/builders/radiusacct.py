#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, UDP, Raw, wrpcap

PROTO = "radiusacct"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "radius_accounting.pcap"
    packets = []
    # RADIUS Accounting 使用 UDP 1813，4 会话 × 4 轮 × 双向 = 32 包
    for i in range(4):
        user_ip = f"192.168.50.{10+i}"
        sport = 55100 + i
        for j in range(4):
            acc_req = Ether() / IP(src=user_ip, dst="192.168.50.1") / UDP(sport=sport, dport=1813) / Raw(load=b"ACCT_REQ_" + bytes([i, j]))
            acc_resp = Ether() / IP(src="192.168.50.1", dst=user_ip) / UDP(sport=1813, dport=sport) / Raw(load=b"ACCT_RESP_" + bytes([i, j]))
            packets.extend([acc_req, acc_resp])
    wrpcap(str(out_path), packets)
    return str(out_path)