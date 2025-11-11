#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, UDP, Raw, wrpcap

PROTO = "capwap"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "capwap_ctrl_data.pcap"
    packets = []
    pairs = [
        ("192.168.0.90", "192.168.0.1"),
        ("192.168.0.91", "192.168.0.1"),
        ("192.168.0.92", "192.168.0.1"),
        ("192.168.0.93", "192.168.0.1"),
    ]
    for i, (src, dst) in enumerate(pairs):
        for j in range(2):  # 每会话两轮：控制与数据各一对，合计 4 对 = 8 包
            # 控制信道 5246
            ctrl = Ether() / IP(src=src, dst=dst) / UDP(sport=52460 + i, dport=5246) / Raw(load=b"CAPWAP_CTRL_" + bytes([i, j]))
            ctrl_resp = Ether() / IP(src=dst, dst=src) / UDP(sport=5246, dport=52460 + i) / Raw(load=b"CAPWAP_CTRL_RESP_" + bytes([i, j]))
            # 数据信道 5247
            data = Ether() / IP(src=src, dst=dst) / UDP(sport=52470 + i, dport=5247) / Raw(load=b"CAPWAP_DATA_" + bytes([i, j]))
            data_resp = Ether() / IP(src=dst, dst=src) / UDP(sport=5247, dport=52470 + i) / Raw(load=b"CAPWAP_DATA_RESP_" + bytes([i, j]))
            packets.extend([ctrl, ctrl_resp, data, data_resp])
    wrpcap(str(out_path), packets)
    return str(out_path)