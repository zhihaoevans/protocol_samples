#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, Raw, wrpcap

PROTO = "lacp"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "lacp_slow_proto.pcap"
    packets = []
    # 使用以太网类型 0x8809（Slow Protocols）模拟 LACPDU
    devices = [
        ("02:00:00:00:10:01", "02:00:00:00:ff:01"),
        ("02:00:00:00:10:02", "02:00:00:00:ff:01"),
        ("02:00:00:00:10:03", "02:00:00:00:ff:01"),
        ("02:00:00:00:10:04", "02:00:00:00:ff:01"),
    ]
    for i, (mac_dev, mac_sw) in enumerate(devices):
        for j in range(4):
            # Actor 信息与 Partner 信息简化负载
            req = Ether(src=mac_dev, dst=mac_sw, type=0x8809) / Raw(load=b"LACPDU_REQ_" + bytes([i, j]))
            resp = Ether(src=mac_sw, dst=mac_dev, type=0x8809) / Raw(load=b"LACPDU_RESP_" + bytes([i, j]))
            packets.extend([req, resp])
    wrpcap(str(out_path), packets)
    return str(out_path)