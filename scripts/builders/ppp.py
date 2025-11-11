#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, Raw, wrpcap

PROTO = "ppp"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "ppp_placeholder.pcap"
    packets = []
    # 使用 PPPoE Session EtherType 0x8864 承载 Raw（PPP 占位）
    devices = [
        ("02:00:00:00:20:01", "02:00:00:00:ff:10"),
        ("02:00:00:00:20:02", "02:00:00:00:ff:10"),
        ("02:00:00:00:20:03", "02:00:00:00:ff:10"),
        ("02:00:00:00:20:04", "02:00:00:00:ff:10"),
    ]
    for i, (mac_cli, mac_srv) in enumerate(devices):
        for j in range(4):
            req = Ether(src=mac_cli, dst=mac_srv, type=0x8864) / Raw(load=b"PPP_LCP_NCP_REQ_" + bytes([i, j]))
            rep = Ether(src=mac_srv, dst=mac_cli, type=0x8864) / Raw(load=b"PPP_LCP_NCP_ACK_" + bytes([i, j]))
            packets.extend([req, rep])
    wrpcap(str(out_path), packets)
    return str(out_path)