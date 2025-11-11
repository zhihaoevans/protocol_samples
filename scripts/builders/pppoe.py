#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, Raw, wrpcap

PROTO = "pppoe"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "pppoe_discovery.pcap"
    packets = []
    # PPPoE Discovery EtherType 0x8863，占位 PADI/PADO/PADR/PADS 循环；4 会话 × 4 轮 × 双向 = 32 包
    pairs = [
        ("02:00:00:00:30:01", "02:00:00:00:ff:20"),
        ("02:00:00:00:30:02", "02:00:00:00:ff:20"),
        ("02:00:00:00:30:03", "02:00:00:00:ff:20"),
        ("02:00:00:00:30:04", "02:00:00:00:ff:20"),
    ]
    for i, (mac_cli, mac_srv) in enumerate(pairs):
        for j in range(4):
            disc_req = Ether(src=mac_cli, dst=mac_srv, type=0x8863) / Raw(load=b"PPPoE_DISC_REQ_" + bytes([i, j]))
            disc_resp = Ether(src=mac_srv, dst=mac_cli, type=0x8863) / Raw(load=b"PPPoE_DISC_RESP_" + bytes([i, j]))
            packets.extend([disc_req, disc_resp])
    wrpcap(str(out_path), packets)
    return str(out_path)