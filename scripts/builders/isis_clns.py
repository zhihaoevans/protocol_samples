#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, Raw, wrpcap

PROTO = "isis_clns"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "isis_clns_ether.pcap"
    packets = []
    # IS-IS CLNS 以太类型常见为 0xFEFE，这里做占位帧；4×4×2=32 包
    for i in range(4):
        for j in range(4):
            p1 = Ether(type=0xFEFE) / Raw(load=b"ISIS_PDU_" + bytes([i, j]))
            p2 = Ether(type=0xFEFE) / Raw(load=b"ISIS_ACK_" + bytes([i, j]))
            packets.extend([p1, p2])
    wrpcap(str(out_path), packets)
    return str(out_path)