#!/usr/bin/env python
from pathlib import Path

from scapy.all import Ether, wrpcap, Raw

PROTO = "stp"

try:
    from scapy.layers.l2 import LLC
except Exception:
    LLC = None


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "stp_bpdu.pcap"
    packets = []
    # 4 个设备与交换机之间的 BPDU 交互，每设备 4 轮双向，共 8 包 × 4 = 32
    devices = [
        ("02:00:00:00:20:01"),
        ("02:00:00:00:20:02"),
        ("02:00:00:00:20:03"),
        ("02:00:00:00:20:04"),
    ]
    sw_mac = "02:00:00:00:20:ff"
    # STP BPDU 使用组播目的 MAC 01:80:c2:00:00:00
    dst_bpdu = "01:80:c2:00:00:00"
    for i, mac in enumerate(devices):
        for j in range(4):
            if LLC:
                dev_bpdu = Ether(src=mac, dst=dst_bpdu) / LLC(dsap=0x42, ssap=0x42, ctrl=0x03) / Raw(load=b"BPDU-DEV-%d-%d" % (i, j))
                sw_bpdu = Ether(src=sw_mac, dst=dst_bpdu) / LLC(dsap=0x42, ssap=0x42, ctrl=0x03) / Raw(load=b"BPDU-SW-%d-%d" % (i, j))
            else:
                # 回退：不使用 LLC，直接以 Raw 占位
                dev_bpdu = Ether(src=mac, dst=dst_bpdu) / Raw(load=b"BPDU-DEV-%d-%d" % (i, j))
                sw_bpdu = Ether(src=sw_mac, dst=dst_bpdu) / Raw(load=b"BPDU-SW-%d-%d" % (i, j))
            packets.extend([dev_bpdu, sw_bpdu])
    wrpcap(str(out_path), packets)
    return str(out_path)