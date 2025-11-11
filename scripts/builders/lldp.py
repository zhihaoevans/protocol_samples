#!/usr/bin/env python
from pathlib import Path

from scapy.all import Ether, wrpcap, Raw

PROTO = "lldp"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "lldp_frames.pcap"
    packets = []
    # 4 个设备与交换机之间的 LLDP 交互，每设备 4 轮双向，共 8 包 × 4 = 32
    devices = [
        ("02:00:00:00:10:01", "192.168.10.10"),
        ("02:00:00:00:10:02", "192.168.11.10"),
        ("02:00:00:00:10:03", "192.168.12.10"),
        ("02:00:00:00:10:04", "192.168.13.10"),
    ]
    sw_mac = "02:00:00:00:10:ff"
    # LLDP 组播目的 MAC
    dst_mcast = "01:80:c2:00:00:0e"
    for i, (mac, ip) in enumerate(devices):
        for j in range(4):
            # 设备发 LLDP（简化 Raw TLV 占位），以以太类型 0x88cc
            dev_lldp = Ether(src=mac, dst=dst_mcast, type=0x88CC) / Raw(
                load=(f"LLDP DEV{i} R{j} {ip}".encode())
            )
            # 交换机回 LLDP（同样简化）
            sw_lldp = Ether(src=sw_mac, dst=dst_mcast, type=0x88CC) / Raw(
                load=(f"LLDP SW R{j} to DEV{i}".encode())
            )
            packets.extend([dev_lldp, sw_lldp])
    wrpcap(str(out_path), packets)
    return str(out_path)