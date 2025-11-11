#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, Raw, wrpcap

PROTO = "igmp"

try:
    from scapy.layers.inet import IGMP
except Exception:
    IGMP = None


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "igmp_reports.pcap"
    packets = []

    # 4 个会话，每会话 4 轮（请求/查询），总计 32 包
    groups = ["239.255.0.10", "239.255.0.11", "239.255.0.12", "239.255.0.13"]
    for i, grp in enumerate(groups):
        host = f"192.168.0.{10+i}"
        for j in range(4):
            if IGMP:
                # Membership Report（v2/通用），路由器查询模拟
                report = Ether() / IP(src=host, dst=grp) / IGMP(type=0x16, gaddr=grp)
                query = Ether() / IP(src="192.168.0.1", dst="224.0.0.1") / IGMP(type=0x11)
            else:
                report = Ether() / IP(src=host, dst=grp, proto=2) / Raw(load=b"IGMP_REPORT_" + bytes([i, j]))
                query = Ether() / IP(src="192.168.0.1", dst="224.0.0.1", proto=2) / Raw(load=b"IGMP_QUERY_" + bytes([i, j]))
            packets.extend([report, query])

    wrpcap(str(out_path), packets)
    return str(out_path)