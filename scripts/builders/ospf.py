#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, wrpcap
try:
    from scapy.layers.ospf import OSPF_Hdr, OSPF_Hello
except Exception:
    OSPF_Hdr = None
    OSPF_Hello = None

PROTO = "ospf"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "ospf_hello.pcap"
    packets = []
    for i in range(4):
        src = f"192.168.0.{20+i}"
        for j in range(4):
            if OSPF_Hdr and OSPF_Hello:
                hello1 = Ether() / IP(src=src, dst="192.168.0.1", proto=89) / OSPF_Hdr(type=1) / OSPF_Hello(mask="255.255.255.0")
                hello2 = Ether() / IP(src="192.168.0.1", dst=src, proto=89) / OSPF_Hdr(type=1) / OSPF_Hello(mask="255.255.255.0")
            else:
                # 回退：仅 IP(proto=89) 的占位负载，保持双向
                hello1 = Ether() / IP(src=src, dst="192.168.0.1", proto=89)
                hello2 = Ether() / IP(src="192.168.0.1", dst=src, proto=89)
            packets.extend([hello1, hello2])
    wrpcap(str(out_path), packets)
    return str(out_path)