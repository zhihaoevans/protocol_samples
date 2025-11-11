#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, UDP, Raw, wrpcap
try:
    from scapy.layers.inet import GRE
except Exception:
    GRE = None

PROTO = "gre"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "gre_tunneled_udp.pcap"
    packets = []
    flows = [
        ("192.168.0.30", "192.168.0.1"),
        ("192.168.0.31", "192.168.0.1"),
        ("192.168.0.32", "192.168.0.1"),
        ("192.168.0.33", "192.168.0.1"),
    ]
    for i, (src, dst) in enumerate(flows):
        for j in range(4):
            inner = IP(src=src, dst=dst) / UDP(sport=40000 + i, dport=40010) / Raw(load=b"inner-" + bytes([j]))
            if GRE:
                fwd = Ether() / IP(src=src, dst=dst) / GRE() / inner
                rev = Ether() / IP(src=dst, dst=src) / GRE() / (IP(src=dst, dst=src) / UDP(sport=40010, dport=40000 + i) / Raw(load=b"resp-" + bytes([j])))
            else:
                # 回退：使用 IP(proto=47) 代表 GRE
                fwd = Ether() / IP(src=src, dst=dst, proto=47) / inner
                rev = Ether() / IP(src=dst, dst=src, proto=47) / (IP(src=dst, dst=src) / UDP(sport=40010, dport=40000 + i) / Raw(load=b"resp-" + bytes([j])))
            packets.extend([fwd, rev])
    wrpcap(str(out_path), packets)
    return str(out_path)