#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, TCP, Raw, wrpcap

PROTO = "nfs"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "nfs_tcp2049.pcap"
    packets = []
    # NFS 常见使用 TCP 2049，这里用占位的 READ/WRITE 请求/响应；4×4×2=32 包
    for i in range(4):
        src = f"172.16.{i}.2"
        sport = 55020 + i
        for j in range(4):
            op = b"READ" if j % 2 == 0 else b"WRITE"
            req = Ether() / IP(src=src, dst=f"172.16.{i}.1") / TCP(sport=sport, dport=2049, flags="PA") / Raw(load=b"NFS_" + op + b"_" + bytes([i, j]))
            resp = Ether() / IP(src=f"172.16.{i}.1", dst=src) / TCP(sport=2049, dport=sport, flags="PA") / Raw(load=b"NFS_OK_" + op + b"_" + bytes([i, j]))
            packets.extend([req, resp])
    wrpcap(str(out_path), packets)
    return str(out_path)