#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, TCP, Raw, wrpcap

PROTO = "tacacs"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "tacacs_tcp49.pcap"
    packets = []
    # TACACS+ 使用 TCP 49，占位认证请求/响应；4 会话 × 4 轮 × 双向 = 32 包
    for i in range(4):
        src = f"192.0.2.{10+i}"
        sport = 55010 + i
        for j in range(4):
            req = Ether() / IP(src=src, dst="192.0.2.1") / TCP(sport=sport, dport=49, flags="PA") / Raw(load=b"TAC_REQ_" + bytes([i, j]))
            resp = Ether() / IP(src="192.0.2.1", dst=src) / TCP(sport=49, dport=sport, flags="PA") / Raw(load=b"TAC_RESP_" + bytes([i, j]))
            packets.extend([req, resp])
    wrpcap(str(out_path), packets)
    return str(out_path)