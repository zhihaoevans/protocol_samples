#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, TCP, Raw, wrpcap

PROTO = "ssh"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "ssh_tcp22.pcap"
    packets = []
    # SSH 使用 TCP 22，占位版本交换/密钥协商；4 会话 × 4 轮 × 双向 = 32 包
    for i in range(4):
        src = f"198.18.{i}.2"
        sport = 55030 + i
        for j in range(4):
            cli = Ether() / IP(src=src, dst=f"198.18.{i}.1") / TCP(sport=sport, dport=22, flags="PA") / Raw(load=b"SSH_CLI_" + bytes([i, j]))
            srv = Ether() / IP(src=f"198.18.{i}.1", dst=src) / TCP(sport=22, dport=sport, flags="PA") / Raw(load=b"SSH_SRV_" + bytes([i, j]))
            packets.extend([cli, srv])
    wrpcap(str(out_path), packets)
    return str(out_path)