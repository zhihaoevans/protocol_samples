#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, TCP, Raw, wrpcap

PROTO = "ssh"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "ssh_tcp22.pcap"
    packets = []
    # SSH 使用 TCP 22，采用可识别的版本交换首包，便于 tshark 解码；
    # 4 会话 × 4 轮 × 双向 = 32 包
    for i in range(4):
        src = f"198.18.{i}.2"
        sport = 55030 + i
        for j in range(4):
            # SSH 标识行："SSH-2.0-...\r\n"（客户端与服务端各一帧）
            cli_banner = f"SSH-2.0-ProtoSamples-{i}-{j}\r\n".encode()
            srv_banner = f"SSH-2.0-OpenSSH_9.0-ProtoSamples-{i}-{j}\r\n".encode()
            cli = Ether() / IP(src=src, dst=f"198.18.{i}.1") / TCP(sport=sport, dport=22, flags="PA") / Raw(load=cli_banner)
            srv = Ether() / IP(src=f"198.18.{i}.1", dst=src) / TCP(sport=22, dport=sport, flags="PA") / Raw(load=srv_banner)
            packets.extend([cli, srv])
    wrpcap(str(out_path), packets)
    return str(out_path)