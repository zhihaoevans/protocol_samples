#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, UDP, Raw, wrpcap

PROTO = "tftp"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "tftp_rrq_multi.pcap"
    packets = []
    base_sports = [12369, 12370, 12371, 12372]
    for i, sport in enumerate(base_sports):
        src = f"192.168.0.{10+i}"
        # 每会话仅数据/应答 4 轮（DATA#1~4 与 ACK），保证每会话 8 包
        # 服务器数据端口（简化为 6969+i）
        server_dport = 6969 + i
        for blk in range(1, 5):
            data = b"\x00\x03" + blk.to_bytes(2, "big") + (b"DATA" + bytes([i, blk]))
            dpk = Ether() / IP(src="192.168.0.1", dst=src) / UDP(sport=server_dport, dport=sport) / Raw(load=data)
            ack = b"\x00\x04" + blk.to_bytes(2, "big")
            ackpk = Ether() / IP(src=src, dst="192.168.0.1") / UDP(sport=sport, dport=server_dport) / Raw(load=ack)
            packets.extend([dpk, ackpk])
    wrpcap(str(out_path), packets)
    return str(out_path)