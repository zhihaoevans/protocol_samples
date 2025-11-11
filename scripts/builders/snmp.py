#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, UDP, Raw, wrpcap

PROTO = "snmp"

try:
    from scapy.layers.snmp import SNMP, SNMPget, SNMPvarbind
except Exception:
    SNMP = None
    SNMPget = None
    SNMPvarbind = None


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    packets = []
    # 统一使用回退：原始 GET 与响应字节，4 会话，每会话 4 次（总 32 包）
    for i in range(4):
        src = f"192.168.0.{10+i}"
        for j in range(4):
            rid = (0x12340000 + i * 0x100 + j).to_bytes(4, "big")
            get = (
                Ether()
                / IP(src=src, dst="192.168.0.1")
                / UDP(sport=54000 + i, dport=161)
                / Raw(load=b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04" + rid + b"\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00")
            )
            resp = Ether() / IP(src="192.168.0.1", dst=src) / UDP(sport=161, dport=54000 + i) / Raw(load=b"\x30\x26RESP")
            packets.extend([get, resp])
    out_path = out_dir / "snmp_get_raw.pcap"
    wrpcap(str(out_path), packets)
    return str(out_path)