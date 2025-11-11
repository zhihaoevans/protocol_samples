#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, TCP, Raw, wrpcap
import struct

PROTO = "tacacs"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "tacacs_tcp49.pcap"
    packets = []
    # TACACS+ 使用 TCP 49，添加最小可识别的 12 字节头（version/type/seq/flags/session_id/length），
    # 便于 tshark 解码；4 会话 × 4 轮 × 双向 = 32 包
    for i in range(4):
        src = f"192.0.2.{10+i}"
        sport = 55010 + i
        for j in range(4):
            # 构造最小 TACACS+ 头（大端）：version(0x0C), type(0x01 request / 0x02 response), seq_no, flags(0x00),
            # session_id(4B), length(4B)。随后的负载用零填充。
            version = 0x0C
            seq_no = j + 1
            flags = 0x00
            session_id = 0x12340000 + (i << 8) + j
            body_len = 8
            req_hdr = struct.pack("!BBBBII", version, 0x01, seq_no, flags, session_id, body_len)
            resp_hdr = struct.pack("!BBBBII", version, 0x02, seq_no, flags, session_id, body_len)
            req_body = b"\x00" * body_len
            resp_body = b"\x00" * body_len
            req = Ether() / IP(src=src, dst="192.0.2.1") / TCP(sport=sport, dport=49, flags="PA") / Raw(load=req_hdr + req_body)
            resp = Ether() / IP(src="192.0.2.1", dst=src) / TCP(sport=49, dport=sport, flags="PA") / Raw(load=resp_hdr + resp_body)
            packets.extend([req, resp])
    wrpcap(str(out_path), packets)
    return str(out_path)