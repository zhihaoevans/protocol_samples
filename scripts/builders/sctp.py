#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, Raw, wrpcap

PROTO = "sctp"

try:
    from scapy.layers.inet import SCTP
except Exception:
    SCTP = None


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "sctp_control_data.pcap"
    packets = []

    # 若 SCTP 不可用则回退为 IP 协议号 132 + Raw；4 会话 × 4 轮 × 双向
    for i in range(4):
        a = f"172.16.{i}.10"
        b = f"172.16.{i}.1"
        for j in range(4):
            if SCTP:
                fwd = Ether() / IP(src=a, dst=b) / SCTP() / Raw(load=b"SCTP_DATA_" + bytes([i, j]))
                rev = Ether() / IP(src=b, dst=a) / SCTP() / Raw(load=b"SCTP_ACK_" + bytes([i, j]))
            else:
                fwd = Ether() / IP(src=a, dst=b, proto=132) / Raw(load=b"SCTP_DATA_" + bytes([i, j]))
                rev = Ether() / IP(src=b, dst=a, proto=132) / Raw(load=b"SCTP_ACK_" + bytes([i, j]))
            packets.extend([fwd, rev])

    wrpcap(str(out_path), packets)
    return str(out_path)