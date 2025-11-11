#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, UDP, Raw, wrpcap

PROTO = "rtp"

try:
    from scapy.contrib.rtp import RTP, RTCP
except Exception:
    RTP = None
    RTCP = None


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "rtp_rtcp.pcap"
    packets = []
    base_ports = [16384, 16386, 16388, 16390]
    for i, rtp_port in enumerate(base_ports):
        for j in range(4):
            seq = 1 + j
            ts = 1000 + j * 160
            # RTP 正向
            if RTP:
                rtp_f = Ether() / IP(src=f"192.168.0.{10+i}", dst="192.168.0.1") / UDP(sport=rtp_port, dport=rtp_port) / RTP(version=2, payload_type=0, sequence=seq, timestamp=ts, sourcesync=0xDEADBEEF) / Raw(load=b"\x7f" * 160)
            else:
                rtp_hdr = b"\x80\x00" + seq.to_bytes(2, "big") + ts.to_bytes(4, "big") + (0xDEADBEEF).to_bytes(4, "big")
                rtp_f = Ether() / IP(src=f"192.168.0.{10+i}", dst="192.168.0.1") / UDP(sport=rtp_port, dport=rtp_port) / Raw(load=rtp_hdr + b"\x7f" * 160)
            # RTP 反向
            if RTP:
                rtp_r = Ether() / IP(src="192.168.0.1", dst=f"192.168.0.{10+i}") / UDP(sport=rtp_port, dport=rtp_port) / RTP(version=2, payload_type=0, sequence=seq, timestamp=ts, sourcesync=0xCAFEBABE) / Raw(load=b"\x7f" * 160)
            else:
                rtp_hdr_r = b"\x80\x00" + seq.to_bytes(2, "big") + ts.to_bytes(4, "big") + (0xCAFEBABE).to_bytes(4, "big")
                rtp_r = Ether() / IP(src="192.168.0.1", dst=f"192.168.0.{10+i}") / UDP(sport=rtp_port, dport=rtp_port) / Raw(load=rtp_hdr_r + b"\x7f" * 160)
            packets.extend([rtp_f, rtp_r])
    wrpcap(str(out_path), packets)
    return str(out_path)