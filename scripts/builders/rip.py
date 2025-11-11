#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, UDP, wrpcap, Raw
try:
    from scapy.contrib.rip import RIP, RIPEntry
except Exception:
    RIP = None
    RIPEntry = None

PROTO = "rip"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "rip_v2.pcap"
    packets = []
    for i in range(4):
        src = f"192.168.0.{30+i}"
        sport = 520 + i
        for j in range(4):
            if RIP and RIPEntry:
                req = Ether() / IP(src=src, dst="192.168.0.1") / UDP(sport=sport, dport=520) / RIP(cmd=1)
                resp = Ether() / IP(src="192.168.0.1", dst=src) / UDP(sport=520, dport=sport) / RIP(cmd=2) / RIPEntry(addr="10.0.%d.0" % j, mask="255.255.255.0", metric=1)
            else:
                req = Ether() / IP(src=src, dst="192.168.0.1") / UDP(sport=sport, dport=520) / Raw(load=b"RIP-REQ")
                resp = Ether() / IP(src="192.168.0.1", dst=src) / UDP(sport=520, dport=sport) / Raw(load=b"RIP-RESP")
            packets.extend([req, resp])
    wrpcap(str(out_path), packets)
    return str(out_path)