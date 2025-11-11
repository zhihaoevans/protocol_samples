#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IPv6, UDP, wrpcap
try:
    from scapy.layers.dhcp6 import DHCP6_Solicit, DHCP6_Advertise, DHCP6_Request, DHCP6_Reply
except Exception:
    DHCP6_Solicit = None
    DHCP6_Advertise = None
    DHCP6_Request = None
    DHCP6_Reply = None

PROTO = "dhcpv6"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "dhcp_v6_lease.pcap"
    packets = []
    for i in range(4):
        src = f"fe80::10{i}"
        trid = 0x200000 + i
        if all([DHCP6_Solicit, DHCP6_Advertise, DHCP6_Request, DHCP6_Reply]):
            # 基本四步：Solicit/Advertise/Request/Reply
            sol = Ether() / IPv6(src=src, dst="ff02::1:2") / UDP(sport=546, dport=547) / DHCP6_Solicit(trid=trid)
            adv = Ether() / IPv6(src="fe80::1", dst=src) / UDP(sport=547, dport=546) / DHCP6_Advertise(trid=trid)
            req = Ether() / IPv6(src=src, dst="fe80::1") / UDP(sport=546, dport=547) / DHCP6_Request(trid=trid + 1)
            rep = Ether() / IPv6(src="fe80::1", dst=src) / UDP(sport=547, dport=546) / DHCP6_Reply(trid=trid + 1)
            # 再来一次请求/回复以达到每会话约 8 包
            req2 = Ether() / IPv6(src=src, dst="fe80::1") / UDP(sport=546, dport=547) / DHCP6_Request(trid=trid + 2)
            rep2 = Ether() / IPv6(src="fe80::1", dst=src) / UDP(sport=547, dport=546) / DHCP6_Reply(trid=trid + 2)
            req3 = Ether() / IPv6(src=src, dst="fe80::1") / UDP(sport=546, dport=547) / DHCP6_Request(trid=trid + 3)
            rep3 = Ether() / IPv6(src="fe80::1", dst=src) / UDP(sport=547, dport=546) / DHCP6_Reply(trid=trid + 3)
            packets.extend([sol, adv, req, rep, req2, rep2, req3, rep3])
        else:
            # 回退为 UDP 原始负载以保持双向样本
            sol = Ether() / IPv6(src=src, dst="ff02::1:2") / UDP(sport=546, dport=547)
            adv = Ether() / IPv6(src="fe80::1", dst=src) / UDP(sport=547, dport=546)
            req = Ether() / IPv6(src=src, dst="fe80::1") / UDP(sport=546, dport=547)
            rep = Ether() / IPv6(src="fe80::1", dst=src) / UDP(sport=547, dport=546)
            req2 = Ether() / IPv6(src=src, dst="fe80::1") / UDP(sport=546, dport=547)
            rep2 = Ether() / IPv6(src="fe80::1", dst=src) / UDP(sport=547, dport=546)
            req3 = Ether() / IPv6(src=src, dst="fe80::1") / UDP(sport=546, dport=547)
            rep3 = Ether() / IPv6(src="fe80::1", dst=src) / UDP(sport=547, dport=546)
            packets.extend([sol, adv, req, rep, req2, rep2, req3, rep3])
    wrpcap(str(out_path), packets)
    return str(out_path)