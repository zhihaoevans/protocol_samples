#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, wrpcap

PROTO = "dhcp"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "dhcp_v4_lease.pcap"

    packets = []
    # 4 个会话，每会话 8 包：DORA(4) + Renew(2) + Release/Ack(2)
    for i in range(4):
        mac = bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x01 + i])
        chaddr = mac
        client_ip = f"192.168.0.{10+i}"
        xid = 0x01020000 + i

        # Discover
        discover = (
            Ether(src="02:00:00:00:00:%02x" % (1 + i), dst="ff:ff:ff:ff:ff:ff")
            / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / BOOTP(chaddr=chaddr, xid=xid, flags=0x8000)
            / DHCP(options=[("message-type", "discover"), "end"])
        )
        # Offer
        offer = (
            Ether(src="02:00:00:00:00:02", dst="ff:ff:ff:ff:ff:ff")
            / IP(src="192.168.0.1", dst="255.255.255.255")
            / UDP(sport=67, dport=68)
            / BOOTP(chaddr=chaddr, xid=xid, yiaddr=client_ip, siaddr="192.168.0.1")
            / DHCP(options=[("message-type", "offer"), ("server_id", "192.168.0.1"), ("lease_time", 3600), "end"])
        )
        # Request
        request = (
            Ether(src="02:00:00:00:00:%02x" % (1 + i), dst="ff:ff:ff:ff:ff:ff")
            / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / BOOTP(chaddr=chaddr, xid=xid)
            / DHCP(options=[("message-type", "request"), ("server_id", "192.168.0.1"), ("requested_addr", client_ip), "end"])
        )
        # Ack
        ack = (
            Ether(src="02:00:00:00:00:02", dst="ff:ff:ff:ff:ff:ff")
            / IP(src="192.168.0.1", dst="255.255.255.255")
            / UDP(sport=67, dport=68)
            / BOOTP(chaddr=chaddr, xid=xid, yiaddr=client_ip, siaddr="192.168.0.1")
            / DHCP(options=[("message-type", "ack"), ("server_id", "192.168.0.1"), ("lease_time", 3600), "end"])
        )

        # Renew Request/Ack（客户端从已分配地址发起）
        renew_req = (
            Ether(src="02:00:00:00:00:%02x" % (1 + i), dst="ff:ff:ff:ff:ff:ff")
            / IP(src=client_ip, dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / BOOTP(chaddr=chaddr, xid=xid + 1)
            / DHCP(options=[("message-type", "request"), ("server_id", "192.168.0.1"), ("requested_addr", client_ip), "end"])
        )
        renew_ack = (
            Ether(src="02:00:00:00:00:02", dst="ff:ff:ff:ff:ff:ff")
            / IP(src="192.168.0.1", dst="255.255.255.255")
            / UDP(sport=67, dport=68)
            / BOOTP(chaddr=chaddr, xid=xid + 1, yiaddr=client_ip, siaddr="192.168.0.1")
            / DHCP(options=[("message-type", "ack"), ("server_id", "192.168.0.1"), ("lease_time", 3600), "end"])
        )

        # Release + Ack（为满足双向与包数要求，这里简化为服务器回送 ACK）
        release = (
            Ether(src="02:00:00:00:00:%02x" % (1 + i), dst="ff:ff:ff:ff:ff:ff")
            / IP(src=client_ip, dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / BOOTP(chaddr=chaddr, xid=xid + 2)
            / DHCP(options=[("message-type", "release"), ("server_id", "192.168.0.1"), ("ciaddr", client_ip), "end"])
        )
        release_ack = (
            Ether(src="02:00:00:00:00:02", dst="ff:ff:ff:ff:ff:ff")
            / IP(src="192.168.0.1", dst="255.255.255.255")
            / UDP(sport=67, dport=68)
            / BOOTP(chaddr=chaddr, xid=xid + 2, yiaddr="0.0.0.0", siaddr="192.168.0.1")
            / DHCP(options=[("message-type", "ack"), ("server_id", "192.168.0.1"), "end"])
        )

        packets.extend([discover, offer, request, ack, renew_req, renew_ack, release, release_ack])

    wrpcap(str(out_path), packets)
    return str(out_path)