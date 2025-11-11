#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, UDP, Raw, wrpcap

PROTO = "sip"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "sip_invite_sdp.pcap"
    packets = []
    for i in range(4):
        src = f"192.168.0.{10+i}"
        sport = 5060 + i
        for j in range(4):
            sdp = (
                "v=0\r\n"
                f"o=- 0 0 IN IP4 {src}\r\n"
                "s=Scapy Call\r\n"
                f"c=IN IP4 {src}\r\n"
                "t=0 0\r\n"
                "m=audio 16384 RTP/AVP 0\r\n"
                "a=rtpmap:0 PCMU/8000\r\n"
            ).encode()
            call_id = f"{100000+i*100+j}@{src}"
            invite = (
                "INVITE sip:bob@example.com SIP/2.0\r\n"
                f"Via: SIP/2.0/UDP {src};branch=z9hG4bK-{i}{j}\r\n"
                "From: <sip:alice@example.com>;tag=111\r\n"
                "To: <sip:bob@example.com>\r\n"
                f"Call-ID: {call_id}\r\n"
                "CSeq: 1 INVITE\r\n"
                f"Contact: <sip:alice@{src}>\r\n"
                "Content-Type: application/sdp\r\n"
                f"Content-Length: {len(sdp)}\r\n\r\n"
            ).encode() + sdp
            ok = (
                "SIP/2.0 200 OK\r\n"
                f"Via: SIP/2.0/UDP {src};branch=z9hG4bK-{i}{j}\r\n"
                "From: <sip:alice@example.com>;tag=111\r\n"
                "To: <sip:bob@example.com>;tag=222\r\n"
                f"Call-ID: {call_id}\r\n"
                "CSeq: 1 INVITE\r\n\r\n"
            ).encode()
            req = Ether() / IP(src=src, dst="192.168.0.1") / UDP(sport=sport, dport=5060) / Raw(load=invite)
            resp = Ether() / IP(src="192.168.0.1", dst=src) / UDP(sport=5060, dport=sport) / Raw(load=ok)
            packets.extend([req, resp])
    wrpcap(str(out_path), packets)
    return str(out_path)