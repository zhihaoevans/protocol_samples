#!/usr/bin/env python
from pathlib import Path
from scapy.all import Ether, IP, UDP, Raw, wrpcap

PROTO = "ssdp"


def build(output_root: Path) -> str:
    out_dir = output_root / PROTO
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "ssdp_msearch.pcap"
    packets = []
    sts = ["ssdp:all", "upnp:rootdevice", "urn:schemas-upnp-org:device:MediaServer:1", "urn:schemas-upnp-org:service:ContentDirectory:1"]
    for i, st in enumerate(sts):
        for j in range(4):
            msearch = (
                Ether(src="02:00:00:00:00:01", dst="01:00:5e:7f:ff:fa")
                / IP(src=f"192.168.0.{10+i}", dst="239.255.255.250")
                / UDP(sport=1900 + i + 1, dport=1900)
                / Raw(load=(
                    f"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: {st}\r\n\r\n".encode()
                ))
            )
            resp = (
                Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
                / IP(src="192.168.0.1", dst=f"192.168.0.{10+i}")
                / UDP(sport=1900, dport=1900 + i + 1)
                / Raw(load=(
                    b"HTTP/1.1 200 OK\r\nST: " + st.encode() + b"\r\nUSN: uuid:device-1234::" + st.encode() + b"\r\n\r\n"
                ))
            )
            packets.extend([msearch, resp])
    wrpcap(str(out_path), packets)
    return str(out_path)