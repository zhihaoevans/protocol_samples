#!/usr/bin/env python
from scapy.all import rdpcap
import pyshark


def validate_pcap(pcap_path: str, expected_protocol: str):
    """
    验证 PCAP 文件
    返回: (is_valid, validation_report)
    """
    checks = {
        "file_readable": False,
        "packets_exist": False,
        "protocol_correct": False,
        "no_corruption": False,
    }

    try:
        packets = rdpcap(pcap_path)
        checks["file_readable"] = True
        checks["packets_exist"] = len(packets) > 0

        # 使用 tshark 验证协议（pyshark）
        cap = pyshark.FileCapture(pcap_path)
        for pkt in cap:
            if expected_protocol.upper() in str(pkt.layers):
                checks["protocol_correct"] = True
                break
        cap.close()

        checks["no_corruption"] = True

    except Exception as e:
        return False, {"error": str(e), "checks": checks}

    is_valid = all(checks.values())
    return is_valid, checks


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="验证单个 PCAP")
    parser.add_argument("pcap", help="pcap 文件路径")
    parser.add_argument("protocol", help="预期协议名")
    args = parser.parse_args()
    ok, report = validate_pcap(args.pcap, args.protocol)
    print("VALID" if ok else "INVALID", report)