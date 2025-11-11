#!/usr/bin/env python
"""按优先级生成 PCAP（调用 scripts.generate_all 的构建器并标准化输出）。

示例：
  python tools/generators/batch_generate.py --priority 1
"""

import argparse
from pathlib import Path
from scripts.generate_all import load_builders, _standardize_and_metadata, PROTO_TO_LAYER


PRIORITY_MAP = {
    1: [
        "http", "tcp", "udp", "ipv4", "ipv6", "dns", "tls",
        "icmp", "arp"
    ],
    2: [
        "ftp", "ssh", "smtp", "pop3", "imap", "dhcp", "ntp", "snmp",
        "bgp", "ospf", "rip", "vlan"
    ],
    3: [
        "sip", "rtp", "mqtt", "coap", "modbus", "bacnet", "websocket",
        "grpc", "quic"
    ],
}


def main():
    parser = argparse.ArgumentParser(description="按优先级批量生成 PCAP")
    parser.add_argument("--priority", type=int, default=1, help="优先级 1-4")
    args = parser.parse_args()

    builders = load_builders()
    pcaps_root = Path(__file__).resolve().parents[2] / "pcaps"
    protocols_root = Path(__file__).resolve().parents[2] / "protocols"
    pcaps_root.mkdir(parents=True, exist_ok=True)
    protocols_root.mkdir(parents=True, exist_ok=True)

    targets = PRIORITY_MAP.get(args.priority, [])
    generated = []
    missing = []

    for proto in targets:
        mod = builders.get(proto)
        if not mod:
            missing.append(proto)
            continue
        try:
            out = mod.build(pcaps_root)
            std = _standardize_and_metadata(proto, Path(out), protocols_root)
            generated.append(str(std))
        except Exception as e:
            print(f"[ERROR] 生成 {proto} 失败: {e}")

    print("生成完成：")
    for g in generated:
        print(f"  - {g}")
    if missing:
        print("缺少构建器：")
        for m in sorted(set(missing)):
            print(f"  - {m}")


if __name__ == "__main__":
    main()