#!/usr/bin/env python
"""按 Scapy 层枚举调度各协议构建脚本，生成 pcap/pcapng 样本。

用法：
  - 列出可用 Scapy 层：
      python scripts/generate_all.py --list-layers
  - 列出可用构建器：
      python scripts/generate_all.py --list-builders
  - 生成（按层枚举驱动，默认模式）：
      python scripts/generate_all.py
  - 仅生成所有已知构建器：
      python scripts/generate_all.py --mode known
  - 指定输出根目录：
      python scripts/generate_all.py --pcaps-root /path/to/pcaps
"""

import argparse
import json
import importlib
import sys
from pathlib import Path
from typing import Dict, List, Set

# 确保项目根目录在 sys.path 中，便于以包形式导入 scripts.builders
BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from scapy.packet import Packet


def list_scapy_layers() -> List[str]:
    names: Set[str] = set()

    def safe_name(subcls) -> str:
        n = getattr(subcls, "name", None)
        if isinstance(n, str) and n:
            return n
        return getattr(subcls, "__name__", str(subcls))

    def walk(cls):
        try:
            subs = cls.__subclasses__()
        except Exception:
            subs = []
        for sub in subs:
            name = safe_name(sub)
            if isinstance(name, str) and name and not name.startswith("_"):
                names.add(name)
            walk(sub)

    walk(Packet)
    return sorted(names)


def load_builders() -> Dict[str, object]:
    pkg = importlib.import_module("scripts.builders")
    pkg_path = Path(pkg.__file__).parent
    builders: Dict[str, object] = {}
    for py in pkg_path.glob("*.py"):
        if py.name == "__init__.py":
            continue
        mod_name = f"scripts.builders.{py.stem}"
        mod = importlib.import_module(mod_name)
        proto = getattr(mod, "PROTO", py.stem)
        builders[proto.lower()] = mod
    return builders


# Scapy 层名到构建器协议名的常用映射（可扩展）
LAYER_TO_PROTO = {
    "ARP": "arp",
    "IP": "ipv4",
    "IPv6": "ipv6",
    "TCP": "tcp",
    "UDP": "udp",
    "DNS": "dns",
    "BOOTP": "dhcp",
    "DHCP": "dhcp",
    "ICMP": "icmp",
    "ICMPv6": "icmpv6",
    "SNMP": "snmp",
    "NTP": "ntp",
    "SSDP": "ssdp",
    "RTP": "rtp",
    "RTCP": "rtp",
    "SIP": "sip",
    "TFTP": "tftp",
    "SMTP": "smtp",
    "IMAP": "imap",
    "POP": "pop3",
    "POP3": "pop3",
    "MQTT": "mqtt",
    "MDNS": "mdns",
}


def main():
    parser = argparse.ArgumentParser(description="按 Scapy 层枚举调用各协议构建器")
    parser.add_argument("--list-layers", action="store_true", help="仅列出可用 Scapy 层")
    parser.add_argument("--list-builders", action="store_true", help="仅列出可用构建器")
    parser.add_argument("--mode", choices=["layers", "known"], default="layers", help="驱动模式：按层枚举或仅执行已知构建器")
    parser.add_argument("--pcaps-root", type=Path, default=(Path(__file__).resolve().parents[1] / "pcaps"), help="输出根目录")
    parser.add_argument("--progress-file", type=Path, default=None, help="增量模式下记录已生成协议的临时文件")
    parser.add_argument("--incremental", action="store_true", help="仅生成进度文件中未记录的协议，并将新生成的协议追加到进度文件")
    args = parser.parse_args()

    builders = load_builders()

    if args.list_builders:
        for k in sorted(builders.keys()):
            print(k)
        return

    layers = list_scapy_layers()
    if args.list_layers:
        for l in layers:
            print(l)
        return

    args.pcaps_root.mkdir(parents=True, exist_ok=True)
    generated: List[str] = []
    missing: List[str] = []

    if args.mode == "known":
        # 仅执行所有已知构建器（支持增量跳过）
        progressed = set()
        skipped: List[str] = []
        if args.incremental and args.progress_file:
            if args.progress_file.exists():
                try:
                    with args.progress_file.open("r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if line:
                                progressed.add(line)
                except Exception as e:
                    print(f"[WARN] 读取进度文件失败，将不使用增量: {e}")
                    progressed = set()
            else:
                # 创建空进度文件
                args.progress_file.parent.mkdir(parents=True, exist_ok=True)
                args.progress_file.touch()

        for proto, mod in builders.items():
            if args.incremental and args.progress_file and proto in progressed:
                skipped.append(proto)
                continue
            try:
                out = mod.build(args.pcaps_root)
                generated.append(out)
                # 追加写入进度
                if args.incremental and args.progress_file:
                    with args.progress_file.open("a", encoding="utf-8") as pf:
                        pf.write(proto + "\n")
            except Exception as e:
                print(f"[ERROR] builder {proto} failed: {e}", file=sys.stderr)
        _report(generated, missing, skipped)
        return

    # layers 模式：按 Scapy 层枚举映射到构建器
    normalized_layers = {l.lower(): l for l in layers}
    invoked: Set[str] = set()
    for layer_name in layers:
        proto = LAYER_TO_PROTO.get(layer_name)
        if not proto:
            continue
        mod = builders.get(proto)
        if not mod:
            missing.append(proto)
            continue
        if proto in invoked:
            continue
        try:
            out = mod.build(args.pcaps_root)
            generated.append(out)
            invoked.add(proto)
        except Exception as e:
            print(f"[ERROR] builder {proto} failed: {e}", file=sys.stderr)

    # 对未被层枚举覆盖、但我们有构建器的剩余项，也执行一次
    for proto, mod in builders.items():
        if proto in invoked:
            continue
        try:
            out = mod.build(args.pcaps_root)
            generated.append(out)
        except Exception as e:
            print(f"[ERROR] builder {proto} failed: {e}", file=sys.stderr)

    _report(generated, missing)


def _report(generated: List[str], missing: List[str], skipped: List[str] | None = None):
    print("生成完成：")
    for p in generated:
        print(f"  - {p}")
    if missing:
        print("以下协议映射缺少构建器，可按需补充：")
        for m in sorted(set(missing)):
            print(f"  - {m}")
    if skipped:
        print("本次跳过（增量模式）：")
        for s in sorted(skipped):
            print(f"  - {s}")


if __name__ == "__main__":
    main()