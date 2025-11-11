#!/usr/bin/env python
import os
import json
from datetime import datetime
from pathlib import Path
from scapy.all import rdpcap


def generate_metadata_for_pcap(pcap_path: Path):
    try:
        pkts = rdpcap(str(pcap_path))
        meta = {
            "protocol": pcap_path.stem.replace("_standard", ""),
            "pcap_file": str(pcap_path),
            "generated_at": datetime.now().isoformat(),
            "packet_count": len(pkts),
            "file_size": os.path.getsize(pcap_path),
        }
        meta_path = pcap_path.with_suffix(pcap_path.suffix + ".meta.json")
        with meta_path.open("w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2, ensure_ascii=False)
        print(f"[OK] 元数据: {meta_path}")
    except Exception as e:
        print(f"[ERROR] 生成元数据失败 {pcap_path}: {e}")


def main():
    root = Path(__file__).resolve().parents[2] / "protocols"
    count = 0
    for layer_dir in root.iterdir():
        if not layer_dir.is_dir():
            continue
        for p in layer_dir.glob("*.pcap"):
            meta_path = p.with_suffix(p.suffix + ".meta.json")
            if meta_path.exists():
                continue
            generate_metadata_for_pcap(p)
            count += 1
    print(f"完成生成缺失元数据，共 {count} 项")


if __name__ == "__main__":
    main()