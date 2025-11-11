#!/usr/bin/env python
import json
from pathlib import Path


def main():
    repo_root = Path(__file__).resolve().parents[2]
    protocols_root = repo_root / "protocols"
    items = []
    for layer_dir in protocols_root.iterdir():
        if not layer_dir.is_dir():
            continue
        layer = layer_dir.name
        for pcap in layer_dir.glob("*_standard.pcap"):
            proto = pcap.stem.replace("_standard", "").upper()
            item = {
                "protocol_name": proto,
                "layer": layer,
                "category": layer,  # 初始用层作为分类占位
                "rfc": [],
                "port": [],
                "status": "pending",
                "priority": "high" if layer in {"application", "transport", "network", "datalink", "security", "routing"} else "medium",
            }
            items.append(item)

    out_path = repo_root / "protocols_list.json"
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(items, f, indent=2, ensure_ascii=False)
    print(f"协议清单已生成: {out_path}，共 {len(items)} 项")


if __name__ == "__main__":
    main()