#!/usr/bin/env python
import json
import os
from datetime import datetime


def generate_markdown_from_protocols(protocols: list[dict]) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    total = len(protocols)
    completed = sum(1 for _ in protocols)  # 简化：已存在元数据视为完成
    in_progress = 0
    pending = 0

    lines = []
    lines.append("# 网络协议 PCAP 样本库")
    lines.append("")
    lines.append(f"最后更新: {now}")
    lines.append("")
    lines.append("## 统计信息")
    lines.append(f"- 总协议数: {total}")
    lines.append(f"- 已完成: {completed}")
    lines.append(f"- 进行中: {in_progress}")
    lines.append(f"- 待处理: {pending}")
    lines.append("")
    lines.append("## 协议分类")

    # 按路径中的层级聚合
    by_layer: dict[str, list[dict]] = {}
    for m in protocols:
        path = m.get("pcap_file", "")
        parts = path.split(os.sep)
        layer = "unknown"
        try:
            idx = parts.index("protocols")
            layer = parts[idx + 1]
        except Exception:
            pass
        by_layer.setdefault(layer, []).append(m)

    layer_names = {
        "application": "应用层协议 (Application Layer)",
        "transport": "传输层协议 (Transport Layer)",
        "network": "网络层协议 (Network Layer)",
        "datalink": "数据链路层协议 (Data Link Layer)",
        "security": "安全协议 (Security)",
        "routing": "路由协议 (Routing)",
        "industrial": "工业协议 (Industrial)",
        "iot": "物联网协议 (IoT)",
        "unknown": "未分类 (Unknown)",
    }

    for layer, items in by_layer.items():
        lines.append("")
        lines.append(f"### {layer_names.get(layer, layer)}")
        lines.append("")
        for m in sorted(items, key=lambda x: x.get("protocol", "")):
            proto = m.get("protocol", "")
            file = m.get("pcap_file", "")
            size = m.get("file_size", 0)
            count = m.get("packet_count", 0)
            lines.append(f"#### {proto.upper()} ")
            lines.append(f"- 文件: `{file}`")
            lines.append(f"- 数据包数: {count}")
            lines.append(f"- 文件大小: {size} B")
            lines.append(f"- 验证状态: ⏳ 未验证")
            lines.append("")

    return "\n".join(lines)


def update_protocol_doc():
    """
    扫描 protocols 目录,更新协议说明.md
    """
    protocols = []
    for root, dirs, files in os.walk("protocols"):
        for file in files:
            if file.endswith(".pcap"):
                meta_file = os.path.join(root, file + ".meta.json")
                if os.path.exists(meta_file):
                    with open(meta_file, encoding="utf-8") as f:
                        protocols.append(json.load(f))
    markdown = generate_markdown_from_protocols(protocols)
    with open("协议说明.md", "w", encoding="utf-8") as f:
        f.write(markdown)


if __name__ == "__main__":
    update_protocol_doc()