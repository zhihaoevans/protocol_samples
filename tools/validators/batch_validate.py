#!/usr/bin/env python
import json
import sys
from pathlib import Path

# 兼容直接运行脚本的相对导入
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.validators.validate_pcap import validate_pcap


def infer_expected_proto_from_path(pcap_path: Path) -> str:
    name = pcap_path.stem
    if name.endswith("_standard"):
        name = name[:-9]
    return name


def main():
    import argparse
    parser = argparse.ArgumentParser(description="批量验证 protocols 下的所有 PCAP")
    parser.add_argument("--output", type=Path, default=None, help="输出验证报告 JSON 文件路径")
    args = parser.parse_args()

    protocols_root = Path(__file__).resolve().parents[2] / "protocols"
    results = []
    total = 0
    passed = 0

    for layer_dir in protocols_root.iterdir():
        if not layer_dir.is_dir():
            continue
        for pcap in layer_dir.glob("*.pcap"):
            total += 1
            expected = infer_expected_proto_from_path(pcap)
            ok, report = validate_pcap(str(pcap), expected)
            results.append({
                "pcap": str(pcap),
                "expected_protocol": expected,
                "valid": ok,
                "checks": report,
            })
            if ok:
                passed += 1
            print(f"[{'OK' if ok else 'FAIL'}] {pcap}")

    summary = {"total": total, "passed": passed, "failed": total - passed}
    print(f"汇总: {summary}")

    if args.output:
        payload = {"summary": summary, "results": results}
        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
            print(f"报告已保存: {args.output}")
        except Exception as e:
            print(f"报告写入失败: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()