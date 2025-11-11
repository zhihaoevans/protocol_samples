# 网络协议 PCAP 仓库 AI 自动化规则

## 项目概述

本项目旨在创建一个包含世界上所有主流网络协议的 PCAP 样本文件库,并自动生成、验证和维护相关文档。

## 目录结构规范

```
protocol-pcap-repository/
├── README.md                    # 项目总览
├── 协议说明.md                   # 所有协议的汇总说明
├── protocols/                   # 协议分类目录
│   ├── application/            # 应用层协议
│   ├── transport/              # 传输层协议
│   ├── network/                # 网络层协议
│   ├── datalink/               # 数据链路层协议
│   ├── physical/               # 物理层协议
│   ├── security/               # 安全协议
│   ├── routing/                # 路由协议
│   ├── industrial/             # 工业协议
│   └── iot/                    # 物联网协议
├── tools/                      # 工具脚本
│   ├── generators/             # PCAP 生成工具
│   ├── validators/             # PCAP 验证工具
│   └── analyzers/              # PCAP 分析工具
└── docs/                       # 详细文档
```

## AI 执行任务流程

### 阶段 1: 协议清单生成

**任务**: 生成完整的网络协议清单

**执行步骤**:

1. 搜索并整理所有标准化网络协议(RFC、IEEE、ITU-T 等)
2. 按 OSI 七层模型和功能分类
3. 创建协议清单文件: `protocols_list.json`

**输出格式**:

```json
{
  "protocol_name": "HTTP",
  "layer": "application",
  "category": "web",
  "rfc": ["RFC 2616", "RFC 7230"],
  "port": [80, 8080],
  "status": "pending",
  "priority": "high"
}
```

### 阶段 2: PCAP 文件生成

**任务**: 为每个协议生成标准 PCAP 样本

**生成工具优先级**:

1. **Scapy** (Python) - 首选,适用于大多数协议
2. **Tcpreplay** - 用于重放和编辑
3. **hping3** - 用于特定协议测试
4. **nping** (Nmap) - 用于探测包生成
5. **专用工具** - 针对特殊协议(如 Modbus, CAN 等)

**生成脚本模板** (`tools/generators/generate_pcap.py`):

```python
from scapy.all import *
import json

def generate_protocol_pcap(protocol_name, config):
    """
    为指定协议生成 PCAP 文件
    Args:
        protocol_name: 协议名称
        config: 协议配置(端口、参数等)
    """
    packets = []
  
    # 根据协议类型生成数据包
    # ... 协议特定逻辑
  
    # 保存 PCAP
    output_path = f"protocols/{config['layer']}/{protocol_name.lower()}.pcap"
    wrpcap(output_path, packets)
  
    return output_path

# 生成元数据
def generate_metadata(protocol_name, pcap_path):
    metadata = {
        "protocol": protocol_name,
        "pcap_file": pcap_path,
        "generated_at": datetime.now().isoformat(),
        "packet_count": len(rdpcap(pcap_path)),
        "file_size": os.path.getsize(pcap_path)
    }
  
    with open(f"{pcap_path}.meta.json", "w") as f:
        json.dump(metadata, f, indent=2)
```

**每个协议必须包含**:

- 正常通信流程(握手、数据传输、断开)
- 典型请求/响应示例
- 错误场景(如果适用)
- 文件命名: `{protocol_name}_standard.pcap`

### 阶段 3: PCAP 验证

**任务**: 验证生成的 PCAP 文件完整性和正确性

**验证脚本** (`tools/validators/validate_pcap.py`):

```python
from scapy.all import *
import pyshark

def validate_pcap(pcap_path, expected_protocol):
    """
    验证 PCAP 文件
    返回: (is_valid, validation_report)
    """
    checks = {
        "file_readable": False,
        "packets_exist": False,
        "protocol_correct": False,
        "no_corruption": False
    }
  
    try:
        packets = rdpcap(pcap_path)
        checks["file_readable"] = True
        checks["packets_exist"] = len(packets) > 0
      
        # 使用 tshark 验证协议
        cap = pyshark.FileCapture(pcap_path)
        for pkt in cap:
            if expected_protocol.upper() in str(pkt.layers):
                checks["protocol_correct"] = True
                break
      
        checks["no_corruption"] = True
      
    except Exception as e:
        return False, {"error": str(e), "checks": checks}
  
    is_valid = all(checks.values())
    return is_valid, checks
```

**验证要求**:

- 文件可读性
- 包含至少 1 个数据包
- 协议字段正确
- 无损坏的包
- 通过 Wireshark 解析测试

### 阶段 4: 文档生成与更新

**任务**: 自动生成和更新 `协议说明.md`

**文档模板**:

```markdown
# 网络协议 PCAP 样本库

最后更新: {datetime}

## 统计信息
- 总协议数: {total_count}
- 已完成: {completed_count}
- 进行中: {in_progress_count}
- 待处理: {pending_count}

## 协议分类

### 应用层协议 (Application Layer)

#### HTTP - 超文本传输协议
- **文件**: `protocols/application/http_standard.pcap`
- **RFC**: RFC 2616, RFC 7230
- **端口**: 80, 8080
- **描述**: Web 浏览器与服务器之间的通信协议
- **PCAP 内容**: 
  - GET/POST 请求示例
  - 响应头和响应体
  - Cookie 处理
- **数据包数**: 15
- **文件大小**: 2.3 KB
- **生成工具**: Scapy
- **验证状态**: ✅ 已验证
- **最后更新**: 2024-01-15

---

#### DNS - 域名系统
...
```

**自动更新脚本** (`tools/update_docs.py`):

```python
import json
import os
from datetime import datetime

def update_protocol_doc():
    """
    扫描 protocols 目录,更新协议说明.md
    """
    protocols = []
  
    # 扫描所有 .pcap 文件
    for root, dirs, files in os.walk("protocols"):
        for file in files:
            if file.endswith(".pcap"):
                meta_file = os.path.join(root, file + ".meta.json")
                if os.path.exists(meta_file):
                    with open(meta_file) as f:
                        protocols.append(json.load(f))
  
    # 生成 Markdown
    markdown = generate_markdown_from_protocols(protocols)
  
    with open("协议说明.md", "w", encoding="utf-8") as f:
        f.write(markdown)
```

### 阶段 5: 持续集成与验证

**任务**: 设置 CI/CD 自动化流程

**GitHub Actions 工作流** (`.github/workflows/pcap-ci.yml`):

```yaml
name: PCAP Generation and Validation

on:
  push:
    branches: [ main ]
  schedule:
    - cron: '0 0 * * 0'  # 每周运行

jobs:
  generate-and-validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
    
      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y tshark tcpdump
          pip install scapy pyshark
    
      - name: Generate missing PCAPs
        run: python tools/generators/batch_generate.py
    
      - name: Validate all PCAPs
        run: python tools/validators/batch_validate.py
    
      - name: Update documentation
        run: python tools/update_docs.py
    
      - name: Commit changes
        run: |
          git config --local user.email "action@github.com"
          git config --local user.name "GitHub Action"
          git add .
          git commit -m "Auto-update: Generate and validate PCAPs" || exit 0
          git push
```

## AI 执行清单

### 优先级 1 - 核心协议 (必须完成)

- [ ] HTTP/HTTPS (应用层)
- [ ] TCP/UDP (传输层)
- [ ] IP/IPv6 (网络层)
- [ ] Ethernet (数据链路层)
- [ ] DNS (应用层)
- [ ] TLS/SSL (安全)
- [ ] ICMP (网络层)
- [ ] ARP (网络层)

### 优先级 2 - 常用协议

- [ ] FTP/SFTP
- [ ] SSH
- [ ] SMTP/POP3/IMAP
- [ ] DHCP
- [ ] NTP
- [ ] SNMP
- [ ] BGP/OSPF/RIP
- [ ] VLAN (802.1Q)

### 优先级 3 - 专业协议

- [ ] SIP/RTP (VoIP)
- [ ] MQTT/CoAP (IoT)
- [ ] Modbus/BACnet (工业)
- [ ] WebSocket
- [ ] gRPC
- [ ] QUIC/HTTP3

### 优先级 4 - 其他协议

- [ ] 所有 RFC 标准化协议
- [ ] 厂商专有协议

## AI 自动化命令

### 初始化项目

```bash
# AI 执行: 创建目录结构
mkdir -p protocols/{application,transport,network,datalink,physical,security,routing,industrial,iot}
mkdir -p tools/{generators,validators,analyzers}
mkdir -p docs
```

### 生成单个协议 PCAP

```bash
# AI 执行: 生成 HTTP 协议 PCAP
python tools/generators/generate_pcap.py --protocol HTTP --output protocols/application/
```

### 批量生成

```bash
# AI 执行: 根据优先级批量生成
python tools/generators/batch_generate.py --priority 1
```

### 验证所有 PCAP

```bash
# AI 执行: 验证并生成报告
python tools/validators/batch_validate.py --output validation_report.json
```

### 更新文档

```bash
# AI 执行: 重新生成协议说明文档
python tools/update_docs.py
```

## 质量标准

### PCAP 文件要求

1. 文件大小: 1KB - 10MB (合理范围)
2. 数据包数量: 至少 5 个包(完整通信流程)
3. 时间戳: 必须有效
4. 校验和: 正确
5. 协议层次: 完整(如 Ethernet -> IP -> TCP -> HTTP)

### 文档要求

1. 每个协议必须有描述
2. 必须列出 RFC/标准文档
3. 必须说明 PCAP 内容
4. 必须包含验证状态
5. 必须有最后更新时间

### 代码要求

1. Python 3.8+ 兼容
2. 使用虚拟环境
3. 依赖列在 requirements.txt
4. 所有脚本可独立运行
5. 错误处理完善

## 依赖安装

```bash
# AI 自动执行
pip install scapy pyshark dpkt kamene
pip install requests beautifulsoup4  # 用于爬取协议列表
apt-get install tshark tcpdump wireshark-common  # Linux
```

## 错误处理规则

1. **生成失败**: 记录到 `generation_errors.log`,标记状态为 "failed"
2. **验证失败**: 重新生成最多 3 次,仍失败则人工介入
3. **文档冲突**: 使用最新数据,保留历史版本
4. **工具缺失**: 自动安装或提示用户

## 进度追踪

AI 应维护 `progress.json`:

```json
{
  "last_update": "2024-01-15T10:30:00Z",
  "total_protocols": 500,
  "completed": 120,
  "in_progress": 50,
  "failed": 5,
  "pending": 325,
  "next_batch": ["QUIC", "HTTP3", "WebRTC"]
}
```

## 人工审核触发条件

以下情况需要人工审核:

1. 验证失败超过 3 次
2. 生成的 PCAP 异常(空文件、超大文件)
3. 协议文档缺失关键信息
4. 新增非标准协议

---

## AI 启动指令

**开始执行时,AI 应该**:

1. 读取 `progress.json` 确定当前进度
2. 按优先级选择下一批协议
3. 生成 PCAP 文件
4. 验证生成结果
5. 更新文档和进度
6. 提交更改
7. 循环直到完成所有协议

**立即开始**:

```bash
python tools/ai_coordinator.py --mode auto --priority 1
```
