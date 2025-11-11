"""协议构建器集合

每个构建器模块需暴露：
- PROTO: 协议的规范化名字（用于输出子目录）
- build(output_root: pathlib.Path) -> str: 构建并返回生成文件的路径或摘要
"""