import os
import re
from pathlib import Path
from typing import Set, Optional

def is_valid_domain(domain: str) -> bool:
    """检查是否为有效域名（更宽松）"""
    if not domain or '.' not in domain:
        return False

    # 允许字母、数字、连字符、下划线（某些内部系统使用）
    # 不强制要求顶级域名长度（支持 .co.uk 等）
    pattern = r'^[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)*$'
    return re.match(pattern, domain) is not None

def process_hosts_file(filepath: Path) -> Set[str]:
    """处理 hosts 文件格式：提取 127.0.0.1 或 0.0.0.0 后的域名"""
    rules = set()
    try:
        for line in filepath.read_text(encoding='utf-8', errors='ignore').splitlines():
            line = line.strip()
            if not line or line.startswith(('#', '!')):
                continue

            parts = line.split()
            if len(parts) >= 2 and parts[0] in ('127.0.0.1', '0.0.0.0'):
                domain = parts[1].lower()
                if is_valid_domain(domain):
                    rules.add(domain)
    except Exception as e:
        print(f"  ❌ Error processing {filepath}: {e}")
    return rules

def process_adguard_file(filepath: Path) -> Set[str]:
    """处理 AdGuard 规则文件"""
    rules = set()
    try:
        for line in filepath.read_text(encoding='utf-8', errors='ignore').splitlines():
            line = line.strip()
            if not line or line.startswith(('!', '[')):
                continue

            # 支持格式: ||domain^ 和 ||domain^$third-party
            domain = None
            if line.startswith('||'):
                # 移除选项部分
                rule_part = line.split('^$')[0] if '^$' in line else line
                domain = rule_part[2:].strip()

            if domain and is_valid_domain(domain):
                rules.add(domain.lower())
    except Exception as e:
        print(f"  ❌ Error processing {filepath}: {e}")
    return rules

def detect_file_type(filepath: Path) -> str:
    """检测文件类型（更可靠）"""
    try:
        content = filepath.read_text(encoding='utf-8', errors='ignore')
        lines = content.splitlines()

        # 检查前10行非空非注释行
        sample_lines = [
            line.strip() for line in lines[:20]
            if line.strip() and not line.startswith(('!', '#', '['))
        ]

        # 统计特征
        has_adguard_format = any(
            line.startswith('||') and ('^' in line or '$' in line)
            for line in sample_lines
        )
        has_hosts_format = any(
            line.split()[0] in ('127.0.0.1', '0.0.0.0') if line.split() else False
            for line in sample_lines
        )

        if has_adguard_format and not has_hosts_format:
            return 'adguard'
        elif has_hosts_format and not has_adguard_format:
            return 'hosts'
        else:
            # 默认或混合格式：尝试两种
            return 'mixed'
    except:
        return 'unknown'

def merge_category_rules(category: str) -> bool:
    """合并特定分类的规则"""
    print(f"  🔄 Merging {category} rules...")
    all_rules = set()
    source_dir = Path('sources') / category

    if not source_dir.exists():
        print(f"  ⚠️  No sources directory: {source_dir}")
        return False

    files = list(source_dir.glob('*'))
    if not files:
        print(f"  ⚠️  No files in {source_dir}")
        return False

    for filepath in files:
        if not filepath.is_file():
            continue

        print(f"    📄 Processing: {filepath.name}")

        # 检测文件类型
        file_type = detect_file_type(filepath)
        print(f"      Detected format: {file_type}")

        if file_type == 'adguard':
            rules = process_adguard_file(filepath)
        elif file_type == 'hosts':
            rules = process_hosts_file(filepath)
        elif file_type == 'mixed':
            # 尝试两种方式，合并结果
            rules = process_adguard_file(filepath) | process_hosts_file(filepath)
        else:
            print(f"      ⚠️  Unknown format, skipping")
            continue

        all_rules.update(rules)
        print(f"      ➕ Extracted {len(rules)} rules")

    if not all_rules:
        print(f"  ⚠️  No rules extracted for {category}")
        return False

    # 保存合并后的规则
    output_dir = Path('filters')
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / f'{category}-blacklist.txt'

    try:
        # 保持原始格式：如果是从hosts转换，保留为||格式
        # 但记录原始来源信息
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"! Generated from {len(files)} sources\n")
            f.write(f"! Total unique rules: {len(all_rules)}\n")
            for rule in sorted(all_rules):
                f.write(f"||{rule}^\n")

        print(f"  💾 {category}: {len(all_rules)} unique rules saved to {output_file}")
        return True
    except Exception as e:
        print(f"  ❌ Error saving {output_file}: {e}")
        return False

def merge_all_categories(categories: Optional[list] = None) -> bool:
    """合并所有分类规则"""
    print("🔄 Starting rule merging process...")

    if categories is None:
        categories = ['ads', 'malware', 'adult']

    # 验证sources目录
    if not Path('sources').exists():
        print("❌ 'sources' directory not found!")
        return False

    success_count = 0

    for category in categories:
        if merge_category_rules(category):
            success_count += 1

    print(f"\n✅ Merging complete: {success_count}/{len(categories)} categories processed")
    return success_count > 0

if __name__ == '__main__':
    merge_all_categories()
