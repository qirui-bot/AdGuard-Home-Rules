import os
import re
from pathlib import Path

def load_custom_whitelist():
    """加载自定义白名单文件"""
    whitelist_files = [
        'filters/ad-whitelist.txt',
        'filters/adult-whitelist.txt',
        'filters/malware-whitelist.txt'
    ]
    custom_whitelist = set()

    for whitelist_file in whitelist_files:
        if not os.path.exists(whitelist_file):
            print(f"  ⚠️  Whitelist file not found: {whitelist_file}")
            continue

        try:
            with open(whitelist_file, 'r', encoding='utf-8') as f:
                domains = {
                    line.strip() for line in f
                    if (domain := line.strip()) and not domain.startswith('#')
                }
                custom_whitelist.update(domains)
            print(f"  📋 Loaded {len(domains)} domains from {whitelist_file}")
        except Exception as e:
            print(f"  ❌ Error loading {whitelist_file}: {e}")

    print(f"  📋 Total custom whitelist domains: {len(custom_whitelist)}")
    return custom_whitelist

def extract_domain_from_rule(rule):
    """从规则中提取域名"""
    # 支持格式: ||domain^, ||domain/path^, ||domain:port^
    match = re.match(r'^\|\|([^\/\^:\s]+)', rule)
    return match.group(1).lower() if match else None

def apply_whitelist_to_category(category):
    """对特定分类应用白名单"""
    input_file = Path('filters') / f'{category}-blacklist.txt'
    output_file = Path('filters') / f'{category}-blacklist-whitelisted.txt'

    if not input_file.exists():
        print(f"  ⚠️  Input file not found: {input_file}")
        return False

    try:
        # 读取黑名单规则
        rules = [
            line.strip() for line in input_file.read_text(encoding='utf-8').splitlines()
            if line.strip()
        ]

        if not rules:
            print(f"  ⚠️  No rules found in {input_file}")
            return False

        print(f"  📥 {category}: {len(rules)} rules loaded")

        # 加载白名单（转换为小写）
        whitelist = {d.lower() for d in load_custom_whitelist()}
        if not whitelist:
            print(f"  ⚠️  No whitelist domains loaded, skipping filtering")
            return False

        # 构建快速匹配结构
        whitelist_suffixes = {f".{d}" for d in whitelist}

        # 应用白名单过滤
        filtered_rules = []
        removed_rules = []

        for rule in rules:
            domain = extract_domain_from_rule(rule)

            if domain and (domain in whitelist or any(domain.endswith(s) for s in whitelist_suffixes)):
                removed_rules.append(f"{rule}  # removed: {domain}")
                continue

            filtered_rules.append(rule)

        # 保存处理后的规则
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(
            '\n'.join(filtered_rules) + ('\n' if filtered_rules else ''),
            encoding='utf-8'
        )

        print(f"  ✅ {category}: {len(filtered_rules)} rules after whitelist ({len(removed_rules)} removed)")

        # 可选：记录被移除的规则
        if removed_rules:
            removed_file = Path('filters') / f'{category}-whitelisted-removed.txt'
            removed_file.write_text('\n'.join(removed_rules) + '\n', encoding='utf-8')
            print(f"  📝 Removed rules saved to {removed_file}")

        return True

    except Exception as e:
        print(f"  ❌ Error processing {category}: {e}")
        return False

def process_all_categories(categories=None):
    """处理所有分类的白名单"""
    print("🔄 Applying whitelist processing...")

    if categories is None:
        categories = ['ads', 'malware', 'adult']

    success_count = 0

    for category in categories:
        print(f"\n📂 Processing category: {category}")
        if apply_whitelist_to_category(category):
            # 替换原文件
            input_file = Path('filters') / f'{category}-blacklist.txt'
            output_file = Path('filters') / f'{category}-blacklist-whitelisted.txt'
            if output_file.exists():
                os.replace(output_file, input_file)
                print(f"  🔄 Updated {input_file}")
            success_count += 1

    print(f"\n✅ Whitelist processing complete: {success_count}/{len(categories)} categories processed")
    return success_count > 0

if __name__ == '__main__':
    process_all_categories()
