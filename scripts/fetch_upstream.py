import requests
import os
import time
from pathlib import Path
from urllib.parse import urlparse
from typing import Tuple, Optional

# 上游规则源配置
SOURCES = {
    'ads': [
        'https://raw.githubusercontent.com/ppfeufer/adguard-filter-list/refs/heads/master/blocklist',
        'https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt',
        'https://easylist-downloads.adblockplus.org/easylist.txt',
        'https://easylist-downloads.adblockplus.org/easylistchina.txt',
        'https://raw.githubusercontent.com/chinanjh/hosts/refs/heads/master/fuck%20youtube.txt',
        'https://raw.githubusercontent.com/BlueSkyXN/AdGuardHomeRules/master/all.txt',
        'https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt',
        'https://cdn.jsdelivr.net/gh/banbendalao/ADgk@master/ADgk.txt',
        'https://raw.githubusercontent.com/lingeringsound/adblock_auto/refs/heads/main/Rules/adblock_auto.txt',
        'https://raw.githubusercontent.com/kl0711/adRlues/refs/heads/main/Ad-rules.txt',
        'https://raw.githubusercontent.com/kl0711/adRlues/refs/heads/main/AdGuard-fanqie.txt',
        'https://raw.githubusercontent.com/KiryChanOfficial/AdFilterForAdGuard/refs/heads/main/KR_DNS_Filter.txt',
        'https://raw.githubusercontent.com/H-i-H/AdGuard-Home-Rules/refs/heads/main/Release/Supplement-rules.txt',
        'https://anti-ad.net/easylist.txt'
    ],
    'malware': [
        'https://malware-filter.pages.dev/urlhaus-filter-online.txt',
        'https://malware-filter.pages.dev/phishing-filter.txt'
    ],
    'adult': [
        'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts'
    ]
}

# 请求配置
REQUEST_TIMEOUT = 30
RETRY_DELAY = 2
MAX_RETRIES = 3
MIN_FILE_SIZE = 50  # 最小文件大小（字节）
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'

def get_filename_from_url(url: str) -> str:
    """从URL生成有意义的文件名"""
    parsed = urlparse(url)
    domain = parsed.netloc.replace('www.', '')
    path_parts = [p for p in parsed.path.split('/') if p]

    if path_parts:
        name = path_parts[-1].split('.')[0]  # 去掉扩展名
        return f"{domain}_{name}.txt"
    return f"{domain}.txt"

def download_with_retry(url: str, filepath: Path, max_retries: int = MAX_RETRIES) -> Tuple[bool, str]:
    """带重试机制的下载"""
    for attempt in range(max_retries):
        try:
            print(f"    📥 Attempt {attempt + 1}/{max_retries}: {url}")

            headers = {'User-Agent': USER_AGENT}
            response = requests.get(
                url,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
                verify=True
            )
            response.raise_for_status()

            # 验证内容
            content = response.content
            if len(content) < MIN_FILE_SIZE:
                return False, f"File too small ({len(content)} bytes)"

            # 检查是否返回HTML错误页面
            content_type = response.headers.get('content-type', '').lower()
            if 'text/html' in content_type and 'filter' not in url:
                # 检查内容是否包含HTML标签
                if b'<html' in content[:100].lower() or b'<!doctype' in content[:100].lower():
                    return False, "Response appears to be HTML error page"

            # 保存文件
            filepath.parent.mkdir(parents=True, exist_ok=True)
            with open(filepath, 'wb') as f:
                f.write(content)

            return True, f"Saved {len(content)} bytes"

        except requests.exceptions.Timeout:
            if attempt == max_retries - 1:
                return False, "Timeout after all retries"
            print(f"    ⚠️  Timeout, retrying in {RETRY_DELAY}s...")
            time.sleep(RETRY_DELAY)

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                return False, "404 Not Found"
            elif e.response.status_code == 403:
                return False, "403 Forbidden (check User-Agent)"
            else:
                return False, f"HTTP {e.response.status_code}"

        except requests.exceptions.RequestException as e:
            if attempt == max_retries - 1:
                return False, f"Network error: {e}"
            print(f"    ⚠️  Error: {e}, retrying in {RETRY_DELAY}s...")
            time.sleep(RETRY_DELAY)

    return False, "Unknown error"

def fetch_all_sources():
    """获取所有上游规则"""
    print("🔄 Fetching upstream rules...")

    stats = {'success': 0, 'failed': 0, 'skipped': 0}

    for category, urls in SOURCES.items():
        print(f"\n📂 Processing category: {category}")
        category_dir = Path('sources') / category
        category_dir.mkdir(parents=True, exist_ok=True)

        for i, url in enumerate(urls):
            filename = get_filename_from_url(url)
            filepath = category_dir / filename

            # 检查是否已存在且有效
            if filepath.exists():
                size = filepath.stat().st_size
                if size > MIN_FILE_SIZE:
                    print(f"    ⏭️  Already exists: {filename} ({size} bytes)")
                    stats['skipped'] += 1
                    continue
                else:
                    # 删除无效的旧文件
                    filepath.unlink()

            success, message = download_with_retry(url, filepath)

            if success:
                print(f"    ✅ {message} -> {filename}")
                stats['success'] += 1
            else:
                print(f"    ❌ {message}")
                stats['failed'] += 1

            # 避免请求过于频繁
            time.sleep(RETRY_DELAY)

    print(f"\n📊 Summary: {stats['success']} succeeded, {stats['failed']} failed, {stats['skipped']} skipped")
    return stats['failed'] == 0

def validate_downloaded_files():
    """验证下载的文件"""
    print("\n🔍 Validating downloaded files...")

    issues = []
    for category in SOURCES.keys():
        category_dir = Path('sources') / category
        if not category_dir.exists():
            continue

        for filepath in category_dir.glob('*.txt'):
            size = filepath.stat().st_size
            if size == 0:
                issues.append(f"Empty file: {filepath}")
            elif size < MIN_FILE_SIZE:
                issues.append(f"Small file ({size} bytes): {filepath}")

            # 检查文件内容是否为空或只有空白
            try:
                content = filepath.read_text(encoding='utf-8', errors='ignore')
                if not content.strip():
                    issues.append(f"File contains only whitespace: {filepath}")
            except:
                issues.append(f"Cannot read file: {filepath}")

    if issues:
        print("  ⚠️  Validation issues found:")
        for issue in issues:
            print(f"    - {issue}")
        return False

    print("  ✅ All files validated")
    return True

if __name__ == '__main__':
    success = fetch_all_sources()
    if success:
        validate_downloaded_files()
    else:
        print("\n❌ Some downloads failed. Please check the logs.")
        exit(1)
