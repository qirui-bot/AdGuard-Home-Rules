import requests
import os
import time
from pathlib import Path
from urllib.parse import urlparse
from typing import Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

# 上游规则源配置 (已彻底清理URL中的所有奇怪空格)
SOURCES = {
    'ads': [
        'https://raw.githubusercontent.com/ppfeufer/adguard-filter-list/master/blocklist',
        'https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt',
        'https://easylist-downloads.adblockplus.org/easylist.txt',
        'https://easylist-downloads.adblockplus.org/easylistchina.txt',
        'https://raw.githubusercontent.com/chinanjh/hosts/master/fuck%20youtube.txt',
        'https://raw.githubusercontent.com/BlueSkyXN/AdGuardHomeRules/master/all.txt',
        'https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt',
        'https://cdn.jsdelivr.net/gh/banbendalao/ADgk@master/ADgk.txt',
        'https://raw.githubusercontent.com/lingeringsound/adblock_auto/main/Rules/adblock_auto.txt',
        'https://raw.githubusercontent.com/kl0711/adRlues/main/Ad-rules.txt',
        'https://raw.githubusercontent.com/kl0711/adRlues/main/AdGuard-fanqie.txt',
        'https://raw.githubusercontent.com/KiryChanOfficial/AdFilterForAdGuard/main/KR_DNS_Filter.txt',
        'https://raw.githubusercontent.com/H-i-H/AdGuard-Home-Rules/main/Release/Supplement-rules.txt',
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
REQUEST_TIMEOUT = 60      # 超时时间 60 秒
RETRY_DELAY = 3           # 基础重试延迟 3 秒
MAX_RETRIES = 5           # 重试次数 5 次
MIN_FILE_SIZE = 50        # 最小文件大小（字节）
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

def is_valid_file_content(filepath: Path) -> bool:
    """检查文件内容是否为有效的规则列表，而非HTML错误页"""
    try:
        with open(filepath, 'rb') as f:
            # 读取前1KB，足够判断是否为HTML
            content = f.read(1024)
            if not content:
                return False
            lower_content = content.lower()
            # 若包含HTML标签或404错误，视为无效
            if b'<html' in lower_content or b'404 not found' in lower_content:
                return False
            return True
    except Exception:
        return False

def download_with_retry(url: str, filepath: Path, max_retries: int = MAX_RETRIES) -> Tuple[bool, str]:
    """带重试机制的下载（支持指数退避）"""
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

            # 验证内容大小
            content = response.content
            if len(content) < MIN_FILE_SIZE:
                return False, f"File too small ({len(content)} bytes)"

            # 检查是否返回HTML错误页面 (修复了原代码截断的问题)
            content_type = response.headers.get('content-type', '').lower()
            if 'text/html' in content_type:
                # 如果返回的是HTML，大概率是404或错误页面，直接拒绝
                if b'<html' in content.lower() or b'404 not found' in content.lower():
                    return False, "Received HTML error page instead of rule list"

            # 【核心修复】将内容写入文件
            filepath.write_bytes(content)
            return True, f"Downloaded {len(content)} bytes"

        except requests.exceptions.RequestException as e:
            if attempt < max_retries - 1:
                # 指数退避延迟
                sleep_time = RETRY_DELAY * (2 ** attempt)
                print(f"    ⏳ Retrying in {sleep_time}s... Error: {e}")
                time.sleep(sleep_time)
            else:
                return False, f"Failed after {max_retries} attempts: {e}"
        except Exception as e:
            return False, f"Unexpected error: {e}"
            
    return False, "Max retries exceeded"

def fetch_all_sources() -> bool:
    """并发获取所有上游规则源"""
    stats = {'success': 0, 'failed': 0, 'skipped': 0}
    tasks = []
    
    for category, urls in SOURCES.items():
        category_dir = Path('sources') / category
        category_dir.mkdir(parents=True, exist_ok=True)
        
        for url in urls:
            filename = get_filename_from_url(url)
            filepath = category_dir / filename
            
            # 检查是否已存在且大小足够且内容有效
            if filepath.exists():
                size = filepath.stat().st_size
                if size >= MIN_FILE_SIZE and is_valid_file_content(filepath):
                    print(f"    ⏭️  Already exists and valid: {filename} ({size} bytes)")
                    stats['skipped'] += 1
                    continue
                else:
                    # 删除无效或过小的旧文件
                    if size < MIN_FILE_SIZE:
                        print(f"    ⚠️  Existing file too small ({size} bytes), re-downloading: {filename}")
                    else:
                        print(f"    ⚠️  Existing file invalid (HTML/error), re-downloading: {filename}")
                    filepath.unlink()
            
            tasks.append((url, filepath))
            
    if not tasks:
        print("\n📊 Summary: 0 succeeded, 0 failed, all skipped or already exist.")
        return True

    print(f"\n🚀 Starting concurrent downloads for {len(tasks)} files...")
    
    # 使用线程池并发下载
    with ThreadPoolExecutor(max_workers=8) as executor:
        future_to_url = {executor.submit(download_with_retry, url, filepath): (url, filepath) for url, filepath in tasks}
        
        for future in as_completed(future_to_url):
            url, filepath = future_to_url[future]
            filename = filepath.name
            try:
                success, message = future.result()
                if success:
                    print(f"    ✅ {message} -> {filename}")
                    stats['success'] += 1
                else:
                    print(f"    ❌ {message} -> {filename}")
                    stats['failed'] += 1
            except Exception as e:
                print(f"    ❌ Exception occurred for {filename}: {e}")
                stats['failed'] += 1

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
            except Exception:
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
