import requests
import os
import time
import hashlib
from pathlib import Path
from urllib.parse import urlparse
from typing import Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# 上游规则源配置
SOURCES = {
    'ads': [
        'https://raw.githubusercontent.com/ppfeufer/adguard-filter-list/master/blocklist',
        'https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt',
        'https://easylist-downloads.adblockplus.org/easylist.txt',
        'https://easylist-downloads.adblockplus.org/easylistchina.txt',
        'https://raw.githubusercontent.com/chinanjh/hosts/master/fuck%20youtube.txt',
        'https://raw.githubusercontent.com/BlueSkyXN/AdGuardHomeRules/master/all.txt',
        'https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt',
        'https://raw.githubusercontent.com/banbendalao/ADgk/master/ADgk.txt',
        'https://raw.githubusercontent.com/lingeringsound/adblock_auto/main/Rules/adblock_auto.txt',
        'https://raw.githubusercontent.com/kl0711/adRlues/main/Ad-rules.txt',
        'https://raw.githubusercontent.com/kl0711/adRlues/main/AdGuard-fanqie.txt',
        'https://raw.githubusercontent.com/KiryChanOfficial/AdFilterForAdGuard/main/KR_DNS_Filter.txt',
        'https://raw.githubusercontent.com/H-i-H/AdGuard-Home-Rules/main/Release/Supplement-rules.txt',
        'https://anti-ad.net/easylist.txt',
        'https://raw.githubusercontent.com/SamirPaulb/filter-lists/main/filters.txt',
        'https://raw.githubusercontent.com/siankatabg/FuFu-AdGuard-blacklist/master/fufu-adguard-blacklist.txt',
        'https://raw.githubusercontent.com/Ealenn/AdGuard-Home-List/gh-pages/AdGuard-Home-List.Block.txt',
        'https://github.com/H-i-H/AdGuard-Home-Rules/releases/download/latest/combined-rules.txt',
        #以下规则长时间未更新
        #'https://raw.githubusercontent.com/Lyceris-chan/dns-blocklist-generator/main/blocklist.txt',
        #'https://pishangujeniya.github.io/layman-adlist/layman_adlist_hosts.txt',
        #'https://raw.githubusercontent.com/louisa-uno/DNSBlocklists/auto-update/list.adguard',
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

# 并发配置
MAX_WORKERS = 10  # 同时下载的线程数，可根据网络情况调整

# 线程安全锁：保护共享的统计字典与打印输出，避免多线程竞态
_stats_lock = threading.Lock()

def get_filename_from_url(url: str) -> str:
    """从URL生成有意义的唯一文件名（附加URL哈希后缀，避免同名覆盖）"""
    parsed = urlparse(url)
    domain = parsed.netloc.replace('www.', '')
    path_parts = [p for p in parsed.path.split('/') if p]

    if path_parts:
        name = path_parts[-1].split('.')[0]  # 去掉扩展名
    else:
        name = 'index'

    # 用完整 URL 的哈希前 8 位作为唯一后缀
    url_hash = hashlib.md5(url.encode('utf-8')).hexdigest()[:8]
    return f"{domain}_{name}_{url_hash}.txt"

def clean_sources_files(root: str = "sources") -> None:
    """
    删除 sources 目录下的所有文件，但保留子目录结构。
    用于每次更新前清空旧缓存，确保重新下载全部文件。
    """
    root_path = Path(root)
    if not root_path.exists():
        return

    # 递归遍历所有文件和目录，只删除文件
    for p in root_path.rglob('*'):
        if p.is_file():
            try:
                p.unlink()
                print(f"    🗑️  已删除旧文件: {p}")
            except Exception as e:
                print(f"    ⚠️  删除文件失败 {p}: {e}")

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

def _download_single(url: str, category_dir: Path, stats: dict) -> None:
    """
    单个 URL 的下载任务（供线程池调用）。
    每个线程独立完成：存在性检查 -> 下载 -> 更新共享统计（加锁）。
    """
    filename = get_filename_from_url(url)
    filepath = category_dir / filename

    # 检查是否已存在且有效
    # 注意：由于前面已清空所有文件，此处通常不会命中，保留逻辑仅为兼容
    if filepath.exists():
        size = filepath.stat().st_size
        if size > MIN_FILE_SIZE:
            with _stats_lock:
                stats['skipped'] += 1
                print(f"    ⏭️  Already exists: {filename} ({size} bytes)")
            return
        else:
            # 删除无效的旧文件
            filepath.unlink()

    success, message = download_with_retry(url, filepath)

    # 加锁更新共享统计与打印，避免多线程交错输出与竞态
    with _stats_lock:
        if success:
            print(f"    ✅ {message} -> {filename}")
            stats['success'] += 1
        else:
            print(f"    ❌ {message}")
            stats['failed'] += 1
            # 记录失败源及原因，供结尾汇总打印
            stats['failed_urls'].append((url, message))

def fetch_all_sources():
    """获取所有上游规则（并行模式）"""
    print("🔄 Fetching upstream rules (parallel mode)...")

    # 每次更新前先清空 sources 下的所有文件（保留子目录）
    clean_sources_files()

    stats = {'success': 0, 'failed': 0, 'skipped': 0, 'failed_urls': []}

    # 收集所有 (url, category_dir) 任务，一次性提交到线程池
    tasks = []
    for category, urls in SOURCES.items():
        print(f"\n📂 Processing category: {category}")
        category_dir = Path('sources') / category
        category_dir.mkdir(parents=True, exist_ok=True)
        for url in urls:
            tasks.append((url, category_dir))

    print(f"\n🚀 Total {len(tasks)} sources, max workers: {MAX_WORKERS}")

    # 使用线程池并行下载，显着缩短总耗时
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {
            executor.submit(_download_single, url, cat_dir, stats): url
            for url, cat_dir in tasks
        }

        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                future.result()
            except Exception as e:
                # 兜底：捕获任务内部未处理的异常，避免影响其他下载
                with _stats_lock:
                    stats['failed'] += 1
                    stats['failed_urls'].append((url, f"Unexpected error: {e}"))
                    print(f"    ❌ Unexpected error for {url}: {e}")

    print(f"\n📊 Summary: {stats['success']} succeeded, {stats['failed']} failed, {stats['skipped']} skipped")
    if stats['failed_urls']:
        print(f"⚠️  {len(stats['failed_urls'])} source(s) failed but pipeline continues:")
        for url, reason in stats['failed_urls']:
            print(f"   - {url}  ({reason})")
    return stats

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
    stats = fetch_all_sources()
    # 方案一：个别源失败不再中断流水线，只做警告；后续验证照常执行
    if stats['failed'] > 0:
        print(f"\n⚠️  {stats['failed']} download(s) failed, but pipeline continues.")
    validate_downloaded_files()
