#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
custom_rules_injector.py —— 自定义规则剔除器（上游排除源）

功能：
  1. 从 EXCLUDE_SOURCES 中指定的上游源下载规则文件，提取其中所有域名，
     作为"排除域名集合"。
  2. 从 TARGET_FILES 中逐行剔除包含排除域名的规则，同时更新文件头部的
     "! Total count:" 统计行。
  3. 若 UPDATE_README 为 True，同步更新 README.md 中类似
     "规则数量: 12345" 的文本。
  4. 自动清理旧版脚本残留的 CUSTOM_INJECT_START / CUSTOM_INJECT_END
     标记块，保证多次运行幂等。
"""

import os
import re
import sys
import time
import requests
from typing import Set

# ==================== 环境自适应 ====================
IS_CI = os.getenv("GITHUB_ACTIONS") == "true"

class C:
    R, G, Y, B, CY, E = ("", "", "", "", "", "") if IS_CI else ("\033[91m", "\033[92m", "\033[93m", "\033[94m", "\033[96m", "\033[0m")
    BOLD = "" if IS_CI else "\033[1m"

log = lambda m, c=C.B: print(f"{c}{m}{C.E}", flush=True)

# ==================== 〖配置区域〗 ====================
# 需要〖去除〗的上游源链接（按需添加你想排除的规则源）
EXCLUDE_SOURCES = [
    # 示例（按需取消注释使用）：
    "https://raw.githubusercontent.com/Natsuki-Kaede/Natsuki-List/main/adguardhome.txt",
    "https://raw.githubusercontent.com/Natsuki-Kaede/Natsuki-List/main/hosts.txt",
    "https://filters.adtidy.org/android/filters/15_optimized.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.roku.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.lgwebos.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.samsung.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.apple.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.amazon.txt",
    "https://raw.githubusercontent.com/ABPindo/indonesianadblockrules/master/subscriptions/abpindo.txt",
    "https://raw.githubusercontent.com/yous/YousList/master/hosts.txt",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/NorwegianExperimentalList%20alternate%20versions/NordicFiltersAdGuardHome.txt",
    "https://raw.githubusercontent.com/lassekongo83/Frellwits-filter-lists/master/Frellwits-Swedish-Hosts-File.txt",
    "https://easylist-downloads.adblockplus.org/easylistdutch.txt",
    "https://raw.githubusercontent.com/DRSDavidSoft/additional-hosts/master/domains/blacklist/unwanted-iranian.txt",
    "https://raw.githubusercontent.com/cchevy/macedonian-pi-hole-blocklist/master/hosts.txt",
    "https://www.github.developerdan.com/hosts/lists/facebook-extended.txt",
    "https://www.github.developerdan.com/hosts/lists/dating-services-extended.txt",
    "https://raw.githubusercontent.com/anudeepND/blacklist/master/facebook.txt",
    "https://abpvn.com/android/abpvn.txt",
    "https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts",
    "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/GoodbyeAds-YouTube-Adblock-Extension/hosts",
    "https://raw.githubusercontent.com/nextdns/native-tracking-domains/main/domains/alexa",
    "https://raw.githubusercontent.com/nextdns/native-tracking-domains/main/domains/apple",
    "https://raw.githubusercontent.com/nextdns/native-tracking-domains/main/domains/roku",
    "https://raw.githubusercontent.com/nextdns/native-tracking-domains/main/domains/samsung",
    "https://raw.githubusercontent.com/nextdns/native-tracking-domains/main/domains/sonos",
    "https://raw.githubusercontent.com/xxcriticxx/.pl-host-file/master/hosts.txt",
    "https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Formats/GoodbyeAds-YouTube-AdBlock-Filter.txt",
    "https://raw.githubusercontent.com/hectorm/hmirror/master/data/turkish-ad-hosts/list.txt",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/NorwegianExperimentalList%20alternate%20versions/DandelionSproutsNorskeFiltreDomains.txt",
    "https://easylist-downloads.adblockplus.org/Liste_AR.txt",
    "https://easylist-downloads.adblockplus.org/bulgarian_list.txt",
    "https://easylist-downloads.adblockplus.org/easylistczechslovak.txt",
    "https://easylist-downloads.adblockplus.org/easylistgermany.txt",
    "https://easylist-downloads.adblockplus.org/liste_fr.txt",
    "https://easylist-downloads.adblockplus.org/israellist.txt",
    "https://easylist-downloads.adblockplus.org/abpindo.txt",
    "https://easylist-downloads.adblockplus.org/easylistitaly.txt",
    "https://easylist-downloads.adblockplus.org/koreanlist.txt",
    "https://easylist-downloads.adblockplus.org/latvianlist.txt",
    "https://easylist-downloads.adblockplus.org/easylistlithuania.txt",
    "https://easylist-downloads.adblockplus.org/easylistpolish.txt",
    "https://easylist-downloads.adblockplus.org/easylistportuguese.txt",
    "https://easylist-downloads.adblockplus.org/advblock.txt",
    "https://easylist-downloads.adblockplus.org/easylistspanish.txt",
    "https://raw.githubusercontent.com/FilteringDev/filterslists-KO/refs/heads/master/filterslists/adblocking/filters-share/1st_domains.txt",
    "https://raw.githubusercontent.com/FilteringDev/filterslists-KO/refs/heads/master/filterslists/adblocking/filters-share/3rd_domains.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_7_Japanese/filter.txt",
    "https://raw.githubusercontent.com/tofukko/filter/master/Adblock_Plus_list.txt",
    "https://easylist-downloads.adblockplus.org/ruadlist.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_1_Russian/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_16_French/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_6_German/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_9_Spanish/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_13_Turkish/filter.txt",
    "https://raw.githubusercontent.com/omerdduran/turk-adfilter/main/turk-adfilter.txt",
    "https://raw.githubusercontent.com/remad0/TurkHosts404/refs/heads/main/dns-blocklists/adblock.txt",
    "https://raw.githubusercontent.com/symbuzzer/Turkish-Ad-Hosts/main/hosts",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_23_Ukrainian/filter.txt",
    "https://raw.githubusercontent.com/ukrainianfilters/lists/main/ads/ads.txt",
    "https://raw.githubusercontent.com/ukrainianfilters/lists/main/combined/combined.txt",
    "https://raw.githubusercontent.com/ukrainianfilters/lists/main/privacy/privacy.txt",
    "https://easylist-downloads.adblockplus.org/indianlist.txt",
    "https://raw.githubusercontent.com/brave/adblock-lists/refs/heads/master/custom/is.txt",
    "https://raw.githubusercontent.com/DandelionSprout/Swedish-List-for-Adblock-Plus/refs/heads/main/Swedish%20List%20for%20All-Nordic.txt",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/NorwegianExperimentalList%20alternate%20versions/NordicFiltersABP-Inclusion.txt",
    "https://raw.githubusercontent.com/Hakame-kun/uBlock-Filters-Indonesia/master/uBlock%20Indo/ubindo.txt",
    "https://raw.githubusercontent.com/easylist-thailand/easylist-thailand/master/subscription/easylist-thailand.txt",
    "https://raw.githubusercontent.com/bigdargon/hostsVN/master/filters/adservers.txt",
    "https://raw.githubusercontent.com/bigdargon/hostsVN/master/option/hosts-VN",
    "https://codeberg.org/KhodeKiaa/PersianBlocker/raw/branch/main/PersianBlocker.txt",
    "https://raw.githubusercontent.com/MasterKia/PersianBlocker/main/PersianBlockerAds-Hosts.txt",
    "https://raw.githubusercontent.com/MasterKia/PersianBlocker/main/PersianBlockerHosts.txt",
    "https://raw.githubusercontent.com/MasterKia/PersianBlocker/main/PersianBlockerTrackers-Hosts.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_8_Dutch/filter.txt",
    "https://cdn.jsdelivr.net/gh/hufilter/hufilter@gh-pages/hufilter.txt",
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/SerboCroatianList.txt",
    "https://raw.githubusercontent.com/DeepSpaceHarbor/Macedonian-adBlock-Filters/refs/heads/master/Filters",
    "https://raw.githubusercontent.com/betterwebleon/slovenian-list/refs/heads/master/filters.txt",
    "https://www.zoso.ro/pages/rolist.txt",
    "https://www.zoso.ro/pages/rolist2.txt",
    "https://www.void.gr/kargig/void-gr-filters.txt",
    "https://raw.githubusercontent.com/andromedarabbit/List-KR/master/filter.txt",
    "https://raw.githubusercontent.com/unchartedsky/adguard-kr/master/adguard-kr.txt",
    "https://raw.githubusercontent.com/Yuki2718/adblock/master/japanese/jp-filters.txt",
    "https://raw.githubusercontent.com/Yuki2718/adblock/master/japanese/jp-paranoid.txt",
    "https://raw.githubusercontent.com/Yuki2718/adblock/master/japanese/jp-annoyances.txt",
    "https://raw.githubusercontent.com/bkrcrc/turk-adlist/master/hosts",
    "https://raw.githubusercontent.com/MajkiIT/polish-ads-filter/master/polish-adblock-filters/adblock.txt",
    "https://raw.githubusercontent.com/olegwukr/polish-privacy-filters/master/adblock.txt",
    "https://raw.githubusercontent.com/tomasko126/easylistczechandslovak/master/filters.txt",
    "https://raw.githubusercontent.com/ConvolutionExpected/CZ-SK-hosts-file-to-block-trackers-and-ads/main/AdsAndTrackers",
    "https://raw.githubusercontent.com/ABPindo/indonesianadblockrules/master/subscriptions/domain.txt",
    "https://raw.githubusercontent.com/jakdev121/AMS2/master/pi_indo_ads.txt",
    "https://raw.githubusercontent.com/farrokhi/adblock-iran/master/filter.txt",
    "https://raw.githubusercontent.com/lassekongo83/Frellwits-filter-lists/master/Frellwits-Swedish-Filter.txt",
    "https://filters.hufilter.hu/hufilter-dns.txt",
    "https://raw.githubusercontent.com/kargig/greek-adblockplus-filter/master/void-gr-filters.txt",
    "https://raw.githubusercontent.com/hosts-file/BulgarianHostsFile/master/bhf.txt",
    "https://raw.githubusercontent.com/KokichaKolevTM/BG-Adblock-list/main/BG-Adblock-list.txt",
    "https://lists.blocklist.de/lists/all.txt",
    "https://raw.githubusercontent.com/BlackJack8/iOSAdblockList/master/Regular%20Hosts.txt",
    "https://raw.githubusercontent.com/mitchellkrogza/Top-Attacking-IP-Addresses-Against-Wordpress-Sites/master/wordpress-attacking-ips.txt",
    "https://raw.githubusercontent.com/Dogino/Discord-Phishing-URLs/main/scam-urls.txt",
    "https://filters.adtidy.org/extension/chromium/filters/246.txt",
    "https://raw.githubusercontent.com/MajkiIT/polish-ads-filter/master/polish-pihole-filters/adguard_mobile_host.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/GermanFilter/sections/adservers.txt",
    "https://raw.githubusercontent.com/PolishFiltersTeam/PolishAnnoyanceFilters/master/PAF_push.txt",
    "https://filters.adtidy.org/extension/chromium/filters/108.txt",
    "https://filters.adtidy.org/extension/chromium/filters/107.txt",
    "https://fanboy.co.nz/fanboy-korean.txt",
    "https://filters.adtidy.org/extension/ublock/filters/7.txt",
    "https://filters.adtidy.org/extension/chromium/filters/243.txt",
    "https://fanboy.co.nz/fanboy-turkish.txt",
    "https://easylist-downloads.adblockplus.org/latvianlist-minified.txt",
    "https://raw.githubusercontent.com/ElCap1tan/PiHole-Parsed-Filter-Lists/master/lists/easylistdutch.host",
    "https://raw.githubusercontent.com/ElCap1tan/PiHole-Parsed-Filter-Lists/master/lists/easylistgermany.host",
    "https://raw.githubusercontent.com/ElCap1tan/PiHole-Parsed-Filter-Lists/master/lists/abpindo.host",
    "https://filters.adtidy.org/extension/chromium/filters/232.txt",
    "https://filters.adtidy.org/extension/chromium/filters/109.txt",
    "https://easylist-downloads.adblockplus.org/advblock+cssfixes.txt",
    "https://filters.adtidy.org/extension/chromium/filters/249.txt",
    "https://raw.githubusercontent.com/michalterbert/pihole_pl/master/hosts.txt.txt",
    "https://v.firebog.net/hosts/Prigent-Crypto.txt",
    "https://v.firebog.net/hosts/Prigent-Ads.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_37.txt",
    "https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt",
    "https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/Bad_JAV_Sites/master/domains.list",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social-only/hosts",
    "https://dl.red.flag.domains/red.flag.domains.txt",
    "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt",  #替换"https://phish.co.za/latest/phishing-domains-ACTIVE.txt",
    "https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/hosts",
    "https://v.firebog.net/hosts/Prigent-Malware.txt",
    "https://easylist.to/easylist/fanboy-social.txt",
    "https://filters.adtidy.org/windows/filters/4.txt",
    "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/malware",
    "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/Phishing-Angriffe",
    "https://blocklistproject.github.io/Lists/porn.txt",
    "https://blocklistproject.github.io/Lists/abuse.txt",
    "https://github.com/ramazansancar/notes/raw/main/piHoleAdList.txt",
    "https://github.com/easylist-thailand/easylist-thailand/raw/master/subscription/easylist-thailand.txt",
    "https://github.com/SlashArash/adblockfa/raw/master/adblockfa.txt",
    "https://raw.githubusercontent.com/blocklistproject/Lists/main/facebook.txt",
    "https://raw.githubusercontent.com/blocklistproject/Lists/main/adobe.txt",
    "https://raw.githubusercontent.com/blocklistproject/Lists/main/fortnite.txt",
    "https://easylist.to/easylistgermany/easylistgermany.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/CyrillicFilters/RussianFilter/sections/adservers_firstparty.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/TurkishFilter/sections/adservers.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/TurkishFilter/sections/adservers_firstparty.txt",
    "https://raw.githubusercontent.com/easylist/EasyListHebrew/master/EasyListHebrew.txt",
    "https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_international_specific_block.txt",
    "https://raw.githubusercontent.com/easylist/easylist/master/easylist_cookie/easylist_cookie_specific_block.txt",
    "https://raw.githubusercontent.com/blocklistproject/Lists/main/torrent.txt",
    "https://raw.githubusercontent.com/blocklistproject/Lists/main/twitter.txt",
    "https://raw.githubusercontent.com/blocklistproject/Lists/main/vaping.txt",
    "https://raw.githubusercontent.com/blocklistproject/Lists/main/whatsapp.txt",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.Spam/hosts",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.Risk/hosts",
    "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/UncheckyAds/hosts",
    "https://paulgb.github.io/BarbBlock/blacklists/hosts-file.txt",
    "https://raw.githubusercontent.com/chadmayfield/my-pihole-blocklists/master/lists/pi_blocklist_porn_top1m.list",
    "https://phishing.army/download/phishing_army_blocklist_extended.txt",
    "https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Extension/GoodbyeAds-Samsung-AdBlock.txt",
    "https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Extension/GoodbyeAds-Spotify-AdBlock.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_62.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_35.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_22.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_19.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_43.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_25.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_15.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_36.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_20.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_13.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_41.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_14.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_17.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_26.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_40.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_16.txt",
]

# 需要清洗的目标文件
TARGET_FILES = [
    "Release/combined-rules.txt",
]

# 是否更新 README.md 和规则文件头部的数量统计
UPDATE_README = True
UPDATE_TOTAL_COUNT = True
README_FILE = "README.md"

# 网络请求超时（秒）
FETCH_TIMEOUT = 15

# 旧版标记块（用于自动清理）
MARKER_START = "CUSTOM_INJECT_START"
MARKER_END = "CUSTOM_INJECT_END"

# ==================== 正则 ====================
# AdGuard 格式：||example.com^
RE_ADGUARD = re.compile(r'^\|\|([^\^/\s*$]+)')
# hosts 格式：0.0.0.0 example.com / 127.0.0.1 example.com
RE_HOSTS = re.compile(
    r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1|::)\s+'
    r'([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?'
    r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)+)\s*$'
)
# 合法域名校验
RE_VALID_DOMAIN = re.compile(
    r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?'
    r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)+$'
)
# README 中数量统计文本（容错多种写法）
RE_README_COUNT = re.compile(
    r'(规则数量|拦截规则数量|Rules?\s*Count)[:：]?\s*`?([\d,]+)`?',
    re.IGNORECASE
)

# ==================== 下载与解析 ====================
def fetch_rules(url: str) -> str:
    """从 URL 下载规则内容，失败返回空字符串。"""
    try:
        r = requests.get(
            url,
            timeout=FETCH_TIMEOUT,
            headers={"User-Agent": "Mozilla/5.0 (custom-rules-injector)"}
        )
        r.raise_for_status()
        return r.text
    except Exception as e:
        log(f"  ⚠️ 下载失败 {url}: {e}", C.Y)
        return ""


def _normalize_domain(core: str) -> str:
    """从 ||example.com^ 或 example.com/path:80 中提取纯域名。"""
    if core.endswith('^'):
        core = core[:-1]
    core = core.split('/')[0].split(':')[0].split('*')[0]
    d = re.sub(r'[^a-zA-Z0-9\-\.]', '', core).lower()
    return d if d and RE_VALID_DOMAIN.match(d) else ""


def parse_domains(content: str) -> Set[str]:
    """从规则内容中解析出域名集合。"""
    domains = set()
    for line in content.splitlines():
        s = line.strip()
        if not s or s[0] in '![#':
            continue

        # 去掉修饰符
        core = s.split('$')[0].split('#')[0].strip()

        # AdGuard 格式：||example.com^
        if core.startswith('||'):
            d = _normalize_domain(core[2:])
            if d:
                domains.add(d)
            continue

        # hosts 格式：0.0.0.0 example.com
        parts = core.split()
        if len(parts) >= 2 and parts[0] in ('0.0.0.0', '127.0.0.1', '::', '::1'):
            d = parts[1].strip().lower()
            if RE_VALID_DOMAIN.match(d):
                domains.add(d)
    return domains


def build_exclude_set() -> Set[str]:
    """遍历 EXCLUDE_SOURCES，构建排除域名集合。"""
    all_domains: Set[str] = set()
    for url in EXCLUDE_SOURCES:
        log(f"  ⬇️ 下载排除源: {url}")
        content = fetch_rules(url)
        if not content:
            continue
        domains = parse_domains(content)
        log(f"     └─ 提取到 {len(domains)} 个域名")
        all_domains |= domains
    return all_domains


# ==================== 目标文件清洗 ====================
def clean_target_file(path: str, exclude: Set[str]) -> dict:
    """清洗单个目标文件，返回统计信息。"""
    stats = {"orig": 0, "removed": 0, "kept": 0}
    if not os.path.exists(path):
        log(f"  ⚠️ 文件不存在: {path}", C.Y)
        return stats

    with open(path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    output = []
    in_marker_block = False

    for line in lines:
        s = line.strip()

        # ---- 清理旧版注入块（幂等性保证） ----
        if MARKER_START in s:
            in_marker_block = True
            continue
        if MARKER_END in s:
            in_marker_block = False
            continue
        if in_marker_block:
            continue

        # ---- 注释与空行直接保留 ----
        if not s or s[0] in '![':
            output.append(line)
            continue

        stats["orig"] += 1

        # ---- 提取该行域名 ----
        domain = ""
        m = RE_ADGUARD.match(s)
        if m:
            domain = _normalize_domain(m.group(1))
        else:
            m = RE_HOSTS.match(s)
            if m:
                domain = m.group(1).lower()

        # ---- 命中排除集合则剔除 ----
        if domain and domain in exclude:
            stats["removed"] += 1
            continue

        output.append(line)
        stats["kept"] += 1

    # ---- 更新头部 Total count ----
    if UPDATE_TOTAL_COUNT:
        for i, l in enumerate(output):
            if l.startswith("! Total count:"):
                output[i] = f"! Total count: {stats['kept']}\n"
                break

    with open(path, 'w', encoding='utf-8') as f:
        f.writelines(output)

    return stats


# ==================== README 更新 ====================
def update_readme(total_kept: int):
    """更新 README.md 中的数量统计文本。"""
    if not UPDATE_README:
        return
    if not os.path.exists(README_FILE):
        log(f"  ⚠️ {README_FILE} 不存在，跳过更新", C.Y)
        return

    with open(README_FILE, 'r', encoding='utf-8') as f:
        content = f.read()

    new_content, count = RE_README_COUNT.subn(
        lambda m: f"{m.group(1)}: {total_kept:,}", content
    )

    if count > 0:
        with open(README_FILE, 'w', encoding='utf-8') as f:
            f.write(new_content)
        log(f"  ✅ 已更新 {README_FILE}（{count} 处）", C.G)
    else:
        log(f"  ℹ️ {README_FILE} 中未找到匹配的数量统计文本", C.Y)


# ==================== 主流程 ====================
def main():
    t0 = time.time()
    log(f"\n{C.BOLD}{C.CY}🧩 自定义规则剔除器{C.E}\n")

    if not EXCLUDE_SOURCES:
        log("  ℹ️ EXCLUDE_SOURCES 为空，未配置任何排除源，脚本退出。", C.Y)
        return

    # [1/2] 构建排除集合
    log(f"{C.BOLD}📥 [1/2] 下载并解析排除源{C.E}")
    exclude = build_exclude_set()
    if not exclude:
        log("  ⚠️ 未提取到任何排除域名，跳过清洗。", C.Y)
        return
    log(f"  ✅ 排除域名集合共 {len(exclude)} 个\n")

    # [2/2] 清洗目标文件
    log(f"{C.BOLD}🧼 [2/2] 清洗目标文件{C.E}")
    t_orig = t_removed = t_kept = 0
    for fp in TARGET_FILES:
        stats = clean_target_file(fp, exclude)
        if stats["orig"] == 0 and stats["kept"] == 0:
            continue
        log(f"  ✅ {fp}: 原 {stats['orig']:,} → 保留 {stats['kept']:,} (剔除 {stats['removed']:,})")
        t_orig += stats["orig"]
        t_removed += stats["removed"]
        t_kept += stats["kept"]

    # 更新 README
    if t_kept > 0:
        update_readme(t_kept)

    # 汇总
    log(f"\n{C.BOLD}📊 剔除体检报告{C.E}")
    print(f" ├─ 原始规则总数:   {t_orig:,}", flush=True)
    print(f" ├─ 排除域名数量:   {len(exclude):,}", flush=True)
    print(f" ├─ 命中剔除规则:   {C.R}{t_removed:,}{C.E}", flush=True)
    print(f" ├─ {C.G}最终保留规则: {C.BOLD}{t_kept:,}{C.E}", flush=True)
    print(f" └─ ⏱️  总耗时:      {C.Y}{time.time() - t0:.1f} 秒{C.E}\n", flush=True)

    # GitHub Actions Summary
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], 'a', encoding='utf-8') as f:
            f.write("### 🧩 自定义规则剔除报告\n\n")
            f.write("| 项目 | 数量 |\n| --- | --- |\n")
            f.write(f"| 📥 排除域名 | `{len(exclude):,}` |\n")
            f.write(f"| 📊 原始总数 | `{t_orig:,}` |\n")
            f.write(f"| 🗑️ 命中剔除 | `{t_removed:,}` |\n")
            f.write(f"| ✅ 最终保留 | `{t_kept:,}` |\n")
            f.write(f"| ⏱️ 耗时 | `{time.time() - t0:.1f}s` |\n")
        log(f"{C.G}✅ 已生成 GitHub Actions Summary 报告！{C.E}", C.G)


if __name__ == "__main__":
    main()
