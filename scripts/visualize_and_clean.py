import os, re, time, gzip, json, threading
import dns.resolver
import dns.exception
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ============ 0. 环境自适应 ============
IS_CI = os.getenv("GITHUB_ACTIONS") == "true"
if os.name == 'nt' and not IS_CI: os.system('')

class C:
    R, G, Y, B, CY, E = ("", "", "", "", "", "") if IS_CI else ("\033[91m", "\033[92m", "\033[93m", "\033[94m", "\033[96m", "\033[0m")
    BOLD = "" if IS_CI else "\033[1m"

log = lambda m, c=C.B: print(f"{c}{m}{C.E}", flush=True)

# ============ 1. 核心配置 ============
# 待清洗的规则文件（按你仓库实际结构修改）
FILES = ["Release/combined-rules.txt"]

CACHE_FILE = "dns_cache.json.gz"

# 并发与超时（runner 仅 2 核，500 是经验值；800 会打爆 DNS 解析器导致集体超时）
MAX_WORKERS   = 500
DNS_TIMEOUT   = 3.0
# 心跳间隔：无论是否有结果返回都按时打印，避免"假死"观感
HEARTBEAT_SEC = 10

# 缓存有效期（天）：alive 域名 7 天复检一次，dead 域名 3 天再确认一次
CACHE_ALIVE_DAYS, CACHE_DEAD_DAYS = 7, 3

# AdGuard 规则域名提取正则（必须转义 ||，否则提取全失败）
RE_DOMAIN = re.compile(r'^\|\|([^\^/\s*]+)')

# 顶级域名通配匹配：*.com、*.net、*.xn--xxx 等一律跳过，避免大面积误杀
RE_TLD_WILDCARD     = re.compile(r'^\*\.[a-zA-Z]{2,6}$')
RE_IDN_TLD_WILDCARD = re.compile(r'^\*\.xn--[a-zA-Z0-9-]+$')


def is_bad_tld_wildcard(rule: str) -> bool:
    """跳过形如 *.com、*.net、*.xn--xxx 等顶级域名通配，避免大面积误杀。"""
    s = rule.split('!')[0].split('#')[0].strip()
    if not s:
        return False

    # hosts 格式：0.0.0.0 *.com / 127.0.0.1 *.com / :: *.com
    parts = s.split()
    if len(parts) >= 2 and parts[0] in ('0.0.0.0', '127.0.0.1', '::'):
        s = parts[1]

    # 去掉 AdGuard / ABP 前缀
    if s.startswith('@@||'):
        s = s[4:]
    elif s.startswith('||'):
        s = s[2:]
    elif s.startswith('@@'):
        s = s[2:]

    # 去掉修饰符、结尾 ^、路径、端口
    s = s.split('$')[0].strip()
    if s.endswith('^'):
        s = s[:-1]
    s = s.split('/')[0].split(':')[0].strip().lower()

    # 跳过形如 *.com、*.net 等顶级域名通配
    if RE_TLD_WILDCARD.match(s):
        return True
    # 跳过国际化顶级域名通配（如 *.xn--xxx）
    if RE_IDN_TLD_WILDCARD.match(s):
        return True
    return False


# ============ 2. 域名提取与 DNS 查询 ============
def extract_domain(rule):
    """
    从单条规则中提取主域名。
    - AdGuard 格式：||example.com^ → example.com
    - 返回 None 表示该行没有可提取的域名（注释、空行、纯通配等）
    """
    rule = rule.strip()
    if not rule or rule[0] in '![@#':
        return None
    m = RE_DOMAIN.match(rule)
    if m and m.group(1):
        # 清理非域名字符，去掉端口
        d = re.sub(r'[^a-zA-Z0-9.-]', '', m.group(1).split(':')[0])
        if '.' in d:
            return d
    return None


def check_dns(domain):
    """
    对单个域名做 DNS A 记录查询。
    返回 (domain, alive: bool)

    判死策略（保守优先）：
    - NXDOMAIN          → 死刑（唯一死刑）
    - 其它任何异常/超时 → 视为存活，保留，避免因网络抖动误杀有效规则
    """
    try:
        dns.resolver.resolve(domain, 'A', lifetime=DNS_TIMEOUT)
        return domain, True
    except dns.resolver.NXDOMAIN:
        return domain, False
    except Exception:
        # Timeout / NoNameservers / NoAnswer / 未知异常 一律保守保留
        return domain, True


def load_cache():
    """从 gzip 压缩的 JSON 中读取历史 DNS 查询结果，不存在或损坏则返回空字典。"""
    if os.path.exists(CACHE_FILE):
        try:
            with gzip.open(CACHE_FILE, 'rt', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    return {}


# ============ 3. 主流程 ============
def main():
    t0 = time.time()
    log(f"\n{C.BOLD}{C.CY}🧹 死链清洗与 DNS 缓存生成{C.E}\n")

    # ---------- 3.1 读取规则文件、提取域名 ----------
    log(f"{C.BOLD}📖 [1/3] 读取规则与域名提取{C.E}")
    all_domains, file_data = set(), {}

    for fp in FILES:
        if not os.path.exists(fp):
            log(f"  ⚠️ 文件不存在，跳过: {fp}", C.Y)
            continue

        with open(fp, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        # 拆分头部注释/空行 与 实际规则行，便于回写时保持头部整洁
        hdr, rules, r_map, u_doms = [], [], {}, set()
        for line in lines:
            s = line.strip()
            (hdr if not s or s[0] in '![' else rules).append(line)

        # 对每条规则提取域名，建立"整行 → 域名"的映射，方便后续判死
        for r in rules:
            d = extract_domain(r)
            if d:
                r_map[r.strip()] = d
                u_doms.add(d)

        file_data[fp] = {
            'hdr': hdr,          # 头部（注释、空行）
            'rules': rules,      # 原始规则行
            'map': r_map,        # 规则内容 → 域名
            'orig': len(rules),  # 原始规则数（用于统计）
        }
        all_domains |= u_doms

    if not all_domains:
        log(f"  ⚠️ 未提取到任何域名，退出。", C.Y)
        return

    log(f"  ✅ 共提取 {len(all_domains)} 个唯一域名")

    # ---------- 3.2 缓存命中判定，分离需查询域名 ----------
    log(f"{C.BOLD}💾 [2/3] 缓存命中与 DNS 查询{C.E}")
    cache, now, to_check = load_cache(), datetime.now(), set()

    for d in all_domains:
        if d in cache:
            try:
                days = (now - datetime.fromtimestamp(cache[d]['time'])).days
                # alive 用长 TTL，dead 用短 TTL（定期复检，避免误判长期生效）
                if (cache[d]['alive'] and days < CACHE_ALIVE_DAYS) or \
                   (not cache[d]['alive'] and days < CACHE_DEAD_DAYS):
                    continue
            except Exception:
                pass
        to_check.add(d)

    log(f"  💾 缓存命中 {len(all_domains) - len(to_check)} 个，需查询 {len(to_check)} 个")
    if len(to_check) > 50000:
        log(f"  ⚠️ 需查询量巨大（多半是首次运行无缓存），耗时较长属正常，心跳会持续播报...", C.Y)

    # ---------- 3.3 并发 DNS 查询（带独立心跳线程） ----------
    dead_set = set()
    if to_check:
        total, done = len(to_check), 0
        lock = threading.Lock()
        stop_evt = threading.Event()

        def heartbeat():
            # 独立线程按时打印，不依赖任务是否返回，杜绝"假死"
            while not stop_evt.wait(HEARTBEAT_SEC):
                with lock:
                    cur = done
                log(f"  🔄 进度: {cur}/{total} ({cur/total*100:.1f}%) | 死链: {len(dead_set)}", C.CY)

        threading.Thread(target=heartbeat, daemon=True).start()
        t_dns = time.time()
        try:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as exe:
                futs = [exe.submit(check_dns, d) for d in to_check]
                for f in as_completed(futs):
                    domain, alive = f.result()
                    if not alive:
                        dead_set.add(domain)
                    cache[domain] = {'alive': alive, 'time': now.timestamp()}
                    with lock:
                        done += 1
        finally:
            stop_evt.set()

        log(f"  ✅ DNS 检查完成，耗时 {time.time() - t_dns:.0f}s，发现 {len(dead_set)} 个死链", C.G)

        # ---------- 3.4 缓存持久化（gzip 压缩的 JSON） ----------
        try:
            with gzip.open(CACHE_FILE, 'wt', encoding='utf-8') as f:
                json.dump(cache, f, separators=(',', ':'))
            log(f"  💾 缓存已保存: {CACHE_FILE}（{len(cache)} 条记录）", C.G)
        except Exception as e:
            log(f"  ⚠️ 保存缓存失败: {e}", C.Y)

    # ---------- 3.5 规则清洗：剔除死链 + 去重 + 跳过 TLD 通配 ----------
    log(f"{C.BOLD}🧼 [3/3] 规则清洗与去重{C.E}")
    t_orig = t_dead = t_dup = t_tld = t_final = 0

    for fp, data in file_data.items():
        seen, clean, dead, dup, tld_skip = set(), [], 0, 0, 0

        for r in data['rules']:
            s = r.strip()

            # 跳过形如 *.com、*.net 等顶级域名通配（会造成大面积误杀）
            if is_bad_tld_wildcard(s):
                tld_skip += 1
                continue

            # 剔除死链（匹配到域名且该域名在 dead_set 中）
            if s in data['map'] and data['map'][s] in dead_set:
                dead += 1
                continue

            # 去重（基于整行内容）
            if s not in seen:
                clean.append(r)
                seen.add(s)
            else:
                dup += 1

        # 更新头部 ! Total count: 行（如果存在）
        for i, h in enumerate(data['hdr']):
            if h.startswith("! Total count:"):
                data['hdr'][i] = f"! Total count: {len(clean)}\n"
                break

        # 回写文件
        with open(fp, 'w', encoding='utf-8') as f:
            f.writelines(data['hdr'])
            f.writelines(clean)

        log(f"  ✅ {fp}: 原 {data['orig']:,} → 保留 {len(clean):,} "
            f"(死链 {dead:,} / 去重 {dup:,} / TLD通配 {tld_skip:,})")

        t_orig += data['orig']
        t_dead += dead
        t_dup  += dup
        t_tld  += tld_skip
        t_final += len(clean)

    # ---------- 3.6 汇总报告 ----------
    log(f"\n{C.BOLD}📊 清洗体检报告{C.E}")
    print(f" ├─ 原始规则总数:   {t_orig:,}", flush=True)
    print(f" ├─ 死链剔除:       {C.R}{t_dead:,}{C.E}", flush=True)
    print(f" ├─ 规则去重:       {C.Y}{t_dup:,}{C.E}", flush=True)
    print(f" ├─ TLD 通配剔除:   {C.Y}{t_tld:,}{C.E}", flush=True)
    print(f" ├─ {C.G}最终保留规则: {C.BOLD}{t_final:,}{C.E}", flush=True)
    print(f" └─ ⏱️  总耗时:      {C.Y}{time.time() - t0:.1f} 秒{C.E}\n", flush=True)

    # ---------- 3.7 写入 GitHub Actions Summary ----------
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], 'a', encoding='utf-8') as f:
            f.write(f"### 🧹 死链清洗与 DNS 缓存报告\n\n")
            f.write(f"| 项目 | 数量 |\n| --- | --- |\n")
            f.write(f"| 📥 原始总数 | `{t_orig:,}` |\n")
            f.write(f"| 💀 死链剔除 | `{t_dead:,}` |\n")
            f.write(f"| 🔄 去重剔除 | `{t_dup:,}` |\n")
            f.write(f"| 🌐 TLD通配剔除 | `{t_tld:,}` |\n")
            f.write(f"| ✅ 最终保留 | `{t_final:,}` |\n")
            f.write(f"| ⏱️ 耗时 | `{time.time() - t0:.1f}s` |\n")
        log(f"{C.G}✅ 已生成 GitHub Actions Summary 报告！{C.E}", C.G)


if __name__ == "__main__":
    main()
