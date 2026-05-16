import requests, socket, time, re, json, os
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# ==================== 用户配置区（按需修改） ====================
TEST_URL = "http://connectivitycheck.platform.hicloud.com/generate_204"
TCP_TIMEOUT = 3          # TCP 连通测试超时(秒)
HTTP_TIMEOUT = 8         # HTTP 代理测试超时(秒)
MAX_LATENCY_MS = 5000    # 最大可接受延迟(毫秒)
VALID_STATUS = {200, 204, 301, 302}
MAX_WORKERS = 80         # 并发验证线程数
TOP_N = 30               # PAC 中保留的代理数（按延迟取最快）

# 代理抓取源：支持 JSON数组 / 纯文本 ip:port / 带协议头的URL
SOURCES = [
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.json",
    "https://api.proxyscrape.com/v2/?request=get&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
]
# ==================== 配置区结束 ====================

def fetch_sources():
    raw = []
    for url in SOURCES:
        try:
            r = requests.get(url, timeout=20)
            if r.status_code != 200:
                print(f"[SKIP] {url} -> HTTP {r.status_code}")
                continue
            text = r.text.strip()
            if not text:
                continue
            ct = r.headers.get('content-type', '')
            if 'json' in ct or text.startswith('[') or text.startswith('{'):
                try:
                    data = json.loads(text)
                    if isinstance(data, list):
                        for item in data:
                            if isinstance(item, dict):
                                proto = item.get('protocol', 'http')
                                host = item.get('ip') or item.get('host')
                                port = item.get('port')
                                if host and port:
                                    raw.append(f"{proto}://{host}:{port}")
                            elif isinstance(item, str) and re.match(r'\d+\.\d+\.\d+\.\d+:\d+', item):
                                raw.append(f"http://{item}")
                    elif isinstance(data, dict):
                        for key in ['proxies', 'data', 'list']:
                            if key in data and isinstance(data[key], list):
                                for p in data[key]:
                                    if isinstance(p, dict):
                                        proto = p.get('protocol', 'http')
                                        host = p.get('ip') or p.get('host')
                                        port = p.get('port')
                                        if host and port:
                                            raw.append(f"{proto}://{host}:{port}")
                except Exception as e:
                    print(f"[JSON_ERR] {url}: {e}")
            else:
                for line in text.splitlines():
                    line = line.strip()
                    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$', line):
                        raw.append(f"http://{line}")
        except Exception as e:
            print(f"[FETCH_ERR] {url}: {e}")
    seen = set()
    result = []
    for p in raw:
        if p not in seen:
            seen.add(p)
            result.append(p)
    return result

def tcp_check(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TCP_TIMEOUT)
        t0 = time.time()
        s.connect((host, int(port)))
        lat = (time.time() - t0) * 1000
        s.close()
        return True, lat
    except Exception:
        return False, 99999

def proxy_check(proxy_url):
    try:
        proxies = {"http": proxy_url, "https": proxy_url}
        t0 = time.time()
        r = requests.get(TEST_URL, proxies=proxies, timeout=HTTP_TIMEOUT, allow_redirects=False)
        lat = (time.time() - t0) * 1000
        if r.status_code in VALID_STATUS and lat <= MAX_LATENCY_MS:
            return True, lat, r.status_code
        return False, lat, r.status_code
    except Exception as e:
        return False, 99999, str(e)

def validate_one(proxy_url):
    parsed = urlparse(proxy_url)
    host, port = parsed.hostname, parsed.port
    if not host or not port:
        return None
    ok, _ = tcp_check(host, port)
    if not ok:
        return None
    ok, lat, status = proxy_check(proxy_url)
    if ok:
        return {
            "url": proxy_url,
            "scheme": parsed.scheme if parsed.scheme else "http",
            "host": host,
            "port": port,
            "latency": round(lat, 2),
            "status": status
        }
    return None

print("=" * 60)
print("[1/4] Fetching proxy sources...")
candidates = fetch_sources()
print(f"      Total unique proxies fetched: {len(candidates)}")

print("[2/4] Validating proxies (TCP + HTTP)...")
alive = []
dead = 0
with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
    futures = {ex.submit(validate_one, p): p for p in candidates}
    for future in as_completed(futures):
        res = future.result()
        if res:
            alive.append(res)
            print(f"      ✓ ALIVE {res['url']} | {res['latency']}ms | HTTP {res['status']}")
        else:
            dead += 1

print(f"[3/4] Validation complete: {len(alive)} alive / {dead} dead")

alive.sort(key=lambda x: x['latency'])
selected = alive[:TOP_N]
print(f"      Selected top {len(selected)} proxies by latency")

proxy_directives = []
for item in selected:
    scheme = item['scheme']
    host = item['host']
    port = item['port']
    if scheme == 'socks5':
        proxy_directives.append(f"SOCKS5 {host}:{port}")
    elif scheme == 'socks4':
        proxy_directives.append(f"SOCKS {host}:{port}")
    else:
        proxy_directives.append(f"PROXY {host}:{port}")

proxy_chain = "; ".join(proxy_directives) + "; DIRECT" if proxy_directives else "DIRECT"

pac_content = f"""function FindProxyForURL(url, host) {{
    if (shExpMatch(host, "*.cn") ||
        shExpMatch(host, "*.com.cn") ||
        shExpMatch(host, "*.gov.cn") ||
        shExpMatch(host, "*.edu.cn") ||
        isInNet(host, "10.0.0.0", "255.0.0.0") ||
        isInNet(host, "172.16.0.0", "255.240.0.0") ||
        isInNet(host, "192.168.0.0", "255.255.0.0") ||
        isInNet(host, "127.0.0.0", "255.255.255.0") ||
        isPlainHostName(host)) {{
        return "DIRECT";
    }}
    return "{proxy_chain}";
}}"""

os.makedirs("output", exist_ok=True)
with open("output/proxy.pac", "w", encoding="utf-8") as f:
    f.write(pac_content)

with open("output/proxy_list.txt", "w", encoding="utf-8") as f:
    f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    f.write(f"# Test URL: {TEST_URL}\n")
    f.write(f"# Criteria: TCP<{TCP_TIMEOUT}s, HTTP<{HTTP_TIMEOUT}s, Latency<{MAX_LATENCY_MS}ms, Status in {VALID_STATUS}\n")
    f.write("-" * 50 + "\n")
    for item in selected:
        f.write(f"{item['url']} | {item['latency']}ms | HTTP {item['status']}\n")

summary = f"Fetched {len(candidates)}, Alive {len(alive)}, Selected {len(selected)}"
gh_out = os.environ.get('GITHUB_OUTPUT', '/dev/null')
with open(gh_out, 'a') as fh:
    print(f"summary={summary}", file=fh)

print(f"[4/4] {summary}")
print("      Files written: output/proxy.pac , output/proxy_list.txt")
print("=" * 60)
