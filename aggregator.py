"""
Clash / Mihomo 节点自动聚合、清洗、测速及配置生成脚本
功能：
1. 定时拉取多个活跃公开源（支持多协议解析与镜像加速回退）；
2. 高并发多线程 TCP 连通性测速，彻底剔除死节点；
3. 过滤国内节点与垃圾广告节点，按延迟排序筛选最优质节点；
4. 输出自带 .2/.201 双网关自动切换、策略组及分流规则的完整配置文件。
"""

import base64
import concurrent.futures
import json
import re
import socket
import time
import urllib.parse
import requests
import yaml

# ==================== 配置项 ====================
SUBSCRIBE_URLS = [
    # === 原有核心稳定源 ===
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/clash.yaml",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/clash.yaml",
    "https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/all",
    "https://raw.githubusercontent.com/aiboboxx/clashfree/master/clash.yml",

    # === 新增：soroushmirzaei/telegram-configs-collector（每小时从TG频道高频采集）===
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/splitted/mixed",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/channels/protocols/vmess",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/channels/protocols/trojan",

    # === 额外补充的高质量聚合源 ===
    "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity.yml",

    # === 你自己 Fork 的 V2RayAggregator（Clash YAML 格式，若有可解开注释）===
    "https://raw.githubusercontent.com/wzapple/V2RayAggregator/master/Eternity.yml",
]

# 保留最大节点数
MAX_PROXIES = 80
TCP_TIMEOUT = 1.8        # 单个节点测速超时时间（秒）
MAX_WORKERS = 50         # 测速并发线程数

# 生成配置中的更新网关：.2 优先，.201 备用，由 OpenClash/Mihomo 检测外网连通性。
GATEWAY_GROUP_NAME = "订阅网关自动切换"
GATEWAY_NODES = [
    {"name": "2付费网关", "type": "http", "server": "192.168.0.2", "port": 7890},
    {"name": "201付费网关", "type": "http", "server": "192.168.0.201", "port": 7890},
]
GATEWAY_TEST_URL = "https://www.gstatic.com/generate_204"
GATEWAY_TEST_INTERVAL = 60   # 检测间隔，单位：秒
GATEWAY_TEST_TIMEOUT = 5000  # 每个网关检测超时，单位：毫秒


def fetch_url_content(url):
    """拉取远程源，支持镜像前缀智能回退"""
    candidate_urls = [url]
    # 对 raw.githubusercontent.com 支持主流 GitHub 加速代理
    if "raw.githubusercontent.com" in url:
        path = url.replace("https://raw.githubusercontent.com/", "")
        candidate_urls.extend([
            f"https://ghproxy.net/https://raw.githubusercontent.com/{path}",
            f"https://mirror.ghproxy.com/https://raw.githubusercontent.com/{path}",
            f"https://fastly.jsdelivr.net/gh/{path.replace('/master/', '@master/').replace('/main/', '@main/')}"
        ])

    headers = {
        "User-Agent": "ClashMeta; ClashforWindows/0.20.39; clash.meta"
    }

    for u in candidate_urls:
        try:
            resp = requests.get(u, headers=headers, timeout=10)
            if resp.status_code == 200 and len(resp.text.strip()) > 50:
                print(f"[成功] 成功获取源数据: {u[:60]}... 长度: {len(resp.text)}")
                return resp.text
        except Exception:
            continue
    print(f"[失败] 所有镜像均无法访问: {url}")
    return ""


def parse_clash_yaml(content):
    """解析 YAML 格式的 Clash 配置"""
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict) and "proxies" in data and isinstance(data["proxies"], list):
            return data["proxies"]
    except Exception:
        pass
    return []


def parse_vmess(link):
    """解析 vmess:// 链接"""
    try:
        raw = link[8:]
        padded = raw + '=' * (-len(raw) % 4)
        info = json.loads(base64.b64decode(padded).decode('utf-8', errors='ignore'))
        return {
            "name": info.get("ps", "vmess-node").strip(),
            "type": "vmess",
            "server": info.get("add"),
            "port": int(info.get("port")),
            "uuid": info.get("id"),
            "alterId": int(info.get("aid", 0)),
            "cipher": info.get("scy", "auto"),
            "network": info.get("net", "tcp"),
            "tls": True if info.get("tls") == "tls" else False
        }
    except Exception:
        return None


def parse_trojan(link):
    """解析 trojan:// 链接"""
    try:
        url = urllib.parse.urlparse(link)
        name = urllib.parse.unquote(url.fragment) if url.fragment else "trojan-node"
        return {
            "name": name.strip(),
            "type": "trojan",
            "server": url.hostname,
            "port": url.port,
            "password": url.username,
            "sni": url.hostname
        }
    except Exception:
        return None


def parse_shadowsocks(link):
    """解析 ss:// 链接"""
    try:
        url = urllib.parse.urlparse(link)
        name = urllib.parse.unquote(url.fragment) if url.fragment else "ss-node"
        userinfo = url.username
        if not url.password and userinfo:
            padded = userinfo + '=' * (-len(userinfo) % 4)
            userinfo = base64.b64decode(padded).decode('utf-8', errors='ignore')
        if ":" in userinfo:
            cipher, password = userinfo.split(":", 1)
            return {
                "name": name.strip(),
                "type": "ss",
                "server": url.hostname,
                "port": url.port,
                "cipher": cipher,
                "password": password
            }
    except Exception:
        return None


def extract_proxies_from_raw(content):
    """从原始内容提取节点列表（兼容 YAML 与 Base64 订阅）"""
    # 优先尝试 YAML
    proxies = parse_clash_yaml(content)
    if proxies:
        return proxies

    # 尝试 Base64 解码
    lines = []
    try:
        padded = content.strip() + '=' * (-len(content.strip()) % 4)
        decoded = base64.b64decode(padded).decode('utf-8', errors='ignore')
        lines = [line.strip() for line in decoded.splitlines() if line.strip()]
    except Exception:
        lines = [line.strip() for line in content.splitlines() if line.strip()]

    parsed = []
    for line in lines:
        node = None
        if line.startswith("vmess://"):
            node = parse_vmess(line)
        elif line.startswith("trojan://"):
            node = parse_trojan(line)
        elif line.startswith("ss://"):
            node = parse_shadowsocks(line)
        if node and node.get("server") and node.get("port"):
            parsed.append(node)
    return parsed


def check_proxy_tcp(proxy):
    """高并发 TCP 握手测速，返回 (proxy, 延迟ms) 元组，失败返回 None"""
    server = proxy.get("server")
    port = proxy.get("port")
    if not server or not port:
        return None

    # 过滤明显的垃圾广告节点
    name = proxy.get("name", "")
    ad_keywords = ["网站", "官网", "流量", "重置", "到期", "TG群", "通知", "群", "客服"]
    if any(k in name for k in ad_keywords):
        return None

    try:
        port = int(port)
        start = time.time()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TCP_TIMEOUT)
        s.connect((server, port))
        latency = (time.time() - start) * 1000
        s.close()
        return (proxy, latency)
    except Exception:
        return None


def main():
    print("=" * 50)
    print("开始拉取公开节点源...")
    raw_nodes = []
    for url in SUBSCRIBE_URLS:
        content = fetch_url_content(url)
        if content:
            nodes = extract_proxies_from_raw(content)
            print(f"-> 从源解析到 {len(nodes)} 个原始节点")
            raw_nodes.extend(nodes)

    print(f"\n汇总得到 {len(raw_nodes)} 个节点，去重并过滤无效节点...")
    unique_nodes = {}
    for node in raw_nodes:
        key = f"{node.get('server')}:{node.get('port')}"
        if key not in unique_nodes:
            unique_nodes[key] = node
    candidates = list(unique_nodes.values())
    print(f"去重后剩余候选节点: {len(candidates)} 个")

    print(f"\n启动 {MAX_WORKERS} 线程高并发 TCP 连通性测速 (超时: {TCP_TIMEOUT}s)...")
    valid_proxies = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(check_proxy_tcp, node) for node in candidates]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                proxy, latency = res
                valid_proxies.append((proxy, latency))

    print(f"测速完成，共存活节点: {len(valid_proxies)} 个")

    # 按延迟升序排序并格式化重命名
    valid_proxies.sort(key=lambda x: x[1])
    final_proxies = []
    used_names = set()
    for idx, (proxy, latency) in enumerate(valid_proxies[:MAX_PROXIES]):
        p_type = proxy.get("type", "").upper()
        # 命名规则：协议-延迟ms（取地区缩写）
        region = ""
        name_raw = proxy.get("name", "")
        for tag in ["HK", "TW", "SG", "JP", "US", "DE", "UK", "KR", "AU"]:
            if tag in name_raw.upper():
                region = f"{tag}-"
                break
        clean_name = f"{region}{p_type}-{int(latency)}ms"
        # 避免重名
        base_name = clean_name
        counter = 1
        while clean_name in used_names:
            clean_name = f"{base_name}-{counter}"
            counter += 1
        used_names.add(clean_name)
        proxy["name"] = clean_name
        final_proxies.append(proxy)

    if not final_proxies:
        print("[警告] 测速后无可用节点，保留原有配置不覆盖！")
        return

    # 构建包含双网关自动切换、策略组和分流规则的完整配置文件
    node_names = [p["name"] for p in final_proxies]

    # 两个网关保留为独立 HTTP 节点，由 fallback 组按可用性自动切换
    full_proxies = [gateway.copy() for gateway in GATEWAY_NODES] + final_proxies

    full_config = {
        "proxies": full_proxies,
        "proxy-groups": [
            {
                "name": "YouTube",
                "type": "select",
                "proxies": ["YouTube自动优选", GATEWAY_GROUP_NAME, "Proxies", "DIRECT"] + node_names,
            },
            {
                "name": "YouTube自动优选",
                "type": "url-test",
                "url": "https://www.youtube.com/generate_204",
                "interval": 180,
                "tolerance": 50,
                "lazy": True,
                "proxies": [gateway["name"] for gateway in GATEWAY_NODES] + node_names,
            },
            {
                "name": "GitHub",
                "type": "select",
                "proxies": ["GitHub自动优选", GATEWAY_GROUP_NAME, "Proxies", "DIRECT"] + node_names,
            },
            {
                "name": "GitHub自动优选",
                "type": "url-test",
                "url": "https://raw.githubusercontent.com",
                "interval": 300,
                "tolerance": 50,
                "lazy": True,
                "proxies": [gateway["name"] for gateway in GATEWAY_NODES] + node_names,
            },
            {
                "name": "自动选择",
                "type": "url-test",
                "url": "https://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 50,
                "proxies": node_names,
            },
            {
                "name": GATEWAY_GROUP_NAME,
                "type": "fallback",
                "proxies": [gateway["name"] for gateway in GATEWAY_NODES],
                "url": GATEWAY_TEST_URL,
                "interval": GATEWAY_TEST_INTERVAL,
                "timeout": GATEWAY_TEST_TIMEOUT,
            },
            {
                "name": "节点选择",
                "type": "select",
                "proxies": ["自动选择", GATEWAY_GROUP_NAME, "DIRECT"] + node_names,
            },
            {
                "name": "Proxies",
                "type": "select",
                "proxies": ["自动选择", GATEWAY_GROUP_NAME, "DIRECT"] + node_names,
            },
        ],
        "rules": [
            # ✅ 第一优先级：局域网 & 国内直连（必须放最前，否则后续规则全部失效！）
            "GEOIP,LAN,DIRECT",
            "GEOIP,CN,DIRECT",

            # 常用国内大流量域名直连（GEOIP,CN 兜底前的快速匹配）
            "DOMAIN-SUFFIX,bilibili.com,DIRECT",
            "DOMAIN-SUFFIX,byteoversea.com,DIRECT",
            "DOMAIN-SUFFIX,bytedance.com,DIRECT",
            "DOMAIN-SUFFIX,qq.com,DIRECT",
            "DOMAIN-SUFFIX,weixin.qq.com,DIRECT",
            "DOMAIN-SUFFIX,baidu.com,DIRECT",

            # GitHub 流量专属策略组（自动测速选优 + 双付费网关兜底）
            "DOMAIN-KEYWORD,github,GitHub",
            "DOMAIN-SUFFIX,github.com,GitHub",
            "DOMAIN-SUFFIX,github.io,GitHub",
            "DOMAIN-SUFFIX,githubusercontent.com,GitHub",
            "DOMAIN-SUFFIX,githubassets.com,GitHub",

            # YouTube 流量专属策略组（专属 204 测速选优 + 双付费网关兜底）
            "DOMAIN-KEYWORD,youtube,YouTube",
            "DOMAIN-SUFFIX,youtube.com,YouTube",
            "DOMAIN-SUFFIX,googlevideo.com,YouTube",
            "DOMAIN-SUFFIX,ytimg.com,YouTube",
            "DOMAIN-SUFFIX,youtu.be,YouTube",
            "DOMAIN-SUFFIX,ggpht.com,YouTube",

            # AI 服务定向走付费网关
            f"DOMAIN-KEYWORD,openai,{GATEWAY_GROUP_NAME}",
            f"DOMAIN-SUFFIX,chatgpt.com,{GATEWAY_GROUP_NAME}",
            f"DOMAIN-KEYWORD,anthropic,{GATEWAY_GROUP_NAME}",
            f"DOMAIN-SUFFIX,claude.ai,{GATEWAY_GROUP_NAME}",
            f"DOMAIN-KEYWORD,gemini,{GATEWAY_GROUP_NAME}",
            f"DOMAIN-SUFFIX,bard.google.com,{GATEWAY_GROUP_NAME}",

            # 海外流媒体 & 社交走免费节点代理池
            "DOMAIN-SUFFIX,google.com,Proxies",
            "DOMAIN-SUFFIX,twitter.com,Proxies",
            "DOMAIN-SUFFIX,x.com,Proxies",
            "DOMAIN-SUFFIX,telegram.org,Proxies",
            "DOMAIN-SUFFIX,t.me,Proxies",
            "DOMAIN-SUFFIX,netflix.com,Proxies",
            "DOMAIN-SUFFIX,instagram.com,Proxies",
            "DOMAIN-SUFFIX,facebook.com,Proxies",

            # 兜底：其余流量走代理
            "MATCH,Proxies",
        ],
    }

    with open("config.yaml", "w", encoding="utf-8") as f:
        yaml.dump(full_config, f, allow_unicode=True, sort_keys=False)
    print(f"\n[完成] 成功写入完整配置至 config.yaml，包含 {len(full_proxies)} 个节点！")


if __name__ == "__main__":
    main()
