# -*- coding: utf-8 -*-
"""
GitHub 免费 Clash 节点自动抓取、清洗与并发健康测速工具
功能：
1. 定时拉取多个活跃公开源（支持多协议解析与镜像加速回退）；
2. 高并发多线程 TCP 连通性测速，彻底剔除死节点；
3. 过滤国内节点与垃圾广告节点，按延迟排序筛选最优质节点；
4. 输出自带 .2/.201 双网关自动切换、策略组及防蹭网隔离规则的完整配置文件。
"""

import base64
import json
import re
import socket
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import yaml

# 活跃的高质量免费节点源池（涵盖 Clash YAML、Base64 等格式）
SOURCE_URLS = [
    # === 原有 5 个源（保留）===
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/clash.yaml",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/clash.yaml",
    "https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/all",

    # === 新增：soroushmirzaei/telegram-configs-collector（每小时从TG频道采集）===
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/splitted/mixed",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/channels/protocols/vmess",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/channels/protocols/trojan",

    # === 额外补充高质量源 ===
    "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity.yml",
]

# GitHub 加速镜像前缀（直连拉取失败时自动降级尝试）
MIRRORS = [
    "https://gh-proxy.com/",
    "https://ghproxy.cn/",
]

OUTPUT_FILE = "config.yaml"
MAX_NODES = 30           # 最终保留的最优活节点数量
TCP_TIMEOUT = 1.8        # 单个节点测速超时时间（秒）
MAX_WORKERS = 50         # 测速并发线程数

# 生成配置中的更新网关：.2 优先，.201 备用，由 OpenClash/Mihomo 检测外网连通性。
GATEWAY_GROUP_NAME = "订阅网关自动切换"
GATEWAY_NODES = [
    {"name": "2付费网关", "type": "http", "server": "192.168.0.2", "port": 7890},
    {"name": "201付费网关", "type": "http", "server": "192.168.0.201", "port": 7890},
]
GATEWAY_TEST_URL = "https://www.gstatic.com/generate_204"
GATEWAY_TEST_INTERVAL = 60  # 检测间隔，单位：秒
GATEWAY_TEST_TIMEOUT = 5000  # 每个网关检测超时，单位：毫秒


def fetch_url_content(url):
    """拉取远程源，支持镜像前缀智能回退"""
    candidate_urls = [url]
    for mirror in MIRRORS:
        if "raw.githubusercontent.com" in url:
            candidate_urls.append(mirror + url)

    headers = {
        "User-Agent": "ClashforWindows/0.20.39 (Clash-Auto-Collector)"
    }

    for target_url in candidate_urls:
        try:
            resp = requests.get(target_url, headers=headers, timeout=12)
            if resp.status_code == 200 and resp.text.strip():
                return resp.text
        except Exception:
            continue
    print(f"[警告] 无法拉取源: {url}")
    return None


def parse_vmess(link):
    """解析 vmess:// 链接"""
    try:
        raw_b64 = link[8:].strip()
        raw_b64 += "=" * ((4 - len(raw_b64) % 4) % 4)
        data = json.loads(base64.b64decode(raw_b64).decode("utf-8", errors="ignore"))
        server = data.get("add", "").strip()
        port = int(data.get("port", 0))
        if not server or not port:
            return None
        return {
            "name": f"VMess_{data.get('ps', 'Node')}".replace(":", "_"),
            "type": "vmess",
            "server": server,
            "port": port,
            "uuid": data.get("id"),
            "alterId": int(data.get("aid", 0)),
            "cipher": "auto",
            "tls": True if str(data.get("tls")).lower() in ["tls", "1", "true"] else False,
            "network": data.get("net", "tcp"),
            "ws-opts": {"path": data.get("path", "/")} if data.get("net") == "ws" else None,
            "udp": True,
        }
    except Exception:
        return None


def parse_trojan(link):
    """解析 trojan:// 链接"""
    try:
        url_obj = urllib.parse.urlparse(link.strip())
        server = url_obj.hostname
        port = int(url_obj.port or 443)
        if not server or not port:
            return None
        query = urllib.parse.parse_qs(url_obj.query)
        name = urllib.parse.unquote(url_obj.fragment) or "Trojan_Node"
        return {
            "name": f"Trojan_{name}".replace(":", "_"),
            "type": "trojan",
            "server": server,
            "port": port,
            "password": url_obj.username,
            "sni": query.get("sni", [server])[0],
            "skip-cert-verify": True,
            "udp": True,
        }
    except Exception:
        return None


def extract_proxies_from_raw(text):
    """从源内容中提取节点字典"""
    proxies = []

    # 1. 尝试作为 YAML 解析 (Clash 格式)
    try:
        yaml_data = yaml.safe_load(text)
        if isinstance(yaml_data, dict) and "proxies" in yaml_data:
            for p in yaml_data["proxies"]:
                if isinstance(p, dict) and p.get("server") and p.get("port"):
                    proxies.append(p)
            if proxies:
                return proxies
    except Exception:
        pass

    # 2. 尝试作为 Base64 订阅解析
    decoded_text = text
    try:
        clean = re.sub(r"\s+", "", text)
        clean += "=" * ((4 - len(clean) % 4) % 4)
        decoded_text = base64.b64decode(clean).decode("utf-8", errors="ignore")
    except Exception:
        pass

    # 3. 按行解析单链接
    for line in decoded_text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("vmess://"):
            node = parse_vmess(line)
            if node:
                proxies.append(node)
        elif line.startswith("trojan://"):
            node = parse_trojan(line)
            if node:
                proxies.append(node)

    return proxies


def test_tcp_ping(node):
    """测试单个节点的 TCP 端口连通性与握手延迟"""
    server = node.get("server")
    port = node.get("port")
    try:
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TCP_TIMEOUT)
        result = sock.connect_ex((server, int(port)))
        sock.close()
        if result == 0:
            delay_ms = int((time.time() - start_time) * 1000)
            return (node, delay_ms)
    except Exception:
        pass
    return None


def is_junk_or_domestic_node(name):
    """过滤国内不能出海的节点及垃圾广告"""
    junk_keywords = [
        "中国", "移动", "联通", "电信", "回国", "直连",
        "官网", "群", "返利", "购买", "剩余", "到期", "测试", "通知"
    ]
    for kw in junk_keywords:
        if kw in name:
            return True
    return False


def main():
    print("=== 开始并发抓取远程节点池 ===")
    all_proxies = []

    for url in SOURCE_URLS:
        print(f"-> 正在拉取: {url}")
        content = fetch_url_content(url)
        if content:
            extracted = extract_proxies_from_raw(content)
            print(f"   提取原始节点数: {len(extracted)}")
            all_proxies.extend(extracted)

    # 1. IP+端口初步去重
    seen = set()
    deduped_proxies = []
    for p in all_proxies:
        server = p.get("server")
        port = p.get("port")
        if not server or not port:
            continue
        key = f"{server}:{port}"
        if key not in seen:
            seen.add(key)
            deduped_proxies.append(p)

    print(f"=== 初步去重后待测速候选节点: {len(deduped_proxies)} 个 ===")
    if not deduped_proxies:
        print("[错误] 未抓取到任何候选节点，跳过更新！")
        return

    # 2. 多线程高并发 TCP 握手测速（核心过滤死节点）
    print(f"=== 正在进行高并发 TCP 连通性测速 (线程数: {MAX_WORKERS}) ===")
    alive_nodes = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(test_tcp_ping, node) for node in deduped_proxies]
        for f in as_completed(futures):
            res = f.result()
            if res:
                alive_nodes.append(res)

    print(f"=== 测速完成！真实连通活节点数: {len(alive_nodes)} / {len(deduped_proxies)} ===")

    # 3. 按延迟升序排序并过滤垃圾广告/国内无效节点
    alive_nodes.sort(key=lambda x: x[1])

    final_proxies = []
    for node, delay in alive_nodes:
        original_name = node.get("name", "Node")
        if is_junk_or_domestic_node(original_name):
            continue

        # 重新美化节点名称：带序号与真实延迟提示
        clean_name = re.sub(r"^\[\d+\]\s*", "", original_name)
        node["name"] = f"[{len(final_proxies)+1:02d}] ⚡{delay}ms - {clean_name}"
        final_proxies.append(node)

        if len(final_proxies) >= MAX_NODES:
            break

    print(f"=== 最终精选优质活节点数: {len(final_proxies)} 个 ===")

    if not final_proxies:
        print("[警告] 测速后无可用节点，保留原有配置不覆盖！")
        return

    # 4. 构建包含双网关自动切换、策略组和原有规则的完整配置文件
    node_names = [p["name"] for p in final_proxies]

    # 两个网关均保留为独立 HTTP 节点，由下方 fallback 组按可用性选择。
    full_proxies = [gateway.copy() for gateway in GATEWAY_NODES] + final_proxies

    full_config = {
        "proxies": full_proxies,
        "proxy-groups": [
            {
                "name": "Proxies",
                "type": "select",
                "proxies": ["自动选择"] + node_names,
            },
            {
                "name": "自动选择",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
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
                "lazy": False,
                "max-failed-times": 1,
            },
        ],
        "rules": [
            # 1. 局域网其他人的设备（192.168.0.X），访问 GitHub 强制走免费策略组 Proxies
            "SRC-IP-CIDR,192.168.0.0/24,Proxies",

            # 2. 软路由本机更新拉取 GitHub，走双网关自动切换组
            f"DOMAIN-KEYWORD,github,{GATEWAY_GROUP_NAME}",
            f"DOMAIN-SUFFIX,githubusercontent.com,{GATEWAY_GROUP_NAME}",

            # 3. 订阅转换服务器使用双网关兜底
            f"DOMAIN-SUFFIX,dler.io,{GATEWAY_GROUP_NAME}",
            f"DOMAIN-SUFFIX,wcc.best,{GATEWAY_GROUP_NAME}",
            f"DOMAIN-SUFFIX,id9.cc,{GATEWAY_GROUP_NAME}",
            f"DOMAIN-SUFFIX,v1.mk,{GATEWAY_GROUP_NAME}",

            # 4. OpenAI / Gemini 使用相同的双网关切换组
            f"DOMAIN-KEYWORD,openai,{GATEWAY_GROUP_NAME}",
            f"DOMAIN-SUFFIX,chatgpt.com,{GATEWAY_GROUP_NAME}",
            f"DOMAIN-KEYWORD,gemini,{GATEWAY_GROUP_NAME}",
            f"DOMAIN-SUFFIX,bard.google.com,{GATEWAY_GROUP_NAME}",

            # 5. 国内及局域网直连
            "GEOIP,LAN,DIRECT",
            "GEOIP,CN,DIRECT",
            "MATCH,Proxies",
        ],
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        yaml.dump(full_config, f, allow_unicode=True, sort_keys=False)

    print(f"=== 成功生成完整高质量配置文件: {OUTPUT_FILE} ===")


if __name__ == "__main__":
    main()
