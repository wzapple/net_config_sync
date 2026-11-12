# -*- coding: utf-8 -*-
"""
GitHub 免费 Clash 节点自动抓取与清洗工具
功能：定时拉取公开源、解析 Base64/YAML、去除重复与无效节点、输出标准 Proxy Provider
"""

import base64
import json
import re
import urllib.parse
import requests
import yaml

# 长期维护的免费节点源池（可自行追加或替换为你找到的高质量源）
SOURCE_URLS = [
    # 示例源：包含每日更新的 Clash YAML 格式源或 Base64 订阅源
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/clash.yaml",
]

OUTPUT_FILE = "free_proxies.yaml"


def fetch_url_content(url):
    """安全拉取远程内容，设置超时与防封请求头"""
    headers = {
        "User-Agent": "ClashforWindows/0.20.39 (Clash-Auto-Collector)"
    }
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            return resp.text
    except Exception as e:
        print(f"[警告] 拉取源失败 {url}: {e}")
    return None


def parse_vmess(link):
    """解析 vmess:// 链接为 Clash 代理字典"""
    try:
        raw_b64 = link[8:]
        # 补全 Base64 填充
        raw_b64 += "=" * ((4 - len(raw_b64) % 4) % 4)
        data = json.loads(base64.b64decode(raw_b64).decode("utf-8", errors="ignore"))
        return {
            "name": f"VMess_{data.get('ps', 'FreeNode')}".replace(":", "_"),
            "type": "vmess",
            "server": data.get("add"),
            "port": int(data.get("port")),
            "uuid": data.get("id"),
            "alterId": int(data.get("aid", 0)),
            "cipher": "auto",
            "tls": True if data.get("tls") == "tls" else False,
            "network": data.get("net", "tcp"),
            "ws-opts": {"path": data.get("path", "/")} if data.get("net") == "ws" else None,
        }
    except Exception:
        return None


def parse_trojan(link):
    """解析 trojan:// 链接为 Clash 代理字典"""
    try:
        url_obj = urllib.parse.urlparse(link)
        query = urllib.parse.parse_qs(url_obj.query)
        name = urllib.parse.unquote(url_obj.fragment) or "Trojan_Free"
        return {
            "name": f"Trojan_{name}".replace(":", "_"),
            "type": "trojan",
            "server": url_obj.hostname,
            "port": int(url_obj.port),
            "password": url_obj.username,
            "sni": query.get("sni", [url_obj.hostname])[0],
            "skip-cert-verify": True,
        }
    except Exception:
        return None


def extract_proxies_from_raw(text):
    """根据文本类型智能提取节点"""
    proxies = []

    # 1. 尝试作为 YAML 解析 (Clash 配置文件格式)
    try:
        yaml_data = yaml.safe_load(text)
        if isinstance(yaml_data, dict) and "proxies" in yaml_data:
            return yaml_data["proxies"]
    except Exception:
        pass

    # 2. 尝试作为 Base64 订阅解析
    decoded_text = text
    try:
        padding = "=" * ((4 - len(text.strip()) % 4) % 4)
        decoded_text = base64.b64decode(text.strip() + padding).decode("utf-8", errors="ignore")
    except Exception:
        pass

    # 3. 按行解析协议单链接
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


def deduplicate_proxies(proxies):
    """按 服务器IP/域名 + 端口 去重，防止冗余节点"""
    seen = set()
    unique = []
    for p in proxies:
        if not p.get("server") or not p.get("port"):
            continue
        key = f"{p['server']}:{p['port']}"
        if key not in seen:
            seen.add(key)
            # 处理节点重名问题
            p["name"] = f"[{len(unique)+1:03d}] {p.get('name', 'Node')}"
            unique.append(p)
    return unique


def main():
    print("=== 开始并发抓取远程节点 ===")
    all_proxies = []

    for url in SOURCE_URLS:
        print(f"正在拉取: {url}")
        content = fetch_url_content(url)
        if content:
            extracted = extract_proxies_from_raw(content)
            print(f"-> 成功提取节点数: {len(extracted)}")
            all_proxies.extend(extracted)

    # 去重与清洗
    valid_proxies = deduplicate_proxies(all_proxies)
    print(f"=== 清洗完毕，去重后有效节点数: {len(valid_proxies)} ===")

    # 输出为标准的 Clash Proxy Provider 格式
    provider_dict = {
        "proxies": valid_proxies
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        yaml.dump(provider_dict, f, allow_unicode=True, sort_keys=False)

    print(f"配置文件已生成至: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
