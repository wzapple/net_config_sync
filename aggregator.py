"""
Clash / Mihomo 节点自动聚合、清洗、测速及配置生成脚本
功能：
1. 定时拉取多个活跃公开源（支持多协议解析与镜像加速回退）；
2. 多线程 TCP 预筛选候选节点，不将握手成功视为代理可用；
3. 生成按站点主动检测的 OpenClash / Mihomo 策略组。
"""

import base64
import concurrent.futures
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import tempfile
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

MAX_PROXIES = 80
TCP_TIMEOUT = 2
MAX_WORKERS = 32
PROBE_TIMEOUT_MS = 6000
TARGETS = {
    "Google": ("https://www.google.com/generate_204", "204"),
    "Telegram": ("https://web.telegram.org/", "200"),
    "YouTube自动优选": ("https://www.youtube.com/generate_204", "204"),
    "GitHub自动优选": ("https://raw.githubusercontent.com/wzapple/net_config_sync/main/requirements.txt", "200"),
    "自动选择": ("https://www.gstatic.com/generate_204", "204"),
}

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
        network = info.get("net") or "tcp"
        node = {
            "name": info.get("ps", "vmess-node").strip(),
            "type": "vmess",
            "server": info.get("add"),
            "port": int(info.get("port")),
            "uuid": info.get("id"),
            "alterId": int(info.get("aid", 0)),
            "cipher": info.get("scy") or "auto",
            "network": network,
            "tls": info.get("tls") == "tls",
        }
        host = info.get("host") or ""
        if info.get("sni") or (node["tls"] and host and network in ("ws", "httpupgrade")):
            node["servername"] = info.get("sni") or host
        if network in ("ws", "httpupgrade"):
            node["network"] = "ws"
            node["ws-opts"] = {"path": info.get("path") or "/"}
            if host:
                node["ws-opts"]["headers"] = {"Host": host}
            if network == "httpupgrade":
                node["ws-opts"]["v2ray-http-upgrade"] = True
        elif network == "grpc":
            node["grpc-opts"] = {"grpc-service-name": info.get("path") or ""}
        elif network != "tcp" or info.get("type") not in (None, "", "none"):
            return None
        return node
    except Exception:
        return None


def parse_trojan(link):
    """解析 trojan:// 链接"""
    try:
        url = urllib.parse.urlparse(link)
        name = urllib.parse.unquote(url.fragment) if url.fragment else "trojan-node"
        params = dict(urllib.parse.parse_qsl(url.query))
        if params.get("security", "tls") != "tls" or not url.username:
            return None
        network = params.get("type", "tcp")
        node = {
            "name": name.strip(),
            "type": "trojan",
            "server": url.hostname,
            "port": url.port,
            "password": urllib.parse.unquote(url.username),
            "sni": params.get("sni") or url.hostname,
        }
        if network == "ws":
            node["network"] = "ws"
            node["ws-opts"] = {"path": params.get("path") or "/"}
            if params.get("host"):
                node["ws-opts"]["headers"] = {"Host": params["host"]}
        elif network == "grpc":
            node["network"] = "grpc"
            node["grpc-opts"] = {"grpc-service-name": params.get("serviceName") or ""}
        elif network != "tcp":
            return None
        return node
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

    lines = content.splitlines()
    if not any(line.strip().startswith(("vmess://", "trojan://", "ss://")) for line in lines):
        try:
            encoded = "".join(content.split())
            lines = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True).decode("utf-8").splitlines()
        except (ValueError, UnicodeError):
            return []

    parsed = []
    for line in lines:
        line = line.strip()
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
        start = time.monotonic()
        for family, kind, proto, _, address in socket.getaddrinfo(server, port, type=socket.SOCK_STREAM):
            if not ipaddress.ip_address(address[0]).is_global:
                continue
            try:
                with socket.socket(family, kind, proto) as sock:
                    sock.settimeout(TCP_TIMEOUT)
                    sock.connect(address)
                return proxy, (time.monotonic() - start) * 1000
            except OSError:
                continue
    except (OSError, ValueError, UnicodeError):
        pass
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
        if not isinstance(node, dict):
            continue
        if not all(isinstance(node.get(key), str) and node[key] for key in ("type", "server")):
            continue
        if not isinstance(node.get("name"), str):
            continue
        try:
            port = int(node.get("port"))
        except (TypeError, ValueError):
            continue
        if not 1 <= port <= 65535:
            continue
        node = {**node, "port": port}
        # 同一 CDN 地址可以托管多个节点，不能按 IP 和端口去重。
        signature = yaml.safe_dump({k: v for k, v in node.items() if k != "name"}, sort_keys=True)
        unique_nodes.setdefault(signature, node)
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

    print(f"TCP 预筛选完成，共 {len(valid_proxies)} 个候选；实际可用性由 OpenClash 检测。")
    if not valid_proxies:
        raise SystemExit("TCP 预筛选无候选，保留旧配置且将本次更新标记为失败。")

    final_proxies = []
    for proxy, _ in sorted(valid_proxies, key=lambda item: item[1])[:MAX_PROXIES]:
        identity = yaml.safe_dump({k: v for k, v in proxy.items() if k != "name"}, sort_keys=True)
        fingerprint = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12]
        final_proxies.append({**proxy, "name": f"{proxy['type'].upper()}-{fingerprint}"})

    config_path = Path(__file__).with_name("config.yaml")
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=config_path.parent, delete=False) as file:
        tmp_path = Path(file.name)
        try:
            yaml.safe_dump(build_config(final_proxies), file, allow_unicode=True, sort_keys=False)
            file.close()
            os.replace(tmp_path, config_path)
        finally:
            tmp_path.unlink(missing_ok=True)
    print(f"\n[完成] 成功写入 config.yaml，包含 {len(final_proxies)} 个候选节点。")


def build_config(final_proxies):
    node_names = [p["name"] for p in final_proxies]
    return {
        "proxies": final_proxies,
        "proxy-groups": [
            *[
                {
                    "name": name,
                    "type": "url-test",
                    "url": url,
                    "expected-status": status,
                    "interval": 120,
                    "timeout": PROBE_TIMEOUT_MS,
                    "max-failed-times": 3,
                    "tolerance": 50,
                    "lazy": False,
                    "proxies": node_names,
                }
                for name, (url, status) in TARGETS.items()
            ],
            *[
                {
                    "name": name,
                    "type": "select",
                    "proxies": [auto_group] + node_names,
                }
                for name, auto_group in (
                    ("YouTube", "YouTube自动优选"),
                    ("GitHub", "GitHub自动优选"),
                    ("节点选择", "自动选择"),
                    ("Proxies", "自动选择"),
                )
            ],
        ],
        "rules": [
            "GEOIP,LAN,DIRECT,no-resolve",
            "DOMAIN,youtubei.googleapis.com,YouTube",
            "DOMAIN,youtube.googleapis.com,YouTube",
            "DOMAIN-SUFFIX,google.com,Google",
            "DOMAIN-SUFFIX,gstatic.com,Google",
            "DOMAIN-SUFFIX,googleapis.com,Google",
            "DOMAIN-SUFFIX,googleusercontent.com,Google",
            "DOMAIN-SUFFIX,telegram.org,Telegram",
            "DOMAIN-SUFFIX,t.me,Telegram",
            "DOMAIN-SUFFIX,telegra.ph,Telegram",
            "DOMAIN-SUFFIX,tdesktop.com,Telegram",

            # 常用国内大流量域名直连（GEOIP,CN 兜底前的快速匹配）
            "DOMAIN-SUFFIX,bilibili.com,DIRECT",
            "DOMAIN-SUFFIX,byteoversea.com,DIRECT",
            "DOMAIN-SUFFIX,bytedance.com,DIRECT",
            "DOMAIN-SUFFIX,qq.com,DIRECT",
            "DOMAIN-SUFFIX,weixin.qq.com,DIRECT",
            "DOMAIN-SUFFIX,baidu.com,DIRECT",

            # GitHub 流量专属策略组
            "DOMAIN-KEYWORD,github,GitHub",
            "DOMAIN-SUFFIX,github.com,GitHub",
            "DOMAIN-SUFFIX,github.io,GitHub",
            "DOMAIN-SUFFIX,githubusercontent.com,GitHub",
            "DOMAIN-SUFFIX,githubassets.com,GitHub",

            # YouTube 流量专属策略组（专属 204 测速选优）
            "DOMAIN-KEYWORD,youtube,YouTube",
            "DOMAIN-SUFFIX,youtube.com,YouTube",
            "DOMAIN-SUFFIX,googlevideo.com,YouTube",
            "DOMAIN-SUFFIX,ytimg.com,YouTube",
            "DOMAIN-SUFFIX,youtu.be,YouTube",
            "DOMAIN-SUFFIX,ggpht.com,YouTube",

            # 海外流媒体 & 社交走免费节点代理池
            "DOMAIN-SUFFIX,twitter.com,Proxies",
            "DOMAIN-SUFFIX,x.com,Proxies",
            "DOMAIN-SUFFIX,netflix.com,Proxies",
            "DOMAIN-SUFFIX,instagram.com,Proxies",
            "DOMAIN-SUFFIX,facebook.com,Proxies",

            "GEOIP,telegram,Telegram,no-resolve",
            "GEOIP,LAN,DIRECT",
            "GEOIP,CN,DIRECT",
            "MATCH,Proxies",
        ],
    }


if __name__ == "__main__":
    main()
