// ======  Proxy Controller  ======

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const domain = url.origin;

    // --- 提取并处理云端安全隔离变量 ---
    const WEB_USER = env.WEB_USER || "admin";        
    const WEB_PASS = env.WEB_PASS || "admin888";     
    const PROXY_USER = env.PROXY_USER || "proxy";    
    const PROXY_PASS = env.PROXY_PASS || "888888";   

    // ====================================================
    // [基础防御] 浏览器与安全节点 Basic Auth 鉴权函数
    // ====================================================
    const authenticate = (request) => {
      const authHeader = request.headers.get("Authorization");
      if (!authHeader) return false;
      const [scheme, encoded] = authHeader.split(" ");
      if (scheme !== "Basic") return false;
      try {
        const decoded = atob(encoded);
        const [username, password] = decoded.split(":");
        return username === WEB_USER && password === WEB_PASS;
      } catch (e) {
        return false;
      }
    };

    const unauthorizedResponse = () => {
      return new Response("Unauthorized Access. Scanner Blocked.", {
        status: 401,
        headers: {
          "WWW-Authenticate": 'Basic realm="Proxy System Security Control"',
          "Content-Type": "text/plain;charset=UTF-8"
        }
      });
    };

    // ====================================================
    // [1] 数据库建表 (D1)
    // ====================================================
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS servers (
        ip TEXT PRIMARY KEY,
        details TEXT,
        last_seen INTEGER
      )
    `).run();

    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS global_config (
        key TEXT PRIMARY KEY,
        value TEXT
      )
    `).run();

    // ====================================================
    // [2] 动态分发：Proxy Server 引擎源码 
    // ====================================================
    if (url.pathname === "/scripts/proxy_server.py") {
      const PROXY_CODE = `#!/usr/bin/env python3
from __future__ import annotations
import select, socket, threading, urllib.parse, time, base64
from typing import Any

PROXY_USER = b"${PROXY_USER}"
PROXY_PASS = b"${PROXY_PASS}"

def parse_int(value: Any) -> int:
    try: return int(value)
    except: return 0

def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk: raise ConnectionError("Unexpected disconnect.")
        data += chunk
    return data

def create_connection(address: tuple[str, int], bind_interface: str, timeout: float = 20) -> socket.socket:
    host, port = address
    err = None
    for res in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
        af, socktype, proto, canonname, sa = res
        sock = None
        try:
            sock = socket.socket(af, socktype, proto)
            sock.settimeout(timeout)
            if bind_interface:
                sock.setsockopt(socket.SOL_SOCKET, 25, bind_interface.encode('utf-8'))
            sock.connect(sa)
            return sock
        except OSError as e:
            err = e
            if sock: sock.close()
    raise err or OSError("getaddrinfo empty")

def relay(left: socket.socket, right: socket.socket) -> None:
    sockets = [left, right]
    while True:
        readable, _, errored = select.select(sockets, [], sockets, 120)
        if errored: return
        for source in readable:
            target = right if source is left else left
            data = source.recv(65536)
            if not data: return
            target.sendall(data)

def socks5_client(client: socket.socket, first_byte: bytes, bind_interface: str) -> None:
    upstream = None
    try:
        methods_count = recv_exact(client, 1)[0]
        methods = recv_exact(client, methods_count)
        
        if b"\\x02" not in methods:
            client.sendall(b"\\x05\\xFF") 
            return
        client.sendall(b"\\x05\\x02")
        
        auth_req = recv_exact(client, 2)
        if auth_req[0] != 1: return
        ulen = auth_req[1]
        uname = recv_exact(client, ulen)
        plen = recv_exact(client, 1)[0]
        upass = recv_exact(client, plen)
        
        if uname != PROXY_USER or upass != PROXY_PASS:
            client.sendall(b"\\x01\\x01") 
            return
        client.sendall(b"\\x01\\x00") 

        version, command, _, address_type = recv_exact(client, 4)
        if version != 5 or command != 1: return
        if address_type == 1: host = socket.inet_ntoa(recv_exact(client, 4))
        elif address_type == 3: host = recv_exact(client, recv_exact(client, 1)[0]).decode("idna")
        elif address_type == 4: host = socket.inet_ntop(socket.AF_INET6, recv_exact(client, 16))
        else: return
        port = int.from_bytes(recv_exact(client, 2), "big")
        
        upstream = create_connection((host, port), bind_interface, timeout=20)
        client.sendall(b"\\x05\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00")
        relay(client, upstream)
    except: pass
    finally:
        client.close()
        if upstream: upstream.close()

def http_client(client: socket.socket, first_byte: bytes, bind_interface: str) -> None:
    upstream = None
    try:
        data = first_byte
        while b"\\r\\n\\r\\n" not in data and len(data) < 65536:
            chunk = client.recv(4096)
            if not chunk: break
            data += chunk
        head, rest = data.split(b"\\r\\n\\r\\n", 1)
        lines = head.decode("iso-8859-1", errors="replace").split("\\r\\n")
        
        expected_auth = "Basic " + base64.b64encode(PROXY_USER + b":" + PROXY_PASS).decode("ascii")
        auth_passed = False
        for line in lines[1:]:
            if line.lower().startswith("proxy-authorization:"):
                if line.split(":", 1)[1].strip() == expected_auth:
                    auth_passed = True
                    break
                    
        if not auth_passed:
            client.sendall(b"HTTP/1.1 407 Proxy Authentication Required\\r\\nProxy-Authenticate: Basic realm=\\"Proxy\\"\\r\\n\\r\\n")
            return

        method, target, version = lines[0].split(" ", 2)
        if method.upper() == "CONNECT":
            host, _, port_text = target.partition(":")
            upstream = create_connection((host, parse_int(port_text) or 443), bind_interface, timeout=20)
            client.sendall(b"HTTP/1.1 200 Connection Established\\r\\n\\r\\n")
            if rest: upstream.sendall(rest)
            relay(client, upstream)
            return
        parsed = urllib.parse.urlsplit(target)
        if not parsed.hostname: return
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        headers = [line for line in lines[1:] if not line.lower().startswith(("proxy-connection:", "connection:", "proxy-authorization:"))]
        request = f"{method} {path} {version}\\r\\n" + "\\r\\n".join(headers) + "\\r\\nConnection: close\\r\\n\\r\\n"
        upstream = create_connection((parsed.hostname, port), bind_interface, timeout=20)
        upstream.sendall(request.encode("iso-8859-1") + rest)
        relay(client, upstream)
    except: pass
    finally:
        client.close()
        if upstream: upstream.close()

def proxy_client(client: socket.socket, address: tuple[str, int], bind_interface: str) -> None:
    try:
        client.settimeout(30)
        first = recv_exact(client, 1)
        if first == b"\\x05": socks5_client(client, first, bind_interface)
        else: http_client(client, first, bind_interface)
    except:
        try: client.close()
        except: pass

def start_proxy_server(host: str, port: int, bind_interface: str = "tun0") -> None:
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(256)
    except Exception as e: return
    while True:
        try:
            client, address = server.accept()
            threading.Thread(target=proxy_client, args=(client, address, bind_interface), daemon=True).start()
        except: time.sleep(0.5)
`;
      return new Response(PROXY_CODE, { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
    }

    // ====================================================
    // [3] 动态分发：Lite Manager 调度引擎源码 (降级:仅测 YouTube)
    // ====================================================
    if (url.pathname === "/scripts/lite_manager.py") {
      const MANAGER_CODE = `#!/usr/bin/env python3
import base64, csv, os, subprocess, threading, time, urllib.request, json
from pathlib import Path

PROXY_PORT = 7920
API_URL = "https://www.vpngate.net/api/iphone/"
C2_URL = "${domain}"

WORKSPACE = Path("/opt/proxy_lite")
CONFIG_DIR = WORKSPACE / "configs"
AUTH_FILE = WORKSPACE / "auth.txt"

WEB_USER = "${WEB_USER}"
WEB_PASS = "${WEB_PASS}"

target_country = "JP"
current_process = None
current_ip = ""
current_country = ""
connected_at = 0
is_connecting = False
last_switch_trigger = 0  

state_lock = threading.Lock()
dead_ips = set()
last_blacklist_clear = time.time()
public_ip = ""

global_node_reservoir = {} 
reservoir_lock = threading.Lock()

def get_public_ip():
    global public_ip
    try:
        req = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": "curl/7.68.0"})
        with urllib.request.urlopen(req, timeout=5) as res:
            public_ip = res.read().decode("utf-8").strip()
    except: public_ip = "Unknown_IP"

def get_c2_headers():
    auth_ptr = base64.b64encode(f"{WEB_USER}:{WEB_PASS}".encode()).decode()
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Authorization": f"Basic {auth_ptr}"
    }

def update_config_loop():
    global target_country, current_process, current_country, last_switch_trigger, current_ip, dead_ips
    while True:
        try:
            req = urllib.request.Request(f"{C2_URL}/api/config", headers=get_c2_headers())
            with urllib.request.urlopen(req, timeout=10) as res:
                data = json.loads(res.read().decode("utf-8"))
                desired_country = str(data.get("0", "JP")).upper()
                switch_trigger = int(data.get("switch_trigger", 0))
                
                with state_lock:
                    force_switch = (switch_trigger > last_switch_trigger)
                    
                    if target_country != desired_country or force_switch:
                        target_country = desired_country
                        
                        if current_process and current_process.poll() is None:
                            if force_switch or (current_country and current_country != desired_country):
                                if force_switch:
                                    print(f"[*] 收到强制更换 IP 指令，正在将当前节点 {current_ip} 关入小黑屋并准备重拨...", flush=True)
                                    if current_ip: dead_ips.add(current_ip)
                                else:
                                    print(f"[*] 策略热切换: 目标重定向到 {desired_country}，正在掐断旧连接...", flush=True)
                                try: current_process.terminate(); current_process.wait(timeout=2)
                                except: current_process.kill()
                        
                        last_switch_trigger = switch_trigger
        except Exception as e:
            pass
        time.sleep(15)

def c2_heartbeat_loop():
    global public_ip, current_process, current_country, current_ip, connected_at
    if not public_ip or public_ip == "Unknown_IP": get_public_ip()
    try:
        payload = json.dumps({"ip": public_ip, "details": []}).encode('utf-8')
        req = urllib.request.Request(f"{C2_URL}/api/report", data=payload, headers=get_c2_headers(), method='POST')
        urllib.request.urlopen(req, timeout=10)
    except: pass

    while True:
        time.sleep(30)
        if not public_ip or public_ip == "Unknown_IP": get_public_ip()
        details = []
        with state_lock:
            if current_process and current_process.poll() is None:
                uptime = time.time() - connected_at
                if uptime > 10: 
                    details.append({
                        "slot": 0, 
                        "country": current_country or target_country, 
                        "port": PROXY_PORT, 
                        "connected_time": int(uptime), 
                        "node_ip": current_ip
                    })
        
        payload = json.dumps({"ip": public_ip, "details": details}).encode('utf-8')
        try:
            req = urllib.request.Request(f"{C2_URL}/api/report", data=payload, headers=get_c2_headers(), method='POST')
            urllib.request.urlopen(req, timeout=10)
        except Exception as e: pass

def setup_env():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not AUTH_FILE.exists():
        AUTH_FILE.write_text("vpn\\nvpn\\n", encoding="utf-8")
        AUTH_FILE.chmod(0o600)

def harvest_snapshot_nodes() -> list:
    try:
        req = urllib.request.Request(API_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as res: text = res.read().decode("utf-8", errors="replace")
        lines = [line for line in text.splitlines() if line and not line.startswith("*")]
        if lines and lines[0].startswith("#"): lines[0] = lines[0][1:]
        nodes = []
        for row in csv.DictReader(lines):
            ip = row.get("IP")
            if not ip or not row.get("OpenVPN_ConfigData_Base64"): continue
            raw_ping = row.get("Ping", "")
            nodes.append({
                "ip": ip, 
                "ping": int(raw_ping) if raw_ping.isdigit() else 9999, 
                "country": row.get("CountryShort", "").upper(), 
                "config": base64.b64decode(row["OpenVPN_ConfigData_Base64"]).decode("utf-8", errors="replace"),
                "harvested_at": time.time()
            })
        return nodes
    except Exception as e: 
        print(f"[-] 从 VPNGate 拉取瞬时快照失败: {e}", flush=True)
        return []

def setup_routing():
    dev, table = "tun0", "100"
    subprocess.run(["ip", "rule", "del", "table", table], capture_output=True)
    subprocess.run(["ip", "route", "flush", "table", table], capture_output=True)
    subprocess.run(["ip", "route", "add", "default", "dev", dev, "table", table], capture_output=True)
    subprocess.run(["ip", "rule", "add", "oif", dev, "table", table], capture_output=True)

def connect_node(node: dict):
    global current_process, current_ip, current_country, connected_at, is_connecting, dead_ips
    try:
        dev, cfg_path, log_file = "tun0", CONFIG_DIR / "tun0.ovpn", WORKSPACE / "ovpn_err.log"
        cfg_path.write_text(node["config"], encoding="utf-8")
        ovpn_version = subprocess.run(["openvpn", "--version"], capture_output=True, text=True).stdout
        cipher_args = ["--ncp-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"] if "2.4" in ovpn_version else ["--data-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305", "--data-ciphers-fallback", "AES-128-CBC"]
        cmd = ["openvpn", "--config", str(cfg_path), "--dev", dev, "--dev-type", "tun", "--pull-filter", "ignore", "route-ipv6", "--pull-filter", "ignore", "ifconfig-ipv6", "--route-nopull", "--auth-user-pass", str(AUTH_FILE), "--auth-nocache", "--connect-timeout", "5", "--connect-retry-max", "1", "--verb", "3"] + cipher_args
        with open(log_file, "w") as f: process = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT)
        
        success = False
        for _ in range(12):
            time.sleep(1)
            if process.poll() is not None: break
            try:
                if "Initialization Sequence Completed" in log_file.read_text():
                    success = True; break
            except: pass
                
        if success and process.poll() is None:
            is_residential = True
            try:
                print(f"[*] 节点 ({node['country']}) 隧道打通，鉴定是否为纯正住宅IP...", flush=True)
                req_url = f"https://ip.net.coffee/ip/{node['ip']}"
                check_req = urllib.request.Request(req_url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(check_req, timeout=10) as check_res:
                    api_resp = check_res.read().decode("utf-8").lower()
                    if "residential" in api_resp or "isp" in api_resp or "住宅" in api_resp:
                        is_residential = True
                    else:
                        clean_resp = api_resp.replace(" ", "").replace("\\n", "").replace("\\r", "")
                        if "hosting" in api_resp or "datacenter" in api_resp or "机房" in api_resp or "data center" in api_resp:
                            if '"hosting":false' not in clean_resp and '"datacenter":false' not in clean_resp:
                                is_residential = False
            except Exception as e: pass
            
            if not is_residential:
                print(f"[-] 节点 ({node['country']}) 检测为机房IP，残忍抛弃: {node['ip']}", flush=True)
                try: process.terminate(); process.wait(timeout=2)
                except: process.kill()
                dead_ips.add(node["ip"])
                with state_lock: is_connecting = False
                return

            setup_routing()
            time.sleep(1) 
            
            # ===== 修改：仅检测 YouTube 流媒体连通性 =====
            print(f"[*] 节点 ({node['country']}) 正在进行流媒体解锁测试 (仅测 YouTube)...", flush=True)
            services = {
                "YouTube": "https://www.youtube.com"
            }
            check_passed = True
            for name, url in services.items():
                res = subprocess.run(["curl", "-I", "-s", "-A", "Mozilla/5.0", "-m", "5", "--interface", "tun0", url], capture_output=True)
                if res.returncode != 0:
                    print(f"[-] 节点 ({node['country']}) 无法连通 {name} (ErrCode: {res.returncode})，直接拉黑更换: {node['ip']}", flush=True)
                    check_passed = False
                    break
                    
            if not check_passed:
                try: process.terminate(); process.wait(timeout=2)
                except: process.kill()
                dead_ips.add(node["ip"])
                with state_lock: is_connecting = False
                return
            # ==========================================

            with state_lock:
                current_process = process
                current_ip = node["ip"]
                current_country = node["country"]
                connected_at = time.time()
            print(f"[+] 代理节点 ({node['country']}) 完全就绪 (住宅与 YouTube 双重检测通过): {node['ip']}", flush=True)
            
        else:
            try: process.terminate(); process.wait(timeout=2)
            except: process.kill()
            dead_ips.add(node["ip"])
    finally:
        with state_lock: is_connecting = False

def health_check_loop():
    global current_process, current_ip, connected_at, dead_ips
    while True:
        time.sleep(20)
        need_reconnect = False
        target_ip = ""
        process_ref = None
        
        with state_lock:
            if current_process and current_process.poll() is None and (time.time() - connected_at > 15):
                need_reconnect = True
                target_ip = current_ip
                process_ref = current_process
                
        if need_reconnect:
            res = subprocess.run(["curl", "-s", "-m", "5", "--interface", "tun0", "https://api.ipify.org"], capture_output=True)
            if res.returncode != 0:
                print(f"[!] 通道假死断流，果断踢线重拨: {target_ip}", flush=True)
                dead_ips.add(target_ip)
                try: process_ref.terminate(); process_ref.wait(timeout=2)
                except: process_ref.kill()

def maintain_pool():
    global dead_ips, last_blacklist_clear, global_node_reservoir, current_process, current_ip, current_country, is_connecting, target_country
    while True:
        if time.time() - last_blacklist_clear > 600:
            dead_ips.clear()
            last_blacklist_clear = time.time()

        snapshot = harvest_snapshot_nodes()
        with reservoir_lock:
            for n in snapshot:
                if n["ip"] not in dead_ips:
                    global_node_reservoir[n["ip"]] = n
            now = time.time()
            stale_ips = [ip for ip, node in global_node_reservoir.items() if now - node["harvested_at"] > 10800]
            for ip in stale_ips:
                global_node_reservoir.pop(ip, None)
            print(f"[*] ⚡ 蓄水池每5秒合并去重，当前囤积有效全球节点 -> {len(global_node_reservoir)} 个", flush=True)

        needs_dispatch = False
        with state_lock:
            if not is_connecting and (current_process is None or current_process.poll() is not None):
                needs_dispatch = True
                current_process = None
                current_ip = ""
                current_country = ""
        
        if needs_dispatch:
            with reservoir_lock:
                all_pool_nodes = sorted(list(global_node_reservoir.values()), key=lambda x: x["ping"])
                
                candidates = [n for n in all_pool_nodes if n["country"] == target_country and n["ip"] not in dead_ips]
                
                if not candidates:
                    has_blacklisted = any(n["country"] == target_country for n in all_pool_nodes)
                    if has_blacklisted:
                        dead_ips.clear()
                        print(f"[!] ⚡ 紧急熔断触发：[{target_country}] 节点枯竭，已解锁历史黑名单救场！", flush=True)
                        candidates = [n for n in all_pool_nodes if n["country"] == target_country and n["ip"] not in dead_ips]

                if candidates:
                    node = candidates.pop(0)
                    with state_lock: is_connecting = True
                    threading.Thread(target=connect_node, args=(node,), daemon=True).start()
                    time.sleep(0.5)
                else:
                    print(f"[-] 蓄水池中暂无 [{target_country}] 可用。持续滚动等待...", flush=True)
        
        time.sleep(5)

def main():
    if os.geteuid() != 0: return
    get_public_ip()
    setup_env()
    subprocess.run(["pkill", "-f", "openvpn.*tun[0-9]"], capture_output=True)
    
    print("========================================", flush=True)
    print("  Proxy Controller 引擎启动！", flush=True)
    print("========================================", flush=True)

    threading.Thread(target=update_config_loop, daemon=True).start()

    import proxy_server
    threading.Thread(target=proxy_server.start_proxy_server, args=("0.0.0.0", PROXY_PORT, "tun0"), daemon=True).start()
    
    threading.Thread(target=health_check_loop, daemon=True).start()
    threading.Thread(target=c2_heartbeat_loop, daemon=True).start()
    maintain_pool()

if __name__ == "__main__":
    main()
`;
      return new Response(MANAGER_CODE, { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
    }

    // ====================================================
    // [4] 动态分发：VPS 一键安装脚本
    // ====================================================
    if (url.pathname === "/agent") {
      const agentScript = `#!/usr/bin/env bash
echo "=========================================================="
echo "     Proxy Controller    "
echo "=========================================================="

crontab -l 2>/dev/null | grep -v "/opt/proxy_lite/heartbeat.sh" | crontab -
rm -f /opt/proxy_lite/heartbeat.sh

apt-get update -q
apt-get install -y openvpn python3 curl iproute2 iptables cron

mkdir -p /opt/proxy_lite/configs
cd /opt/proxy_lite

echo "[1/3] 从安全中心拉取极速引擎..."
curl -sLo lite_manager.py ${domain}/scripts/lite_manager.py
curl -sLo proxy_server.py ${domain}/scripts/proxy_server.py

echo "[2/3] 配置系统守护服务..."
cat > /lib/systemd/system/proxy-lite.service << 'EOF'
[Unit]
Description=  Proxy Core Engine
After=network.target

[Service]
Type=simple
Environment="PYTHONIOENCODING=utf-8"
Environment="LANG=C.UTF-8"
WorkingDirectory=/opt/proxy_lite
ExecStart=/usr/bin/python3 -u lite_manager.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable proxy-lite.service
systemctl restart proxy-lite.service

echo "[+] 引擎更新成功！全息日志和5秒超高频机制已加载。"
`;
      return new Response(agentScript, { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
    }

    // ====================================================
    // [5] 开放API接口
    // ====================================================
    if (url.pathname === "/api/countries") {
        try {
            const response = await fetch("https://www.vpngate.net/api/iphone/");
            const text = await response.text();
            const lines = text.split('\n');
            const countries = new Set();
            for (let i = 2; i < lines.length; i++) {
                const parts = lines[i].split(',');
                if (parts.length > 6) {
                    const country = parts[6];
                    if (country && country.length === 2 && country !== "xx" && country !== "--") countries.add(country);
                }
            }
            return new Response(JSON.stringify(Array.from(countries)), { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
        } catch(err) {
            return new Response(JSON.stringify(["JP", "KR", "US", "GB", "TW"]), { headers: { "Content-Type": "application/json" } }); 
        }
    }

    // ====================================================
    // [6] 安全敏感接口拦截区
    // ====================================================
    if (url.pathname === "/" || url.pathname === "/api/config" || url.pathname === "/api/nodes" || url.pathname === "/api/proxies" || url.pathname === "/api/report") {
      if (!authenticate(request)) return unauthorizedResponse();
    }

    if (url.pathname === "/api/config" && request.method === "GET") {
        const { results } = await env.DB.prepare(`SELECT value FROM global_config WHERE key = 'slot_map'`).all();
        if (results && results.length > 0) return new Response(results[0].value, { headers: { "Content-Type": "application/json" } });
        
        return new Response(JSON.stringify({ "0": "JP" }), { headers: { "Content-Type": "application/json" } });
    }

    if (url.pathname === "/api/config" && request.method === "POST") {
        const data = await request.json();
        const sanitizedMap = { "0": data["0"] || "JP" };
        if (data.switch_trigger) sanitizedMap.switch_trigger = data.switch_trigger;
        
        await env.DB.prepare(`
            INSERT INTO global_config (key, value) VALUES ('slot_map', ?1)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
        `).bind(JSON.stringify(sanitizedMap)).run();
        return new Response("OK");
    }

    if (url.pathname === "/api/report" && request.method === "POST") {
      try {
        const data = await request.json();
        await env.DB.prepare(`
          INSERT INTO servers (ip, details, last_seen) VALUES (?1, ?2, ?3)
          ON CONFLICT(ip) DO UPDATE SET details = excluded.details, last_seen = excluded.last_seen
        `).bind(data.ip, JSON.stringify(data.details || []), Date.now()).run();
        return new Response("OK", { status: 200 });
      } catch (err) { return new Response("Error", { status: 500 }); }
    }

    if (url.pathname === "/api/proxies") {
      const cutoff = Date.now() - 120000;
      await env.DB.prepare(`DELETE FROM servers WHERE last_seen < ?1`).bind(cutoff).run();
      const { results } = await env.DB.prepare(`SELECT ip, details FROM servers`).all();
      let proxyList = [];
      if (results) {
        for (let server of results) {
          for (let node of JSON.parse(server.details)) {
            proxyList.push(`socks5://${PROXY_USER}:${PROXY_PASS}@${server.ip}:${node.port}#${node.country}_Node_${node.node_ip || 'IP'}`);
          }
        }
      }
      return new Response(proxyList.join('\n'), { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
    }

    if (url.pathname === "/api/nodes") {
      const cutoff = Date.now() - 120000;
      await env.DB.prepare(`DELETE FROM servers WHERE last_seen < ?1`).bind(cutoff).run();
      const { results } = await env.DB.prepare(`SELECT * FROM servers ORDER BY last_seen DESC`).all();
      return new Response(JSON.stringify(results || []), { headers: { "Content-Type": "application/json" } });
    }

    if (url.pathname === "/") {
      return new Response(DASHBOARD_HTML(domain, WEB_USER, WEB_PASS, PROXY_USER, PROXY_PASS), { headers: { "Content-Type": "text/html;charset=UTF-8" } });
    }

    return new Response("Not Found", { status: 404 });
  }
};

const DASHBOARD_HTML = (domain, webUser, webPass, proxyUser, proxyPass) => `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>  Proxy Controller</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-gray-100 font-sans p-6">
    <div class="max-w-7xl mx-auto">
        <div class="flex justify-between items-end mb-6">
            <div>
                <h1 class="text-3xl font-bold text-blue-400">  代理调度控制器</h1>
                <p class="text-gray-400 mt-2">量化提取直链: <a href="/api/proxies" target="_blank" class="text-blue-300 hover:underline border-b border-blue-300 border-dashed pb-0.5">${domain}/api/proxies</a></p>
            </div>
            
            <div class="flex flex-col items-end gap-2">
                <div class="bg-gray-800 p-3 rounded-lg border border-gray-700">
                    <p class="text-sm text-gray-400 mb-1">一行命令纳管全新 VPS</p>
                    <code class="text-green-400 text-sm select-all">bash <(curl -sL ${domain}/agent)</code>
                </div>
                <div class="bg-gray-800 p-2 px-4 rounded-lg border border-gray-700 w-full text-right text-xs text-gray-400">
                    <div>面板凭证: <span class="text-blue-300 font-bold font-mono">${webUser}</span> / <span class="text-blue-300 font-bold font-mono">${webPass}</span></div>
                    <div class="mt-1">代理凭证: <span class="text-yellow-400 font-bold font-mono">${proxyUser}</span> / <span class="text-yellow-400 font-bold font-mono">${proxyPass}</span></div>
                </div>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-4 gap-6 mb-6">
            <div class="lg:col-span-1 bg-gray-800 p-4 rounded-lg border border-gray-700 shadow-lg">
                <h2 class="text-xl font-bold text-blue-400 mb-1">全球精选国家库</h2>
                <p class="text-xs text-gray-400 mb-3">蓄水池监听覆盖的国家</p>
                <div id="countries-list" class="flex flex-wrap gap-2">
                    <span class="text-gray-500 text-sm">正在拉取节点数据库...</span>
                </div>
            </div>
            <div class="lg:col-span-3 bg-gray-800 p-4 rounded-lg border border-gray-700 shadow-lg flex flex-col justify-center items-start">
                <div class="flex justify-between items-center w-full mb-4">
                    <div>
                        <h2 class="text-xl font-bold text-blue-400">策略配置</h2>
                        <p class="text-xs text-gray-400">任何卡顿假死将在几秒内由蓄水池顶替新节点！</p>
                    </div>
                </div>
                <div class="flex items-center gap-4 bg-gray-900 border border-gray-700 rounded p-4" id="config-form">
                    <span class="text-gray-400 text-sm">当前监听目标国家:</span>
                    <input type="text" id="slot-cfg-0" value="JP" class="bg-transparent border border-gray-600 rounded p-2 text-white font-bold text-lg uppercase focus:outline-none focus:border-blue-400 transition w-24 text-center" />
                    <button onclick="saveConfig()" class="bg-blue-600 hover:bg-blue-500 text-white px-6 py-2 rounded text-sm font-bold shadow transition ml-4">强制下发配置</button>
                    <button onclick="switchIP()" class="bg-purple-600 hover:bg-purple-500 text-white px-6 py-2 rounded text-sm font-bold shadow transition">更换新IP</button>
                </div>
            </div>
        </div>
        
        <div class="bg-gray-800 rounded-lg shadow-lg overflow-hidden border border-gray-700">
            <table class="w-full text-left border-collapse">
                <thead>
                    <tr class="bg-gray-700 text-gray-300">
                        <th class="py-3 px-4 font-semibold text-sm w-1/6">VPS 母机 IP</th>
                        <th class="py-3 px-4 font-semibold text-sm">已就绪纯净代理 (国家 | 节点IP:端口)</th>
                        <th class="py-3 px-4 font-semibold text-sm w-1/12">心跳状态</th>
                        <th class="py-3 px-4 font-semibold text-sm text-right w-1/12">在线率</th>
                    </tr>
                </thead>
                <tbody id="nodes-table" class="divide-y divide-gray-700">
                    <tr><td colspan="4" class="py-8 text-center text-gray-500">正在与数据库通信...</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <script>
        async function fetchCountries() {
            try {
                const res = await fetch('/api/countries');
                const list = await res.json();
                const requestedCountries = ["SG", "HK", "MY", "PH", "KH", "LA", "GB", "CA", "MX", "BR", "JP", "KR", "US", "TW"];
                const combined = Array.from(new Set([...requestedCountries, ...list]));
                const container = document.getElementById('countries-list');
                container.innerHTML = combined.map(c => \`<span class="bg-gray-700 px-2 py-1 rounded text-xs font-bold text-gray-300 border border-gray-600">\${c}</span>\`).join('');
            } catch(e) {}
        }

        async function loadConfig() {
            try {
                const res = await fetch('/api/config');
                const map = await res.json();
                document.getElementById('slot-cfg-0').value = map["0"] || 'JP';
            } catch(e) {}
        }

        async function saveConfig() {
            const val = document.getElementById(\`slot-cfg-0\`).value.toUpperCase().trim() || 'JP';
            await fetch('/api/config', {
                method: 'POST',
                body: JSON.stringify({ "0": val })
            });
            alert('指令下发成功！代理引擎将自动平滑切换。');
        }

        async function switchIP() {
            const val = document.getElementById(\`slot-cfg-0\`).value.toUpperCase().trim() || 'JP';
            await fetch('/api/config', {
                method: 'POST',
                body: JSON.stringify({ "0": val, "switch_trigger": Date.now() })
            });
            alert('更换 IP 指令已发送！VPS 将在 15 秒的心跳周期内拉黑当前 IP 并顶替新节点。');
        }

        async function fetchNodes() {
            try {
                const res = await fetch('/api/nodes');
                const servers = await res.json();
                const tbody = document.getElementById('nodes-table');
                
                if (!servers || servers.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="4" class="py-8 text-center text-gray-500">当前没有被纳管的机器，请在 VPS 运行右上角命令接入</td></tr>';
                    return;
                }

                tbody.innerHTML = servers.map(server => {
                    const details = JSON.parse(server.details || '[]');
                    const timeAgo = Math.floor((Date.now() - server.last_seen) / 1000);
                    
                    let proxyBadges = details.map(d => 
                        \`<div class="inline-flex items-center bg-gray-700 border border-gray-600 rounded px-3 py-2 mr-2 mb-2 text-sm">
                            <span class="text-blue-400 font-bold mr-3">\${d.country}</span>
                            <span class="font-mono text-blue-200 mr-3" title="节点物理IP">\${d.node_ip || '分配中...'}:\${d.port}</span>
                            <span class="text-green-400" title="已通过住宅 IP 与 YouTube 连通性双重检测">● 纯净解锁 (YT)</span>
                        </div>\`
                    ).join('');

                    if (details.length === 0) proxyBadges = '<span class="text-yellow-500 text-sm">调度分配中... 正在抓取最佳匹配配置...</span>';

                    return \`
                        <tr class="hover:bg-gray-750 transition-colors">
                            <td class="py-4 px-4 font-mono text-lg text-blue-300 align-middle">\${server.ip}</td>
                            <td class="py-4 px-4 align-middle">\${proxyBadges}</td>
                            <td class="py-4 px-4 text-gray-400 align-middle">\${timeAgo}s 前</td>
                            <td class="py-4 px-4 align-middle text-right">
                                <span class="\${details.length === 1 ? 'bg-green-900 text-green-300' : 'bg-yellow-900 text-yellow-300'} py-1 px-3 rounded-full text-xs font-bold">\${details.length} / 1</span>
                            </td>
                        </tr>
                    \`;
                }).join('');
            } catch (err) {}
        }
        
        fetchCountries();
        loadConfig();
        fetchNodes();
        setInterval(fetchNodes, 5000);
    </script>
</body>
</html>
`;
