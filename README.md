[💬 Telegram 交流群](https://t.me/kejikkkcom) | [📺 YouTube 频道：科技KKK](https://www.youtube.com/@%E7%A7%91%E6%8A%80KKK)
* **🏠 双ISP住宅IP检测**： https://testisp.info 
---

本项目资源完全免费，均免费来自于互联网整合而成，如果有人问你收费，你肯定是上当受骗了！！！

# 一键极速部署

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/a6216abcd/Free-Residential-IP-Proxy-Controller)

KUI面板正在集成融合免费免费住宅IP代理调度系统 https://github.com/a6216abcd/K-UI

老用户覆盖代码，记得重新去vps运行agent命令，长时间获取不到IP，记得装一下warp ipv4,安装warp ipv4后，导出的IP会变warp ipv4需要手动修改成本机真实IP

```bash
wget -N https://gitlab.com/fscarmen/warp/-/raw/main/menu.sh && bash menu.sh

```

# 免费住宅IP代理调度系统 (Active-Standby 终极版) 🌐

这是一个轻量级且极具韧性的智能代理调度系统。基于 Cloudflare Workers 与 D1 数据库构建中心控制节点，配合 VPS 守护进程，实现 **主备双活 (Active-Standby)** 无缝切换、自动优选纯净住宅 IP 的 Socks5/HTTP 代理服务。

系统资源占用极低，同时集成了顶级的 IP 资产测绘引擎，非常适合用于个人量化交易、跨境电商防关联、网络测试或高频数据抓取。

<img width="3715" height="1759" alt="图片" src="https://github.com/user-attachments/assets/2877288a-d969-475f-92b1-18ceef651273" />
<img width="3715" height="1759" alt="图片" src="https://github.com/user-attachments/assets/c8df6abe-029a-4b55-ad25-d367257ccec2" />

> **致谢**：本项目的原生 IP 深度质检与风险评分感知模块，由 [TestISP.info](https://testisp.info) (商业级住宅IP与本地环境检测沙箱平台) 提供 API 支持。

---

## ✨ 核心特性

* **⚔️ 主备双活引擎 (Active-Standby)**：彻底重构底层网络，双路隧道 (`tun_main` / `tun_backup`) 并发建连。当主卡突发断流或死亡时，软开关秒级接管业务至备用卡，真正实现业务零感知切换。
* **🏠 双ISP住宅IP检测**：内置原生判定逻辑，无缝对接 https://testisp.info  执行 BGP 宣告审计、rDNS 探测、Geo-Drift 物理偏移计算与 Spamhaus 全球蜜罐预警，冷酷剔除一切机房 (Hosting/Datacenter) 伪装 IP。
* **⚡ 毫秒级极速调度与容错**：多维 HTTP/ICMP 探针高频心跳检测，采用 5 秒超时设定与高频蓄水池抓取机制，节点假死后立刻踢线熔断。
* **🔄 主动热切与端口云控**：支持面板一键发送时间戳指令强制清退当前通道并重拨；支持云端下发服务端口变更指令，守护进程自动重启适配。
* **📊 Serverless 全息看板**：零服务器成本部署控制端，提供可视化 Web UI，实时渲染 VPS 日志流、通道存活状态与 IP 深度质检体检报告。面板集成防呆复制设计，一键直达 TestISP 官网复核。
* **🚀 极简纳管**：VPS 节点端（Agent）无需复杂环境配置，一行 Bash 命令即可完成内核反向路径过滤 (`rp_filter`) 修复、依赖安装与守护进程驻留。

---

## 🛠️ 架构说明

1. **C2 控制端 (Cloudflare Workers)**：负责下发国家策略、端口配置、处理主动换 IP 指令、提供 Web 面板及可视化报告、存储节点心跳状态。
2. **状态存储 (Cloudflare D1)**：轻量级 SQLite 数据库，记录全局调度配置和 VPS 纳管矩阵。
3. **VPS 节点端 (Python3)**：作为高可用执行单元，拉取全球节点快照，建立主备 OpenVPN 隧道，双重质检（TestISP 探测 + YouTube 流媒体验证），并对外提供原生纯净的 Socks5/HTTP 代理端口。
4. **质检网关 (TestISP.info)**：负责为 C2 总控面板提供 IP 的原生性、ISP 商业属性及风险维度的深度数据支撑。

---

## 🚀 部署指南

### 第一步：创建 Cloudflare D1 数据库

1. 登录 Cloudflare 控制台，进入 **Workers & Pages** -> **D1 SQL Database**。
2. 点击 **Create database**，创建一个数据库（例如命名为 `proxy-db`）。

> **注意**：无需手动建表，系统首次运行将自动初始化表结构。

### 第二步：部署 Cloudflare Worker

1. 进入 **Workers & Pages**，点击 **Create application** -> **Create Worker**，随意命名（例如 `proxy-controller`）并部署。
2. 点击刚创建的 Worker，进入 **Settings** -> **Variables**。
3. **绑定 D1 数据库**：
   * 在 `D1 Database Bindings` 处添加绑定。
   * **Variable name** 必须严格填入：`DB`
   * **D1 Database** 选择第一步创建的 `proxy-db`。
4. **配置环境变量 (Environment Variables)**（必须设置！！！不填则使用系统弱口令，极易被扫描器爆破）：

| 变量名 | 默认值 | 作用说明 |
| --- | --- | --- |
| `WEB_USER` | `admin` | 面板 Web 登录用户名 |
| `WEB_PASS` | `admin888` | 面板 Web 登录密码 |
| `PROXY_USER` | `proxy` | Socks5/HTTP 代理连接用户名 |
| `PROXY_PASS` | `888888` | Socks5/HTTP 代理连接密码 |

5. 进入 **Quick edit**（快速编辑），将本仓库提供的 `Worker` 全量代码粘贴覆盖，点击 **Save and Deploy**。

### 第三步：纳管 VPS 节点

准备一台干净的 Linux VPS（推荐 Ubuntu 20.04/22.04 或 Debian 11/12 系统），通过 SSH 以 `root` 身份登录。

访问您刚才部署的 Cloudflare Worker 域名（需输入配置的 `WEB_USER` 和 `WEB_PASS` 进行 Basic Auth 认证）。在面板右上角复制自动生成的纳管命令并执行：

```bash
bash <(curl -sL (https://您的worker域名.workers.dev/agent))

```

脚本将自动执行以下操作：

1. 修复 Linux 内核 `rp_filter`（防止双网卡路由回包丢弃）。
2. 安装 OpenVPN 核心包及相关依赖。
3. 从 C2 控制端拉取最新版本的双活调度引擎（`lite_manager.py` / `proxy_server.py`）。
4. 配置并启动 `proxy-lite.service` 系统级守护进程。

---

## 💻 面板使用与客户端连接

### 管理面板核心功能

直接在浏览器访问您的 Worker 域名进入总控中心。

* **策略下发与端口云配**：在主控区输入目标国家代码（如 `JP`, `US`, `GB`）并可动态修改节点监听端口（默认 `7920`）。点击**下发策略**，Agent 将在下一次心跳周期（~15s）内无缝应用。
* **强制斩断与重拨**：点击紫色的**强制更换 IP**，系统将瞬间销毁当前双活通道，将物理 IP 关入黑名单，并从底层重新拉起建连。
* **TestISP 深度质检报告**：面板下方自动生成当前活跃出口 (Active) 的深度体检报告（包含原生性、运营类型、Spamhaus 情报等）。点击右上角**原版页面**，系统会自动将该 IP 复制到您的剪贴板并跳转至 TestISP.info 官网供您比对查验。
* **实时 Auto-Sync 日志流**：面板底部可直接窥视 VPS 母机的实时运行日志，方便排查故障。

### 代理调用格式

系统提供了一个直链 API，用于快速提取当前 Active 状态的代理地址（完美兼容量化程序和指纹浏览器插件导入）：

```http
GET [https://您的worker域名.workers.dev/api/proxies](https://您的worker域名.workers.dev/api/proxies)

```

*(注：调用此 API 需携带 `Authorization: Basic <Base64>` 认证头)*

**标准客户端连接格式：**

```text
socks5://<PROXY_USER>:<PROXY_PASS>@<VPS母机IP>:<服务端口>
http://<PROXY_USER>:<PROXY_PASS>@<VPS母机IP>:<服务端口>

```

---

## 🗑️ 终极卸载命令

如需彻底移除 VPS 上的节点调度程序并恢复网络路由状态，请执行以下命令（已适配双活表 101/102）：

```bash
# 1. 停止并禁用守护进程
systemctl stop proxy-lite.service 2>/dev/null
systemctl disable proxy-lite.service 2>/dev/null
rm -f /lib/systemd/system/proxy-lite.service
systemctl daemon-reload

# 2. 强杀残留的 Python 调度器和 OpenVPN 进程
pkill -f "lite_manager.py" 2>/dev/null
pkill -f "proxy_server.py" 2>/dev/null
pkill -f "openvpn.*tun_main|tun_backup" 2>/dev/null

# 3. 清理主备双路策略路由 (防止宿主机断网)
ip rule del lookup 101 pref 101 2>/dev/null
ip rule del lookup 101 pref 1101 2>/dev/null
ip route flush table 101 2>/dev/null
ip rule del lookup 102 pref 102 2>/dev/null
ip rule del lookup 102 pref 1102 2>/dev/null
ip route flush table 102 2>/dev/null

# 4. 删除所有引擎代码和配置文件
rm -rf /opt/proxy_lite

echo "✅ 双活代理引擎及所有配置已彻底卸载清理完毕！"

```

---

## ⚠️ 声明与限制

* **合法合规**：本系统仅供个人网络学习、数据科学实验与路由隔离技术测试。请务必确保您的网络抓取及访问行为严格遵守您所在国家以及目标服务器所在国家/地区的法律法规。
* **严禁滥用**：请勿将系统用于发送垃圾邮件、发动 DDoS 攻击或其他任何导致上游提供商触发 `Spamhaus` 封禁的行为。

```

```
