[💬 Telegram 交流群](https://t.me/kejikkkcom) | [📺 YouTube 频道：科技KKK](https://www.youtube.com/@%E7%A7%91%E6%8A%80KKK)

---

# 免费住宅 IP 代理调度系统 🌐

这是一个轻量级的智能代理调度系统。基于 Cloudflare Workers 与 D1 数据库构建中心控制节点，配合 VPS 守护进程，实现高频自动切换、优选纯净住宅 IP 的 Socks5/HTTP 代理服务。

系统资源占用极低，非常适合用于个人量化交易、网络测试或轻度数据抓取。

## ✨ 核心特性

* **⚡ 毫秒级极速调度**：采用 5 秒超时设定与 5 秒高频蓄水池抓取机制，节点假死后几秒内自动熔断并顶替新节点。
* **🏠 纯净解锁双重质检**：内置节点检测器，自动判定并剔除机房（Hosting/Datacenter）IP；同时强制探测 YouTube 流媒体连通性，确保线路真正纯净且可用。
* **🔄 主动强制换 IP**：支持面板一键发送时间戳指令，主动将当前 IP 关入小黑屋并触发重拨，彻底解决因延迟排序导致总是连上同一节点的问题。
* **📊 Serverless 全息看板**：零服务器成本部署控制端，提供可视化 Web UI，支持实时监控 VPS 状态与一键切换目标国家。
* **🚀 一行命令纳管**：VPS 节点端（Agent）无需复杂环境配置，一行 Bash 命令即可完成自动化部署与守护进程驻留。

---

## 🛠️ 架构说明

1. **C2 控制端 (Cloudflare Workers)**：负责下发国家策略、处理主动换 IP 指令、提供 Web 面板、分发节点端脚本以及存储心跳数据。
2. **状态存储 (Cloudflare D1)**：轻量级 SQLite 数据库，记录全局配置和 VPS 纳管状态。
3. **VPS 节点端 (Python3)**：作为执行单元，拉取 VPN 节点快照，进行双重质检（住宅判定 + YT 连通性），建立隧道，并对外提供鉴权的 Socks5/HTTP 代理端口。

---

## 🚀 部署指南

### 第一步：创建 Cloudflare D1 数据库

1. 登录 Cloudflare 控制台，进入 **Workers & Pages** -> **D1 SQL Database**。
2. 点击 **Create database**，创建一个数据库（例如命名为 `proxy-db`）。

> **注意**：无需手动建表，系统代码内置了自动建表逻辑。

### 第二步：部署 Cloudflare Worker

1. 进入 **Workers & Pages**，点击 **Create application** -> **Create Worker**，随意命名（例如 `proxy-controller`）并部署。
2. 点击刚创建的 Worker，进入 **Settings** -> **Variables**。
3. **绑定 D1 数据库**：

* 在 `D1 Database Bindings` 处添加绑定。
* **Variable name** 必须填入：`DB`
* **D1 Database** 选择第一步创建的 `proxy-db`。

4. **配置环境变量 (Environment Variables)**（可选，不填则使用系统默认值）：

| 变量名 | 默认值 | 作用说明 |
| --- | --- | --- |
| `WEB_USER` | `admin` | 面板 Web 登录用户名 |
| `WEB_PASS` | `admin888` | 面板 Web 登录密码 |
| `PROXY_USER` | `proxy` | Socks5/HTTP 代理连接用户名 |
| `PROXY_PASS` | `888888` | Socks5/HTTP 代理连接密码 |

5. 进入 **Quick edit**（编辑代码），将本仓库提供的 Worker 代码全量复制并粘贴，点击 **Save and Deploy**。

### 第三步：纳管 VPS 节点

准备一台干净的 Linux VPS（推荐 Ubuntu/Debian 系统），通过 SSH 登录。

访问您刚才部署的 Cloudflare Worker 域名（会自动弹出 Basic Auth 认证，输入您配置的 `WEB_USER` 和 `WEB_PASS` 登录）。在面板右上角复制一键安装命令并执行：

```bash
bash <(curl -sL https://您的worker域名.workers.dev/agent)

```

脚本将自动执行以下操作：

1. 安装 OpenVPN、Python3 等依赖环境。
2. 从 C2 控制端拉取最新版本的调度引擎。
3. 配置并启动 `proxy-lite.service` 系统守护进程。

---

## 💻 面板使用与客户端连接

### 管理面板

直接在浏览器访问您的 Worker 域名。

* **修改国家策略**：在“策略配置”区域，输入目标国家代码（如 `JP`, `US`, `KR` 等），点击“强制下发配置”，VPS 节点将在下一次心跳周期内自动切换到新国家的节点。
* **更换新 IP**：点击紫色的“更换新IP”按钮，系统会在 15 秒的心跳周期内主动拉黑当前节点，并从蓄水池中调取新的纯净住宅 IP 顶替。
* **监控状态**：底部列表会实时显示已纳管的 VPS 母机 IP、当前隧道物理 IP、心跳状态及 `● 纯净解锁 (YT)` 的质检状态。

### 代理调用

系统提供了一个直链 API，用于快速提取当前的代理信息（兼容量化程序和代理插件批量导入格式）：

```http
GET https://您的worker域名.workers.dev/api/proxies

```

> **注意**：调用此 API 同样需要带有 Basic Auth Header (Base64 编码的 `WEB_USER:WEB_PASS`)。

**客户端连接格式：**

```text
socks5://proxy:888888@<VPS母机IP>:7920
http://proxy:888888@<VPS母机IP>:7920

```

**VPS 实时日志查看命令：**

```bash
journalctl -u proxy-lite.service -f

```

---

## ⚠️ 声明与限制

* **合规性**：请确保您使用本系统抓取或访问的网络行为符合您所在国家及目标服务器所在地区的法律法规。
