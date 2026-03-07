# SmartDNS 部署脚本

基于 Docker 的 SmartDNS 一键部署，支持三种使用场景。

## 模式

| 模式 | 命令 | 功能 |
|------|------|------|
| 纯缓存 | `./deploy-smartdns.sh` | DNS 缓存加速 |
| 分流解锁 | `./deploy-smartdns.sh -d` | DNS 缓存 + 流媒体分流 |
| 强制 IPv6 | `./deploy-smartdns.sh -6` | DNS 缓存 + 指定域名强制 IPv6 |

模式可组合，例如 `-d -6` 同时启用分流解锁和强制 IPv6。

## 快速开始

```bash
# 纯 DNS 缓存
bash <(curl -fsSL "https://raw.githubusercontent.com/AlexKris/profile/main/tool/smartdns/deploy-smartdns.sh?$(date +%s)")

# DNS 缓存 + 流媒体分流
bash <(curl -fsSL "https://raw.githubusercontent.com/AlexKris/profile/main/tool/smartdns/deploy-smartdns.sh?$(date +%s)") -d -u 22.22.22.22

# DNS 缓存 + 强制 IPv6（Anthropic/Claude 走 IPv6 出站）
bash <(curl -fsSL "https://raw.githubusercontent.com/AlexKris/profile/main/tool/smartdns/deploy-smartdns.sh?$(date +%s)") -6

# 全部组合
bash <(curl -fsSL "https://raw.githubusercontent.com/AlexKris/profile/main/tool/smartdns/deploy-smartdns.sh?$(date +%s)") -d -6 -u 22.22.22.22
```

## 参数说明

```
-d, --download-lists       启用分流模式
-6, --force-ipv6           启用强制 IPv6（屏蔽指定域名 A 记录，只返回 AAAA）
-i, --intranet-dns <IP>    设置内网 DNS（可选）
-u, --unlock-dns <IP>      设置解锁 DNS（默认: 103.214.22.32，仅 -d 模式）
-t, --timezone <TZ>        设置时区（默认: Asia/Hong_Kong）
--uninstall                卸载
-h, --help                 帮助
```

## 强制 IPv6

通过 `-6` 参数启用。SmartDNS 会屏蔽指定域名的 A 记录（`address /domain-set:force-ipv6/#4`），使系统只能解析到 AAAA 记录，从而强制走 IPv6 出站。

**典型场景：** soga 代理节点需要通过 IPv6 连接 Anthropic API（如 SoftBank VPS 的 IPv6 出口更优）。

默认域名列表（`/root/smartdns/config/force-ipv6.list`）：
- `anthropic.com`
- `claude.ai`

部署后可直接编辑该文件增减域名，然后 `docker restart smartdns` 生效。

**验证：**
```bash
dig api.anthropic.com @127.0.0.1 A +short       # 应为空
dig api.anthropic.com @127.0.0.1 AAAA +short     # 应返回 IPv6 地址
dig claude.ai @127.0.0.1 A +short                # 应为空
dig api.openai.com @127.0.0.1 A +short           # 不受影响，正常返回 IPv4
```

## 部署后

### 目录结构

```
/root/smartdns/
├── config/
│   ├── smartdns.conf
│   ├── force-ipv6.list      # 仅 -6 模式
│   └── domain-lists/        # 仅 -d 模式
│       ├── netflix.conf
│       ├── disney.conf
│       └── youtube.conf
├── docker/
│   └── docker-compose.yaml
└── update-lists.sh          # 仅 -d 模式
```

### 常用命令

```bash
# 查看状态
docker ps | grep smartdns

# 查看日志
docker logs -f smartdns

# 重启服务
cd /root/smartdns/docker && docker compose restart

# 停止服务
cd /root/smartdns/docker && docker compose down

# 更新镜像
cd /root/smartdns/docker && docker compose pull && docker compose up -d

# 测试解析
dig google.com @127.0.0.1
```

### 域名列表更新（分流模式）

```bash
# 手动更新
/root/smartdns/update-lists.sh

# 定时更新（每周日凌晨 3 点）
crontab -e
# 添加：
0 3 * * 0 /root/smartdns/update-lists.sh >> /var/log/smartdns-update.log 2>&1
```

## 域名列表来源

分流模式使用 [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) 作为数据源，包含：
- Netflix
- Disney+
- YouTube
