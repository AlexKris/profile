# SmartDNS 部署脚本

基于 Docker 的 SmartDNS 一键部署，支持两种模式。

## 模式

| 模式 | 命令 | 功能 |
|------|------|------|
| 纯缓存 | `./deploy-smartdns.sh` | DNS 缓存加速 |
| 分流解锁 | `./deploy-smartdns.sh -d` | DNS 缓存 + 流媒体分流 |

## 快速开始

```bash
# 纯 DNS 缓存
bash <(curl -fsSL "https://raw.githubusercontent.com/AlexKris/profile/main/tool/smartdns/deploy-smartdns.sh?$(date +%s)")

# DNS 缓存 + 流媒体分流
bash <(curl -fsSL "https://raw.githubusercontent.com/AlexKris/profile/main/tool/smartdns/deploy-smartdns.sh?$(date +%s)") -d -u 22.22.22.22
```

## 参数说明

```
-d, --download-lists       启用分流模式
-i, --intranet-dns <IP>    设置内网 DNS（可选）
-u, --unlock-dns <IP>      设置解锁 DNS（默认: 103.214.22.32，仅 -d 模式）
-t, --timezone <TZ>        设置时区（默认: Asia/Hong_Kong）
--uninstall                卸载
-h, --help                 帮助
```

## 部署后

### 目录结构

```
/root/smartdns/
├── config/
│   ├── smartdns.conf
│   └── domain-lists/      # 仅 -d 模式
├── docker/
│   └── docker-compose.yaml
└── update-lists.sh        # 仅 -d 模式
```

### 常用命令

```bash
# 查看状态
docker ps | grep smartdns

# 查看日志
docker logs -f smartdns

# 重启服务
cd /root/smartdns/docker && docker compose restart

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
