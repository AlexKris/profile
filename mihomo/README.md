# Mihomo 配置

基于 Surge.conf 分组结构和 [skk.moe](https://ruleset.skk.moe) 规则集的 mihomo (Clash Meta) 配置。

## 核心设计

- **fake-ip 模式**：非直连域名不在本地做 DNS 解析，根本性避免 DNS 污染和泄漏
- **域名优先规则排序**：域名规则在前（不触发 DNS），IP 规则在后（触发 DNS）
- **DNS 分流**：国内厂商域名走各自 DNS，Netflix 走 Cloudflare DoH，内网域名走系统 DNS
- **TUN 模式**：`stack: mixed`，系统级全局代理
- **QUIC 阻止**：海外 UDP 443 端口 REJECT，强制走 TCP 提高代理兼容性

## 文件结构

```
mihomo/
├── mihomo.yaml              # 主配置文件
├── rule/                    # 自定义规则（classical 格式）
│   ├── netflix.txt          # Netflix
│   ├── youtube.txt          # YouTube
│   ├── bilibili.txt         # Bilibili（含港澳台）
│   ├── bahamut.txt          # 巴哈姆特
│   ├── iqiyi.txt            # 爱奇艺
│   ├── tencent.txt          # 腾讯视频
│   ├── crypto.txt           # 加密货币（交易所/DeFi/NFT/钱包）
│   ├── paypal.txt           # PayPal
│   ├── twitter.txt          # Twitter/X
│   ├── agentide.txt         # AgentIDE
│   └── process.txt          # 进程直连规则
├── MihomoPro.yaml           # 参考配置（MihomoPro）
├── iKeLeeMihomo.yaml        # 参考配置（iKeLee）
└── MihomoProREADME.md       # MihomoPro 说明
```

## 规则集来源

| 来源 | 用途 | 格式 |
|---|---|---|
| [skk.moe](https://ruleset.skk.moe) | CDN / Global / Domestic / AI / Telegram / 流媒体 / Apple / Microsoft / Download / Speedtest | text (domain/classical) |
| [666OS/rules](https://github.com/666OS/rules) | Games / Google / Instagram(Facebook) | mrs (domain) |
| 自定义 (`mihomo/rule/`) | Netflix / YouTube / Bilibili / Crypto 等 | text (classical) |
| [skk.moe NSP](https://ruleset.skk.moe/Internal/mihomo_nameserver_policy/) | DNS 分流（阿里/腾讯/百度/字节等） | text (classical) |

## 策略组结构

```
Proxy (手动选择)
├── DIRECT
├── Opt        ← HK/JP/KR 节点（ISP 级筛选）
├── Core       ← HK / TW / JP（手动切换地区）
└── Edge       ← HK/JP 节点

专用策略组:
├── Telegram / YouTube / Netflix / GlobalMedia / ChinaMedia
├── AIGC / Google / Speedtest / Download / CDN
├── Instagram / Twitter / Crypto / PayPal
├── GlobalEmby / RFCEmby / DirectEmby
├── AppleCDN / AppleCN / MicrosoftCDN
└── Gaming    ← HK-Auto / JP-Auto / SG-Auto / US-Auto（自动测速）

Final (兜底) → Proxy / DIRECT
```

## 使用前配置

1. **替换订阅地址**：编辑 `mihomo.yaml` 第 105 行，将 `'订阅地址'` 改为实际的订阅 URL
2. **设置管理密码**：第 131 行 `secret: ''` 设置密码
3. **推送规则文件**：`mihomo/rule/*.txt` 需要推送到 GitHub，rule-providers 引用的是 `raw.githubusercontent.com` 地址

## DNS 配置

| 域名类别 | DNS 服务器 | 说明 |
|---|---|---|
| 阿里系 | `quic://dns.alidns.com:853` | 阿里 QUIC DNS |
| 腾讯系 | `https://doh.pub/dns-query` | 腾讯 DoH |
| 百度系 | `180.76.76.76` | 百度 DNS |
| 字节系 | `180.184.2.2` | 字节 DNS |
| Netflix | `https://cloudflare-dns.com/dns-query` | Cloudflare DoH |
| 内网/门户 | `system` | 系统 DNS |
| 代理节点域名 | 阿里 + 腾讯 DoH | 直连解析 |
| 其他域名 | fake-ip (198.18.0.0/16) | 不做本地解析 |

## fake-ip-filter（真实 IP 域名）

以下域名返回真实 IP 而非 fake-ip：

- Netflix 全系域名（解锁检测需要真实 IP）
- 游戏域名：EA / Blizzard / Steam / Xbox / PlayStation（UDP 兼容）
- 系统检测：msftconnecttest / msftncsi
- STUN/TURN 服务
- LAN / 内网域名

## 平台兼容性

| 特性 | macOS | Windows | Linux |
|---|---|---|---|
| TUN (mixed) | ✅ | ✅ | ✅ |
| auto-route | ✅ | ✅ | ✅ |
| auto-redirect | ❌ | ❌ | ✅ |
| PROCESS-NAME 规则 | ✅ | ✅ | ✅ |
| 防火墙注意 | 需放行 mihomo | 需放行 mihomo | - |

## 已知限制

- **Netflix DoH 走向**：mihomo 没有 Surge 的 `encrypted-dns-follow-outbound-mode`，Cloudflare DoH 请求默认走 DIRECT。如果 Netflix 掉解锁，在 DNS 配置中加 `respect-rules: true`
- **Snell 协议**：mihomo 不支持 Snell，仅使用订阅源返回的 SS 等兼容协议
- **USER-AGENT 规则**：mihomo 不支持，由 sniffer TLS SNI 嗅探替代
