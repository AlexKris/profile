# sing-box 1.14 XBoard 模板

审计日期：2026-09-16（sing-box 1.14.1）；2026-10-10 与 Surge/mihomo 对齐分流逻辑，使用 sing-box **1.14.2** 重新生成、加载和测试。

适用文件：`xboard_singbox_realip_ipv4_only.json`、`xboard_singbox_fakeip_ipv4_only.json`、`protocols_data/SingBox.php`。
JSON 是 XBoard 输入模板，含节点筛选扩展字段，不能直接当成 sing-box 成品配置运行。
这组模板明确要求 1.14；PHP 不再按 UA 进行 1.13/1.14 格式迁移。保留节点协议生成逻辑，不把旧客户端重新兼容进来。

## 设计边界

- 家庭、办公室 IPv4 网络和手机双栈网络统一使用客户端 IPv4 业务流量，包括直连及连接代理节点入口。代理协议将目标域名交给远端解析时，出口使用哪个地址族仍由远端决定，客户端模板不能据此保证出口也只使用 IPv4。
- DNS 的 AAAA 查询返回 NOERROR 空结果；TUN 配置 IPv6 地址以接管 IPv6，再在路由中拒绝非 DNS 的 IPv6 目标。这不是开启 IPv6 出站，也不会关闭手机系统 IPv6。
- DNS 劫持先于 IPv6 拒绝，允许应用通过 IPv6 地址提交 DNS 查询；公共 DoH 上游使用 IPv4，`dns_local` 仍遵循平台本地解析实现。
- IPv6 拒绝先于私网、Direct、Global；`no_drop: true` 避免频繁命中后变成静默丢包，减少应用等待超时。
- 客户端直连 IPv6-only 目标不在支持范围内；节点入口本身也应具备可用的 IPv4。系统明确排除在 VPN 外的流量不受模板控制。
- 分流逻辑与 Surge/mihomo 一致：未命中任何域名规则的连接直接走 Final，路由中不解析域名；`geoip-cn`、`telegram-ip` 只对目标本身是 IP 的连接生效。国内域名依赖自建 `cn-domain`（v2fly `cn` ∪ 经 Tranco 前 100 万过滤的 Loyalsoldier direct-list，约 1.39 万条），不再保留与 Final 等价的 `proxy`、`geolocation-!cn` 海外兜底。
- 所有远程 SRS 统一使用自建 Pages；其中 4 个基础集合（geosite-private、geosite-telegram、geosite-google、geoip-cn）按 SagerNet 原文件同步，不改变其正则语义。
- Apple 按现有域名规则分流，不设整个 `17.0.0.0/8` 直连兜底；Surge 的历史 QUIC 修复不移植到此模板。
- 规则顺序与 Surge/mihomo 一致：stream → apple-proxy → apple。Apple TV+ 走 GlobalMedia，iCloud 专用代理、Apple News、开发者服务走 Proxy，其余 Apple 域名直连。

## 问题与修正

| 原问题 | 修正 | 原因 |
| --- | --- | --- |
| 兜底 `resolve` 让未命中域名先真实解析，再匹配 `geoip-cn` | 删除兜底 `resolve` 及其后的私网检查，未命中直接走 Final | 与 Surge/mihomo 一致；FakeIP 下省去一次经 Proxy 的 DoH 往返，DoH 故障不再阻断连接 |
| 私有域名提前路由 Direct，但没有指定本地解析 | 私有域名先用 `dns_local` 解析，再 Direct | Direct 拨号的默认解析器不是 `dns.rules`，不能只改 DNS 规则而忽略路由 |
| DNS 中 CN 规则早于 Global 和专用服务 | 局域网例外、模式、专用服务、CN、兜底 | 避免路由选代理而解析先被 CN 大规则接走 |
| FakeIP 的 Global 规则没有限制查询类型 | 只有 A 进入 FakeIP；其他类型走真实 DNS | FakeIP 不能承接 MX、TXT、SRV 等查询 |
| FakeIP 真实地址例外全部走国内 DNS | 按国内、境外、局域网分别解析 | STUN 等需要真实地址，不等于需要国内解析器或直连 |
| FakeIP 模板没有 `reverse_mapping` | 两份均开启 | FakeIP 的真实地址例外也需要域名映射辅助路由 |
| HTTPS/SVCB 拒绝位置不统一，另有笼统 PTR 拒绝 | 统一返回 NOERROR 空结果；恢复 PTR/SOA 分流路径 | 避免笼统拒绝；Apple 平台非 A/AAAA 的本地解析仍须实机验证 |
| 所有连接先 sniff | DNS 53 端口、私网、强制模式先处理；只对 IPv4 目的地址 sniff | FQDN 和已还原的 FakeIP 已有目标域名，不必等待首包；RealIP 仍保留 HTTP/TLS/QUIC/DNS 嗅探 |
| 空筛选组默认填 Direct | 模板显式 fallback 到 Proxy；无节点、重名、保留组名冲突报错 | 避免节点缺失或命名问题使流量悄悄直连 |
| `DE`、`US`、`ATT` 等正则匹配单词内部 | 国家代码和运营商名加字母边界，同时列出地区别名；复合筛选从行首匹配 | 兼容 HKG/USA/JPN 等命名，又避免 `Node` 命中 DE、`Seattle` 命中 ATT |
| 无效正则只记录警告并继续 | 生成失败，要求修正模板 | 特别是 `exclude` 失效时，继续生成会放宽原本的排除条件 |
| API secret 漏填或仍为公开占位符时也能生成订阅 | `handle()` 加载模板后检查 API secret，含回退模板中实际启用的旧 Clash API 监听 | 文件模板及后台回退模板都不能输出空密钥或 `REPLACE_WITH_SECRET` |
| 日常连接和 DNS 日志需要可见 | 默认 info | 保留日常排查信息；深入诊断时临时调为 debug |
| SagerNet geosite-cn（约 9.3k 条）加 `proxy`、`geolocation-!cn` 海外兜底 | 换自建 `cn-domain`，删除海外兜底 | 与 Surge/mihomo 共用同一份国内列表；海外兜底与 Final 等价 |
| 缺 `direct`、`domestic`、`apple-proxy` 和非 IP 的 `download` | 补齐，DNS 同步 | PT/学术站等 167 条不在 cn-domain，原先走代理；iCloud 专用代理原先被 apple 直连 |
| apple 先于 stream，Apple TV+ 被 apple 直连 | 路由和 DNS 都改为 stream → apple-proxy → apple | rules 仓库要求的顺序，避免 TV+ 链路分到不同出口 |
| Crypto（默认 TW）、microsoft → Proxy | 删除，交给 Final | 与 Surge 一致 |
| 地区正则没有中文地名；TW 等组含 🇨🇳 | 加中文地名，去掉 🇨🇳 | 台湾节点名含 TW（如 `🇨🇳TW.Hinet`）；避免 🇨🇳 中转节点混入 TW/GlobalMedia/Speedtest/AIGC |

专用组 fallback 到 Proxy 只在没有合适节点时发生，会记录服务端警告。此时不保证原来的地区/ISP 条件，但不自动直连。Proxy 本身没有可用节点时生成失败，不输出一份全直连的“成功”订阅。

地区匹配保留国旗和中文地名（香港、台湾/台灣、日本、新加坡、美国、德国），英文别名按完整词匹配且不区分大小写：HK/HKG/Hong Kong、TW/TWN/Taiwan、JP/JPN/Japan、US/USA/United States、DE/DEU/GER/Germany、SG/SGP/Singapore；AIGC 另支持 UK/GB/GBR/United Kingdom 和“英国”。🇨🇳 不作为任何地区条件：台湾节点按名字中的 TW 匹配（如 `🇨🇳TW.Hinet`），所以台湾节点名必须含 TW/TWN/Taiwan/台湾。地区组及复合服务组使用同样的别名，运营商条件不放宽。测试覆盖这些名字，但本轮未读取 XBoard 实际节点清单，部署前仍须检查真实生成结果，不能只看订阅是否成功。

## DNS 逻辑

| Rule 模式下的目标 | RealIP | FakeIP 的 A 查询 |
| --- | --- | --- |
| 私有域名、路由器域名、局域网下载缓存 | 系统本地 DNS | 系统本地 DNS |
| 连通性检查、direct-extra | 阿里 DoH 直连 | 阿里 DoH 直连 |
| AI、测速、PayPal、流媒体、Telegram、apple-proxy | Cloudflare DoH 经 Proxy | FakeIP，真实地址例外除外 |
| Apple、微软 CDN | 阿里 DoH 直连 | 阿里 DoH 直连 |
| Download、Google | Cloudflare DoH 经 Proxy | FakeIP，真实地址例外除外 |
| domestic、direct、cn-domain | 阿里 DoH 直连 | 阿里 DoH 直连 |
| 其余目标 | Cloudflare DoH 经 Proxy | FakeIP；真实地址例外使用 Cloudflare DoH |

Direct 模式：除局域网外使用阿里 DNS。Global 模式：除局域网外使用代理 DNS，FakeIP 模板的普通 A 查询使用 FakeIP。两种模式均保留 IPv4 边界及 HTTPS/SVCB 处理。

STUN、主机游戏等真实地址例外集中在 `dns-realip`，**只决定不使用 FakeIP，不改变业务路由**。MX/TXT/SRV/SOA 按对应真实 DNS 分流，不送进 FakeIP。

`route.default_domain_resolver` 仍指向阿里 DNS，用于节点域名引导和 Direct 拨号。否则节点域名可能依赖尚未建立的代理，形成启动循环。它只影响 Direct 拨号和节点引导，不能改成强制代理 DNS。

路由中没有兜底 `resolve`。sing-box 的 IP 规则不会隐式解析域名：FakeIP 还原出的域名、HTTP/SOCKS 域名入站在未命中域名规则时直接进入 Final，由代理协议把域名交给出口解析，本机不发出 DNS 查询（测试用不可达 SOCKS 节点验证）。RealIP 下 TUN 连接本身带应用已解析的真实地址，`geoip-cn`、`telegram-ip` 仍按该地址判断。

代价：未收录在 cn-domain 的国内域名在 FakeIP 下会走代理，依赖列表覆盖面；公网域名解析到私网地址的情况在 FakeIP 下不再自动直连，私网例外只认 geosite-private/local-extra 和目标本身是私网 IP 的连接。

DNS 处理不等于所有代理目标都在本机解析。域名提前命中代理规则时，可由代理协议把域名交给出口解析；这通常能更好地匹配出口所在地。

`dns_local` 的平台行为不完全相同：Apple NetworkExtension 的系统解析接口只处理 A/AAAA，macOS 还会优先尝试 DHCP。不能据此证明 iOS/tvOS 的私网 PTR、SOA、SRV 都正确。当前不无证据恢复笼统拒绝；若实机发现私网 PTR 回环，才针对受影响的私网反向区域返回 predefined NXDOMAIN，不把所有公网 PTR 或 `.local` 一并拒绝。[本地 DNS 文档](https://sing-box.sagernet.org/configuration/dns/server/local/)。

## 内存、网络与规则效率

- 普通 DNS LRU 使用核心默认的 1024 项下限，删除了等同默认值的显式 `cache_capacity: 1024`。这是去冗余，不是内存优化；字段本身有效，设为更大值会改变容量。反向域名映射是核心另一份 1024 项缓存。[1.14.1 缓存实现](https://github.com/SagerNet/sing-box/blob/v1.14.1/dns/client.go)、[反向映射实现](https://github.com/SagerNet/sing-box/blob/v1.14.1/dns/router.go)。
- 尊重 DNS TTL；不启用长期 stale/optimistic 结果、不禁用过期、不强行延长 TTL，避免 CDN 地址改变后继续使用失效 IP。
- FakeIP 保留 `store_fakeip`，避免重启后应用缓存的假地址失去域名对应关系。该映射和普通 DNS 缓存不同，不建议为节省少量磁盘直接关闭。
- 继续使用二进制 SRS，同一规则集在 DNS 和路由中按 tag 复用；合并相邻的同目的匹配（如 domestic/direct/cn-domain → Direct），不改变专用服务优先级。
- 当前 21 个远程 SRS 合计 179,456 字节，约 175 KiB，其中 cn-domain 约 63 KiB。**这是下载体积，不是进程内存**。实测 1.14.2 的 Go 在用内存（clash_api `/memory`）：11.2 万条版本的 cn-domain 单独加载比空配置多约 1 MiB（精简后未重测，条数约为原来的八分之一）；被替换掉的 geosite-cn、geolocation-!cn、proxy×2、microsoft、cryptocurrency 合计多约 2.3 MiB，换源后内存反而下降。
- 规则和 Dashboard 共用具名 `http_proxy`，由 `route.default_http_client` 指定。删除旧 `download_detour` 及重复逐项配置，避免未来格式移除。
- 保留 `mixed` 栈、MTU 1400 和平台默认 UDP 会话容量，不凭经验扩大缓冲、强加多路复用、TCP Fast Open 或频繁主动测速。路径 MTU、节点协议及实际负载决定这些参数是否有收益。
- `endpoint_independent_nat` 早已不生效，删除它；1.14 的 `udp_mapping`、`udp_filtering` 默认就是 endpoint-independent，不重复配置。NAT 最终结果还受转发链及出口实现影响，客户端配置不能保证 NAT A。[UDP NAT 文档](https://sing-box.sagernet.org/configuration/shared/udp-nat/)。

这是以正确分流、可靠连接和受控开销为目标的基线，不代表在所有设备上同时取得最低内存和最大吞吐。未测量真实手机负载、峰值 RSS、长时间下载和漫游切网，不能虚构性能提升百分比。

## 保留的明确取舍

- HTTPS/SVCB 返回空结果是现有“优先确定性分流”策略的统一实现，不是 DNS 协议要求。会放弃这些记录提供的 ECH、地址提示及部分协议发现能力；普通 A/TLS 和通过其他机制发现的 HTTP/3 不因此被禁止。
- MSCDN 按当前默认 Direct 设计国内 DNS；手动切到 Proxy 不会自动换解析器。Final 也是路由选择，不是 DNS 选择。需要全局直连语义时应切 Direct 模式。
- 不为每个专用策略组创建单独 DoH 实例，避免传输、缓存和维护项膨胀。RealIP 的代理 DNS 出口可能与专用组出口不同，无法承诺每个 CDN 均获得该专用出口的最优地址。
- 首次没有规则缓存时需要 Proxy 可用；有有效缓存后可先从缓存启动。没有改成国内网络可能无法访问的全直连下载，也没有去掉关键规则。
- 应用自带 DoH、系统缓存未清理及平台 VPN 排除项不保证经过这里的 DNS 分流。RealIP 对域名的识别依赖反向映射和可嗅探内容，不可能在共享 IP、ECH 等所有场景都精确还原域名。
- 1.14.1 反向映射保存的是答案中 A/AAAA 记录的属主名，不保证是原始查询名。CNAME 链可能留下 CDN 主机名；非嗅探协议或无法提取 Host/SNI 的连接可能因此错过原域名规则。FakeIP 的真实地址例外也受此限制，不能把 `reverse_mapping` 当成原域名恢复保证。

## 官方 Dashboard

- 本机：`http://127.0.0.1:9090/dashboard/`。
- 局域网：`http://设备内网IPv4:9091/dashboard/`。
- 面板 URL 填对应的 API 基址，不加 `/dashboard/`。远程设备不要填自己的 `127.0.0.1`。
- 两个地址都是 IPv4 监听，不监听 `::1`；本机验收应使用明确的 `127.0.0.1`，不能假定 localhost 的 IPv6 解析一定可用。
- 两个监听器分别使用 `dashboard`、`dashboard-lan`，避免两个下载器同时替换同一目录。保留此前为 SFM 验证有效的独立回环监听，不再依赖通配监听兼容回环访问。
- 两份 Dashboard 首次各下载、解压一份资源，托管目录默认各每 24 小时检查更新；有 ETag 时可以返回 304，不代表每天必定重下整个压缩包。压缩包大小随版本变化，两份磁盘资源和更新请求是双入口的实际代价。[1.14.1 Dashboard 实现](https://github.com/SagerNet/sing-box/blob/v1.14.1/service/api/dashboard.go)。
- CORS 列表限制浏览器普通 HTTP/gRPC-Web 的跨域读取许可，不是请求来源 ACL；同源页面不依赖这份许可。`localhost:9090` 与 `127.0.0.1:9090` 互访、9090 页面连接 9091 API 仍属于跨域。
- 1.14.1 的 WebSocket 升级不校验 Origin，不能由 HTTP CORS 设置推导出 WebSocket 来源被限制；API 权限必须依赖 secret。[1.14.1 WebSocket 实现](https://github.com/SagerNet/sing-box/blob/v1.14.1/service/api/web_bridge_websocket.go)。
- **`0.0.0.0` 不是“仅限内网”**。必须保留服务端私有强 secret；`REPLACE_WITH_SECRET` 不可用于实际部署。不要把 9091 暴露至公网，只在可信局域网使用明文 HTTP。
- PHP 拒绝缺失、空白、非字符串或公开占位符 secret，且报错不打印密钥。这个检查不是密码强度审计，部署仍需使用私有随机密钥；不要每次生成订阅时随机换密钥，以免已保存的面板连接失效。
- CORS 和 `access_control_allow_private_network` 不是客户端 IP ACL，尤其不能代替鉴权或主机防火墙。[API 文档](https://sing-box.sagernet.org/configuration/service/api/)。

## 验证与部署

在仓库根目录执行：

```sh
php -l singbox/protocols_data/SingBox.php
python3 singbox/tests/test_templates.py
git diff --check
```

需要 PHP 和 sing-box 1.14.x；可用 `SING_BOX=/path/to/sing-box` 指定核心。测试仅运行 CLI 核心和随机回环端口的 DNS/HTTP 服务，不启用 TUN、不打开 SFM、不改变系统代理、不连接真实节点。

生成测试使用最小 Laravel 桩调用实际 `handle()`，覆盖文件模板/后台回退模板加载、两处原生 API 及旧 Clash API 监听的 secret 校验、空组/重名/正则及地区别名；只有 `default_mode` 而不监听的 Clash API 不要求 secret。在临时模板中注入测试专用密钥，不改仓库占位符。它仍不是生产 Laravel HTTP 集成测试。

运行测试覆盖核心配置校验、两种模板三种模式、DNS 查询类型与缓存、未命中域名不在本机解析、中文地名与 `🇨🇳TW` 节点筛选、IPv6 拒绝、FakeIP 重启映射、SRS 缓存启动、两个 API 的页面/鉴权/HTTP CORS。但代理传输换成了 Direct（未命中解析测试改用不可达 SOCKS）、本地 DNS/DoH 换成 UDP 桩、远程规则多数换成小样例、Dashboard 页面换成静态样例，不能代替真实节点、Apple 本地 DNS、原生面板 WebSocket 或 TUN 验证。2026-10-10 另下载 Pages 上全部 21 个实际远程 SRS（与仓库逐字节一致），全部反编译，并用生成的两份配置加载检查：vrzwk.top、kskwai.com、hdsky.me、www.ieee.org → Direct；mask.icloud.com → Proxy；tv.apple.com → GlobalMedia；www.apple.com → Direct；223.5.5.5 → geoip-cn；未收录域名、1.1.1.1 及 FakeIP 还原的域名 → Final，路由阶段本机无 DNS 查询。

以下实机项目尚未完成，暂不据离线测试通过直接部署：

| 项目 | 验收要求 |
| --- | --- |
| FakeIP/FQDN 冷启动解析 | 同一网络、节点下比较首次与缓存命中的连接耗时；核对实际 DNS/出站，确认代理 DNS 故障时的表现 |
| iPhone 本地 DNS | 在 Wi-Fi/蜂窝分别观察私网 PTR、`.local` 的 A/SOA/SRV 查询去向及耗时，确认没有回环或持续重试；tvOS 需单独验证 |
| SFM Dashboard | 127.0.0.1:9090 和另一台局域网设备访问 9091 均成功，正确 secret 可控制、错误 secret 被拒绝，不能只看静态页面 200 |
| 问题网站与 IPv4 边界 | 两模板 Rule 模式下验证 TLS、页面和实际 DNS/路由；FakeIP 给应用假地址是正常行为，CDN 的真实 IP 可变化，不以固定 IP 段作为验收条件；同时验证 TUN 接管后的 IPv6 不绕行 |

这些验证不得擅自启动 SFM、切换系统代理或连接生产服务器；应先取得用户授权。调试日志及私有配置只放临时目录，不提交 Git。

生产部署属于独立操作，本轮未执行。部署时必须：

1. 备份服务器上 PHP、两份模板及私有差异。
2. 仅在服务器临时目录合并私有域名和 API secret，不能把私有成品回写或提交到本仓库。
3. 保留私有规则既有优先级，并同时检查 DNS。私有直连域名通常应显式选择合适的真实解析器且先于 CN/FakeIP 兜底：局域网用本地解析，国内可用阿里，受污染的公网域名不能一律改给阿里；FQDN 直连若需要非默认解析器，还需在直连前显式 resolve。私有代理域名若会被 Apple/CN 等 DNS 直连规则先命中，也需补 DNS 例外，不能假定走 Proxy 就无需检查。保留现有模式规则的相对优先级。
4. 用实际节点生成订阅并执行 1.14 配置校验，确认每组实际成员、私有域名的 DNS/出站、无模板扩展字段、引用有效、两处 secret 已替换，再替换生产文件。文件缺失时的后台回退模板也必须兼容 1.14；密钥检查不会替它自动迁移旧格式。
5. 客户端更新订阅并重启连接；切换 RealIP/FakeIP 或验证此前缓存错误的域名时，清理客户端/系统 DNS 缓存后重测。不要无条件删除 `cache.db`，以免一并丢失规则缓存、模式/分组选择和 FakeIP 映射。
