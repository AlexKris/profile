# profile
个人使用配置

## Mihomo

维护两份完整配置，所有策略组均为手动选择；订阅健康检查只检测节点状态，不自动切换节点。

| 配置 | 适用设备 | 区别 |
| --- | --- | --- |
| [desktop.yaml](mihomo/desktop.yaml) | Windows、Mac | 保留进程分流、独立游戏下载策略和桌面 TUN/DNS 设置 |
| [mobile.yaml](mihomo/mobile.yaml) | iPhone、iPad、Apple TV、Android | 关闭进程查找，无桌面进程规则和独立游戏下载策略 |

使用前将 `proxy-providers.sub.url` 中的“订阅地址”替换为自己的节点订阅。
这些是 Mihomo YAML 模板，设备上的客户端必须支持该格式。ProjectClash 的 Clash 支持在 iPhone、iPad 和 Apple TV 上导入，参见[官方兼容性说明](https://clash.md/guide/compatibility/mihomo)。

对标准 Mihomo 1.19.33，桌面版的 `dns-mode: hijack` 显式接管 macOS 的系统 DNS；`strict-route: true` 用于阻止 Windows 多宿主 DNS 绕行，该版本的 macOS 实现不使用这一选项。参见 [Mihomo TUN 文档](https://wiki.metacubex.one/config/inbound/tun/)及 [macOS 实现](https://github.com/MetaCubeX/sing-tun/blob/v0.4.28/tun_darwin.go)。
移动端的系统 VPN/TUN 接管由客户端负责。FlClash 会覆盖部分端口、TUN 和进程查找设置；桌面进程分流需在客户端开启“查找进程”。

### ProjectClash 使用说明

ProjectClash 的 Clash 使用自己的 Apple Network Extension 接入实现，不能直接套用标准 Mihomo 的平台行为：它会接管 `auto-route`、`auto-detect-interface` 和 `dns-hijack`，并清空 `dns-mode`；`strict-route` 在没有显式配置对应地址族的 `route-address` 时，会影响默认路由的拆分方式。因此，“macOS 不使用 strict-route”不适用于 ProjectClash。参见[官方 TUN 说明](https://clash.md/zh/guide/config/inbound)。

- 导入后保留配置自身的规则，避免叠加其他规则方案或覆写脚本，并使用 Rule 模式。
- Apple TV 选择“配置自带规则”；“默认配置”和“懒人配置”只使用配置地址里的节点。IP Stack 的“IP 查询模式”和“IPv6”两组均选“跟随配置”。参见 [Apple TV 指南](https://clash.md/zh/guide/tvos)及 [IPv6 字段说明](https://clash.md/zh/guide/config/inbound)。
- 手动切换节点后，检查新连接实际命中的规则与代理链。Apple TV 不主动关闭旧连接，需要立即应用新节点时停止并重新连接 Tunnel。参见[日常使用说明](https://clash.md/zh/guide/everyday-use)。

### 旧配置迁移

| 旧文件 | 新文件 |
| --- | --- |
| `mihomo.yaml`、`mac.yaml`、`windows.yaml` | `desktop.yaml` |
| `iphone.yaml`、`android.yaml` | `mobile.yaml` |

旧文件已合并移除。使用旧文件远程链接的客户端，需要修改配置 URL 后重新加载；本地导入的配置需要重新导入。

### 验证

已使用 Mihomo 1.19.33 检查配置。离线 DNS 回归测试使用本地模拟节点和解析服务器，不修改系统网络设置：

```sh
python3 -B mihomo/tests/test_dns.py
```

需要安装 Python、PyYAML 和 Mihomo。

## Surge

| 配置 | 适用设备 |
| --- | --- |
| [mac.conf](surge/mac.conf) | Mac |
| [mobile.conf](surge/mobile.conf) | iPhone、iPad、Apple TV |

移动端以原 iPhone 配置的完整分流为基础，统一保留 PayPal、AI、Telegram、微软 CDN 等策略，全部手动选择，Ponte 组也改为手动选择。

模块和 HTTPS 解密按设备管理。移动端模板仅保留 MITM 排除项，不提供解密证书或需要解密的域名；需要解密时，在对应设备单独配置证书、目标域名和开关。重新导入或替换整份远程配置可能覆盖本机修改，更新后检查模块和解密设置。

原 `surge/iphone.conf`、`surge/ipad.conf`、`surge/appletv.conf` 已合并移除，旧配置链接应改为 `surge/mobile.conf`。
使用前仍需自行提供 `proxy.conf`，并替换 `sub` 组中的“订阅地址”。Apple TV 的部署方式参见 [Surge tvOS 官方说明](https://kb.nssurge.com/surge-knowledge-base/guidelines/tvos)。

不再维护 Loon、Stash、Shadowrocket，相关配置目录已移除。
