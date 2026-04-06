# Personal / Sparkle Override

主 `mihomo.yaml` 是**公开干净**版本，提交到 GitHub 后任何人看都不含个人隐私域名。所有个人/私有内容（个人域名、Emby 服务器、订阅域名 DNS 分流等）通过 **Sparkle 的"覆写 (Override)"机制** 在客户端本地注入。

## 文件清单

| 文件 | 是否 commit | 用途 |
|---|---|---|
| `README.md` | ✓ | 本文档 |
| `sparkle-override.example.yaml` | ✓ | 占位符模板，新机器上 copy 一份改成真实内容 |
| `sparkle-override.yaml` | ✗ gitignored | **真实个人内容**（你自己创建/维护） |

`.gitignore` 规则在仓库根 `.gitignore`，对应：
```
mihomo/personal/*
!mihomo/personal/README.md
!mihomo/personal/sparkle-override.example.yaml
```

## 新机器初次设置

### Windows + Sparkle

1. **Clone 仓库**
2. **复制模板**：
   ```bash
   cp mihomo/personal/sparkle-override.example.yaml mihomo/personal/sparkle-override.yaml
   ```
3. **编辑 `sparkle-override.yaml`**，把所有 `your-*` 占位符替换成真实个人域名
4. **打开 Sparkle**：
   - **订阅 (Profiles) 页面** → 新建 → 类型 `远程` → URL 填 `https://raw.githubusercontent.com/AlexKris/profile/main/mihomo/mihomo.yaml`（或者 `本地` 直接选本机的 mihomo.yaml）
   - **覆写 (Override) 页面** → 新建 → 类型 `本地` → 扩展 `yaml` → 把 `sparkle-override.yaml` 的全部内容粘贴进去 → 保存
   - **回到订阅页面** → 编辑刚才导入的 profile → 在覆写列表里勾选这个 override → 保存
5. **重启 mihomo 内核**（Sparkle 改 override 一般会自动重载）
6. **验证**：在 Sparkle 的 Connections 面板访问个人域名，确认命中预期的策略组（Self / GlobalEmby / DirectEmby / RFCEmby）

### Mac + Sparkle (macOS 版)

同上。Sparkle 有 macOS 构建。

### Mac 命令行 mihomo（不推荐，仅作 yaml 校验用）

主 `mihomo.yaml` 不引用任何 personal/ 内的文件，所以**不需要 sparkle-override.yaml** 也能 `mihomo -t -f` 校验通过 — 只是没有个人路由功能。

如果一定要在 Mac 命令行用 mihomo 跑代理且要带个人路由，需要用 `yq` 手工合并：
```bash
# 注意：yq 的 *+ 操作符不识别 Sparkle 的 +key prepend 语法
# 需要先把 sparkle-override.yaml 里的 +rules / +proxy-groups 改成 rules / proxy-groups
# 然后用 yq merge：
yq eval-all '. as $i ireduce ({}; . *+ $i)' mihomo.yaml personal/sparkle-override.yaml > .deployed.yaml
mihomo -d ~/.config/mihomo -f .deployed.yaml
```

## 日常更新工作流

1. 改 `mihomo/personal/sparkle-override.yaml`（本地，gitignored）
2. 打开 Sparkle 覆写页面 → 编辑该 local override → 替换为新内容
3. Sparkle 自动重新合并并热重载 mihomo 内核

主 `mihomo.yaml` 与个人内容**完全解耦**，平时随意改 `mihomo.yaml`、commit、push 都不会泄漏个人信息。

## Sparkle deepMerge 语法（关键）

来自 Sparkle 源码 `src/main/utils/merge.ts`：

| 数据形态 | 默认行为 | 特殊键名前/后缀 |
|---|---|---|
| 对象 (map) | 递归 deep merge | 后缀 `!` = 强制整体替换（不递归）|
| 数组 (list) | **整体替换** | 前缀 `+` = prepend / 后缀 `+` = append |
| 标量 | 直接赋值 | — |

### 示例

```yaml
# 1. 递归合并到现有 dns.nameserver-policy（map 默认行为）
dns:
  nameserver-policy:
    "+.example.com": https://example-dns.com

# 2. prepend 到 proxy-groups 数组前面（高优先级位置）
+proxy-groups:
  - name: MyGroup
    type: select
    proxies: [DIRECT]

# 3. append 到 rules 数组末尾
rules+:
  - DOMAIN-SUFFIX,example.com,DIRECT

# 4. 强制整体替换 dns 块（慎用，会丢失主 yaml 所有 dns 设置）
dns!:
  enable: true
```

### 关于 YAML 锚点

Sparkle 的合并发生在 **YAML 解析后**，主 yaml 的锚点（`*BaseSelect` / `*FilterEdge` 等）已经展开成实际值。**override 文件不能引用主 yaml 的锚点**。如果 override 需要类似的过滤正则，必须把正则写完整。

## 必读：跟主 mihomo.yaml 的契约

主 `mihomo.yaml` **不包含**：
- ❌ Self / GlobalEmby / RFCEmby / DirectEmby 这 4 个 proxy-group
- ❌ FilterGlobalEmby / FilterRFCEmby 锚点
- ❌ 任何 `kirsime` / `drkirsi` / `rfchost` / `fantaike` / `longemby` / `uhdnow` 等个人域名
- ❌ `+.kirsime.net` 的 nameserver-policy 条目

这些**全部由 sparkle-override.yaml 注入**。如果哪天你想给主 yaml 加新的非个人内容（比如新的 ad blocking 规则），改 `mihomo.yaml` 即可，override 不受影响（只要键名不冲突）。
