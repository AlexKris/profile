# 如何查找需要分流的域名

## 方法一：使用现成的域名列表（推荐）

### Loyalsoldier/v2ray-rules-dat

最全面的域名分类列表，每天自动更新。

```bash
# 基础 URL
BASE_URL="https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release"

# 可用的列表
curl -sL ${BASE_URL}/netflix.txt      # Netflix
curl -sL ${BASE_URL}/disney.txt       # Disney+
curl -sL ${BASE_URL}/youtube.txt      # YouTube  
curl -sL ${BASE_URL}/google.txt       # Google
curl -sL ${BASE_URL}/telegram.txt     # Telegram
curl -sL ${BASE_URL}/apple.txt        # Apple
curl -sL ${BASE_URL}/microsoft.txt    # Microsoft
curl -sL ${BASE_URL}/tiktok.txt       # TikTok
curl -sL ${BASE_URL}/openai.txt       # OpenAI/ChatGPT
curl -sL ${BASE_URL}/gfw.txt          # GFW 列表
curl -sL ${BASE_URL}/direct-list.txt  # 直连域名（中国）
```

### v2fly/domain-list-community

源数据仓库，更细分的分类。

```bash
# 查看所有可用分类
curl -s https://api.github.com/repos/v2fly/domain-list-community/contents/data | jq -r '.[].name'

# 查看某个服务的域名规则（原始格式）
curl -sL https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/netflix
```

---

## 方法二：自己抓包

### 浏览器开发者工具（最简单）

1. 打开 Chrome/Firefox，按 `F12` 打开开发者工具
2. 切换到 `Network` 标签
3. 访问目标网站（如 netflix.com）
4. 查看所有请求的域名

```
示例 - Netflix 抓包结果：
├── netflix.com           # 主站
├── nflxvideo.net         # 视频 CDN
├── nflximg.net           # 图片 CDN  
├── nflxext.com           # 扩展服务
└── nflxso.net            # 其他服务
```

### 使用 tcpdump/wireshark

```bash
# 在 VPS 上抓取 DNS 请求
tcpdump -i any port 53 -nn

# 过滤特定目标
tcpdump -i any port 53 -nn | grep -E "netflix|nflx"
```

### 使用 SmartDNS 日志

```bash
# 开启详细日志
# 在 smartdns.conf 中添加：
log-level debug
log-file /etc/smartdns/smartdns.log

# 查看日志中的域名请求
tail -f /etc/smartdns/smartdns.log | grep "query"
```

---

## 方法三：查阅公开资料

### 常见流媒体服务域名

#### Netflix
```
netflix.com
netflix.net
nflximg.com
nflximg.net
nflxvideo.net
nflxext.com
nflxso.net
```

#### Disney+
```
disney.com
disneyplus.com
dssott.com
bamgrid.com
disney-plus.net
disneystreaming.com
```

#### YouTube / Google
```
youtube.com
youtu.be
ytimg.com
googlevideo.com
ggpht.com
youtube-nocookie.com
youtubei.googleapis.com
```

#### Spotify
```
spotify.com
spotifycdn.com
scdn.co
spotify.design
```

#### HBO Max
```
hbomax.com
hbo.com
hbonow.com
hbogo.com
```

#### Amazon Prime Video
```
amazon.com
amazonvideo.com
media-amazon.com
aiv-cdn.net
aiv-delivery.net
```

#### TikTok
```
tiktok.com
tiktokv.com
tiktokcdn.com
musical.ly
byteoversea.com
ibytedtos.com
```

#### OpenAI / ChatGPT
```
openai.com
chat.openai.com
api.openai.com
chatgpt.com
oaistatic.com
oaiusercontent.com
```

---

## 方法四：自动化脚本

### 域名列表更新脚本

```bash
#!/bin/bash
# update-domain-lists.sh

DOMAIN_LIST_DIR="/root/smartdns/config/domain-lists"
BASE_URL="https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release"

declare -A LISTS=(
    ["netflix.conf"]="netflix.txt"
    ["disney.conf"]="disney.txt"
    ["youtube.conf"]="youtube.txt"
    ["openai.conf"]="openai.txt"
    ["tiktok.conf"]="tiktok.txt"
)

for local_name in "${!LISTS[@]}"; do
    remote_name="${LISTS[$local_name]}"
    echo "Updating ${local_name}..."
    curl -sL "${BASE_URL}/${remote_name}" -o "${DOMAIN_LIST_DIR}/${local_name}"
    # 清理格式
    sed -i '/^#/d; /^$/d; /^@/d; /^regexp:/d; /^full:/d' "${DOMAIN_LIST_DIR}/${local_name}"
done

# 重载 SmartDNS
docker exec smartdns kill -SIGHUP 1

echo "Done!"
```

### 设置定时更新

```bash
# 每周日凌晨 3 点更新域名列表
crontab -e

# 添加：
0 3 * * 0 /root/smartdns/update-domain-lists.sh >> /var/log/smartdns-update.log 2>&1
```

---

## SmartDNS 域名规则格式

### domain-set 文件格式

```
# 注释以 # 开头
# 每行一个域名，会自动匹配子域名

example.com      # 匹配 example.com 和 *.example.com
sub.example.com  # 只匹配 sub.example.com 和 *.sub.example.com
```

### 在 smartdns.conf 中使用

```bash
# 定义域名集
domain-set -name myservice -file /etc/smartdns/domain-lists/myservice.conf

# 分流到指定 DNS 组
nameserver /domain-set:myservice/unlock

# 或者单独指定某个域名
nameserver /example.com/unlock
server /specific.example.com/8.8.8.8
```

### 常用规则示例

```bash
# 方式1：使用 domain-set（推荐，方便管理）
domain-set -name netflix -file /etc/smartdns/domain-lists/netflix.conf
nameserver /domain-set:netflix/unlock

# 方式2：直接在配置中指定（少量域名时）
nameserver /netflix.com/unlock
nameserver /nflxvideo.net/unlock

# 方式3：混合使用
domain-set -name streaming -file /etc/smartdns/domain-lists/streaming.conf
nameserver /domain-set:streaming/unlock
nameserver /special-service.com/unlock  # 额外添加
```

---

## 验证分流是否生效

```bash
# 1. 测试解锁域名解析
dig netflix.com @127.0.0.1

# 2. 对比直接请求解锁 DNS
dig netflix.com @103.214.22.32

# 3. 查看 SmartDNS 选择的上游
docker logs smartdns 2>&1 | grep netflix

# 4. 开启调试日志
# 在 smartdns.conf 中临时添加:
# log-level debug
# 然后重启并查看日志
```

---

## 注意事项

1. **域名列表不是越多越好**：只添加需要分流的服务，避免不必要的规则
2. **注意更新频率**：流媒体域名变化不频繁，每周或每月更新即可
3. **验证分流效果**：添加新规则后记得测试是否生效
4. **备份配置**：修改前备份原配置文件