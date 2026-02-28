#!/bin/bash

# VPS 初始化状态诊断脚本
# 检查 setup.sh 配置的各项系统状态 + 服务运行状态
# Version: 2.0.0

set -uo pipefail

# 参数解析：--cn（默认）| --global
REGION="cn"
while [ $# -gt 0 ]; do
    case "$1" in
        --global) REGION="global" ;;
        --cn)     REGION="cn" ;;
        --help|-h)
            echo "用法: $0 [--cn|--global]"
            echo "  --cn      大陆 VPS（默认），DNS 测试用 baidu.com"
            echo "  --global  海外 VPS，DNS 测试用 example.com"
            exit 0 ;;
        *) echo "未知参数: $1"; echo "用法: $0 [--cn|--global]"; exit 1 ;;
    esac
    shift
done

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
DIM='\033[2m'
NC='\033[0m'

# 计数器
total=0
pass=0
warn=0
fail=0

ok() {
    ((total++)) || true
    ((pass++)) || true
    printf "  ${GREEN}[OK]${NC}   %s\n" "$1"
}

warning() {
    ((total++)) || true
    ((warn++)) || true
    printf "  ${YELLOW}[WARN]${NC} %s\n" "$1"
}

bad() {
    ((total++)) || true
    ((fail++)) || true
    printf "  ${RED}[FAIL]${NC} %s\n" "$1"
}

info() {
    printf "  ${CYAN}[INFO]${NC} %s\n" "$1"
}

detail() {
    printf "  ${DIM}       %s${NC}\n" "$1"
}

section() {
    echo ""
    printf "${CYAN}━━━ %s ━━━${NC}\n" "$1"
}

# ===== 1. 系统信息 =====
section "系统信息"
info "Hostname: $(hostname)"
info "OS: $(grep '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d'"' -f2)"
info "Kernel: $(uname -r)"
info "Uptime: $(uptime -p 2>/dev/null || uptime)"

# ===== 2. 基础软件包 =====
section "基础软件包"

required_cmds=("curl" "wget" "vim" "unzip" "zip" "mtr" "iperf3")
for cmd in "${required_cmds[@]}"; do
    if command -v "$cmd" &>/dev/null; then
        ok "$cmd 已安装"
    else
        bad "$cmd 未安装"
    fi
done

if command -v nc &>/dev/null || command -v ncat &>/dev/null; then
    ok "netcat 已安装"
else
    bad "netcat 未安装"
fi

# ===== 3. 用户和鉴权 =====
section "用户和鉴权"

# 列出可登录用户（按 UID_MIN 过滤，root 单独保留）
uid_min=$(awk '/^UID_MIN/ {print $2}' /etc/login.defs 2>/dev/null || true)
uid_min="${uid_min:-1000}"
login_users=$(awk -F: -v uid_min="$uid_min" '$7 !~ /(nologin|false|sync|shutdown|halt)$/ && ($3 == 0 || $3 >= uid_min) {print $1"(uid="$3")"}' /etc/passwd)
info "可登录用户:"
while IFS= read -r u; do
    detail "$u"
done <<< "$login_users"

# sudo 用户
if getent group sudo &>/dev/null; then
    sudo_members=$(getent group sudo | cut -d: -f4)
    [ -n "$sudo_members" ] && info "sudo 组成员: $sudo_members"
fi
if getent group wheel &>/dev/null; then
    wheel_members=$(getent group wheel | cut -d: -f4)
    [ -n "$wheel_members" ] && info "wheel 组成员: $wheel_members"
fi

# sudoers.d 自定义文件
if [ -d /etc/sudoers.d ]; then
    custom_sudoers=$(ls /etc/sudoers.d/ 2>/dev/null | grep -v '^README$' || true)
    if [ -n "$custom_sudoers" ]; then
        info "sudoers.d 自定义:"
        while IFS= read -r f; do
            detail "$f"
        done <<< "$custom_sudoers"
    fi
fi

# 当前登录用户
who_output=$(who 2>/dev/null)
if [ -n "$who_output" ]; then
    info "当前登录:"
    while IFS= read -r line; do
        detail "$line"
    done <<< "$who_output"
fi

# 认证失败统计（最近 1000 行日志）
auth_log=""
[ -f /var/log/auth.log ] && auth_log="/var/log/auth.log"
[ -z "$auth_log" ] && [ -f /var/log/secure ] && auth_log="/var/log/secure"
if [ -n "$auth_log" ]; then
    fail_count=$(tail -n 1000 "$auth_log" | grep -c 'Failed password\|authentication failure' || true)
    if [ "$fail_count" -gt 100 ]; then
        warning "认证失败（近1000行日志）: $fail_count 次（较多）"
    elif [ "$fail_count" -gt 0 ]; then
        info "认证失败（近1000行日志）: $fail_count 次"
    else
        ok "近1000行日志无认证失败记录"
    fi
fi

# ===== 4. SSH 配置 =====
section "SSH 配置"

# 优先使用 sshd -T 读取实际生效配置，回退到手动 grep
# sshd -T -C 指定上下文，确保 Match 块正确解析（模拟 root 用户登录）
SSHD_EFFECTIVE=""
if command -v sshd &>/dev/null; then
    SSHD_EFFECTIVE=$(sshd -T -C user=root,host=,addr= 2>/dev/null || sshd -T 2>/dev/null || true)
fi

get_ssh_setting() {
    local key="$1"
    local value=""
    # 优先从 sshd -T 的实际生效配置读取
    if [ -n "$SSHD_EFFECTIVE" ]; then
        value=$(echo "$SSHD_EFFECTIVE" | awk -v k="${key,,}" 'tolower($1) == k {print $2; exit}')
    fi
    # 回退: 手动 grep 配置文件
    if [ -z "$value" ]; then
        local SSH_OVERRIDE="/etc/ssh/sshd_config.d/99-security.conf"
        local SSH_CONFIG="/etc/ssh/sshd_config"
        if [ -f "$SSH_OVERRIDE" ]; then
            value=$(grep -i "^${key}" "$SSH_OVERRIDE" 2>/dev/null | tail -1 | awk '{print $2}')
        fi
        if [ -z "$value" ] && [ -f "$SSH_CONFIG" ]; then
            value=$(grep -i "^${key}" "$SSH_CONFIG" 2>/dev/null | tail -1 | awk '{print $2}')
        fi
    fi
    echo "$value"
}

ssh_port=$(get_ssh_setting "Port")
if [ -n "$ssh_port" ] && [ "$ssh_port" != "22" ]; then
    ok "SSH 端口: $ssh_port（已修改）"
else
    warning "SSH 端口: ${ssh_port:-22}（默认端口，建议修改）"
fi

pubkey=$(get_ssh_setting "PubkeyAuthentication")
if [ "${pubkey,,}" = "yes" ]; then
    ok "公钥认证: 已启用"
else
    bad "公钥认证: 未启用"
fi

passwd_auth=$(get_ssh_setting "PasswordAuthentication")
if [ "${passwd_auth,,}" = "no" ]; then
    ok "密码认证: 已禁用"
else
    warning "密码认证: ${passwd_auth:-yes}（建议禁用）"
fi

root_login=$(get_ssh_setting "PermitRootLogin")
info "Root 登录: ${root_login:-yes}"

for key_val in "X11Forwarding:no" "UseDNS:no" "PermitEmptyPasswords:no"; do
    key="${key_val%%:*}"
    expected="${key_val##*:}"
    actual=$(get_ssh_setting "$key")
    if [ "${actual,,}" = "$expected" ]; then
        ok "$key = $actual"
    else
        warning "$key = ${actual:-未设置}（建议 $expected）"
    fi
done

alive_interval=$(get_ssh_setting "ClientAliveInterval")
alive_max=$(get_ssh_setting "ClientAliveCountMax")
if [ -n "$alive_interval" ] && [ "$alive_interval" -gt 0 ] 2>/dev/null; then
    ok "ClientAlive: ${alive_interval}s x ${alive_max:-3}"
else
    warning "ClientAlive: 未配置"
fi

if [ -f /etc/ssh/sshd_config.d/99-security.conf ]; then
    ok "安全覆盖配置: 99-security.conf 存在"
else
    info "安全覆盖配置: 99-security.conf 不存在"
fi

if [ -f /root/.ssh/authorized_keys ] && [ -s /root/.ssh/authorized_keys ]; then
    key_count=$(awk '/^#/{next} /^$/{next} {for(i=1;i<=NF;i++) if($i~/^(ssh-(rsa|dss|ed25519)|ecdsa-sha2-|sk-(ssh|ecdsa)-)/) {n++; break}} END{print n+0}' /root/.ssh/authorized_keys 2>/dev/null)
    ok "Root SSH 密钥: $key_count 个"
else
    bad "Root SSH 密钥: 未配置"
fi

# SSH 服务状态
if command -v systemctl &>/dev/null; then
    if systemctl is-active sshd &>/dev/null || systemctl is-active ssh &>/dev/null; then
        ok "SSH 服务: 运行中"
    else
        bad "SSH 服务: 未运行"
    fi
elif pgrep -x sshd &>/dev/null; then
    ok "SSH 服务: 运行中（非 systemd）"
else
    bad "SSH 服务: 未运行"
fi
# 当前 SSH 连接数
ssh_conns=$(ss -tnp 2>/dev/null | grep -c ":${ssh_port:-22} " || true)
info "当前 SSH 连接数: $ssh_conns"

# ===== 5. Fail2ban =====
section "Fail2ban"

if command -v fail2ban-server &>/dev/null; then
    ok "fail2ban 已安装"
    if (command -v systemctl &>/dev/null && systemctl is-active fail2ban &>/dev/null) || pgrep -x fail2ban-server &>/dev/null; then
        ok "fail2ban 服务运行中"
        if [ -f /etc/fail2ban/jail.d/custom.conf ]; then
            ok "自定义配置: jail.d/custom.conf 存在"
        else
            warning "自定义配置: jail.d/custom.conf 不存在"
        fi
        # jail 状态
        jails=$(fail2ban-client status 2>/dev/null | grep 'Jail list' | sed 's/.*:\s*//' | tr -d ' ')
        if [ -n "$jails" ]; then
            info "活跃 jail: $jails"
            IFS=',' read -ra jail_arr <<< "$jails"
            for jail in "${jail_arr[@]}"; do
                jail_info=$(fail2ban-client status "$jail" 2>/dev/null)
                banned=$(echo "$jail_info" | grep 'Currently banned' | awk '{print $NF}')
                total_banned=$(echo "$jail_info" | grep 'Total banned' | awk '{print $NF}')
                [ -n "$banned" ] && info "  $jail: 当前封禁 $banned 个IP，累计 ${total_banned:-0} 次"
            done
        fi
    else
        bad "fail2ban 服务未运行"
    fi
else
    bad "fail2ban 未安装"
fi

# ===== 6. 时区和 NTP =====
section "时区和 NTP"

current_tz=$(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo "未知")
if [ "$current_tz" = "Asia/Shanghai" ]; then
    ok "时区: $current_tz"
else
    warning "时区: $current_tz（setup.sh 默认设为 Asia/Shanghai）"
fi

if command -v systemctl &>/dev/null; then
    if systemctl is-active chronyd &>/dev/null; then
        ok "NTP 服务: chronyd 运行中"
        ntp_source=$(chronyc sources 2>/dev/null | grep '^\^\*' | awk '{print $2}')
        [ -n "$ntp_source" ] && info "NTP 同步源: $ntp_source"
    elif systemctl is-active systemd-timesyncd &>/dev/null; then
        ok "NTP 服务: timesyncd 运行中"
    elif systemctl is-active ntpd &>/dev/null; then
        ok "NTP 服务: ntpd 运行中"
    else
        bad "NTP 服务: 未运行"
    fi
elif pgrep -x chronyd &>/dev/null; then
    ok "NTP 服务: chronyd 运行中（非 systemd）"
elif pgrep -x ntpd &>/dev/null; then
    ok "NTP 服务: ntpd 运行中（非 systemd）"
else
    warning "NTP 服务: 无法检测（非 systemd 环境）"
fi

if command -v timedatectl &>/dev/null; then
    ntp_synced=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo "unknown")
    if [ "$ntp_synced" = "yes" ]; then
        ok "NTP 同步: 已同步"
    elif [ "$ntp_synced" = "unknown" ]; then
        info "NTP 同步: 无法检测"
    else
        warning "NTP 同步: 未同步"
    fi
else
    info "NTP 同步: timedatectl 不可用，跳过"
fi

# ===== 7. 内核优化 =====
section "内核优化"

congestion=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
if [ "$congestion" = "bbr" ]; then
    ok "TCP 拥塞控制: BBR"
else
    warning "TCP 拥塞控制: ${congestion:-未知}（建议 bbr）"
fi

qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null)
if [ "$qdisc" = "fq" ]; then
    ok "默认队列: fq"
else
    warning "默认队列: ${qdisc:-未知}（建议 fq）"
fi

ip_forward=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
if [ "$ip_forward" = "1" ]; then
    ok "IPv4 转发: 已启用"
else
    warning "IPv4 转发: 未启用"
fi

# ===== 8. 日志服务 =====
section "日志服务"

if (command -v systemctl &>/dev/null && systemctl is-active rsyslog &>/dev/null) || pgrep -x rsyslogd &>/dev/null; then
    ok "rsyslog: 运行中"
else
    warning "rsyslog: 未运行"
fi

if [ -f /var/log/auth.log ]; then
    ok "auth.log: 存在"
elif [ -f /var/log/secure ]; then
    ok "secure: 存在（RHEL 系）"
else
    bad "认证日志: 不存在（fail2ban 无法工作）"
fi

# ===== 9. DNS 配置 =====
section "DNS 配置"

# resolv.conf
if [ -f /etc/resolv.conf ]; then
    dns_servers=$(grep '^nameserver' /etc/resolv.conf | awk '{print $2}' | tr '\n' ' ')
    info "DNS 服务器: $dns_servers"
    # 检查是否指向本地（SmartDNS 场景）
    if echo "$dns_servers" | grep -q '127.0.0.1'; then
        info "DNS 指向本地 127.0.0.1（可能使用 SmartDNS）"
    fi
else
    warning "/etc/resolv.conf 不存在"
fi

# DNS 解析测试
if [ "$REGION" = "cn" ]; then
    dns_test_domain="baidu.com"
else
    dns_test_domain="example.com"
fi
if command -v dig &>/dev/null; then
    dig_result=$(dig +short +time=3 +tries=1 "$dns_test_domain" 2>/dev/null | head -1)
    if [ -n "$dig_result" ]; then
        ok "DNS 解析正常: $dns_test_domain -> $dig_result"
    else
        bad "DNS 解析失败: $dns_test_domain"
    fi
elif command -v nslookup &>/dev/null; then
    ns_result=$(nslookup -timeout=3 "$dns_test_domain" 2>/dev/null | grep -A1 'Name:' | tail -1 | awk '{print $2}')
    if [ -n "$ns_result" ]; then
        ok "DNS 解析正常: $dns_test_domain"
    else
        bad "DNS 解析失败: $dns_test_domain"
    fi
fi

# SmartDNS
section "SmartDNS"

if command -v docker &>/dev/null && docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^smartdns$'; then
    ok "SmartDNS 容器: 运行中"
    smartdns_image=$(docker inspect smartdns --format '{{.Config.Image}}' 2>/dev/null)
    info "镜像: $smartdns_image"

    # 配置文件
    if [ -f /root/smartdns/config/smartdns.conf ]; then
        ok "配置文件: /root/smartdns/config/smartdns.conf 存在"
        # 检查绑定地址
        bind_line=$(grep '^bind ' /root/smartdns/config/smartdns.conf 2>/dev/null | head -1)
        [ -n "$bind_line" ] && info "绑定: $bind_line"
        # 上游 DNS 数量
        upstream_count=$(grep -c '^server ' /root/smartdns/config/smartdns.conf 2>/dev/null || true)
        info "上游 DNS 数: $upstream_count"
        # 是否有分流组
        if grep -q 'group' /root/smartdns/config/smartdns.conf 2>/dev/null; then
            info "分流模式: 已配置"
        fi
    else
        warning "配置文件不存在"
    fi

    # 域名列表更新脚本
    if [ -f /root/smartdns/update-lists.sh ]; then
        info "域名列表更新脚本: 存在"
    fi

    # 本地 DNS 解析测试
    if command -v dig &>/dev/null; then
        local_dns=$(dig +short +time=2 +tries=1 google.com @127.0.0.1 2>/dev/null | head -1)
        if [ -n "$local_dns" ]; then
            ok "本地 DNS 解析正常: google.com -> $local_dns"
        else
            bad "本地 DNS 解析失败 (@127.0.0.1)"
        fi
    fi
elif command -v docker &>/dev/null && docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q '^smartdns$'; then
    bad "SmartDNS 容器: 已停止"
else
    info "SmartDNS: 未部署"
fi

# ===== 10. Docker 详情 =====
section "Docker"

if command -v docker &>/dev/null; then
    docker_ver=$(docker --version 2>/dev/null | awk '{print $3}' | tr -d ',')
    ok "Docker 已安装: $docker_ver"
    if (command -v systemctl &>/dev/null && systemctl is-active docker &>/dev/null) || pgrep -x dockerd &>/dev/null; then
        ok "Docker 服务: 运行中"
    else
        warning "Docker 服务: 未运行"
    fi

    # daemon.json
    if [ -f /etc/docker/daemon.json ]; then
        if grep -q "registry-mirrors" /etc/docker/daemon.json 2>/dev/null; then
            info "Docker 镜像加速: 已配置"
        fi
        if grep -q "log-driver" /etc/docker/daemon.json 2>/dev/null; then
            ok "Docker 日志轮转: 已配置"
        else
            warning "Docker 日志轮转: 未配置"
        fi
    fi

    # 容器列表
    running_containers=$(docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}' 2>/dev/null)
    if [ -n "$running_containers" ]; then
        container_count=$(echo "$running_containers" | wc -l | tr -d ' ')
        info "运行中容器: $container_count 个"
        while IFS=$'\t' read -r name image status; do
            detail "$name ($image) - $status"
        done <<< "$running_containers"
    else
        info "无运行中容器"
    fi

    # 已停止容器
    stopped_containers=$(docker ps -a --filter "status=exited" --format '{{.Names}}\t{{.Image}}\t{{.Status}}' 2>/dev/null)
    if [ -n "$stopped_containers" ]; then
        stopped_count=$(echo "$stopped_containers" | wc -l | tr -d ' ')
        warning "已停止容器: $stopped_count 个"
        while IFS=$'\t' read -r name image status; do
            detail "$name ($image) - $status"
        done <<< "$stopped_containers"
    fi

    # 镜像列表
    image_count=$(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | wc -l | tr -d ' ')
    info "本地镜像: $image_count 个"
    docker images --format '{{.Repository}}:{{.Tag}}\t{{.Size}}' 2>/dev/null | while IFS=$'\t' read -r img size; do
        detail "$img ($size)"
    done
else
    info "Docker: 未安装"
fi

# ===== 11. 监听端口 =====
section "监听端口"

info "TCP 监听端口:"
ss -tlnp 2>/dev/null | tail -n +2 | while IFS= read -r line; do
    local_addr=$(echo "$line" | awk '{print $4}')
    process=$(echo "$line" | sed -n 's/.*users:(("\([^"]*\)".*/\1/p')
    process="${process:-unknown}"

    # 判断绑定地址
    if echo "$local_addr" | grep -qE '^0\.0\.0\.0:|^\*:|\[::\]:'; then
        bind_type="${YELLOW}全部接口${NC}"
    elif echo "$local_addr" | grep -qE '^127\.0\.0\.1:|^\[::1\]:'; then
        bind_type="${GREEN}仅本地${NC}"
    else
        bind_type="${CYAN}指定IP${NC}"
    fi

    port=$(echo "$local_addr" | awk -F: '{print $NF}')
    port="${port:-?}"
    printf "  ${DIM}       %-6s %-25s ${NC}%b  %s\n" "$port" "$local_addr" "$bind_type" "$process"
done

# UDP 监听
udp_count=$(ss -ulnp 2>/dev/null | tail -n +2 | wc -l | tr -d ' ')
if [ "$udp_count" -gt 0 ]; then
    info "UDP 监听端口: $udp_count 个"
    ss -ulnp 2>/dev/null | tail -n +2 | while IFS= read -r line; do
        local_addr=$(echo "$line" | awk '{print $4}')
        process=$(echo "$line" | sed -n 's/.*users:(("\([^"]*\)".*/\1/p')
        process="${process:-unknown}"
        port=$(echo "$local_addr" | awk -F: '{print $NF}')
        port="${port:-?}"
        printf "  ${DIM}       %-6s %-25s %s${NC}\n" "$port" "$local_addr" "$process"
    done
fi

# ===== 12. Snell =====
section "Snell"

if [ -f /usr/local/bin/snell-server ]; then
    ok "snell-server 二进制: 已安装"
    snell_ver=$(/usr/local/bin/snell-server --version 2>&1 | head -1 || echo "未知")
    info "版本: $snell_ver"

    if (command -v systemctl &>/dev/null && systemctl is-active snell &>/dev/null) || pgrep -x snell-server &>/dev/null; then
        ok "snell 服务: 运行中"
    else
        bad "snell 服务: 未运行"
    fi

    if [ -f /etc/snell/snell-server.conf ]; then
        ok "配置文件: /etc/snell/snell-server.conf 存在"
        snell_port=$(grep '^listen' /etc/snell/snell-server.conf 2>/dev/null | awk -F: '{print $NF}' | tr -dc '0-9')
        snell_listen=$(grep '^listen' /etc/snell/snell-server.conf 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
        [ -n "$snell_port" ] && info "监听: $snell_listen"
        # 检查是否有 PSK
        if grep -q '^psk' /etc/snell/snell-server.conf 2>/dev/null; then
            ok "PSK: 已配置"
        else
            warning "PSK: 未配置"
        fi
    else
        bad "配置文件: /etc/snell/snell-server.conf 不存在"
    fi
else
    info "Snell: 未安装"
fi

# ===== 13. Soga =====
section "Soga"

if command -v docker &>/dev/null; then
    soga_container=$(docker ps --format '{{.Names}}' 2>/dev/null | grep -i soga | head -1)
    if [ -n "$soga_container" ]; then
        ok "Soga 容器: $soga_container 运行中"
        soga_image=$(docker inspect "$soga_container" --format '{{.Config.Image}}' 2>/dev/null)
        info "镜像: $soga_image"
        soga_uptime=$(docker inspect "$soga_container" --format '{{.State.StartedAt}}' 2>/dev/null | cut -dT -f1)
        info "启动时间: $soga_uptime"

        # docker-compose 配置
        if [ -f /root/soga/docker-compose.yml ]; then
            ok "docker-compose 配置: /root/soga/docker-compose.yml 存在"
            # 检查 network_mode
            if grep -q 'network_mode.*host' /root/soga/docker-compose.yml 2>/dev/null; then
                info "网络模式: host"
            fi
            # 提取 node_id
            node_id=$(grep -i 'node_id' /root/soga/docker-compose.yml 2>/dev/null | head -1 | awk -F: '{gsub(/^[[:space:]]+|[[:space:]]+$/,"",$2); print $2}' || true)
            [ -n "$node_id" ] && info "Node ID: $node_id"
        fi

        # 最近日志
        info "最近日志:"
        docker logs --tail 3 "$soga_container" 2>&1 | while IFS= read -r line; do
            detail "$line"
        done
    elif docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qi soga; then
        soga_stopped=$(docker ps -a --format '{{.Names}}' 2>/dev/null | grep -i soga | head -1)
        bad "Soga 容器: $soga_stopped 已停止"
    else
        info "Soga: 未部署"
    fi
else
    info "Soga: Docker 未安装"
fi

# ===== 14. 安全审计（可选） =====
section "安全审计（可选）"

if command -v auditctl &>/dev/null; then
    ok "auditd 已安装"
    if (command -v systemctl &>/dev/null && systemctl is-active auditd &>/dev/null) || pgrep -x auditd &>/dev/null; then
        ok "auditd 服务: 运行中"
    else
        warning "auditd 服务: 未运行"
    fi
else
    info "auditd: 未安装（可选功能）"
fi

if command -v etckeeper &>/dev/null; then
    ok "etckeeper 已安装"
else
    info "etckeeper: 未安装（可选功能）"
fi

# ===== 15. 其他 =====
section "其他"

hostname_str=$(hostname)
if grep -q "$hostname_str" /etc/hosts 2>/dev/null; then
    ok "hostname 已在 /etc/hosts 中"
else
    warning "hostname ($hostname_str) 不在 /etc/hosts 中"
fi

if grep -qr 'tcp_congestion_control' /etc/sysctl.conf /etc/sysctl.d/ 2>/dev/null; then
    ok "sysctl: BBR 配置已持久化"
else
    warning "sysctl: BBR 未持久化（重启后可能丢失）"
fi

if grep -qr 'ip_forward' /etc/sysctl.conf /etc/sysctl.d/ 2>/dev/null; then
    ok "sysctl: IP 转发已持久化"
else
    warning "sysctl: IP 转发未持久化"
fi

# ===== 总结 =====
echo ""
printf "${CYAN}━━━ 诊断结果 ━━━${NC}\n"
echo ""
printf "  总计: %d 项  " "$total"
printf "${GREEN}通过: %d${NC}  " "$pass"
printf "${YELLOW}警告: %d${NC}  " "$warn"
printf "${RED}失败: %d${NC}\n" "$fail"
echo ""

if [ "$fail" -eq 0 ] && [ "$warn" -eq 0 ]; then
    printf "  ${GREEN}系统状态良好，无需重新执行 setup.sh${NC}\n"
elif [ "$fail" -eq 0 ]; then
    printf "  ${YELLOW}存在 %d 个警告项，根据实际需要决定是否重新执行 setup.sh${NC}\n" "$warn"
else
    printf "  ${RED}存在 %d 个失败项，建议检查相关服务${NC}\n" "$fail"
fi
echo ""
