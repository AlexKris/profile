#!/bin/bash
set -euo pipefail

# ============================================================
# SmartDNS 部署脚本（Docker 方案）
# 功能：DNS 缓存 + 强制 IPv6 + 可选流媒体分流解锁
# 目标系统：Debian/Ubuntu
# ============================================================

# 默认配置
SMARTDNS_DIR="/root/smartdns"
CONFIG_DIR="${SMARTDNS_DIR}/config"
DOCKER_DIR="${SMARTDNS_DIR}/docker"
DOMAIN_LIST_DIR="${CONFIG_DIR}/domain-lists"

# DNS 配置
INTRANET_DNS=""
UNLOCK_DNS="103.214.22.32"
TIMEZONE="Asia/Hong_Kong"
FORCE_IPV6=false
PLAIN_DNS=false

# ============================================================
# 工具函数
# ============================================================

log() {
    local level="$1" msg="$2"
    if [[ -t 1 ]]; then
        case "$level" in
            OK)   echo -e "\033[32m[OK]\033[0m $msg" ;;
            WARN) echo -e "\033[33m[WARN]\033[0m $msg" ;;
            ERR)  echo -e "\033[31m[ERR]\033[0m $msg" ;;
            *)    echo "[${level}] $msg" ;;
        esac
    else
        echo "[$level] $msg"
    fi
}

remove_update_cron() {
    local current
    current=$(crontab -l 2>/dev/null) || return 0
    if echo "$current" | grep -qF "${SMARTDNS_DIR}/update-lists.sh"; then
        echo "$current" | grep -vF "${SMARTDNS_DIR}/update-lists.sh" | crontab - || crontab -r 2>/dev/null || true
        log OK "已清除域名列表更新 cron"
    fi
}

is_valid_ip() {
    local ip="$1"
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    local IFS='.'
    read -r a b c d <<< "$ip"
    (( 10#$a <= 255 && 10#$b <= 255 && 10#$c <= 255 && 10#$d <= 255 ))
}

show_help() {
    cat <<EOF
用法: $0 [选项]

模式:
  默认模式                 纯 DNS 缓存（公共 DNS）
  -d 模式                  DNS 缓存 + 流媒体分流解锁
  -6 模式                  启用强制 IPv6（可与 -d 组合）

选项:
  -d, --download-lists       启用分流模式：下载域名列表 + 生成更新脚本
  -6, --force-ipv6           启用强制 IPv6：屏蔽指定域名的 A 记录，只返回 AAAA
  --plain-dns                使用 UDP 明文 DNS（默认使用 DoT/DoH）
  -i, --intranet-dns <IP>    设置内网 DNS（可选）
  -u, --unlock-dns <IP>      设置解锁 DNS（默认: 103.214.22.32，仅 -d 模式）
  -t, --timezone <TZ>        设置时区（默认: Asia/Hong_Kong）
  -s, --status               显示 SmartDNS 状态
  --uninstall                卸载 SmartDNS
  -h, --help                 显示帮助

示例:
  $0                         # 纯 DNS 缓存
  $0 -6                      # DNS 缓存 + 强制 IPv6
  $0 -d                      # DNS 缓存 + 流媒体分流
  $0 -d -6                   # DNS 缓存 + 流媒体分流 + 强制 IPv6
  $0 -d -u 1.2.3.4           # 自定义解锁 DNS
  $0 --plain-dns             # 使用 UDP 明文 DNS
EOF
}

# ============================================================
# 核心函数
# ============================================================

check_docker() {
    log INFO "检查 Docker 环境..."

    if ! command -v docker &> /dev/null; then
        log WARN "Docker 未安装，正在安装..."
        curl -fsSL https://get.docker.com | sh
        systemctl enable docker
        systemctl start docker
        log OK "Docker 安装完成"
    else
        log OK "Docker 已安装: $(docker --version)"
    fi

    if ! docker compose version &> /dev/null; then
        log WARN "Docker Compose V2 未安装，正在安装..."
        apt-get update && apt-get install -y docker-compose-plugin
        log OK "Docker Compose 安装完成"
    else
        log OK "Docker Compose 已安装"
    fi

    # 预装 dnsutils（此时原有 DNS 仍可用）
    if ! command -v dig &>/dev/null; then
        if ! { apt-get update -qq && apt-get install -y -qq dnsutils; } 2>/dev/null; then
            log WARN "dnsutils 安装失败，部署验证将受限"
        fi
    fi
}

create_directories() {
    log INFO "创建目录结构..."
    mkdir -p "${CONFIG_DIR}" "${DOCKER_DIR}" "${DOMAIN_LIST_DIR}"
    log OK "目录创建完成: ${SMARTDNS_DIR}"
}

download_domain_lists() {
    log INFO "下载域名列表..."

    local BASE_URL="https://raw.githubusercontent.com/v2fly/domain-list-community/master/data"
    local SERVICES=(netflix disney youtube)

    for name in "${SERVICES[@]}"; do
        local local_path="${DOMAIN_LIST_DIR}/${name}.conf"

        log INFO "  下载 ${name}..."
        if curl -fsSL "${BASE_URL}/${name}" -o "${local_path}" 2>/dev/null; then
            # 清理：移除注释、空行、include、regexp、full 前缀行
            sed -i '/^#/d; /^$/d; /^@/d; /^include:/d; /^regexp:/d; /^full:/d; s/^domain://g' "${local_path}" 2>/dev/null || true
            local line_count
            line_count=$(wc -l < "${local_path}")
            log OK "    ${name}: ${line_count} 条域名"
        else
            log WARN "    ${name} 下载失败，跳过"
        fi
    done

    log OK "域名列表下载完成"

    # 生成更新脚本
    generate_update_script
}

generate_update_script() {
    log INFO "生成域名列表更新脚本..."

    cat > "${SMARTDNS_DIR}/update-lists.sh" <<'SCRIPT'
#!/bin/bash
set -euo pipefail

DOMAIN_LIST_DIR="/root/smartdns/config/domain-lists"
BASE_URL="https://raw.githubusercontent.com/v2fly/domain-list-community/master/data"
SERVICES=(netflix disney youtube)

echo "[INFO] 开始更新域名列表..."

for name in "${SERVICES[@]}"; do
    local_path="${DOMAIN_LIST_DIR}/${name}.conf"

    if curl -fsSL "${BASE_URL}/${name}" -o "${local_path}" 2>/dev/null; then
        sed -i '/^#/d; /^$/d; /^@/d; /^include:/d; /^regexp:/d; /^full:/d; s/^domain://g' "${local_path}" 2>/dev/null || true
        echo "[OK] ${name}: $(wc -l < "${local_path}") 条域名"
    else
        echo "[WARN] ${name} 下载失败"
    fi
done

# 重载 SmartDNS 配置
docker restart smartdns 2>/dev/null || true

echo "[OK] 域名列表更新完成"
SCRIPT

    chmod +x "${SMARTDNS_DIR}/update-lists.sh"
    log OK "更新脚本已生成: ${SMARTDNS_DIR}/update-lists.sh"
}

generate_docker_compose() {
    log INFO "生成 docker-compose.yaml..."

    cat > "${DOCKER_DIR}/docker-compose.yaml" <<EOF
services:
  smartdns:
    image: pymumu/smartdns:latest
    container_name: smartdns
    restart: always
    network_mode: host
    volumes:
      - ${CONFIG_DIR}:/etc/smartdns
    environment:
      - TZ=${TIMEZONE}
EOF

    log OK "docker-compose.yaml 生成完成"
}

setup_force_ipv6() {
    if [[ "$FORCE_IPV6" != true ]]; then
        return
    fi

    local list_file="${CONFIG_DIR}/force-ipv6.list"

    if [[ -f "$list_file" ]]; then
        log OK "强制 IPv6 域名列表已存在，保留现有内容: ${list_file}"
        return
    fi

    log INFO "生成强制 IPv6 域名列表..."

    cat > "${list_file}" <<EOF
anthropic.com
claude.ai
EOF

    log OK "强制 IPv6 域名列表已生成: ${list_file}"
}

generate_smartdns_config() {
    log INFO "生成 SmartDNS 配置..."

    cat > "${CONFIG_DIR}/smartdns.conf" <<EOF
# ============================================================
# SmartDNS 配置文件
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')
# ============================================================

# 基础设置
bind 127.0.0.1:53 -no-dualstack-selection -no-speed-check
dualstack-ip-selection no
speed-check-mode none

# 缓存设置
cache-size 4096
cache-persist yes
cache-file /etc/smartdns/smartdns.cache
prefetch-domain yes
serve-expired yes
serve-expired-ttl 86400
serve-expired-prefetch-time 21600

# 日志设置
log-level notice

# 上游 DNS 服务器
EOF

    if [[ -n "${INTRANET_DNS}" ]]; then
        cat >> "${CONFIG_DIR}/smartdns.conf" <<EOF

# 内网 DNS
server ${INTRANET_DNS} -group intranet -exclude-default-group
EOF
    fi

    if [[ "$PLAIN_DNS" == true ]]; then
        cat >> "${CONFIG_DIR}/smartdns.conf" <<EOF

# 公共 DNS（默认组）— UDP 明文
server 1.1.1.1
server 8.8.8.8
server 9.9.9.9
server 208.67.222.222
EOF
    else
        cat >> "${CONFIG_DIR}/smartdns.conf" <<EOF

# 公共 DNS（默认组）— DoT/DoH
server-tls 1.1.1.1:853 -tls-host-verify cloudflare-dns.com
server-tls 8.8.8.8:853 -tls-host-verify dns.google
server-tls 9.9.9.9:853 -tls-host-verify dns.quad9.net
server-https https://cloudflare-dns.com/dns-query
server-https https://dns.google/dns-query
EOF
    fi

    # 强制 IPv6
    if [[ "$FORCE_IPV6" == true && -f "${CONFIG_DIR}/force-ipv6.list" ]]; then
        cat >> "${CONFIG_DIR}/smartdns.conf" <<EOF

# ===== 强制 IPv6（屏蔽 A 记录） =====
domain-set -name force-ipv6 -file /etc/smartdns/force-ipv6.list
address /domain-set:force-ipv6/#4
EOF
    fi

    # 检查是否存在域名列表（启用分流模式）
    local has_domain_lists=false
    for name in netflix disney youtube; do
        [[ -f "${DOMAIN_LIST_DIR}/${name}.conf" && -s "${DOMAIN_LIST_DIR}/${name}.conf" ]] && has_domain_lists=true && break
    done

    if [[ "$has_domain_lists" == true ]]; then
        cat >> "${CONFIG_DIR}/smartdns.conf" <<EOF

# ===== 流媒体分流 =====
server ${UNLOCK_DNS} -group unlock -exclude-default-group
EOF

        for name in netflix disney youtube; do
            local list_file="${DOMAIN_LIST_DIR}/${name}.conf"
            [[ -f "${list_file}" && -s "${list_file}" ]] || continue
            cat >> "${CONFIG_DIR}/smartdns.conf" <<EOF

# ${name} 域名分流到解锁 DNS
domain-set -name ${name} -file /etc/smartdns/domain-lists/${name}.conf
nameserver /domain-set:${name}/unlock
EOF
        done
    fi

    if [[ -n "${INTRANET_DNS}" ]]; then
        cat >> "${CONFIG_DIR}/smartdns.conf" <<EOF

# 内网域名规则（示例，取消注释以启用）
# nameserver /lan/intranet
# nameserver /local/intranet
# nameserver /home.arpa/intranet
EOF
    fi

    log OK "SmartDNS 配置生成完成"
}

release_port53() {
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        log WARN "检测到 systemd-resolved，正在停止以释放端口 53..."
        systemctl disable --now systemd-resolved
    fi
    # 若其他进程占用 53（TCP 或 UDP），给出警告
    if ss -tlnp 'sport = :53' 2>/dev/null | grep -q ':53' || \
       ss -ulnp 'sport = :53' 2>/dev/null | grep -q ':53'; then
        log WARN "端口 53 仍被占用:"
        ss -tlunp 'sport = :53' 2>/dev/null || true
    fi
}

backup_resolv_conf() {
    # 兼容旧脚本：将 .bak.TIMESTAMP 迁移为 .bak.smartdns.TIMESTAMP
    for f in /etc/resolv.conf.bak.[0-9]*; do
        [[ -f "$f" ]] || continue
        mv "$f" "${f/.bak./.bak.smartdns.}"
    done

    # 已有备份则跳过（避免重复部署覆盖原始备份）
    if ls /etc/resolv.conf.bak.smartdns.* &>/dev/null; then
        return
    fi

    chattr -i /etc/resolv.conf 2>/dev/null || true

    if [[ -L /etc/resolv.conf ]]; then
        # 符号链接：备份链接目标内容（resolved 停止前调用，目标仍可读）
        local link_target
        link_target=$(readlink -f /etc/resolv.conf 2>/dev/null) || true
        if [[ -n "$link_target" && -f "$link_target" ]]; then
            cp "$link_target" "/etc/resolv.conf.bak.smartdns.$(date +%Y%m%d%H%M%S)"
        fi
    elif [[ -f /etc/resolv.conf ]]; then
        cp /etc/resolv.conf "/etc/resolv.conf.bak.smartdns.$(date +%Y%m%d%H%M%S)"
    fi
}

set_system_dns() {
    log INFO "配置系统 DNS..."

    chattr -i /etc/resolv.conf 2>/dev/null || true
    rm -f /etc/resolv.conf 2>/dev/null || true
    echo "nameserver 127.0.0.1" > /etc/resolv.conf
    chattr +i /etc/resolv.conf 2>/dev/null || true
    log OK "系统 DNS 配置完成"
}

start_service() {
    log INFO "启动 SmartDNS..."

    docker compose -f "${DOCKER_DIR}/docker-compose.yaml" up -d

    local i
    for i in $(seq 1 15); do
        if docker inspect -f '{{.State.Status}}' smartdns 2>/dev/null | grep -q 'running'; then
            log OK "SmartDNS 容器启动成功"
            break
        fi
        sleep 1
    done

    if ! docker inspect -f '{{.State.Status}}' smartdns 2>/dev/null | grep -q 'running'; then
        log ERR "SmartDNS 在 15s 内未就绪，请检查: docker compose -f ${DOCKER_DIR}/docker-compose.yaml ps"
        exit 1
    fi

    # 验证端口 53 监听（TCP + UDP）
    sleep 2
    if ! ss -ulnp 'sport = :53' 2>/dev/null | grep -q ':53' && \
       ! ss -tlnp 'sport = :53' 2>/dev/null | grep -q ':53'; then
        log ERR "SmartDNS 容器运行中但未监听端口 53，请检查: docker logs smartdns"
        exit 1
    fi
    log OK "SmartDNS 已监听端口 53"

    # 验证 DNS 实际可响应
    if command -v dig &>/dev/null; then
        for i in $(seq 1 10); do
            if dig +short +time=1 +tries=1 google.com @127.0.0.1 &>/dev/null; then
                log OK "SmartDNS DNS 解析验证通过"
                return
            fi
            sleep 1
        done
        log ERR "SmartDNS 监听端口 53 但无法解析，请检查: docker logs smartdns"
        exit 1
    fi
}

verify_deployment() {
    if ! command -v dig &>/dev/null; then
        log WARN "dig 未安装，跳过 DNS 验证"
        return
    fi

    log INFO "验证部署..."
    echo "=========================================="

    # 通用域名测试
    local result
    echo -n "测试 google.com: "
    result=$(dig +short google.com @127.0.0.1 2>/dev/null | head -1) && echo "${result:-解析失败}" || echo "dig 命令失败"

    # 流媒体分流测试
    if [[ -f "${DOMAIN_LIST_DIR}/netflix.conf" ]]; then
        echo -n "测试 netflix.com: "
        result=$(dig +short netflix.com @127.0.0.1 2>/dev/null | head -1) && echo "${result:-解析失败}" || echo "dig 命令失败"
    fi

    # 强制 IPv6 测试
    if [[ "$FORCE_IPV6" == true ]]; then
        echo ""
        echo "--- 强制 IPv6 验证 ---"

        echo -n "api.anthropic.com A (应为空): "
        result=$(dig +short api.anthropic.com @127.0.0.1 A 2>/dev/null | head -1)
        echo "${result:-空（正确）}"

        echo -n "api.anthropic.com AAAA: "
        result=$(dig +short api.anthropic.com @127.0.0.1 AAAA 2>/dev/null | head -1)
        echo "${result:-解析失败}"

        echo -n "claude.ai A (应为空): "
        result=$(dig +short claude.ai @127.0.0.1 A 2>/dev/null | head -1)
        echo "${result:-空（正确）}"
    fi

    echo "=========================================="
}

show_deployment_info() {
    local has_unlock=false
    [[ -f "${SMARTDNS_DIR}/update-lists.sh" ]] && has_unlock=true

    local mode="纯 DNS 缓存"
    [[ "$FORCE_IPV6" == true ]] && mode="${mode} + 强制 IPv6"
    [[ "$has_unlock" == true ]] && mode="${mode} + 流媒体分流"

    cat <<EOF

==========================================
部署完成
==========================================

模式: ${mode}
配置目录: ${SMARTDNS_DIR}
配置文件: ${CONFIG_DIR}/smartdns.conf
EOF

    if [[ "$FORCE_IPV6" == true ]]; then
        cat <<EOF
IPv6 列表: ${CONFIG_DIR}/force-ipv6.list
EOF
    fi

    cat <<EOF

常用命令:
  查看状态:    docker ps | grep smartdns
  查看日志:    docker logs -f smartdns
  重启服务:    cd ${DOCKER_DIR} && docker compose restart
  停止服务:    cd ${DOCKER_DIR} && docker compose down
  更新镜像:    cd ${DOCKER_DIR} && docker compose pull && docker compose up -d

测试命令:
  dig google.com @127.0.0.1
EOF

    if [[ "$FORCE_IPV6" == true ]]; then
        cat <<EOF
  dig api.anthropic.com @127.0.0.1 A +short     # 应为空
  dig api.anthropic.com @127.0.0.1 AAAA +short   # 应返回 IPv6
EOF
    fi

    if [[ "$PLAIN_DNS" == true ]]; then
        cat <<EOF

DNS 配置:
  ${INTRANET_DNS:+内网: ${INTRANET_DNS}
  }公共: 1.1.1.1, 8.8.8.8, 9.9.9.9, 208.67.222.222 (UDP)

EOF
    else
        cat <<EOF

DNS 配置:
  ${INTRANET_DNS:+内网: ${INTRANET_DNS}
  }公共: 1.1.1.1, 8.8.8.8 (DoT/DoH) + 9.9.9.9 (DoT)

EOF
    fi

    # 分流模式额外信息
    if [[ "$has_unlock" == true ]]; then
        cat <<EOF
分流配置:
  解锁 DNS: ${UNLOCK_DNS}
  域名列表: ${DOMAIN_LIST_DIR}/
  测试分流: dig netflix.com @127.0.0.1

域名列表更新:
  手动更新: ${SMARTDNS_DIR}/update-lists.sh
  定时更新: 已自动注册（每周日凌晨 3 点），查看: crontab -l

EOF
    fi
}

uninstall() {
    if [[ $EUID -ne 0 ]]; then
        log ERR "请使用 root 权限运行卸载"
        exit 1
    fi

    log WARN "正在卸载 SmartDNS..."

    (cd "${DOCKER_DIR}" 2>/dev/null && docker compose down 2>/dev/null) || true
    chattr -i /etc/resolv.conf 2>/dev/null || true

    # 兼容旧脚本备份格式
    for f in /etc/resolv.conf.bak.[0-9]*; do
        [[ -f "$f" ]] || continue
        mv "$f" "${f/.bak./.bak.smartdns.}"
    done

    restore_resolv_conf
    rm -f /etc/resolv.conf.bak.smartdns.* 2>/dev/null || true

    remove_update_cron

    if [[ -t 0 ]]; then
        read -p "是否删除配置目录 ${SMARTDNS_DIR}? [y/N] " -n 1 -r REPLY || true
        echo
        [[ "${REPLY:-}" =~ ^[Yy]$ ]] && rm -rf "${SMARTDNS_DIR}" && log OK "配置目录已删除"
    else
        log INFO "非交互式模式，保留配置目录: ${SMARTDNS_DIR}"
    fi
    log OK "SmartDNS 已卸载"
}

show_status() {
    echo "=========================================="
    echo "SmartDNS 状态检查"
    echo "=========================================="

    # 1. 容器状态
    echo -n "容器状态: "
    if docker inspect -f '{{.State.Status}}' smartdns 2>/dev/null | grep -q 'running'; then
        echo "运行中 ✓"
    else
        echo "未运行 ✗"
    fi

    # 2. 端口监听
    echo -n "端口 53:  "
    if ss -ulnp 'sport = :53' 2>/dev/null | grep -q ':53' || \
       ss -tlnp 'sport = :53' 2>/dev/null | grep -q ':53'; then
        echo "监听中 ✓"
    else
        echo "未监听 ✗"
    fi

    # 3. DNS 解析
    if command -v dig &>/dev/null; then
        echo -n "DNS 解析: "
        local result
        result=$(dig +short +time=2 +tries=1 google.com @127.0.0.1 2>/dev/null | head -1)
        if [[ -n "$result" ]]; then
            echo "正常 ✓ (${result})"
        else
            echo "失败 ✗"
        fi
    fi

    # 4. resolv.conf
    echo -n "系统 DNS: "
    if grep -qx 'nameserver 127.0.0.1' /etc/resolv.conf 2>/dev/null; then
        echo "127.0.0.1 (SmartDNS) ✓"
    else
        echo "$(grep '^nameserver' /etc/resolv.conf 2>/dev/null | head -1) (非 SmartDNS)"
    fi

    # 5. 配置摘要
    echo ""
    echo "配置:"
    if [[ -f "${CONFIG_DIR}/smartdns.conf" ]]; then
        echo "  上游 DNS: $(grep -E '^server(-tls|-https)? ' "${CONFIG_DIR}/smartdns.conf" 2>/dev/null | grep -v '#' | awk '{print $2}' | tr '\n' ' ')"
        [[ -f "${CONFIG_DIR}/force-ipv6.list" ]] && echo "  强制 IPv6: $(wc -l < "${CONFIG_DIR}/force-ipv6.list") 个域名"
        local unlock_count=0
        for f in "${DOMAIN_LIST_DIR}"/*.conf; do
            [[ -f "$f" ]] && unlock_count=$((unlock_count + $(wc -l < "$f")))
        done
        [[ $unlock_count -gt 0 ]] && echo "  分流规则: ${unlock_count} 条"
    else
        echo "  配置文件不存在"
    fi

    echo "=========================================="
}

restore_resolv_conf() {
    chattr -i /etc/resolv.conf 2>/dev/null || true
    # 如果系统有 systemd-resolved，优先恢复它
    if systemctl list-unit-files systemd-resolved.service &>/dev/null; then
        if systemctl enable --now systemd-resolved 2>/dev/null; then
            ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf 2>/dev/null || true
            log OK "已恢复 systemd-resolved"
            return
        fi
    fi
    # resolved 不可用，尝试从备份恢复（备份内容不含 127.* 才有意义）
    local backup
    backup=$(ls -t /etc/resolv.conf.bak.smartdns.* 2>/dev/null | head -1) || true
    if [[ -n "$backup" ]] && ! grep -qE '^nameserver 127\.' "$backup" 2>/dev/null; then
        cp "$backup" /etc/resolv.conf
        log OK "已恢复 DNS: $backup"
        return
    fi
    # 兜底：公共 DNS
    echo "nameserver 1.1.1.1" > /etc/resolv.conf
    log WARN "DNS 已设为 1.1.1.1（临时），请手动检查"
}

restore_dns_on_failure() {
    log WARN "部署中断，正在恢复 DNS..."
    restore_resolv_conf
}

setup_cron_update() {
    local cron_cmd="0 3 * * 0 ${SMARTDNS_DIR}/update-lists.sh >> /var/log/smartdns-update.log 2>&1"
    local current
    current=$(crontab -l 2>/dev/null) || current=""
    if echo "$current" | grep -qF "${SMARTDNS_DIR}/update-lists.sh"; then
        log OK "域名列表更新 cron 已存在"
        return
    fi
    { echo "$current"; echo "$cron_cmd"; } | crontab -
    log OK "已注册每周日凌晨 3 点自动更新域名列表"
}

# ============================================================
# 主流程
# ============================================================

main() {
    local DOWNLOAD_LISTS=false
    local UNINSTALL=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            -i|--intranet-dns)
                [[ -z "${2:-}" ]] && { log ERR "$1 需要参数"; exit 1; }
                INTRANET_DNS="$2"; shift 2 ;;
            -u|--unlock-dns)
                [[ -z "${2:-}" ]] && { log ERR "$1 需要参数"; exit 1; }
                UNLOCK_DNS="$2"; shift 2 ;;
            -t|--timezone)
                [[ -z "${2:-}" ]] && { log ERR "$1 需要参数"; exit 1; }
                TIMEZONE="$2"; shift 2 ;;
            -d|--download-lists) DOWNLOAD_LISTS=true; shift ;;
            -6|--force-ipv6)     FORCE_IPV6=true; shift ;;
            --plain-dns)         PLAIN_DNS=true; shift ;;
            -s|--status)         show_status; exit 0 ;;
            --uninstall)         UNINSTALL=true; shift ;;
            -h|--help)           show_help; exit 0 ;;
            *) log ERR "未知参数: $1"; show_help; exit 1 ;;
        esac
    done

    if [[ "$UNINSTALL" == true ]]; then
        uninstall
        exit 0
    fi

    if [[ $EUID -ne 0 ]]; then
        log ERR "请使用 root 权限运行此脚本"
        exit 1
    fi

    # 验证 IP 参数
    if [[ -n "$INTRANET_DNS" ]]; then
        is_valid_ip "$INTRANET_DNS" || { log ERR "无效的内网 DNS: $INTRANET_DNS"; exit 1; }
    fi
    if [[ "$DOWNLOAD_LISTS" == true ]]; then
        is_valid_ip "$UNLOCK_DNS" || { log ERR "无效的解锁 DNS: $UNLOCK_DNS"; exit 1; }
    fi

    check_docker
    # 在 DNS 仍可用时预拉取镜像（停 resolved 后 Docker 守护进程可能无法解析）
    log INFO "拉取 SmartDNS 镜像..."
    docker pull pymumu/smartdns:latest
    create_directories

    if [[ "$DOWNLOAD_LISTS" == true ]]; then
        download_domain_lists
        setup_cron_update
    else
        # 清理旧 -d 模式残留
        if ls "${DOMAIN_LIST_DIR}"/*.conf &>/dev/null; then
            rm -f "${DOMAIN_LIST_DIR}"/*.conf
            log OK "已清理旧域名列表文件"
        fi
        if [[ -f "${SMARTDNS_DIR}/update-lists.sh" ]]; then
            rm -f "${SMARTDNS_DIR}/update-lists.sh"
            log OK "已清理旧更新脚本"
        fi
        remove_update_cron
    fi

    setup_force_ipv6
    generate_docker_compose
    generate_smartdns_config
    # 备份原始 resolv.conf（首次部署时，resolved 尚未停止，链接目标可读）
    backup_resolv_conf
    # 停旧容器/resolved 前，确保系统有可用 DNS
    # 覆盖：127.0.0.1（SmartDNS 重复部署）、127.0.0.53（systemd-resolved）、符号链接
    chattr -i /etc/resolv.conf 2>/dev/null || true
    if [[ -L /etc/resolv.conf ]] || grep -qE '^nameserver 127\.' /etc/resolv.conf 2>/dev/null; then
        rm -f /etc/resolv.conf 2>/dev/null || true
        echo "nameserver 1.1.1.1" > /etc/resolv.conf
    fi
    trap restore_dns_on_failure ERR
    docker compose -f "${DOCKER_DIR}/docker-compose.yaml" down 2>/dev/null || true
    release_port53
    start_service
    trap - ERR
    set_system_dns
    verify_deployment
    show_deployment_info
}

main "$@"
