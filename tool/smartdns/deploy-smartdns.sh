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

# ============================================================
# 工具函数
# ============================================================

log() { echo "[$1] $2"; }

is_valid_ip() {
    local ip="$1"
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    local IFS='.'
    read -r a b c d <<< "$ip"
    (( a <= 255 && b <= 255 && c <= 255 && d <= 255 ))
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
  -i, --intranet-dns <IP>    设置内网 DNS（可选）
  -u, --unlock-dns <IP>      设置解锁 DNS（默认: 103.214.22.32，仅 -d 模式）
  -t, --timezone <TZ>        设置时区（默认: Asia/Hong_Kong）
  --uninstall                卸载 SmartDNS
  -h, --help                 显示帮助

示例:
  $0                         # 纯 DNS 缓存
  $0 -6                      # DNS 缓存 + 强制 IPv6
  $0 -d                      # DNS 缓存 + 流媒体分流
  $0 -d -6                   # DNS 缓存 + 流媒体分流 + 强制 IPv6
  $0 -d -u 1.2.3.4           # 自定义解锁 DNS
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
            sed -i '/^#/d; /^$/d; /^@/d; /^include:/d; /^regexp:/d; /^full:/d' "${local_path}" 2>/dev/null || true
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
        sed -i '/^#/d; /^$/d; /^@/d; /^include:/d; /^regexp:/d; /^full:/d' "${local_path}" 2>/dev/null || true
        echo "[OK] ${name}: $(wc -l < "${local_path}") 条域名"
    else
        echo "[WARN] ${name} 下载失败"
    fi
done

# 重载 SmartDNS 配置
docker kill -s HUP smartdns 2>/dev/null || docker restart smartdns 2>/dev/null || true

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

    cat >> "${CONFIG_DIR}/smartdns.conf" <<EOF

# 公共 DNS（默认组）
server 1.1.1.1
server 8.8.8.8
server 9.9.9.9
server 208.67.222.222
EOF

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

configure_system_dns() {
    log INFO "配置系统 DNS..."

    # 解锁以便修改
    chattr -i /etc/resolv.conf 2>/dev/null || true

    # 仅在 resolv.conf 不是指向 127.0.0.1 时才备份
    if [[ -f /etc/resolv.conf ]] && ! grep -qx 'nameserver 127.0.0.1' /etc/resolv.conf 2>/dev/null; then
        cp /etc/resolv.conf "/etc/resolv.conf.bak.$(date +%Y%m%d%H%M%S)"
    fi

    if systemctl is-active --quiet systemd-resolved; then
        log WARN "检测到 systemd-resolved，正在停止..."
        systemctl disable --now systemd-resolved
        rm -f /etc/resolv.conf
    fi

    echo "nameserver 127.0.0.1" > /etc/resolv.conf
    chattr +i /etc/resolv.conf 2>/dev/null || true
    log OK "系统 DNS 配置完成"
}

start_service() {
    log INFO "启动 SmartDNS..."

    docker compose -f "${DOCKER_DIR}/docker-compose.yaml" down 2>/dev/null || true
    docker compose -f "${DOCKER_DIR}/docker-compose.yaml" up -d

    local i
    for i in $(seq 1 15); do
        if docker inspect -f '{{.State.Status}}' smartdns 2>/dev/null | grep -q 'running'; then
            log OK "SmartDNS 启动成功"
            return
        fi
        sleep 1
    done

    log ERR "SmartDNS 在 15s 内未就绪，请检查: docker compose -f ${DOCKER_DIR}/docker-compose.yaml ps"
    exit 1
}

verify_deployment() {
    command -v dig &>/dev/null || { apt-get update -qq && apt-get install -y -qq dnsutils 2>/dev/null || true; }

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

    cat <<EOF

DNS 配置:
  ${INTRANET_DNS:+内网: ${INTRANET_DNS}
  }公共: 1.1.1.1, 8.8.8.8, 9.9.9.9, 208.67.222.222

EOF

    # 分流模式额外信息
    if [[ "$has_unlock" == true ]]; then
        cat <<EOF
分流配置:
  解锁 DNS: ${UNLOCK_DNS}
  域名列表: ${DOMAIN_LIST_DIR}/
  测试分流: dig netflix.com @127.0.0.1

域名列表更新:
  手动更新: ${SMARTDNS_DIR}/update-lists.sh
  定时更新: crontab -e 添加以下内容
            0 3 * * 0 ${SMARTDNS_DIR}/update-lists.sh >> /var/log/smartdns-update.log 2>&1

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

    local backup
    backup=$(ls -t /etc/resolv.conf.bak.* 2>/dev/null | head -1) || true
    if [[ -n "$backup" ]]; then
        cp "$backup" /etc/resolv.conf
        log INFO "已恢复 DNS 配置: $backup"
    else
        echo "nameserver 1.1.1.1" > /etc/resolv.conf
        log INFO "已设置默认 DNS: 1.1.1.1"
    fi

    read -p "是否删除配置目录 ${SMARTDNS_DIR}? [y/N] " -n 1 -r REPLY || true
    echo
    [[ "${REPLY:-}" =~ ^[Yy]$ ]] && rm -rf "${SMARTDNS_DIR}" && log OK "配置目录已删除"
    log OK "SmartDNS 已卸载"
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
            --uninstall)         UNINSTALL=true; shift ;;
            -h|--help)           show_help; exit 0 ;;
            *) log ERR "未知参数: $1"; show_help; exit 1 ;;
        esac
    done

    # 验证 IP 参数
    local ip
    for var in INTRANET_DNS UNLOCK_DNS; do
        ip="${!var}"
        [[ -z "$ip" ]] && continue
        is_valid_ip "$ip" || { log ERR "无效的 IP: $ip"; exit 1; }
    done

    if [[ "$UNINSTALL" == true ]]; then
        uninstall
        exit 0
    fi

    if [[ $EUID -ne 0 ]]; then
        log ERR "请使用 root 权限运行此脚本"
        exit 1
    fi

    check_docker
    create_directories

    [[ "$DOWNLOAD_LISTS" == true ]] && download_domain_lists

    setup_force_ipv6
    generate_docker_compose
    generate_smartdns_config
    start_service
    configure_system_dns
    verify_deployment
    show_deployment_info
}

main "$@"
