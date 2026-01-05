#!/bin/bash
# Linux Network Optimizer v4.0 - Three-Mode Unified Version
# 用法:
#   install -c    国内直连优化 (CN2/9929/CMIN2)
#   install -i    国际优化 (Misaka/DMIT 等商业VPS)
#   install -r    家宽落地 (HKT/Hinet/KDDI)
#   install       交互式选择
#   status        查看当前状态
#   restore       恢复原始配置

set -euo pipefail

readonly KERNEL_CONF="/etc/sysctl.d/99-kernel.conf"
readonly OLD_CUSTOM_CONF="/etc/sysctl.d/99-custom.conf"
readonly SYSCTL_FILE="/etc/sysctl.conf"
readonly LIMITS_CONFIG="/etc/security/limits.conf"

RUN_MODE="interactive"

info() { echo "✅ $1"; }
warn() { echo "⚠️  $1"; }
error() { echo "❌ $1"; exit 1; }
success() { echo "🎉 $1"; }

# === 环境检测 ===
check_env() {
    [[ $EUID -eq 0 ]] || error "需要 root 权限"

    # 检测容器环境（OpenVZ/LXC/Docker 等）
    local virt=$(systemd-detect-virt 2>/dev/null || echo "none")
    if [ -f /proc/user_beancounters ] || [ -d /proc/vz ] || [[ "$virt" != "none" && "$virt" != "kvm" ]]; then
        warn "检测到容器/虚拟化环境 ($virt)，部分功能可能受限..."
        IS_CONTAINER=true
    else
        IS_CONTAINER=false
    fi
}

detect_interface() {
    ip route get 1.1.1.1 2>/dev/null | grep -oP 'dev \K\S+' | head -1 || ls /sys/class/net/ 2>/dev/null | grep -v lo | head -1
}

# === 1. BBR & Limits ===
setup_bbr() {
    [[ "$IS_CONTAINER" == "true" ]] && return 0
    info "检查 BBR 支持..."
    modprobe tcp_bbr 2>/dev/null || true
    if ! grep -wq bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
        case $(grep ^ID= /etc/os-release 2>/dev/null) in
            *ubuntu*|*debian*) apt update >/dev/null 2>&1 && apt install -y linux-modules-extra-$(uname -r) >/dev/null 2>&1 || true ;;
        esac
        modprobe tcp_bbr 2>/dev/null || true
    fi
}

apply_limits() {
    info "配置系统资源限制..."
    [ -f "$LIMITS_CONFIG" ] && [ ! -f "${LIMITS_CONFIG}.bak" ] && cp "$LIMITS_CONFIG" "${LIMITS_CONFIG}.bak"
    for file in /etc/security/limits.d/*nproc.conf; do [[ -f "$file" ]] && mv "$file" "${file}.disabled" 2>/dev/null || true; done
    [[ -f /etc/pam.d/common-session ]] && ! grep -q "pam_limits.so" /etc/pam.d/common-session && echo "session required pam_limits.so" >> /etc/pam.d/common-session

    sed -i '/# Network Optimizer/,$d' "$LIMITS_CONFIG"
    cat >> "$LIMITS_CONFIG" << 'EOF'
# Network Optimizer - 系统资源限制
*     soft   nofile    1048576
*     hard   nofile    1048576
*     soft   nproc     1048576
*     hard   nproc     1048576
root  soft   nofile    1048576
root  hard   nofile    1048576
root  soft   nproc     1048576
root  hard   nproc     1048576
EOF

    # systemd limits - 备份原文件
    [ -f /etc/systemd/system.conf ] && [ ! -f /etc/systemd/system.conf.bak ] && cp /etc/systemd/system.conf /etc/systemd/system.conf.bak
    cat > /etc/systemd/system.conf << 'EOF'
[Manager]
DefaultCPUAccounting=yes
DefaultIOAccounting=yes
DefaultIPAccounting=yes
DefaultMemoryAccounting=yes
DefaultTasksAccounting=yes
DefaultLimitCORE=infinity
DefaultLimitNPROC=infinity
DefaultLimitNOFILE=infinity
EOF
}

# === 2. 额外系统优化 ===
install_haveged() {
    if command -v haveged >/dev/null 2>&1; then
        info "haveged 已安装"
        return 0
    fi

    info "安装 haveged 改善随机数生成器性能（TLS 加速）..."
    if command -v apt >/dev/null 2>&1; then
        apt install haveged -y >/dev/null 2>&1 || warn "haveged 安装失败"
        systemctl enable haveged 2>/dev/null || true
    elif command -v yum >/dev/null 2>&1; then
        yum install -y haveged >/dev/null 2>&1 || warn "haveged 安装失败"
        systemctl enable haveged 2>/dev/null || true
    fi
}

disable_thp() {
    info "禁用 Transparent Huge Pages..."
    cat > /etc/systemd/system/disable-transparent-huge-pages.service << 'EOF'
[Unit]
Description=Disable Transparent Huge Pages (THP)
DefaultDependencies=no
After=sysinit.target local-fs.target
[Service]
Type=oneshot
ExecStart=/bin/sh -c 'echo never | tee /sys/kernel/mm/transparent_hugepage/enabled > /dev/null'
ExecStart=/bin/sh -c 'echo never | tee /sys/kernel/mm/transparent_hugepage/defrag > /dev/null'
[Install]
WantedBy=basic.target
EOF
    systemctl daemon-reload
    systemctl start disable-transparent-huge-pages 2>/dev/null || true
    systemctl enable disable-transparent-huge-pages 2>/dev/null || true
}

disable_ksmtuned() {
    if command -v ksmtuned >/dev/null 2>&1; then
        info "禁用 ksmtuned..."
        echo 2 > /sys/kernel/mm/ksm/run 2>/dev/null || true
        apt purge ksmtuned --autoremove -y >/dev/null 2>&1 || true
        systemctl disable ksmtuned 2>/dev/null || true
    fi
}

setup_journald() {
    info "配置 journald 限制..."
    [ -f /etc/systemd/journald.conf ] && [ ! -f /etc/systemd/journald.conf.bak ] && cp /etc/systemd/journald.conf /etc/systemd/journald.conf.bak
    cat > /etc/systemd/journald.conf << 'EOF'
[Journal]
SystemMaxUse=384M
SystemMaxFileSize=128M
SystemMaxFiles=3
RuntimeMaxUse=256M
RuntimeMaxFileSize=128M
RuntimeMaxFiles=3
MaxRetentionSec=86400
MaxFileSec=259200
ForwardToSyslog=no
EOF
    systemctl reload systemd-journald 2>/dev/null || systemctl restart systemd-journald 2>/dev/null || true
}

# === 3. 模块加载 ===
load_modules() {
    local mode=$1
    if [[ "$mode" == "intl" ]]; then
        info "加载 nf_conntrack 模块..."
        mkdir -p /etc/modules-load.d
        echo "nf_conntrack" > /etc/modules-load.d/network-optimizer.conf
        modprobe nf_conntrack 2>/dev/null || warn "nf_conntrack 模块加载失败（容器环境？）"
    fi
}

# === 4. Sysctl 处理 ===
apply_sysctl() {
    local target_scheme=""
    if [[ "$RUN_MODE" == "china" ]]; then
        target_scheme="china"
    elif [[ "$RUN_MODE" == "intl" ]]; then
        target_scheme="intl"
    elif [[ "$RUN_MODE" == "residential" ]]; then
        target_scheme="residential"
    else
        printf "请选择优化模式:\n"
        printf "  1) 国内直连 (CN2/9929/CMIN2)\n"
        printf "  2) 国际优化 (Misaka/DMIT 等)\n"
        printf "  3) 家宽落地 (HKT/Hinet/KDDI)\n"
        printf "选择 [1-3]: "
        read -r REPLY < /dev/tty || REPLY="1"
        case "$REPLY" in
            1) target_scheme="china" ;;
            2) target_scheme="intl" ;;
            3) target_scheme="residential" ;;
            *) target_scheme="china" ;;
        esac
    fi

    # 醒目的模式展示
    echo "================================================"
    case "$target_scheme" in
        china)
            info "当前方案: [ 国内直连优化 - CN2/9929/CMIN2 ]"
            ;;
        intl)
            info "当前方案: [ 国际优化 - Misaka/DMIT 等 ]"
            ;;
        residential)
            info "当前方案: [ 家宽落地 - HKT/Hinet/KDDI ]"
            ;;
    esac
    echo "================================================"

    # 加载必要的内核模块
    load_modules "$target_scheme"

    local content=""

    # 国内直连模式 - 不调整 TCP 窗口
    if [[ "$target_scheme" == "china" ]]; then
        content=$(cat << 'EOF'
# === 国内直连优化 (CN2/9929/CMIN2) ===
# 协议: anytls/TLS
# 特点: 低延迟，使用系统默认缓冲区

fs.file-max = 6815744
net.ipv4.tcp_no_metrics_save=1
net.ipv4.tcp_ecn=0
net.ipv4.tcp_frto=0
net.ipv4.tcp_mtu_probing=0
net.ipv4.tcp_rfc1337=0
net.ipv4.tcp_sack=1
net.ipv4.tcp_fack=1
net.ipv4.tcp_window_scaling=1
net.ipv4.tcp_adv_win_scale=1
net.ipv4.tcp_moderate_rcvbuf=1
net.ipv4.ip_forward=1
net.ipv4.conf.all.route_localnet=1
net.ipv4.conf.all.forwarding=1
net.ipv4.conf.default.forwarding=1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.default.forwarding=1
net.ipv4.tcp_fastopen=1027
net.ipv4.ip_local_port_range=1024 65535
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_fin_timeout=30
net.ipv4.tcp_keepalive_time=600
net.ipv4.tcp_keepalive_probes=5
net.ipv4.tcp_keepalive_intvl=30
net.core.somaxconn=8192
net.core.netdev_max_backlog=8192
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.udp_rmem_min=8192
net.ipv4.udp_wmem_min=8192
EOF
)
    # 国际优化模式 - 大缓冲区
    elif [[ "$target_scheme" == "intl" ]]; then
        # 动态计算 tcp_mem - 带错误处理
        local mems=$(free --bytes 2>/dev/null | grep Mem | awk '{print $2}')
        local page=$(getconf PAGESIZE 2>/dev/null)
        local tcp_mem="786432 1048576 1572864"  # 默认值

        if [[ -n "$mems" && -n "$page" && "$page" -gt 0 ]]; then
            local size=$((mems/page))
            if [[ "$size" -gt 0 ]]; then
                tcp_mem="$((size/100*12)) $((size/100*50)) $((size/100*70))"
            fi
        fi

        content=$(cat << EOF
# === 国际优化 (Misaka/DMIT/国际VPS) ===
# 协议: ss2022
# 特点: 高延迟，大缓冲区（64MB）

fs.file-max = 6815744
net.ipv4.tcp_no_metrics_save=1
net.ipv4.tcp_ecn=0
net.ipv4.tcp_frto=0
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_rfc1337=0
net.ipv4.tcp_sack=1
net.ipv4.tcp_fack=1
net.ipv4.tcp_window_scaling=1
net.ipv4.tcp_adv_win_scale=1
net.ipv4.tcp_moderate_rcvbuf=1
net.core.rmem_max=67108864
net.core.wmem_max=67108864
net.ipv4.tcp_rmem=8192 174760 67108864
net.ipv4.tcp_wmem=8192 174760 67108864
net.ipv4.tcp_mem=${tcp_mem}
net.ipv4.udp_rmem_min=8192
net.ipv4.udp_wmem_min=8192
net.ipv4.ip_forward=1
net.ipv4.conf.all.route_localnet=1
net.ipv4.conf.all.forwarding=1
net.ipv4.conf.default.forwarding=1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.default.forwarding=1
net.ipv4.tcp_fastopen=1027
net.ipv4.ip_local_port_range=1024 65535
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_keepalive_time=300
net.ipv4.tcp_keepalive_probes=3
net.ipv4.tcp_keepalive_intvl=15
net.core.somaxconn=16384
net.core.netdev_max_backlog=16384
net.ipv4.tcp_max_syn_backlog=16384
net.netfilter.nf_conntrack_max=1048576
net.netfilter.nf_conntrack_tcp_timeout_established=600
net.netfilter.nf_conntrack_tcp_timeout_time_wait=30
EOF
)
    # 家宽落地模式 - 最小化调整
    else
        content=$(cat << 'EOF'
# === 家宽落地 (HKT/Hinet/KDDI) ===
# 协议: ss2022
# 特点: 港内低延迟（<5ms），轻量优化

net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_fastopen=1027
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.default.forwarding=1
EOF
)
    fi

    if [ -f "$OLD_CUSTOM_CONF" ] && [ ! -f "${OLD_CUSTOM_CONF}.bak" ]; then
        mv "$OLD_CUSTOM_CONF" "${OLD_CUSTOM_CONF}.bak"
    fi

    source /etc/os-release
    local config_file=""
    if [[ "${ID:-}" == "debian" && "${VERSION_ID:-}" == "13" ]]; then
        [ -f "$SYSCTL_FILE" ] && [ ! -f "${SYSCTL_FILE}.bak" ] && mv "$SYSCTL_FILE" "${SYSCTL_FILE}.bak"
        echo "$content" > "$KERNEL_CONF"
        config_file="$KERNEL_CONF"
    else
        [ -f "$SYSCTL_FILE" ] && [ ! -f "${SYSCTL_FILE}.backup" ] && cp "$SYSCTL_FILE" "${SYSCTL_FILE}.backup"
        echo "$content" > "$SYSCTL_FILE"
        config_file="$SYSCTL_FILE"
    fi

    # 应用配置并提供反馈
    apply_sysctl_with_feedback "$config_file" "$target_scheme"
}

# === 智能 sysctl 应用函数 ===
apply_sysctl_with_feedback() {
    local config_file=$1
    local mode=$2

    info "应用网络优化配置..."

    # 使用 -e 忽略不存在的键
    local output
    output=$(sysctl -p -e "$config_file" 2>&1)

    # 分析输出
    local success_count=0
    local skip_count=0
    local applied_params=""
    local skipped_params=""

    while IFS= read -r line; do
        if [[ "$line" =~ ^[a-z] ]] && [[ "$line" == *" = "* ]]; then
            # 成功应用的参数
            ((success_count++))
        elif [[ "$line" =~ "cannot stat" ]] || [[ "$line" =~ "No such file" ]] || [[ "$line" =~ "Read-only" ]]; then
            # 跳过的参数
            ((skip_count++))
            local param=$(echo "$line" | grep -oP 'net\.[^ ]+' || echo "$line" | grep -oP 'fs\.[^ ]+' || echo "unknown")
            skipped_params+="  - $param\n"
        fi
    done <<< "$output"

    # 显示结果
    echo ""
    echo "================================================"
    success "网络优化配置应用完成"
    echo "================================================"
    echo "  ✅ 成功应用: ${success_count} 个参数"

    if [[ $skip_count -gt 0 ]]; then
        echo "  ⚠️  跳过参数: ${skip_count} 个 (环境限制)"

        if [[ "$IS_CONTAINER" == "true" ]]; then
            echo ""
            warn "检测到容器环境，部分内核参数受宿主机限制"
        fi

        # 显示跳过的关键参数
        if echo "$skipped_params" | grep -q "nf_conntrack"; then
            echo ""
            warn "nf_conntrack 参数失败 - 可能原因："
            echo "     1. 容器环境不支持"
            echo "     2. 模块加载失败"
            echo "     影响: 连接跟踪优化不生效（一般影响不大）"
        fi
    fi

    # 验证关键参数
    echo ""
    echo "================================================"
    echo "关键参数验证:"
    echo "================================================"
    verify_key_param "BBR 拥塞控制" "net.ipv4.tcp_congestion_control" "bbr"
    verify_key_param "FQ 队列调度" "net.core.default_qdisc" "fq"
    verify_key_param "TCP Fast Open" "net.ipv4.tcp_fastopen" "1027"
    verify_key_param "IP 转发" "net.ipv4.ip_forward" "1"

    if [[ "$mode" == "intl" ]]; then
        verify_key_param "64MB 接收缓冲" "net.core.rmem_max" "67108864"
        verify_key_param "64MB 发送缓冲" "net.core.wmem_max" "67108864"
    fi

    echo "================================================"
    echo ""
}

# 验证单个关键参数
verify_key_param() {
    local name=$1
    local param=$2
    local expected=$3

    local actual=$(sysctl -n "$param" 2>/dev/null)
    if [[ "$actual" == "$expected" ]]; then
        echo "  ✅ $name: $actual"
    else
        echo "  ⚠️  $name: $actual (预期: $expected)"
    fi
}

# === 5. 恢复逻辑 ===
restore_optimization() {
    info "正在全面按备份恢复状态..."

    # 恢复 sysctl 配置
    source /etc/os-release
    if [[ "${ID:-}" == "debian" && "${VERSION_ID:-}" == "13" ]]; then
        [ -f "${SYSCTL_FILE}.bak" ] && mv "${SYSCTL_FILE}.bak" "$SYSCTL_FILE"
        [ -f "$KERNEL_CONF" ] && rm -f "$KERNEL_CONF"
    else
        [ -f "${SYSCTL_FILE}.backup" ] && mv "${SYSCTL_FILE}.backup" "$SYSCTL_FILE"
    fi
    [ -f "${OLD_CUSTOM_CONF}.bak" ] && mv "${OLD_CUSTOM_CONF}.bak" "$OLD_CUSTOM_CONF"

    # 恢复 limits
    [ -f "${LIMITS_CONFIG}.bak" ] && mv "${LIMITS_CONFIG}.bak" "$LIMITS_CONFIG"
    for file in /etc/security/limits.d/*.conf.disabled; do [[ -f "$file" ]] && mv "$file" "${file%.disabled}" 2>/dev/null || true; done

    # 恢复 systemd 配置
    [ -f /etc/systemd/system.conf.bak ] && mv /etc/systemd/system.conf.bak /etc/systemd/system.conf

    # 恢复 journald 配置
    [ -f /etc/systemd/journald.conf.bak ] && mv /etc/systemd/journald.conf.bak /etc/systemd/journald.conf
    systemctl reload systemd-journald 2>/dev/null || true

    # 清理 THP service
    if [ -f /etc/systemd/system/disable-transparent-huge-pages.service ]; then
        systemctl disable disable-transparent-huge-pages 2>/dev/null || true
        systemctl stop disable-transparent-huge-pages 2>/dev/null || true
        rm -f /etc/systemd/system/disable-transparent-huge-pages.service
        systemctl daemon-reload
    fi

    # 清理模块加载配置
    [ -f /etc/modules-load.d/network-optimizer.conf ] && rm -f /etc/modules-load.d/network-optimizer.conf

    local interface=$(detect_interface)
    command -v tc >/dev/null 2>&1 && tc qdisc del dev "$interface" root 2>/dev/null || true
    sysctl --system >/dev/null 2>&1 || true
    success "所有配置已恢复"
}

# === 6. 入口 ===
main() {
    local cmd="install"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            install|restore|status) cmd="$1" ;;
            -c|--china) RUN_MODE="china" ;;
            -i|--intl) RUN_MODE="intl" ;;
            -r|--residential) RUN_MODE="residential" ;;
        esac
        shift
    done

    case "$cmd" in
        install)
            check_env
            setup_bbr
            apply_limits
            setup_journald

            # 根据模式选择额外优化
            if [[ "$RUN_MODE" == "china" ]]; then
                install_haveged
                disable_thp
                disable_ksmtuned
            elif [[ "$RUN_MODE" == "intl" ]]; then
                disable_thp
                disable_ksmtuned
            fi

            apply_sysctl

            local interface=$(detect_interface)
            command -v tc >/dev/null 2>&1 && tc qdisc replace dev "$interface" root fq 2>/dev/null || true

            success "调优完成！"
            info "当前模式: $RUN_MODE"
            ;;
        restore) restore_optimization ;;
        status)
            echo "=== 当前网络优化状态 ==="
            sysctl net.ipv4.tcp_congestion_control net.core.default_qdisc
            if sysctl -n net.core.rmem_max 2>/dev/null | grep -q 67108864; then
                echo "检测到大缓冲区配置 (64MB) - 国际优化模式"
            else
                echo "使用默认缓冲区 - 国内直连或家宽落地模式"
            fi
            ;;
    esac
}

main "$@"
