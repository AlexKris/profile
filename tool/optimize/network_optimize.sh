#!/bin/bash

# 网络性能调优脚本 v2.0
# 用于Linux服务器的网络参数优化
# 支持分级配置和场景自动优化
# 
# 作者: AlexKris
# 版本: 2.0
# 更新: $(date '+%Y-%m-%d')

# 启用严格模式，显式错误处理（移除-e以避免不可预测行为）
set -uo pipefail

# 脚本版本
readonly SCRIPT_VERSION="2.0"

# 获取脚本所在目录（支持管道执行）
if [ -n "${BASH_SOURCE[0]:-}" ] && [[ "${BASH_SOURCE[0]}" != /dev/fd/* ]] && [[ "${BASH_SOURCE[0]}" != /proc/self/fd/* ]]; then
    # 正常文件执行
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
    # 通过管道执行，使用用户家目录或/tmp
    if [ -w "$HOME" ] && [ -d "$HOME" ]; then
        SCRIPT_DIR="$HOME"
    else
        SCRIPT_DIR="/tmp"
    fi
fi

# 时间戳
 readonly TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# 临时文件清理变量
TMP_FILES=""

# 全局变量
readonly BACKUP_DIR="/etc/sysctl.backup"
readonly LOG_FILE="$SCRIPT_DIR/network_optimize-$TIMESTAMP.log"

# 配置变量
PROFILE=""
ENABLE_NAT=false
ENABLE_GATEWAY=false
ENABLE_BBR=false
ENABLE_FASTOPEN=false
DRY_RUN=false
APPLY_CONFIG=false

# 设置安全的临时文件处理
cleanup() {
    # 删除所有临时文件
    if [ -n "$TMP_FILES" ]; then
        rm -f $TMP_FILES >/dev/null 2>&1
    fi
    log_message "INFO" "脚本执行完成，清理临时文件"
}

# 注册EXIT信号处理
trap cleanup EXIT INT TERM

# ==================== 现代化错误处理函数 ====================

# 致命错误处理函数 - 记录错误并退出
die() {
    local msg="${1:-未知致命错误}"
    local exit_code="${2:-1}"
    
    log_message "ERROR" "致命错误: $msg"
    log_message "ERROR" "脚本终止执行 (退出码: $exit_code)"
    
    # 清理资源
    cleanup 2>/dev/null || true
    exit "$exit_code"
}

# 检查命令执行结果 - 非致命错误处理
check_error() {
    local exit_code=$1
    local operation="${2:-操作}"
    local context="${3:-}"
    
    if [ $exit_code -ne 0 ]; then
        local error_msg="$operation 失败 (错误码: $exit_code)"
        [ -n "$context" ] && error_msg="$error_msg - $context"
        
        log_message "WARNING" "$error_msg"
        return 1
    fi
    return 0
}

# 安全执行命令 - 带错误检查的命令执行
safe_execute() {
    local cmd="$1"
    local description="${2:-执行命令}"
    local fatal="${3:-false}"
    
    log_message "DEBUG" "执行: $cmd"
    
    # 执行命令并捕获退出码
    eval "$cmd"
    local exit_code=$?
    
    # 只有非零退出码才算真正失败
    if [ "$exit_code" -ne 0 ]; then
        local error_msg="$description 失败 (错误码: $exit_code)"
        
        if [ "$fatal" = "true" ]; then
            die "$error_msg" "$exit_code"
        else
            log_message "WARNING" "$error_msg"
            return "$exit_code"
        fi
    fi
    
    log_message "DEBUG" "$description 成功"
    return 0
}

# 颜色输出（已禁用）

# 日志记录函数（与setup.sh保持一致）
log_message() {
    local level="${1:-INFO}"
    local message="${2:-}"
    local timestamp
    
    # 参数验证
    [ -z "$message" ] && { echo "[错误] 消息内容不能为空" >&2; return 1; }
    
    # 统一时间戳格式
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # 级别标准化和输出
    case "${level^^}" in
        "ERROR"|"ERR")
            echo "[错误] $message" | tee -a "$LOG_FILE" >&2
            ;;
        "WARNING"|"WARN")
            echo "[警告] $message" | tee -a "$LOG_FILE"
            ;;
        "INFO")
            echo "[信息] $message" | tee -a "$LOG_FILE"
            ;;
        "SUCCESS"|"OK")
            echo "[成功] $message" | tee -a "$LOG_FILE"
            ;;
        "DEBUG")
            [ "${DEBUG:-}" = "1" ] && echo "[调试] $message" | tee -a "$LOG_FILE"
            ;;
        *)
            echo "[信息] $message" | tee -a "$LOG_FILE"
            ;;
    esac
    
    # 写入日志文件（带时间戳）
    echo "[$timestamp][$level] $message" >> "$LOG_FILE" 2>/dev/null || true
}

# 检查是否为root用户
check_root() {
    if [[ $EUID -ne 0 ]]; then
        die "此脚本需要root权限运行"
    fi
}

# 创建备份目录
ensure_backup_dir() {
    if [[ ! -d "$BACKUP_DIR" ]]; then
        mkdir -p "$BACKUP_DIR"
        log_message "INFO" "创建备份目录: $BACKUP_DIR"
    fi
}

# 检测系统信息
detect_system_info() {
    local mem_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local mem_mb=$((mem_kb / 1024))
    local kernel_version=$(uname -r)
    
    log_message "INFO" "系统内存: ${mem_mb}MB"
    log_message "INFO" "内核版本: $kernel_version"
    
    echo -e "\n[系统检测结果]"
    echo "  内存: ${mem_mb}MB"
    echo "  内核: $kernel_version"
    
    # 建议profile
    if [[ $mem_mb -lt 1024 ]]; then
        echo -e "  建议使用: --profile=lite (检测到内存 < 1GB)"
    elif [[ $mem_mb -lt 2048 ]]; then
        echo -e "  建议使用: --profile=balanced (检测到内存 1-2GB)"
    else
        echo -e "  建议使用: --profile=performance (检测到内存 > 2GB)"
    fi
    
    # 检查BBR支持
    if kernel_version_ge "4.9"; then
        echo -e "  ✓ 内核支持BBR拥塞控制"
    else
        echo -e "  ⚠ 内核版本过低，不支持BBR拥塞控制"
    fi
    
    # 检查当前是否已有优化配置
    if grep -q "网络性能优化" /etc/sysctl.conf 2>/dev/null; then
        echo -e "  ⚠ 检测到已有网络优化配置"
    fi
}

# 内核版本比较
kernel_version_ge() {
    local required=$1
    local current=$(uname -r | cut -d. -f1-2)
    
    # 简单的版本比较
    local required_major=${required%.*}
    local required_minor=${required#*.}
    local current_major=${current%.*}
    local current_minor=${current#*.}
    
    if [[ $current_major -gt $required_major ]]; then
        return 0
    elif [[ $current_major -eq $required_major ]] && [[ $current_minor -ge $required_minor ]]; then
        return 0
    else
        return 1
    fi
}

# 备份当前配置
backup_config() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_file="$BACKUP_DIR/sysctl.conf.backup.$timestamp"
    
    if [[ -f /etc/sysctl.conf ]]; then
        cp /etc/sysctl.conf "$backup_file"
        log_message "INFO" "配置已备份到: $backup_file"
    else
        log_message "WARNING" "/etc/sysctl.conf 不存在，创建空白配置文件"
        touch /etc/sysctl.conf
    fi
    
    # 同时备份当前运行时配置
    sysctl -a > "$BACKUP_DIR/sysctl.runtime.$timestamp" 2>/dev/null || true
    log_message "INFO" "运行时配置已备份"
}

# 显示单个参数
show_param() {
    local param=$1
    local value
    value=$(sysctl -n "$param" 2>/dev/null) || value="未设置"
    printf "  %-35s = %s\n" "$param" "$value"
}

# 显示当前网络配置
show_current_config() {
    echo "========== 当前网络配置 =========="
    
    echo -e "\n[TCP缓冲区设置]"
    show_param "net.ipv4.tcp_rmem"
    show_param "net.ipv4.tcp_wmem"
    show_param "net.core.rmem_max"
    show_param "net.core.wmem_max"
    
    echo -e "\n[网络队列设置]"
    show_param "net.core.netdev_max_backlog"
    show_param "net.core.somaxconn"
    show_param "net.ipv4.tcp_max_syn_backlog"
    
    echo -e "\n[TCP高级特性]"
    show_param "net.ipv4.tcp_congestion_control"
    show_param "net.core.default_qdisc"
    show_param "net.ipv4.tcp_fastopen"
    show_param "net.ipv4.tcp_tw_reuse"
    show_param "net.ipv4.ip_forward"
    
    echo -e "\n[连接跟踪]"
    show_param "net.netfilter.nf_conntrack_max"
    
    echo -e "\n[当前TCP连接统计]"
    ss -s | grep -E "TCP:|TIME-WAIT" || true
}

# 生成基础优化配置
generate_base_config() {
    cat << EOF

# ===== 网络性能优化配置 =====
# 生成时间: $(date)
# Profile: $PROFILE
# 应用参数: NAT=$ENABLE_NAT, Gateway=$ENABLE_GATEWAY, BBR=$ENABLE_BBR, FastOpen=$ENABLE_FASTOPEN

# --- 文件系统优化 ---
fs.file-max = 2097152

# --- 端口范围 ---
net.ipv4.ip_local_port_range = 1024 65535

# --- 基础安全设置 ---
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# --- TCP连接管理 ---
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_max_tw_buckets = 200000
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 30

# --- TCP基础特性 ---
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fack = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_retries2 = 5

# --- UDP优化 ---
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192

EOF
}

# LITE Profile - 内存受限型 (<1G内存)
generate_lite_profile() {
    cat << EOF

# --- LITE Profile (<1G内存) ---
# TCP缓冲区 (8MB最大)
net.ipv4.tcp_rmem = 4096 262144 8388608
net.ipv4.tcp_wmem = 4096 262144 8388608
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
net.core.rmem_default = 262144
net.core.wmem_default = 262144

# 网络队列 (较小)
net.core.netdev_max_backlog = 2048
net.core.somaxconn = 2048
net.ipv4.tcp_max_syn_backlog = 2048

# 连接跟踪
net.netfilter.nf_conntrack_max = 500000
net.ipv4.tcp_max_orphans = 1638400

# TCP内存管理
net.ipv4.tcp_mem = 393216 524288 786432

EOF
}

# BALANCED Profile - 均衡型 (1-2G内存)
generate_balanced_profile() {
    cat << EOF

# --- BALANCED Profile (1-2G内存) ---
# TCP缓冲区 (20MB最大)
net.ipv4.tcp_rmem = 4096 524288 20971520
net.ipv4.tcp_wmem = 4096 524288 20971520
net.core.rmem_max = 20971520
net.core.wmem_max = 20971520
net.core.rmem_default = 524288
net.core.wmem_default = 524288

# 网络队列 (中等)
net.core.netdev_max_backlog = 4096
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 4096

# 连接跟踪
net.netfilter.nf_conntrack_max = 1000000
net.ipv4.tcp_max_orphans = 3276800

# TCP内存管理
net.ipv4.tcp_mem = 786432 1048576 1572864

EOF
}

# PERFORMANCE Profile - 性能型 (2G+内存)
generate_performance_profile() {
    cat << EOF

# --- PERFORMANCE Profile (2G+内存) ---
# TCP缓冲区 (32MB最大)
net.ipv4.tcp_rmem = 4096 1048576 33554432
net.ipv4.tcp_wmem = 4096 1048576 33554432
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576

# 网络队列 (大)
net.core.netdev_max_backlog = 8192
net.core.somaxconn = 8192
net.ipv4.tcp_max_syn_backlog = 8192

# 连接跟踪
net.netfilter.nf_conntrack_max = 2000000
net.ipv4.tcp_max_orphans = 6553600

# TCP内存管理
net.ipv4.tcp_mem = 1572864 2097152 3145728

EOF
}

# 生成Profile特定配置
generate_profile_config() {
    case "$PROFILE" in
        "lite")
            generate_lite_profile
            ;;
        "balanced")
            generate_balanced_profile
            ;;
        "performance")
            generate_performance_profile
            ;;
        *)
            die "未知的profile: $PROFILE"
            ;;
    esac
}

# 生成角色特定配置
generate_role_config() {
    if [[ "$ENABLE_NAT" == "true" ]]; then
        cat << EOF

# --- NAT服务器优化 ---
net.ipv4.tcp_tw_reuse = 0
net.netfilter.nf_conntrack_tcp_timeout_established = 7200
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 60

EOF
        log_message "INFO" "应用NAT优化: 禁用tw_reuse，调整连接跟踪超时" >&2
    else
        cat << EOF

# --- 非NAT服务器优化 ---
net.ipv4.tcp_tw_reuse = 1
net.netfilter.nf_conntrack_tcp_timeout_established = 86400
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 120

EOF
    fi
    
    if [[ "$ENABLE_GATEWAY" == "true" ]]; then
        cat << EOF

# --- 网关服务器优化 ---
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 60
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 120

EOF
        log_message "INFO" "应用网关优化: 启用IP转发" >&2
    fi
}

# 生成可选特性配置
generate_optional_config() {
    if [[ "$ENABLE_BBR" == "true" ]]; then
        if kernel_version_ge "4.9"; then
            cat << EOF

# --- BBR拥塞控制 ---
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

EOF
            log_message "INFO" "启用BBR拥塞控制"
        else
            log_message "WARNING" "内核版本过低，跳过BBR配置"
        fi
    fi
    
    if [[ "$ENABLE_FASTOPEN" == "true" ]]; then
        cat << EOF

# --- TCP Fast Open ---
net.ipv4.tcp_fastopen = 3

EOF
        log_message "INFO" "启用TCP Fast Open"
    fi
}

# 生成完整配置
generate_full_config() {
    {
        generate_base_config
        generate_profile_config
        generate_role_config
        generate_optional_config
        echo ""
        echo "# 配置生成完成: $(date)"
    } > /tmp/sysctl_new.conf
}

# 清理旧的优化配置
clean_old_config() {
    # 移除旧的网络优化配置块
    sed -i '/# ===== 网络性能优化/,/# 配置生成完成:/d' /etc/sysctl.conf 2>/dev/null || true
    log_message "INFO" "已清理旧的优化配置"
}

# 应用配置
apply_config() {
    log_message "INFO" "开始应用网络优化配置..."
    
    # 备份现有配置
    backup_config
    
    # 生成新配置
    generate_full_config
    
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "========== 预览模式: 将要应用的配置 =========="
        cat /tmp/sysctl_new.conf
        echo "=========================================="
        echo "预览完成。使用 --apply 来实际应用配置。"
        return 0
    fi
    
    # 清理旧配置
    clean_old_config
    
    # 追加新配置
    cat /tmp/sysctl_new.conf >> /etc/sysctl.conf
    
    # 应用配置
    if safe_execute "sysctl -p /etc/sysctl.conf" "应用网络配置" "false"; then
        log_message "SUCCESS" "网络优化配置应用成功"
        echo "优化完成! Profile: $PROFILE"
        
        # 显示关键参数
        echo -e "\n[关键配置]"
        show_param "net.ipv4.tcp_rmem"
        show_param "net.ipv4.tcp_wmem"
        show_param "net.core.somaxconn"
        
        if [[ "$ENABLE_NAT" == "true" ]]; then
            show_param "net.ipv4.tcp_tw_reuse"
        fi
        
        if [[ "$ENABLE_GATEWAY" == "true" ]]; then
            show_param "net.ipv4.ip_forward"
        fi
        
        if [[ "$ENABLE_BBR" == "true" ]] && kernel_version_ge "4.9"; then
            show_param "net.ipv4.tcp_congestion_control"
        fi
    else
        die "配置应用失败，请检查配置文件" 1
    fi
    
    # 清理临时文件
    TMP_FILES="$TMP_FILES /tmp/sysctl_new.conf"
}

# 恢复备份
restore_backup() {
    echo "可用的备份文件:"
    ls -la "$BACKUP_DIR"/sysctl.conf.backup.* 2>/dev/null | head -10 || {
        echo "没有找到备份文件"
        return 1
    }
    
    echo -e "\n请输入要恢复的完整备份文件路径:"
    read -r backup_file
    
    if [[ -f "$backup_file" ]]; then
        cp "$backup_file" /etc/sysctl.conf
        if safe_execute "sysctl -p /etc/sysctl.conf" "恢复配置" "false"; then
            log_message "SUCCESS" "从备份恢复成功: $backup_file"
        else
            die "恢复失败，配置文件可能有问题" 1
        fi
    else
        log_message "ERROR" "备份文件不存在: $backup_file"
        return 1
    fi
}

# 性能测试和监控建议
show_test_suggestions() {
    echo "========== 性能测试和监控建议 =========="
    
    echo -e "\n[吞吐量测试]"
    echo "  # iperf3测试"
    echo "  服务端: iperf3 -s -p 5201"
    echo "  客户端: iperf3 -c <server_ip> -t 30 -P 4"
    
    echo -e "\n[延迟测试]"
    echo "  # 基础延迟"
    echo "  ping -c 100 <target_ip>"
    echo "  # 路由追踪"
    echo "  mtr -n -c 50 <target_ip>"
    
    echo -e "\n[连接状态监控]"
    echo "  # socket统计"
    echo "  ss -s"
    echo "  # TIME_WAIT连接数"
    echo "  ss -tan | grep TIME-WAIT | wc -l"
    echo "  # 连接状态分布"
    echo "  ss -tan | awk 'NR>1{print \$1}' | sort | uniq -c"
    
    echo -e "\n[缓冲区使用监控]"
    echo "  # socket内存使用"
    echo "  ss -tm | grep skmem"
    echo "  # TCP内存统计"
    echo "  cat /proc/net/sockstat"
    echo "  # 当前TCP内存使用"
    echo "  cat /proc/sys/net/ipv4/tcp_mem"
    
    echo -e "\n[系统负载监控]"
    echo "  # 网络接口统计"
    echo "  cat /proc/net/dev"
    echo "  # 中断统计"
    echo "  cat /proc/interrupts | grep eth"
    echo "  # 网络软中断"
    echo "  cat /proc/softirqs | grep NET"
}

# 诊断当前网络状态
diagnose_network() {
    echo "========== 网络状态诊断 =========="
    
    # TCP连接统计
    echo -e "\n[TCP连接统计]"
    ss -s | grep -E "TCP:|TIME-WAIT"
    
    # 缓冲区使用分析
    echo -e "\n[缓冲区使用TOP10]"
    ss -tm 2>/dev/null | grep skmem | head -10 || echo "无活跃连接"
    
    # 队列状态
    echo -e "\n[网络队列状态]"
    local main_interface
    main_interface=$(ip route | grep default | awk '{print $5}' | head -1)
    if [[ -n "$main_interface" ]]; then
        echo "主网卡: $main_interface"
        ethtool -S "$main_interface" 2>/dev/null | grep -E "(rx_|tx_).*drop" | head -5 || echo "无丢包统计"
    fi
    
    # 连接跟踪使用率
    if [[ -f /proc/sys/net/netfilter/nf_conntrack_count ]]; then
        local count max
        count=$(cat /proc/sys/net/netfilter/nf_conntrack_count)
        max=$(cat /proc/sys/net/netfilter/nf_conntrack_max)
        local usage=$((count * 100 / max))
        echo -e "\n[连接跟踪使用率]"
        echo "  当前: $count / $max ($usage%)"
        if [[ $usage -gt 80 ]]; then
            echo "  ⚠️  警告: 连接跟踪表使用率过高"
        fi
    fi
}

# 显示使用帮助
show_help() {
    cat << EOF
网络性能调优脚本 v2.0

用法: $0 [选项]

主要参数:
  --apply              应用优化配置（需要root权限）
  --profile=<type>     选择预设配置类型
                       lite        - 内存受限型 (<1G内存, 8MB缓冲区)
                       balanced    - 均衡型 (1-2G内存, 20MB缓冲区)
                       performance - 性能型 (2G+内存, 32MB缓冲区)

角色修饰符（可组合）:
  --nat                NAT服务器模式（禁用tw_reuse）
  --gateway            网关模式（启用IP转发）

可选优化:
  --enable-bbr         启用BBR拥塞控制（需要内核4.9+）
  --enable-fastopen    启用TCP Fast Open

其他选项:
  --dry-run           预览模式（显示将要应用的配置）
  --show              显示当前网络配置
  --diagnose          诊断当前网络状态
  --test              显示性能测试建议
  --restore           恢复备份配置
  --detect            检测系统信息并给出建议
  --help              显示此帮助信息

使用示例:
  # 检测系统并获得建议
  $0 --detect
  
  # NAT专线（512M内存）
  $0 --apply --profile=lite --nat --gateway
  
  # 独立IP专线（1-2G内存）
  $0 --apply --profile=balanced --gateway --enable-bbr
  
  # 高性能VPS（2G+内存）
  $0 --apply --profile=performance --gateway --enable-bbr
  
  # 预览配置
  $0 --dry-run --profile=balanced --nat
  
  # 显示当前配置
  $0 --show
  
  # 恢复备份
  $0 --restore

EOF
}

# 主交互菜单
main_menu() {
    while true; do
        clear
        echo "========== 网络性能调优工具 v2.0 =========="
        echo "1. 检测系统信息并获得建议"
        echo "2. 显示当前网络配置"
        echo "3. 诊断网络状态"
        echo "4. 应用优化配置（需要输入参数）"
        echo "5. 恢复备份配置"
        echo "6. 显示性能测试建议"
        echo "7. 显示帮助信息"
        echo "8. 退出"
        echo -n "请选择操作 [1-8]: "
        read -r choice
        
        case $choice in
            1)
                detect_system_info
                ;;
            2)
                show_current_config
                ;;
            3)
                diagnose_network
                ;;
            4)
                echo "提示: 请直接使用命令行参数，例如:"
                echo "$0 --apply --profile=balanced --gateway"
                echo "使用 --help 查看完整参数说明"
                ;;
            5)
                check_root
                restore_backup
                ;;
            6)
                show_test_suggestions
                ;;
            7)
                show_help
                ;;
            8)
                echo "退出"
                exit 0
                ;;
            *)
                echo "无效选择"
                ;;
        esac
        
        echo -e "\n按Enter键继续..."
        read -r
    done
}

# 参数解析
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --apply)
                APPLY_CONFIG=true
                shift
                ;;
            --profile=*)
                PROFILE="${1#*=}"
                shift
                ;;
            --nat)
                ENABLE_NAT=true
                shift
                ;;
            --gateway)
                ENABLE_GATEWAY=true
                shift
                ;;
            --enable-bbr)
                ENABLE_BBR=true
                shift
                ;;
            --enable-fastopen)
                ENABLE_FASTOPEN=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --show)
                show_current_config
                exit 0
                ;;
            --diagnose)
                diagnose_network
                exit 0
                ;;
            --test)
                show_test_suggestions
                exit 0
                ;;
            --restore)
                check_root
                restore_backup
                exit 0
                ;;
            --detect)
                detect_system_info
                exit 0
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                die "未知参数: $1。使用 --help 查看帮助"
                ;;
        esac
    done
}

# 验证参数
validate_arguments() {
    # 检查profile是否指定
    if [[ "$APPLY_CONFIG" == "true" || "$DRY_RUN" == "true" ]]; then
        if [[ -z "$PROFILE" ]]; then
            die "必须指定 --profile 参数。可选值: lite, balanced, performance"
        fi
        
        # 验证profile值
        case "$PROFILE" in
            "lite"|"balanced"|"performance")
                ;;
            *)
                die "无效的profile: $PROFILE。可选值: lite, balanced, performance"
                ;;
        esac
    fi
    
    # 检查BBR内核支持
    if [[ "$ENABLE_BBR" == "true" ]]; then
        if ! kernel_version_ge "4.9"; then
            log_message "WARNING" "内核版本过低，BBR可能不支持"
        fi
    fi
    
    # NAT和tw_reuse冲突检查
    if [[ "$ENABLE_NAT" == "true" ]]; then
        log_message "INFO" "NAT模式: 将禁用tcp_tw_reuse以避免连接问题"
    fi
}

# 主函数
main() {
    # 初始化
    ensure_backup_dir
    
    # 解析参数
    parse_arguments "$@"
    
    # 如果没有参数，显示交互菜单
    if [[ $# -eq 0 ]]; then
        main_menu
        return 0
    fi
    
    # 验证参数
    validate_arguments
    
    # 执行配置应用
    if [[ "$APPLY_CONFIG" == "true" || "$DRY_RUN" == "true" ]]; then
        if [[ "$APPLY_CONFIG" == "true" ]]; then
            check_root
        fi
        apply_config
    fi
}

# 启动脚本
main "$@"