#!/bin/bash

# 通用防火墙配置脚本
# 处理 SSH、ICMP 等通用防火墙规则
# Version: 2.0.0

set -euo pipefail

# 脚本配置
readonly SCRIPT_VERSION="2.0.0"
readonly LOG_FILE="/var/log/firewall_config.log"
readonly DEFAULT_SSH_PORT="22"

# 脚本参数
SSH_PORT="$DEFAULT_SSH_PORT"
SSH_WHITELIST_IPS=""
ENABLE_SSH_WHITELIST="false"
DISABLE_ICMP="false"
ICMP_METHOD="iptables"  # iptables 或 sysctl
PING_WHITELIST_IPS=""
SAVE_RULES="false"

# 统一的日志函数（符合最佳实践）
log_message() {
    local level="${1:-INFO}"
    local message="${2:-}"
    local timestamp
    
    # 参数验证
    [ -z "$message" ] && { echo "[错误] 消息内容不能为空" >&2; return 1; }
    
    # 安全：过滤敏感信息
    if [[ "$message" =~ (ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp[0-9]+)[[:space:]]+[A-Za-z0-9+/]+=*|password.*=|token.*=|key.*= ]]; then
        message="[敏感信息已过滤]"
    fi
    
    # 统一时间戳格式
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # 级别标准化和输出
    case "${level^^}" in
        "ERROR"|"ERR")
            echo "[错误] $message" >&2
            ;;
        "WARNING"|"WARN")
            echo "[警告] $message"
            ;;
        "INFO")
            echo "[信息] $message"
            ;;
        "DEBUG")
            [ "${DEBUG:-}" = "1" ] && echo "[调试] $message"
            ;;
        "SUCCESS"|"OK")
            echo "[成功] $message"
            ;;
        *)
            echo "[日志] $message"
            ;;
    esac
    
    # 文件日志记录（如果定义了 LOG_FILE）
    if [ -n "${LOG_FILE:-}" ]; then
        # 安全创建日志目录
        local log_dir
        log_dir=$(dirname "$LOG_FILE")
        if [ ! -d "$log_dir" ]; then
            mkdir -p "$log_dir" 2>/dev/null || return 0
            chmod 750 "$log_dir" 2>/dev/null || true
        fi
        
        # 写入日志文件
        echo "[$timestamp][$level] $message" >> "$LOG_FILE" 2>/dev/null || true
        chmod 640 "$LOG_FILE" 2>/dev/null || true
        
        # 简单日志轮转（防止过大）
        if [ -f "$LOG_FILE" ] && [ "$(wc -l < "$LOG_FILE" 2>/dev/null || echo 0)" -gt 10000 ]; then
            tail -5000 "$LOG_FILE" > "${LOG_FILE}.tmp" 2>/dev/null && mv "${LOG_FILE}.tmp" "$LOG_FILE" 2>/dev/null
        fi
    fi
    
    # 系统日志记录（错误级别）
    [ "${level^^}" = "ERROR" ] && command -v logger >/dev/null 2>&1 && logger -t "$(basename "$0" .sh)" -p user.err "$message" 2>/dev/null || true
}

# 检查 root 权限
check_root() {
    if [ "$(id -u)" != "0" ]; then
        log_message "ERROR" "此脚本需要 root 权限运行"
        exit 1
    fi
}

# 检测操作系统类型
detect_os() {
    if [ -f /etc/debian_version ]; then
        echo "debian"
    elif [ -f /etc/redhat-release ]; then
        echo "redhat"
    elif [ -f /etc/os-release ]; then
        source /etc/os-release
        echo "$ID"
    else
        echo "unknown"
    fi
}

# 验证 IP 地址格式
validate_ip() {
    local ip="$1"
    local valid_ip_regex="^([0-9]{1,3}\.){3}[0-9]{1,3}$"
    local valid_cidr_regex="^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$"
    
    if [[ "$ip" =~ $valid_ip_regex ]]; then
        # 检查每个数字段是否在0-255范围内
        IFS='.' read -ra ADDR <<< "$ip"
        for i in "${ADDR[@]}"; do
            if [ "$i" -gt 255 ]; then
                return 1
            fi
        done
        return 0
    elif [[ "$ip" =~ $valid_cidr_regex ]]; then
        # 检查CIDR格式
        local network="${ip%/*}"
        local prefix="${ip#*/}"
        if validate_ip "$network" && [ "$prefix" -ge 0 ] && [ "$prefix" -le 32 ]; then
            return 0
        fi
    fi
    return 1
}

# 等待 apt 锁释放
wait_for_apt() {
    local os_type=$(detect_os)
    [ "$os_type" != "debian" ] && return 0
    
    local max_wait=900  # 15分钟
    local waited=0
    local check_interval=5
    local first_wait=true
    
    while true; do
        local locked=false
        
        # 检查各种 apt 锁文件和进程
        if fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || \
           fuser /var/lib/apt/lists/lock >/dev/null 2>&1 || \
           fuser /var/cache/apt/archives/lock >/dev/null 2>&1 || \
           pgrep -x apt-get >/dev/null || \
           pgrep -x apt >/dev/null || \
           pgrep -x dpkg >/dev/null || \
           pgrep -x unattended-upgr >/dev/null; then
            locked=true
        fi
        
        if [ "$locked" = "false" ]; then
            [ "$first_wait" = "false" ] && log_message "INFO" "apt 锁已释放"
            return 0
        fi
        
        if [ "$first_wait" = "true" ]; then
            log_message "INFO" "等待 apt 锁释放..."
            first_wait=false
        fi
        
        if [ $waited -ge $max_wait ]; then
            log_message "WARNING" "等待 apt 锁超时，将尝试继续"
            return 1
        fi
        
        sleep $check_interval
        waited=$((waited + check_interval))
        
        if [ $((waited % 60)) -eq 0 ]; then
            log_message "INFO" "已等待 $((waited / 60)) 分钟..."
        fi
    done
}

# 带重试机制的 apt 安装
apt_install_with_retry() {
    local packages="$1"
    local max_retries=${2:-3}
    local retry_delay=${3:-30}
    local retry_count=0
    
    local os_type=$(detect_os)
    [ "$os_type" != "debian" ] && return 0
    
    while [ $retry_count -lt $max_retries ]; do
        # 等待 apt 锁释放
        if ! wait_for_apt; then
            log_message "ERROR" "等待 apt 锁失败，重试 $((retry_count + 1))/$max_retries"
            ((retry_count++))
            if [ $retry_count -lt $max_retries ]; then
                sleep $retry_delay
                continue
            else
                return 1
            fi
        fi
        
        # 尝试安装
        log_message "INFO" "安装软件包: $packages (尝试 $((retry_count + 1))/$max_retries)"
        
        if DEBIAN_FRONTEND=noninteractive apt-get install -y $packages; then
            log_message "INFO" "软件包安装成功: $packages"
            return 0
        else
            ((retry_count++))
            if [ $retry_count -lt $max_retries ]; then
                log_message "WARNING" "安装失败，${retry_delay}秒后重试..."
                sleep $retry_delay
            else
                log_message "ERROR" "软件包安装最终失败: $packages"
                return 1
            fi
        fi
    done
    
    return 1
}

# 配置 SSH 端口防火墙规则
configure_ssh_rules() {
    log_message "INFO" "配置 SSH 防火墙规则 (端口: $SSH_PORT)..."
    
    if [ "$ENABLE_SSH_WHITELIST" = "true" ] && [ -n "$SSH_WHITELIST_IPS" ]; then
        log_message "INFO" "配置 SSH 白名单模式..."
        
        # 清理现有 SSH 规则
        while iptables -L INPUT -n --line-numbers | grep "tcp dpt:$SSH_PORT" | head -1 | awk '{print $1}' | xargs -r iptables -D INPUT 2>/dev/null; do :; done
        
        # 添加白名单规则
        IFS=',' read -ra IPS <<< "$SSH_WHITELIST_IPS"
        for ip in "${IPS[@]}"; do
            ip=$(echo "$ip" | xargs)  # 去除空格
            if validate_ip "$ip"; then
                iptables -A INPUT -s "$ip" -p tcp --dport "$SSH_PORT" -j ACCEPT
                log_message "INFO" "添加 SSH 白名单: $ip"
            else
                log_message "WARNING" "跳过无效 IP: $ip"
            fi
        done
        
        # 拒绝其他 SSH 连接
        iptables -A INPUT -p tcp --dport "$SSH_PORT" -j DROP
        log_message "INFO" "SSH 白名单配置完成"
        
    else
        # 普通 SSH 规则（允许所有）
        if ! iptables -C INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT 2>/dev/null; then
            iptables -I INPUT 1 -p tcp --dport "$SSH_PORT" -j ACCEPT
            log_message "INFO" "添加 SSH 端口规则: $SSH_PORT"
        else
            log_message "INFO" "SSH 端口规则已存在: $SSH_PORT"
        fi
    fi
}

# 配置 ICMP 规则（仅禁止 ping 响应，保留服务器 ping 外部能力）
configure_icmp_rules() {
    if [ "$DISABLE_ICMP" != "true" ]; then
        log_message "INFO" "ICMP ping 响应保持默认配置"
        return
    fi

    log_message "INFO" "禁用 ICMP ping 响应 (方式: $ICMP_METHOD)..."

    case "$ICMP_METHOD" in
        sysctl)
            configure_icmp_sysctl
            ;;
        iptables)
            configure_icmp_iptables
            ;;
        *)
            log_message "ERROR" "未知的 ICMP 禁用方式: $ICMP_METHOD"
            exit 1
            ;;
    esac
}

# sysctl 方式禁用 ping（内核层，更高效）
configure_icmp_sysctl() {
    local sysctl_conf="/etc/sysctl.conf"
    local ipv4_param="net.ipv4.icmp_echo_ignore_all"

    # 立即生效
    if sysctl -w "${ipv4_param}=1" >/dev/null 2>&1; then
        log_message "INFO" "已通过 sysctl 禁用 IPv4 ping 响应"
    else
        log_message "ERROR" "sysctl 设置失败"
        return 1
    fi

    # 持久化配置
    if grep -q "^${ipv4_param}" "$sysctl_conf" 2>/dev/null; then
        sed -i "s/^${ipv4_param}.*/${ipv4_param} = 1/" "$sysctl_conf"
    else
        echo "${ipv4_param} = 1" >> "$sysctl_conf"
    fi
    log_message "INFO" "sysctl 配置已持久化到 $sysctl_conf"

    # IPv6 (如果支持)
    if [ -f /proc/sys/net/ipv6/icmp/echo_ignore_all ]; then
        sysctl -w net.ipv6.icmp.echo_ignore_all=1 >/dev/null 2>&1
        if grep -q "^net.ipv6.icmp.echo_ignore_all" "$sysctl_conf" 2>/dev/null; then
            sed -i "s/^net.ipv6.icmp.echo_ignore_all.*/net.ipv6.icmp.echo_ignore_all = 1/" "$sysctl_conf"
        else
            echo "net.ipv6.icmp.echo_ignore_all = 1" >> "$sysctl_conf"
        fi
        log_message "INFO" "已通过 sysctl 禁用 IPv6 ping 响应"
    fi
}

# iptables 方式禁用 ping（支持白名单，更灵活）
configure_icmp_iptables() {
    # 如果有白名单，先添加白名单规则
    if [ -n "$PING_WHITELIST_IPS" ]; then
        log_message "INFO" "配置 ping 白名单..."
        IFS=',' read -ra IPS <<< "$PING_WHITELIST_IPS"
        for ip in "${IPS[@]}"; do
            ip=$(echo "$ip" | xargs)
            if validate_ip "$ip"; then
                if ! iptables -C INPUT -s "$ip" -p icmp --icmp-type echo-request -j ACCEPT 2>/dev/null; then
                    iptables -I INPUT 1 -s "$ip" -p icmp --icmp-type echo-request -j ACCEPT
                    log_message "INFO" "添加 ping 白名单: $ip"
                fi
            else
                log_message "WARNING" "跳过无效 IP: $ip"
            fi
        done
    fi

    # IPv4: 禁止入站 ping 请求（echo-request）
    if ! iptables -C INPUT -p icmp --icmp-type echo-request -j DROP 2>/dev/null; then
        iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
        log_message "INFO" "已禁用 IPv4 ping 响应"
    fi

    # IPv6: 同样禁止入站 ping 请求
    if command -v ip6tables &>/dev/null; then
        if ! ip6tables -C INPUT -p icmpv6 --icmpv6-type echo-request -j DROP 2>/dev/null; then
            ip6tables -A INPUT -p icmpv6 --icmpv6-type echo-request -j DROP
            log_message "INFO" "已禁用 IPv6 ping 响应"
        fi
    fi
}

# 保存防火墙规则
save_firewall_rules() {
    log_message "INFO" "保存防火墙规则..."
    
    local os_type=$(detect_os)
    
    if [ "$os_type" = "debian" ]; then
        # 安装 iptables-persistent
        if ! dpkg -l | grep -q iptables-persistent; then
            if wait_for_apt; then
                echo 'iptables-persistent iptables-persistent/autosave_v4 boolean true' | debconf-set-selections
                echo 'iptables-persistent iptables-persistent/autosave_v6 boolean true' | debconf-set-selections
                
                if apt_install_with_retry "iptables-persistent"; then
                    log_message "INFO" "iptables-persistent 安装成功"
                else
                    log_message "WARNING" "iptables-persistent 安装失败，将尝试手动保存"
                fi
            else
                log_message "WARNING" "无法获取 apt 锁，跳过 iptables-persistent 安装"
            fi
        fi
        
        # 保存规则
        mkdir -p /etc/iptables 2>/dev/null
        if iptables-save > /etc/iptables/rules.v4 2>/dev/null; then
            log_message "INFO" "IPv4 防火墙规则已保存"
        else
            log_message "WARNING" "无法保存 IPv4 防火墙规则"
        fi
        
        # 保存 IPv6 规则（如果支持）
        if command -v ip6tables &>/dev/null && ip6tables -L -n &>/dev/null 2>&1; then
            if ip6tables-save > /etc/iptables/rules.v6 2>/dev/null; then
                log_message "INFO" "IPv6 防火墙规则已保存"
            else
                log_message "WARNING" "无法保存 IPv6 防火墙规则"
            fi
        fi
        
    elif [ "$os_type" = "redhat" ]; then
        # RHEL/CentOS
        if iptables-save > /etc/sysconfig/iptables 2>/dev/null; then
            log_message "INFO" "防火墙规则已保存"
        else
            log_message "WARNING" "无法保存防火墙规则"
        fi
    else
        log_message "WARNING" "未知的操作系统类型，请手动保存防火墙规则"
    fi
}

# 显示当前防火墙状态
show_status() {
    echo ""
    echo "========== 防火墙状态 =========="
    
    # SSH 规则
    echo "SSH 规则:"
    local ssh_rules=$(iptables -L INPUT -n --line-numbers | grep "tcp dpt:$SSH_PORT" | wc -l)
    echo "  端口 $SSH_PORT: $ssh_rules 条规则"
    
    if [ $ssh_rules -gt 0 ]; then
        echo "  详情:"
        iptables -L INPUT -n --line-numbers | grep "tcp dpt:$SSH_PORT" | head -5 | sed 's/^/    /'
    fi
    
    # ICMP 规则
    echo ""
    echo "ICMP 规则:"
    local icmp_drop=$(iptables -L INPUT -n | grep -c "ICMP.*DROP" 2>/dev/null || echo 0)
    if [ $icmp_drop -gt 0 ]; then
        echo "  状态: 已禁用"
    else
        echo "  状态: 允许"
    fi
    
    # 规则统计
    echo ""
    echo "规则统计:"
    local total_input=$(iptables -L INPUT -n | grep -c "^[0-9]" 2>/dev/null || echo 0)
    local total_output=$(iptables -L OUTPUT -n | grep -c "^[0-9]" 2>/dev/null || echo 0)
    echo "  INPUT 链: $total_input 条规则"
    echo "  OUTPUT 链: $total_output 条规则"
    
    echo "================================"
    echo ""
}

# 解析命令行参数
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --ssh-port)
                SSH_PORT="$2"
                if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [ "$SSH_PORT" -lt 1 ] || [ "$SSH_PORT" -gt 65535 ]; then
                    log_message "ERROR" "无效的 SSH 端口: $SSH_PORT"
                    exit 1
                fi
                shift 2
                ;;
            --ssh-whitelist)
                ENABLE_SSH_WHITELIST="true"
                SSH_WHITELIST_IPS="$2"
                shift 2
                ;;
            --disable-icmp)
                DISABLE_ICMP="true"
                shift
                ;;
            --icmp-method)
                ICMP_METHOD="$2"
                if [[ "$ICMP_METHOD" != "iptables" && "$ICMP_METHOD" != "sysctl" ]]; then
                    log_message "ERROR" "无效的 ICMP 方式: $ICMP_METHOD (可选: iptables, sysctl)"
                    exit 1
                fi
                shift 2
                ;;
            --ping-whitelist)
                PING_WHITELIST_IPS="$2"
                shift 2
                ;;
            --save-rules)
                SAVE_RULES="true"
                shift
                ;;
            --status)
                show_status
                exit 0
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                log_message "ERROR" "未知参数: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# 显示帮助信息
show_help() {
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  --ssh-port PORT           设置 SSH 端口 (默认: $DEFAULT_SSH_PORT)"
    echo "  --ssh-whitelist IPS       设置 SSH IP 白名单 (逗号分隔)"
    echo "  --disable-icmp            禁用 ping 响应"
    echo "  --icmp-method METHOD      禁用方式: iptables(默认,支持白名单) 或 sysctl(内核层,更高效)"
    echo "  --ping-whitelist IPS      ping 白名单 (仅 iptables 方式有效,逗号分隔)"
    echo "  --save-rules              保存防火墙规则"
    echo "  --status                  显示当前状态"
    echo "  --help                    显示此帮助信息"
    echo ""
    echo "示例:"
    echo "  $0 --ssh-port 2022                                  # 设置 SSH 端口"
    echo "  $0 --ssh-whitelist \"1.2.3.4,5.6.7.8\"                # 设置 SSH 白名单"
    echo "  $0 --disable-icmp                                   # 禁用 ping (iptables 方式)"
    echo "  $0 --disable-icmp --icmp-method sysctl              # 禁用 ping (sysctl 方式,更高效)"
    echo "  $0 --disable-icmp --ping-whitelist \"10.0.0.1\"       # 禁用 ping 但允许特定 IP"
    echo "  $0 --save-rules                                     # 保存当前规则"
    echo "  $0 --status                                         # 查看状态"
    echo ""
    echo "版本: $SCRIPT_VERSION"
}

# 主函数
main() {
    check_root
    
    # 如果没有参数，显示帮助
    if [ $# -eq 0 ]; then
        show_help
        exit 1
    fi
    
    # 解析参数
    parse_args "$@"
    
    log_message "INFO" "开始配置防火墙..."
    
    # 配置 SSH 规则
    configure_ssh_rules
    
    # 配置 ICMP 规则
    configure_icmp_rules
    
    # 保存规则（如果指定）
    if [ "$SAVE_RULES" = "true" ]; then
        save_firewall_rules
    fi
    
    log_message "INFO" "防火墙配置完成"
    
    # 显示配置摘要
    echo ""
    echo "配置摘要:"
    echo "  SSH 端口: $SSH_PORT"
    [ "$ENABLE_SSH_WHITELIST" = "true" ] && echo "  SSH 白名单: 已启用"
    [ "$DISABLE_ICMP" = "true" ] && echo "  ICMP: 已禁用 ($ICMP_METHOD 方式)"
    [ "$SAVE_RULES" = "true" ] && echo "  规则保存: 已执行"
    echo ""
}

# 脚本入口
main "$@"