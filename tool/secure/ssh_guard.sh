#!/bin/bash

# SSH 端口 Rate Limit 防护脚本
# 使用 iptables recent 模块防暴力破解
# Version: 1.0.0

set -euo pipefail

readonly SCRIPT_VERSION="1.0.0"
readonly LOG_FILE="/var/log/ssh_guard.log"
readonly COMMENT_MARK="ssh-guard"

# 日志函数
log_message() {
    local level="${1:-INFO}"
    local message="${2:-}"
    local timestamp

    [ -z "$message" ] && { echo "[错误] 消息内容不能为空" >&2; return 1; }

    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    case "${level^^}" in
        "ERROR"|"ERR")  echo "[错误] $message" >&2 ;;
        "WARNING"|"WARN") echo "[警告] $message" ;;
        "INFO")         echo "[信息] $message" ;;
        "SUCCESS"|"OK") echo "[成功] $message" ;;
        *)              echo "[日志] $message" ;;
    esac

    if [ -n "${LOG_FILE:-}" ]; then
        local log_dir
        log_dir=$(dirname "$LOG_FILE")
        [ ! -d "$log_dir" ] && mkdir -p "$log_dir" 2>/dev/null && chmod 750 "$log_dir" 2>/dev/null || true
        echo "[$timestamp][$level] $message" >> "$LOG_FILE" 2>/dev/null || true
    fi
}

# 检查 root 权限
check_root() {
    if [ "$(id -u)" != "0" ]; then
        log_message "ERROR" "此脚本需要 root 权限运行"
        exit 1
    fi
}

# 保存防火墙规则
save_rules() {
    if [ -f /etc/debian_version ]; then
        mkdir -p /etc/iptables 2>/dev/null
        iptables-save > /etc/iptables/rules.v4 2>/dev/null && log_message "INFO" "规则已保存" || log_message "WARNING" "无法保存规则"
    elif [ -f /etc/redhat-release ]; then
        iptables-save > /etc/sysconfig/iptables 2>/dev/null && log_message "INFO" "规则已保存" || log_message "WARNING" "无法保存规则"
    fi
}

# 清理指定端口的所有 ssh-guard 规则
cleanup_port_rules() {
    local port="$1"
    local removed=0

    log_message "INFO" "清理端口 $port 的所有 iptables 规则..."

    # 清理带 ssh-guard 标记的规则
    while true; do
        local rule_num
        rule_num=$(iptables -L INPUT -n --line-numbers | grep "$COMMENT_MARK" | grep "dpt:${port}" | head -1 | awk '{print $1}')
        [ -z "$rule_num" ] && break
        iptables -D INPUT "$rule_num" 2>/dev/null || break
        ((removed++)) || true
    done

    # 也清理不带标记但匹配端口的 SSH 相关规则（旧规则可能没有 comment）
    while true; do
        local rule_num
        rule_num=$(iptables -L INPUT -n --line-numbers | grep "dpt:${port}" | grep -i "recent" | head -1 | awk '{print $1}')
        [ -z "$rule_num" ] && break
        iptables -D INPUT "$rule_num" 2>/dev/null || break
        ((removed++)) || true
    done

    if [ "$removed" -gt 0 ]; then
        log_message "SUCCESS" "已清理端口 $port 的 $removed 条规则"
        save_rules
    else
        log_message "INFO" "端口 $port 无需清理"
    fi
}

# 启用 SSH rate limit 防护
enable_protection() {
    local port="$1"

    log_message "INFO" "启用 SSH 端口 $port 的 rate limit 防护..."

    # 先清理该端口的旧规则
    cleanup_port_rules "$port"

    # 添加 rate limit 规则（同一 IP 60 秒内超过 5 次新连接 DROP）
    # 规则 1：记录新连接到 SSH_GUARD 列表
    iptables -A INPUT -p tcp --dport "$port" -m conntrack --ctstate NEW \
        -m recent --set --name SSH_GUARD \
        -m comment --comment "$COMMENT_MARK"

    # 规则 2：超过阈值则 DROP
    iptables -A INPUT -p tcp --dport "$port" -m conntrack --ctstate NEW \
        -m recent --update --seconds 60 --hitcount 6 --name SSH_GUARD \
        -j DROP \
        -m comment --comment "$COMMENT_MARK"

    save_rules

    log_message "SUCCESS" "SSH 端口 $port 的 rate limit 防护已启用（60秒/6次）"
}

# 禁用所有 ssh-guard 规则
disable_protection() {
    log_message "INFO" "禁用 SSH rate limit 防护..."

    local removed=0
    while true; do
        local rule_num
        rule_num=$(iptables -L INPUT -n --line-numbers | grep "$COMMENT_MARK" | head -1 | awk '{print $1}')
        [ -z "$rule_num" ] && break
        iptables -D INPUT "$rule_num" 2>/dev/null || break
        ((removed++)) || true
    done

    save_rules

    if [ "$removed" -gt 0 ]; then
        log_message "SUCCESS" "已移除 $removed 条 ssh-guard 规则"
    else
        log_message "INFO" "无 ssh-guard 规则需要移除"
    fi
}

# 显示当前 SSH 防护状态
show_status() {
    echo ""
    echo "========== SSH Guard 防护状态 =========="

    local rules
    rules=$(iptables -L INPUT -n --line-numbers 2>/dev/null | grep "$COMMENT_MARK" || true)

    if [ -n "$rules" ]; then
        local count
        count=$(echo "$rules" | wc -l | tr -d ' ')
        echo "状态: 已启用"
        echo "规则数: $count 条"
        echo ""
        echo "详细规则:"
        echo "$rules"
    else
        echo "状态: 未启用"
    fi

    echo "========================================="
    echo ""
}

# 显示帮助信息
show_help() {
    echo "用法: $0 [选项]"
    echo ""
    echo "SSH 端口 Rate Limit 防暴力破解工具"
    echo ""
    echo "选项:"
    echo "  --enable <端口>      启用指定端口的 rate limit 防护"
    echo "  --disable            移除所有 ssh-guard 规则"
    echo "  --cleanup <端口>     清理指定旧端口的所有 iptables 规则"
    echo "  --status             显示当前 SSH 防护状态"
    echo "  --help               显示此帮助信息"
    echo ""
    echo "示例:"
    echo "  $0 --enable 5002       # 启用端口 5002 的防护"
    echo "  $0 --cleanup 27732     # 清理旧端口 27732 的规则"
    echo "  $0 --disable           # 移除所有防护规则"
    echo "  $0 --status            # 查看当前状态"
    echo ""
    echo "防护策略: 同一 IP 60秒内超过 5 次新连接将被 DROP"
    echo ""
    echo "版本: $SCRIPT_VERSION"
}

# 主函数
main() {
    check_root

    case "${1:-}" in
        --enable)
            if [ -z "${2:-}" ]; then
                log_message "ERROR" "--enable 需要指定端口号"
                echo "用法: $0 --enable <端口>"
                exit 1
            fi
            if ! [[ "$2" =~ ^[0-9]+$ ]] || [ "$2" -lt 1 ] || [ "$2" -gt 65535 ]; then
                log_message "ERROR" "无效的端口号: $2"
                exit 1
            fi
            enable_protection "$2"
            ;;
        --disable)
            disable_protection
            ;;
        --cleanup)
            if [ -z "${2:-}" ]; then
                log_message "ERROR" "--cleanup 需要指定端口号"
                echo "用法: $0 --cleanup <端口>"
                exit 1
            fi
            if ! [[ "$2" =~ ^[0-9]+$ ]] || [ "$2" -lt 1 ] || [ "$2" -gt 65535 ]; then
                log_message "ERROR" "无效的端口号: $2"
                exit 1
            fi
            cleanup_port_rules "$2"
            ;;
        --status)
            show_status
            ;;
        --help)
            show_help
            ;;
        *)
            show_help
            exit 1
            ;;
    esac
}

main "$@"
