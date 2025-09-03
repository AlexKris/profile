#!/bin/bash

# Cloudflare IP 防火墙管理脚本
# 用于管理允许Cloudflare IP访问Web端口的防火墙规则

set -euo pipefail

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 配置
CF_IPV4_URL="https://www.cloudflare.com/ips-v4"
CF_IPV6_URL="https://www.cloudflare.com/ips-v6"
CHAIN_NAME="CLOUDFLARE"
LOG_FILE="/var/log/cloudflare_firewall.log"

# 日志函数
log_info() {
    echo -e "${GREEN}[信息]${NC} $1" | tee -a "$LOG_FILE"
}

log_warn() {
    echo -e "${YELLOW}[警告]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[错误]${NC} $1" | tee -a "$LOG_FILE"
}

# 检查root权限
check_root() {
    if [ "$(id -u)" != "0" ]; then
        log_error "此脚本需要root权限运行"
        exit 1
    fi
}

# 创建自定义链
create_chain() {
    # 创建IPv4链
    if ! iptables -L "$CHAIN_NAME" -n &>/dev/null 2>&1; then
        iptables -N "$CHAIN_NAME"
        log_info "创建IPv4链: $CHAIN_NAME"
    fi
    
    # 创建IPv6链
    if command -v ip6tables &>/dev/null; then
        if ! ip6tables -L "$CHAIN_NAME" -n &>/dev/null 2>&1; then
            ip6tables -N "$CHAIN_NAME"
            log_info "创建IPv6链: $CHAIN_NAME"
        fi
    fi
}

# 清空Cloudflare链
flush_chain() {
    log_info "清空现有Cloudflare规则..."
    
    # 清空IPv4链
    iptables -F "$CHAIN_NAME" 2>/dev/null || true
    
    # 清空IPv6链
    if command -v ip6tables &>/dev/null; then
        ip6tables -F "$CHAIN_NAME" 2>/dev/null || true
    fi
}

# 获取并添加Cloudflare IP
update_cloudflare_ips() {
    local ports="$1"
    
    log_info "获取最新的Cloudflare IP列表..."
    
    # 处理IPv4
    local temp_file="/tmp/cf_ips_v4_$$.txt"
    if curl -s --connect-timeout 10 --max-time 30 "$CF_IPV4_URL" -o "$temp_file"; then
        local count=0
        while IFS= read -r ip; do
            if [ -n "$ip" ] && [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
                for port in $ports; do
                    iptables -A "$CHAIN_NAME" -s "$ip" -p tcp --dport "$port" -j ACCEPT
                done
                ((count++))
            fi
        done < "$temp_file"
        log_info "添加了 $count 个Cloudflare IPv4地址"
        rm -f "$temp_file"
    else
        log_error "无法获取Cloudflare IPv4地址列表"
    fi
    
    # 处理IPv6
    if command -v ip6tables &>/dev/null; then
        temp_file="/tmp/cf_ips_v6_$$.txt"
        if curl -s --connect-timeout 10 --max-time 30 "$CF_IPV6_URL" -o "$temp_file"; then
            local count6=0
            while IFS= read -r ip; do
                if [ -n "$ip" ]; then
                    for port in $ports; do
                        ip6tables -A "$CHAIN_NAME" -s "$ip" -p tcp --dport "$port" -j ACCEPT 2>/dev/null && ((count6++))
                    done
                fi
            done < "$temp_file"
            log_info "添加了 $count6 个Cloudflare IPv6地址"
            rm -f "$temp_file"
        else
            log_error "无法获取Cloudflare IPv6地址列表"
        fi
    fi
}

# 将Cloudflare链插入到主链
link_chain() {
    local ports="$1"
    
    log_info "将Cloudflare链连接到INPUT链..."
    
    for port in $ports; do
        # 检查是否已存在跳转规则
        if ! iptables -C INPUT -p tcp --dport "$port" -j "$CHAIN_NAME" 2>/dev/null; then
            # 插入到INPUT链的开头（在DROP规则之前）
            iptables -I INPUT -p tcp --dport "$port" -j "$CHAIN_NAME"
            log_info "已为端口 $port 添加IPv4跳转规则"
        fi
        
        # IPv6
        if command -v ip6tables &>/dev/null; then
            if ! ip6tables -C INPUT -p tcp --dport "$port" -j "$CHAIN_NAME" 2>/dev/null; then
                ip6tables -I INPUT -p tcp --dport "$port" -j "$CHAIN_NAME"
                log_info "已为端口 $port 添加IPv6跳转规则"
            fi
        fi
    done
}

# 移除Cloudflare链的连接
unlink_chain() {
    log_info "移除Cloudflare链的连接..."
    
    # 移除所有指向CLOUDFLARE链的规则
    while iptables -D INPUT -j "$CHAIN_NAME" 2>/dev/null; do :; done
    
    if command -v ip6tables &>/dev/null; then
        while ip6tables -D INPUT -j "$CHAIN_NAME" 2>/dev/null; do :; done
    fi
}

# 显示当前Cloudflare规则
show_rules() {
    echo -e "${BLUE}===== Cloudflare防火墙规则 =====${NC}"
    echo -e "${BLUE}=== IPv4规则 ===${NC}"
    if iptables -L "$CHAIN_NAME" -n -v 2>/dev/null; then
        iptables -L "$CHAIN_NAME" -n -v --line-numbers
    else
        echo "链不存在"
    fi
    
    if command -v ip6tables &>/dev/null; then
        echo -e "${BLUE}=== IPv6规则 ===${NC}"
        if ip6tables -L "$CHAIN_NAME" -n -v 2>/dev/null; then
            ip6tables -L "$CHAIN_NAME" -n -v --line-numbers
        else
            echo "链不存在"
        fi
    fi
}

# 保存规则
save_rules() {
    log_info "保存防火墙规则..."
    
    if [ -f /etc/debian_version ]; then
        # Debian/Ubuntu
        if ! dpkg -l | grep -q iptables-persistent; then
            log_info "安装iptables-persistent..."
            DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent
        fi
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4
        if command -v ip6tables &>/dev/null; then
            ip6tables-save > /etc/iptables/rules.v6
        fi
    elif [ -f /etc/redhat-release ]; then
        # RHEL/CentOS
        iptables-save > /etc/sysconfig/iptables
        if command -v ip6tables &>/dev/null; then
            ip6tables-save > /etc/sysconfig/ip6tables
        fi
    fi
    
    log_info "规则已保存"
}

# 使用说明
usage() {
    echo "用法: $0 [命令] [选项]"
    echo ""
    echo "命令:"
    echo "  enable [端口]    - 启用Cloudflare IP访问指定端口（默认: 80 443）"
    echo "  disable          - 禁用Cloudflare IP访问"
    echo "  update [端口]    - 更新Cloudflare IP列表"
    echo "  show             - 显示当前规则"
    echo "  test             - 测试Cloudflare IP连通性"
    echo ""
    echo "示例:"
    echo "  $0 enable          # 允许Cloudflare访问80和443端口"
    echo "  $0 enable 443      # 只允许Cloudflare访问443端口"
    echo "  $0 enable \"80 443 8080\"  # 允许访问多个端口"
    echo "  $0 disable         # 移除所有Cloudflare规则"
    echo "  $0 update          # 更新IP列表（默认80 443）"
    echo "  $0 show            # 查看当前规则"
}

# 测试Cloudflare IP连通性
test_connectivity() {
    log_info "测试Cloudflare IP获取..."
    
    echo -e "${BLUE}测试IPv4地址获取:${NC}"
    if curl -s --connect-timeout 5 "$CF_IPV4_URL" | head -5; then
        echo -e "${GREEN}IPv4地址获取正常${NC}"
    else
        echo -e "${RED}IPv4地址获取失败${NC}"
    fi
    
    echo -e "\n${BLUE}测试IPv6地址获取:${NC}"
    if curl -s --connect-timeout 5 "$CF_IPV6_URL" | head -5; then
        echo -e "${GREEN}IPv6地址获取正常${NC}"
    else
        echo -e "${RED}IPv6地址获取失败${NC}"
    fi
}

# 主函数
main() {
    check_root
    
    case "${1:-}" in
        enable)
            ports="${2:-80 443}"
            create_chain
            flush_chain
            update_cloudflare_ips "$ports"
            link_chain "$ports"
            save_rules
            log_info "Cloudflare IP防火墙规则已启用"
            ;;
        disable)
            unlink_chain
            flush_chain
            iptables -X "$CHAIN_NAME" 2>/dev/null || true
            if command -v ip6tables &>/dev/null; then
                ip6tables -X "$CHAIN_NAME" 2>/dev/null || true
            fi
            save_rules
            log_info "Cloudflare IP防火墙规则已禁用"
            ;;
        update)
            ports="${2:-80 443}"
            create_chain
            flush_chain
            update_cloudflare_ips "$ports"
            save_rules
            log_info "Cloudflare IP列表已更新"
            ;;
        show)
            show_rules
            ;;
        test)
            test_connectivity
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

# 执行主函数
main "$@" 