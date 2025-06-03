#!/bin/bash

# 防火墙快速设置脚本
# 用于快速配置常见的防火墙规则

set -euo pipefail

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${GREEN}[信息]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[警告]${NC} $1"
}

log_error() {
    echo -e "${RED}[错误]${NC} $1"
}

# 检查root权限
check_root() {
    if [ "$(id -u)" != "0" ]; then
        log_error "此脚本需要root权限运行"
        exit 1
    fi
}

# 显示当前iptables规则
show_rules() {
    echo "===== 当前防火墙规则 ====="
    echo "=== INPUT链 ==="
    iptables -L INPUT -n -v --line-numbers
    echo ""
    echo "=== OUTPUT链 ==="
    iptables -L OUTPUT -n -v --line-numbers
    echo ""
    echo "=== FORWARD链 ==="
    iptables -L FORWARD -n -v --line-numbers
}

# 基础防火墙设置
basic_setup() {
    log_info "设置基础防火墙规则..."
    
    # 清空现有规则
    iptables -F
    iptables -X
    
    # 设置默认策略
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    
    # 允许本地回环
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    
    # 允许已建立的连接
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    log_info "基础规则设置完成"
}

# 设置SSH白名单
setup_ssh_whitelist() {
    read -p "请输入SSH端口 (默认22): " ssh_port
    ssh_port=${ssh_port:-22}
    
    read -p "请输入允许的IP地址（多个IP用空格分隔）: " ips
    
    if [ -z "$ips" ]; then
        log_error "未输入IP地址"
        return
    fi
    
    # 删除现有SSH规则
    iptables -D INPUT -p tcp --dport "$ssh_port" -j ACCEPT 2>/dev/null || true
    
    # 为每个IP添加规则
    for ip in $ips; do
        if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
            iptables -A INPUT -s "$ip" -p tcp --dport "$ssh_port" -j ACCEPT
            log_info "已允许 $ip 访问SSH端口 $ssh_port"
        else
            log_warn "无效的IP格式: $ip"
        fi
    done
    
    # 拒绝其他SSH访问
    iptables -A INPUT -p tcp --dport "$ssh_port" -j DROP
    log_info "已拒绝白名单外的SSH访问"
}

# 禁用/启用ICMP
toggle_icmp() {
    echo "1) 禁用ICMP（禁止ping）"
    echo "2) 启用ICMP（允许ping）"
    read -p "请选择: " choice
    
    case $choice in
        1)
            iptables -D INPUT -p icmp -j ACCEPT 2>/dev/null || true
            iptables -A INPUT -p icmp -j DROP
            log_info "已禁用ICMP"
            ;;
        2)
            iptables -D INPUT -p icmp -j DROP 2>/dev/null || true
            iptables -A INPUT -p icmp -j ACCEPT
            log_info "已启用ICMP"
            ;;
        *)
            log_error "无效选择"
            ;;
    esac
}

# 保护Web端口
protect_web_ports() {
    log_info "配置Web端口保护..."
    
    # 删除可能存在的旧规则
    iptables -D INPUT -p tcp --dport 80 -j DROP 2>/dev/null || true
    iptables -D INPUT -p tcp --dport 443 -j DROP 2>/dev/null || true
    
    # 允许本地访问
    iptables -A INPUT -p tcp --dport 80 -s 127.0.0.1 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -s 127.0.0.1 -j ACCEPT
    
    # 允许内网访问
    for subnet in "10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16"; do
        iptables -A INPUT -p tcp --dport 80 -s "$subnet" -j ACCEPT
        iptables -A INPUT -p tcp --dport 443 -s "$subnet" -j ACCEPT
    done
    
    # 拒绝公网访问
    iptables -A INPUT -p tcp --dport 80 -j DROP
    iptables -A INPUT -p tcp --dport 443 -j DROP
    
    log_info "Web端口保护配置完成（仅允许本地和内网访问）"
}

# 保存规则
save_rules() {
    if [ -f /etc/debian_version ]; then
        # Debian/Ubuntu
        if ! dpkg -l | grep -q iptables-persistent; then
            log_info "安装iptables-persistent..."
            DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent
        fi
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4
        ip6tables-save > /etc/iptables/rules.v6
    elif [ -f /etc/redhat-release ]; then
        # RHEL/CentOS
        iptables-save > /etc/sysconfig/iptables
        if systemctl is-enabled iptables &>/dev/null; then
            systemctl restart iptables
        fi
    fi
    
    log_info "防火墙规则已保存"
}

# 主菜单
main_menu() {
    while true; do
        echo ""
        echo "===== 防火墙管理菜单 ====="
        echo "1) 显示当前规则"
        echo "2) 设置基础防火墙"
        echo "3) 配置SSH白名单"
        echo "4) 切换ICMP（ping）"
        echo "5) 保护Web端口(80/443)"
        echo "6) 保存规则"
        echo "7) 清空所有规则"
        echo "0) 退出"
        echo ""
        read -p "请选择操作: " choice
        
        case $choice in
            1) show_rules ;;
            2) basic_setup ;;
            3) setup_ssh_whitelist ;;
            4) toggle_icmp ;;
            5) protect_web_ports ;;
            6) save_rules ;;
            7) 
                iptables -F
                iptables -X
                iptables -P INPUT ACCEPT
                iptables -P FORWARD ACCEPT
                iptables -P OUTPUT ACCEPT
                log_info "已清空所有规则"
                ;;
            0) 
                echo "退出程序"
                exit 0
                ;;
            *) log_error "无效选择" ;;
        esac
    done
}

# 主程序
check_root
log_info "防火墙管理工具启动"
main_menu