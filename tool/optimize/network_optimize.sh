#!/bin/bash

# 网络性能调优脚本
# 用于Linux服务器的网络参数优化

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 检查是否为root用户
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}错误: 此脚本需要root权限运行${NC}"
        exit 1
    fi
}

# 备份当前配置
backup_config() {
    echo -e "${BLUE}备份当前sysctl配置...${NC}"
    if [ -f /etc/sysctl.conf ]; then
        cp /etc/sysctl.conf /etc/sysctl.conf.backup.$(date +%Y%m%d_%H%M%S)
        echo -e "${GREEN}备份完成${NC}"
    fi
}

# 显示当前网络配置
show_current_config() {
    echo -e "\n${BLUE}========== 当前网络配置 ==========${NC}"
    
    echo -e "\n${YELLOW}TCP缓冲区设置:${NC}"
    sysctl net.ipv4.tcp_rmem 2>/dev/null || echo "未设置"
    sysctl net.ipv4.tcp_wmem 2>/dev/null || echo "未设置"
    sysctl net.core.rmem_max 2>/dev/null || echo "未设置"
    sysctl net.core.wmem_max 2>/dev/null || echo "未设置"
    sysctl net.core.rmem_default 2>/dev/null || echo "未设置"
    sysctl net.core.wmem_default 2>/dev/null || echo "未设置"
    
    echo -e "\n${YELLOW}网络队列设置:${NC}"
    sysctl net.core.netdev_max_backlog 2>/dev/null || echo "未设置"
    sysctl net.core.somaxconn 2>/dev/null || echo "未设置"
    sysctl net.ipv4.tcp_max_syn_backlog 2>/dev/null || echo "未设置"
    
    echo -e "\n${YELLOW}TCP优化参数:${NC}"
    sysctl net.ipv4.tcp_congestion_control 2>/dev/null || echo "未设置"
    sysctl net.core.default_qdisc 2>/dev/null || echo "未设置"
    sysctl net.ipv4.tcp_fastopen 2>/dev/null || echo "未设置"
    sysctl net.ipv4.tcp_tw_reuse 2>/dev/null || echo "未设置"
    sysctl net.ipv4.tcp_fin_timeout 2>/dev/null || echo "未设置"
    
    echo -e "\n${YELLOW}当前网络接口MTU:${NC}"
    ip link show | grep -E "^[0-9]+:" | while read -r line; do
        iface=$(echo "$line" | cut -d: -f2 | tr -d ' ')
        if [[ "$iface" != "lo" ]]; then
            mtu=$(ip link show "$iface" | grep -oP 'mtu \K[0-9]+' | head -1)
            echo "  $iface: MTU=$mtu"
        fi
    done
}

# 应用基础优化
apply_basic_optimization() {
    echo -e "\n${BLUE}应用基础网络优化...${NC}"
    
    cat >> /etc/sysctl.conf << 'EOF'

# ===== 网络性能优化 =====
# 生成时间: $(date)

# --- 文件描述符限制 ---
fs.file-max = 6815744

# --- TCP/IP缓冲区优化 ---
# TCP接收缓冲区 (最小 默认 最大)
net.ipv4.tcp_rmem = 4096 87380 67108864
# TCP发送缓冲区 (最小 默认 最大)
net.ipv4.tcp_wmem = 4096 65536 67108864
# UDP缓冲区最小值
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
# 系统级别最大缓冲区
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
# 默认缓冲区大小
net.core.rmem_default = 262144
net.core.wmem_default = 262144

# --- 网络队列优化 ---
# 网络设备接收队列长度
net.core.netdev_max_backlog = 16384
# socket监听队列长度
net.core.somaxconn = 8192
# SYN队列长度
net.ipv4.tcp_max_syn_backlog = 8192

# --- TCP连接优化 ---
# TIME_WAIT套接字重用
net.ipv4.tcp_tw_reuse = 1
# FIN_WAIT2超时时间
net.ipv4.tcp_fin_timeout = 30
# TCP keepalive时间
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 30

# --- TCP高级特性 ---
# TCP拥塞控制算法 (bbr需要Linux 4.9+)
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
# TCP Fast Open (0=关闭, 3=双向开启)
net.ipv4.tcp_fastopen = 3
# TCP时间戳
net.ipv4.tcp_timestamps = 1
# TCP SACK
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fack = 1
# TCP窗口缩放
net.ipv4.tcp_window_scaling = 1
# TCP ECN
net.ipv4.tcp_ecn = 2
net.ipv4.tcp_ecn_fallback = 1

# --- 连接跟踪优化 ---
net.netfilter.nf_conntrack_max = 2000000
net.netfilter.nf_conntrack_tcp_timeout_established = 86400
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 120
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 60
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 120

# --- 端口范围 ---
net.ipv4.ip_local_port_range = 1024 65535

# --- 安全相关 ---
# SYN cookies (防止SYN攻击)
net.ipv4.tcp_syncookies = 1
# 反向路径过滤
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
# 忽略ICMP重定向
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# --- 其他优化 ---
# TCP内存压力模式
net.ipv4.tcp_mem = 786432 1048576 1572864
# TCP孤儿连接最大数量
net.ipv4.tcp_max_orphans = 3276800
# TCP失败重试次数
net.ipv4.tcp_retries2 = 5
# 开启TCP自动调节接收缓冲区
net.ipv4.tcp_moderate_rcvbuf = 1
# 禁用TCP度量缓存
net.ipv4.tcp_no_metrics_save = 1

EOF
    
    echo -e "${GREEN}基础优化配置已写入/etc/sysctl.conf${NC}"
}

# 应用高性能优化(适用于高负载服务器)
apply_high_performance() {
    echo -e "\n${BLUE}应用高性能优化配置...${NC}"
    
    cat >> /etc/sysctl.conf << 'EOF'

# ===== 高性能优化 (高负载服务器) =====

# 更大的缓冲区设置
net.ipv4.tcp_rmem = 4096 131072 134217728
net.ipv4.tcp_wmem = 4096 131072 134217728
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 524288
net.core.wmem_default = 524288

# 更大的队列
net.core.netdev_max_backlog = 32768
net.core.somaxconn = 32768
net.ipv4.tcp_max_syn_backlog = 16384

# 更激进的TIME_WAIT处理
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_tw_recycle = 0  # 注意:不推荐在NAT环境下开启

# 连接跟踪表更大
net.netfilter.nf_conntrack_max = 4000000
net.netfilter.nf_conntrack_buckets = 1000000

# TCP内存更大
net.ipv4.tcp_mem = 1572864 2097152 3145728

EOF
    
    echo -e "${GREEN}高性能优化配置已追加${NC}"
}

# 应用优化
apply_optimization() {
    local mode=$1
    
    backup_config
    
    # 清理旧的优化配置
    sed -i '/# ===== 网络性能优化 =====/,/# ===== 高性能优化/d' /etc/sysctl.conf 2>/dev/null || true
    sed -i '/# ===== 高性能优化/,$ d' /etc/sysctl.conf 2>/dev/null || true
    
    apply_basic_optimization
    
    if [ "$mode" = "high" ]; then
        apply_high_performance
    fi
    
    echo -e "\n${BLUE}应用新配置...${NC}"
    sysctl -p /etc/sysctl.conf
    
    echo -e "${GREEN}优化完成!${NC}"
}

# 恢复备份
restore_backup() {
    echo -e "\n${BLUE}可用的备份文件:${NC}"
    ls -la /etc/sysctl.conf.backup.* 2>/dev/null || {
        echo -e "${RED}没有找到备份文件${NC}"
        return 1
    }
    
    echo -e "\n请输入要恢复的备份文件名:"
    read -r backup_file
    
    if [ -f "$backup_file" ]; then
        cp "$backup_file" /etc/sysctl.conf
        sysctl -p /etc/sysctl.conf
        echo -e "${GREEN}恢复完成${NC}"
    else
        echo -e "${RED}文件不存在${NC}"
    fi
}

# 性能测试建议
show_test_suggestions() {
    echo -e "\n${BLUE}========== 性能测试建议 ==========${NC}"
    echo -e "${YELLOW}1. 网络吞吐量测试:${NC}"
    echo "   iperf3 -s  # 服务器端"
    echo "   iperf3 -c <server_ip> -t 30  # 客户端"
    
    echo -e "\n${YELLOW}2. 网络延迟测试:${NC}"
    echo "   ping -c 100 <target_ip>"
    echo "   mtr <target_ip>"
    
    echo -e "\n${YELLOW}3. TCP连接测试:${NC}"
    echo "   ss -s  # 查看socket统计"
    echo "   netstat -an | grep TIME_WAIT | wc -l  # TIME_WAIT连接数"
    
    echo -e "\n${YELLOW}4. 网络队列监控:${NC}"
    echo "   ss -ntu | awk '{print \$6}' | sort | uniq -c  # 连接状态统计"
    echo "   watch -n 1 'cat /proc/net/softnet_stat'  # 软中断统计"
    
    echo -e "\n${YELLOW}5. 缓冲区使用监控:${NC}"
    echo "   ss -m  # 查看socket内存使用"
    echo "   cat /proc/sys/net/ipv4/tcp_mem  # TCP内存使用"
}

# 主菜单
main_menu() {
    while true; do
        echo -e "\n${BLUE}========== 网络性能调优工具 ==========${NC}"
        echo "1. 显示当前网络配置"
        echo "2. 应用基础优化 (一般服务器)"
        echo "3. 应用高性能优化 (高负载服务器)"
        echo "4. 恢复备份配置"
        echo "5. 显示性能测试建议"
        echo "6. 退出"
        echo -e "${YELLOW}请选择操作 [1-6]:${NC} "
        read -r choice
        
        case $choice in
            1)
                show_current_config
                ;;
            2)
                check_root
                apply_optimization "basic"
                ;;
            3)
                check_root
                apply_optimization "high"
                ;;
            4)
                check_root
                restore_backup
                ;;
            5)
                show_test_suggestions
                ;;
            6)
                echo -e "${GREEN}退出${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}无效选择${NC}"
                ;;
        esac
    done
}

# 命令行参数处理
if [ $# -eq 0 ]; then
    main_menu
else
    case "$1" in
        --show)
            show_current_config
            ;;
        --basic)
            check_root
            apply_optimization "basic"
            ;;
        --high)
            check_root
            apply_optimization "high"
            ;;
        --test)
            show_test_suggestions
            ;;
        --help)
            echo "用法: $0 [选项]"
            echo "选项:"
            echo "  --show   显示当前配置"
            echo "  --basic  应用基础优化"
            echo "  --high   应用高性能优化"
            echo "  --test   显示测试建议"
            echo "  --help   显示帮助"
            echo ""
            echo "无参数运行进入交互菜单"
            ;;
        *)
            echo -e "${RED}未知参数: $1${NC}"
            echo "使用 --help 查看帮助"
            exit 1
            ;;
    esac
fi