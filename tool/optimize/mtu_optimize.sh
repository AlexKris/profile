#!/bin/bash

# MTU检测和优化脚本
# 用于检测最优MTU值并应用优化

set -e

# 颜色输出
CYAN='\033[0;36m'

# 默认值
DEFAULT_TARGET="8.8.8.8"
DEFAULT_INTERFACE=""
MIN_MTU=576
MAX_MTU=9000
COMMON_MTUS=(1500 1492 1480 1472 1468 1464 1460 1454 1400 9000 4000 2000)

# 获取默认网络接口
get_default_interface() {
    # 尝试从默认路由获取
    local iface=$(ip route | grep default | awk '{print $5}' | head -1)
    if [ -z "$iface" ]; then
        # 如果没有默认路由，获取第一个非lo接口
        iface=$(ip link show | grep -E "^[0-9]+:" | grep -v "lo:" | head -1 | cut -d: -f2 | tr -d ' ')
    fi
    echo "$iface"
}

# 显示当前MTU设置
show_current_mtu() {
    echo -e "\n========== 当前MTU设置 =========="
    ip link show | grep -E "^[0-9]+:" | while read -r line; do
        local iface=$(echo "$line" | cut -d: -f2 | tr -d ' ')
        if [[ "$iface" != "lo" ]]; then
            local mtu=$(ip link show "$iface" | grep -oP 'mtu \K[0-9]+' | head -1)
            local state=$(ip link show "$iface" | grep -oP 'state \K[A-Z]+' | head -1)
            printf "  %-15s MTU: %-6s 状态: %s\n" "$iface" "$mtu" "$state"
        fi
    done
    
    echo -e "\n========== 路由表MTU信息 =========="
    ip route show | grep -E "mtu|metric" | head -10 || echo "  无特殊MTU路由"
}

# 使用ping测试MTU
test_mtu_with_ping() {
    local target=$1
    local mtu=$2
    local interface=$3
    local packet_size=$((mtu - 28))  # 减去IP头(20字节)和ICMP头(8字节)
    
    if [ -n "$interface" ]; then
        # Linux平台使用-I指定接口
        ping -c 1 -W 1 -M do -s "$packet_size" -I "$interface" "$target" &>/dev/null
    else
        ping -c 1 -W 1 -M do -s "$packet_size" "$target" &>/dev/null
    fi
    return $?
}

# 二分查找最优MTU
find_optimal_mtu() {
    local target=$1
    local interface=$2
    local low=$MIN_MTU
    local high=$MAX_MTU
    local optimal_mtu=$MIN_MTU
    
    echo -e "\n开始MTU探测 (目标: $target)"
    echo "使用二分查找法..."
    
    # 首先测试几个常见值
    echo -e "\n${CYAN}测试常见MTU值:"
    for mtu in "${COMMON_MTUS[@]}"; do
        printf "  测试 MTU %4d ... " "$mtu"
        if test_mtu_with_ping "$target" "$mtu" "$interface"; then
            echo "成功"
            if [ "$mtu" -gt "$optimal_mtu" ]; then
                optimal_mtu=$mtu
                low=$mtu
            fi
        else
            echo "失败"
            if [ "$mtu" -lt "$high" ]; then
                high=$mtu
            fi
        fi
    done
    
    echo -e "\n${CYAN}精确查找最优值 (范围: $low - $high):"
    while [ $((high - low)) -gt 1 ]; do
        local mid=$(((low + high) / 2))
        printf "  测试 MTU %4d ... " "$mid"
        
        if test_mtu_with_ping "$target" "$mid" "$interface"; then
            echo "成功"
            low=$mid
            optimal_mtu=$mid
        else
            echo "失败"
            high=$mid
        fi
    done
    
    echo -e "\n最优MTU值: $optimal_mtu"
    return $optimal_mtu
}

# 路径MTU发现
path_mtu_discovery() {
    local target=$1
    echo -e "\n========== 路径MTU发现 =========="
    
    # 使用tracepath进行路径MTU发现
    if command -v tracepath &>/dev/null; then
        echo -e "${CYAN}使用tracepath探测到$target的路径MTU:"
        tracepath -n "$target" | tail -5
    else
        echo "tracepath未安装，使用ping探测"
        find_optimal_mtu "$target" ""
        local mtu=$?
        echo -e "探测到的路径MTU: $mtu"
    fi
}

# 测试不同MTU的性能
benchmark_mtu() {
    local interface=$1
    local target=$2
    local current_mtu=$(ip link show "$interface" | grep -oP 'mtu \K[0-9]+' | head -1)
    
    echo -e "\n========== MTU性能测试 =========="
    echo "接口: $interface, 目标: $target"
    echo "当前MTU: $current_mtu\n"
    
    local test_mtus=(1400 1450 1480 1492 1500)
    if [ "$current_mtu" -gt 1500 ]; then
        test_mtus+=(2000 4000 9000)
    fi
    
    echo "MTU  | 延迟(ms) | 丢包率 | 吞吐量评分"
    echo "-----|----------|--------|------------"
    
    for mtu in "${test_mtus[@]}"; do
        if [ "$mtu" -le "$MAX_MTU" ]; then
            # 临时设置MTU
            ip link set dev "$interface" mtu "$mtu" 2>/dev/null || continue
            sleep 1
            
            # 测试延迟和丢包率
            local ping_result=$(ping -c 10 -W 1 -i 0.2 "$target" 2>/dev/null | tail -2)
            local loss=$(echo "$ping_result" | grep -oP '\d+(?=% packet loss)' | head -1)
            local latency=$(echo "$ping_result" | grep -oP 'avg = [\d.]+/\K[\d.]+' | head -1)
            
            # 计算吞吐量评分 (MTU越大，开销越小)
            local overhead=$((28 * 100 / mtu))
            local throughput_score=$((100 - overhead))
            
            printf "%4d | %8s | %6s%% | %10d%%\n" \
                "$mtu" \
                "${latency:-N/A}" \
                "${loss:-100}" \
                "$throughput_score"
        fi
    done
    
    # 恢复原始MTU
    ip link set dev "$interface" mtu "$current_mtu"
    echo -e "\nMTU已恢复到: $current_mtu"
}

# 应用MTU设置
apply_mtu() {
    local interface=$1
    local mtu=$2
    
    echo -e "\n应用MTU设置"
    echo -e "接口: $interface"
    echo -e "新MTU: $mtu"
    
    # 检查是否需要root权限
    if [[ $EUID -ne 0 ]]; then
        echo "错误: 需要root权限来修改MTU"
        echo "请使用: sudo ip link set dev $interface mtu $mtu"
        return 1
    fi
    
    # 应用设置
    ip link set dev "$interface" mtu "$mtu"
    
    if [ $? -eq 0 ]; then
        echo "MTU设置成功"
        
        # 持久化配置建议
        echo -e "\n持久化配置建议:"
        echo -e "1. 对于NetworkManager管理的接口:"
        echo "   nmcli con mod <connection-name> 802-3-ethernet.mtu $mtu"
        echo -e "\n2. 对于传统网络配置(/etc/network/interfaces):"
        echo "   在接口配置中添加: mtu $mtu"
        echo -e "\n3. 对于systemd-networkd:"
        echo "   在.network文件中添加: MTUBytes=$mtu"
    else
        echo "MTU设置失败"
        return 1
    fi
}

# MTU问题诊断
diagnose_mtu_issues() {
    echo -e "\n========== MTU问题诊断 =========="
    
    echo -e "\n${CYAN}1. 检查MSS钳制:"
    iptables -t mangle -L FORWARD -n -v | grep -i "tcp.*mss" || echo "  未发现MSS钳制规则"
    
    echo -e "\n${CYAN}2. 检查PMTU黑洞:"
    local icmp_setting=$(sysctl net.ipv4.tcp_mtu_probing 2>/dev/null | cut -d= -f2 | tr -d ' ')
    case "$icmp_setting" in
        0) echo "  PMTU探测: 关闭 (可能存在黑洞问题)" ;;
        1) echo "  PMTU探测: 默认关闭" ;;
        2) echo "  PMTU探测: 始终开启 (推荐)" ;;
        *) echo "  PMTU探测: 未知状态" ;;
    esac
    
    echo -e "\n${CYAN}3. 检查ICMP过滤:"
    local icmp_ignore=$(sysctl net.ipv4.icmp_ignore_all 2>/dev/null | cut -d= -f2 | tr -d ' ')
    if [ "$icmp_ignore" = "1" ]; then
        echo -e "  警告: ICMP被忽略，可能影响PMTU发现"
    else
        echo "  ICMP正常处理"
    fi
    
    echo -e "\n${CYAN}4. 常见MTU问题症状:"
    echo "  - 小文件传输正常，大文件传输失败: MTU过大"
    echo "  - SSH能连接但传输卡住: MTU问题"
    echo "  - 网页部分加载: MTU或MSS问题"
    echo "  - VPN连接后速度慢: MTU需要调整"
    
    echo -e "\n${CYAN}5. 建议的MTU值:"
    echo "  - 以太网标准: 1500"
    echo "  - PPPoE: 1492"
    echo "  - VPN (IPSec): 1400-1420"
    echo "  - VPN (OpenVPN): 1400-1450"
    echo "  - IPv6隧道: 1280"
    echo "  - Jumbo帧: 9000"
}

# 生成MTU优化报告
generate_report() {
    local output_file="mtu_report_$(date +%Y%m%d_%H%M%S).txt"
    
    {
        echo "===== MTU优化报告 ====="
        echo "生成时间: $(date)"
        echo ""
        show_current_mtu
        echo ""
        diagnose_mtu_issues
    } > "$output_file"
    
    echo -e "\n报告已保存到: $output_file"
}

# 主菜单
main_menu() {
    while true; do
        echo -e "\n========== MTU检测和优化工具 =========="
        echo "1. 显示当前MTU设置"
        echo "2. 自动检测最优MTU"
        echo "3. 路径MTU发现"
        echo "4. MTU性能基准测试"
        echo "5. 手动设置MTU"
        echo "6. MTU问题诊断"
        echo "7. 生成优化报告"
        echo "8. 退出"
        echo "请选择操作 [1-8]: "
        read -r choice
        
        case $choice in
            1)
                show_current_mtu
                ;;
            2)
                echo "请输入目标地址 (默认: $DEFAULT_TARGET): "
                read -r target
                target=${target:-$DEFAULT_TARGET}
                
                DEFAULT_INTERFACE=$(get_default_interface)
                echo "请输入网络接口 (默认: $DEFAULT_INTERFACE): "
                read -r interface
                interface=${interface:-$DEFAULT_INTERFACE}
                
                find_optimal_mtu "$target" "$interface"
                ;;
            3)
                echo "请输入目标地址: "
                read -r target
                if [ -n "$target" ]; then
                    path_mtu_discovery "$target"
                fi
                ;;
            4)
                DEFAULT_INTERFACE=$(get_default_interface)
                echo "请输入网络接口 (默认: $DEFAULT_INTERFACE): "
                read -r interface
                interface=${interface:-$DEFAULT_INTERFACE}
                
                echo "请输入测试目标 (默认: $DEFAULT_TARGET): "
                read -r target
                target=${target:-$DEFAULT_TARGET}
                
                if [[ $EUID -ne 0 ]]; then
                    echo "性能测试需要root权限"
                else
                    benchmark_mtu "$interface" "$target"
                fi
                ;;
            5)
                DEFAULT_INTERFACE=$(get_default_interface)
                echo "请输入网络接口 (默认: $DEFAULT_INTERFACE): "
                read -r interface
                interface=${interface:-$DEFAULT_INTERFACE}
                
                echo "请输入MTU值: "
                read -r mtu
                if [ -n "$mtu" ]; then
                    apply_mtu "$interface" "$mtu"
                fi
                ;;
            6)
                diagnose_mtu_issues
                ;;
            7)
                generate_report
                ;;
            8)
                echo "退出"
                exit 0
                ;;
            *)
                echo "无效选择"
                ;;
        esac
    done
}

# 命令行参数
if [ $# -eq 0 ]; then
    main_menu
else
    case "$1" in
        --show)
            show_current_mtu
            ;;
        --detect)
            target=${2:-$DEFAULT_TARGET}
            interface=${3:-$(get_default_interface)}
            find_optimal_mtu "$target" "$interface"
            ;;
        --diagnose)
            diagnose_mtu_issues
            ;;
        --set)
            if [ $# -lt 3 ]; then
                echo "用法: $0 --set <interface> <mtu>"
                exit 1
            fi
            apply_mtu "$2" "$3"
            ;;
        --help)
            echo "MTU检测和优化工具"
            echo ""
            echo "用法: $0 [选项]"
            echo ""
            echo "选项:"
            echo "  --show              显示当前MTU设置"
            echo "  --detect [target]   检测最优MTU"
            echo "  --diagnose          诊断MTU问题"
            echo "  --set <if> <mtu>    设置接口MTU"
            echo "  --help              显示帮助"
            echo ""
            echo "无参数运行进入交互菜单"
            ;;
        *)
            echo "未知参数: $1"
            echo "使用 --help 查看帮助"
            exit 1
            ;;
    esac
fi