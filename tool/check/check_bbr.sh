#!/bin/bash

# BBR版本检测和信息脚本

set -e

# 颜色输出
CYAN='\033[0;36m'

# 检查内核版本
check_kernel_version() {
    echo "========== 内核信息 =========="
    uname -r
    echo ""
}

# 检查BBR支持和版本
check_bbr_version() {
    echo "========== BBR版本检测 =========="
    
    # 检查当前拥塞控制算法
    current_cc=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')
    echo -e "当前拥塞控制算法: $current_cc"
    
    # 检查可用的拥塞控制算法
    echo -e "\n可用的拥塞控制算法:"
    available_cc=$(sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | cut -d= -f2)
    echo "$available_cc" | tr ' ' '\n' | while read cc; do
        if [[ "$cc" == *"bbr"* ]]; then
            echo -e "  $cc"
        else
            echo "  $cc"
        fi
    done
    
    # 检查BBR模块信息
    echo -e "\n${CYAN}BBR模块详细信息:"
    if lsmod | grep -q tcp_bbr; then
        modinfo tcp_bbr 2>/dev/null | grep -E "^(filename|version|description|author|srcversion):" || {
            echo "BBR模块已加载但无法获取详细信息"
        }
    else
        echo "BBR模块未加载"
    fi
    
    # 检查BBR版本特征
    echo -e "\n${CYAN}BBR版本特征检测:"
    
    # BBRv1 特征 (Linux 4.9+)
    if [ -f /proc/sys/net/ipv4/tcp_congestion_control ]; then
        echo "✓ BBRv1 基础支持 (Linux 4.9+)"
    fi
    
    # BBRv2 特征 (Linux 5.4+)
    if [ -f /proc/sys/net/ipv4/tcp_ecn ]; then
        kernel_major=$(uname -r | cut -d. -f1)
        kernel_minor=$(uname -r | cut -d. -f2)
        if [ "$kernel_major" -ge 5 ] && [ "$kernel_minor" -ge 4 ]; then
            echo "✓ BBRv2 特征存在 (Linux 5.4+)"
        fi
    fi
    
    # BBRv3 特征检测
    echo -e "\n${CYAN}BBRv3 特征检测:"
    
    # 检查是否有bbrplus或bbr2
    if echo "$available_cc" | grep -qE "bbrplus|bbr2|bbrv3"; then
        echo "✓ 检测到BBR增强版本"
    fi
    
    # 检查sysctl中的BBR参数
    echo -e "\n${CYAN}BBR相关内核参数:"
    sysctl -a 2>/dev/null | grep -i bbr | head -10 || echo "无BBR特定参数"
    
    # 尝试检测BBR版本通过dmesg
    echo -e "\n${CYAN}内核日志中的BBR信息:"
    dmesg | grep -i bbr | tail -5 2>/dev/null || echo "无相关日志"
}

# 显示BBR版本差异
show_bbr_comparison() {
    echo -e "\n========== BBR版本对比 =========="
    
    cat << 'EOF'

BBRv1 (2016, Linux 4.9+)
------------------------
• 基础BBR实现
• 基于带宽和RTT的拥塞控制
• 单流公平性问题
• 在深缓冲区网络中可能过于激进
• 适合: 一般Web服务、CDN

BBRv2 (2019, Linux 5.4+实验性)
-------------------------------
• 改进的公平性
• 更精确的带宽探测
• ECN支持
• 减少缓冲区膨胀
• 更好的收敛性
• 适合: 数据中心、高并发服务

BBRv3 (2023+, 需要补丁)
------------------------
• 完全重写的状态机
• 更好的多流公平性
• 改进的丢包处理
• 降低排队延迟
• 更精确的pacing
• WiFi/移动网络优化
• 适合: 所有场景，特别是无线网络

主要改进指标:
------------
指标          BBRv1    BBRv2    BBRv3
吞吐量        基准     +10%     +15%
公平性        较差     改进     优秀
缓冲区膨胀    存在     减少     最小
CPU开销       低       中       中
稳定性        稳定     实验性   实验性

EOF
}

# 如何启用BBRv3
show_bbr_v3_installation() {
    echo -e "\n========== 如何启用BBRv3 =========="
    
    cat << 'EOF'

方法1: 使用XanMod内核 (推荐)
----------------------------
# Ubuntu/Debian
wget -qO - https://dl.xanmod.org/gpg.key | sudo apt-key add -
echo 'deb http://deb.xanmod.org releases main' | sudo tee /etc/apt/sources.list.d/xanmod-kernel.list
sudo apt update && sudo apt install linux-xanmod-edge

# 验证
uname -r  # 应显示xanmod字样

方法2: 编译内核补丁
------------------
# 下载BBRv3补丁
git clone https://github.com/google/bbr.git
cd bbr/v3

# 应用到内核源码
cd /usr/src/linux-5.x.x
patch -p1 < /path/to/bbr-v3.patch

# 编译内核
make menuconfig
# 启用: Networking support → Networking options → TCP: advanced congestion control → BBR TCP

make -j$(nproc)
make modules_install
make install

方法3: 使用BBRplus (国内优化版)
------------------------------
# 一键脚本
wget -N --no-check-certificate "https://github.com/ylx2016/Linux-NetSpeed/raw/master/tcp.sh"
chmod +x tcp.sh
./tcp.sh

# 选择BBRplus或BBR2

配置启用:
--------
# 临时启用
sysctl net.ipv4.tcp_congestion_control=bbr
sysctl net.core.default_qdisc=fq

# 永久启用
echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf
sysctl -p

EOF
}

# 测试BBR性能
test_bbr_performance() {
    echo -e "\n========== BBR性能测试建议 =========="
    
    cat << 'EOF'

1. 吞吐量测试
------------
# 服务端
iperf3 -s

# 客户端
iperf3 -c SERVER_IP -t 30 -P 4

2. RTT和抖动测试
---------------
# 持续ping测试
ping -i 0.2 -c 100 SERVER_IP | tee ping_bbr.log

# 分析
grep "rtt min/avg/max/mdev" ping_bbr.log

3. 并发连接测试
--------------
# 使用wrk或ab
wrk -t12 -c400 -d30s http://SERVER_IP/
ab -n 10000 -c 100 http://SERVER_IP/

4. 实时监控
----------
# 查看BBR状态
ss -tin | grep bbr

# 查看拥塞窗口
ss -i | grep -A10 bbr

5. 对比测试
----------
# 切换算法对比
sysctl net.ipv4.tcp_congestion_control=cubic
# 运行测试...

sysctl net.ipv4.tcp_congestion_control=bbr
# 运行测试...

关键指标:
--------
• 带宽利用率 (目标: >90%)
• RTT稳定性 (标准差<10ms)
• 丢包恢复时间 (<2秒)
• 公平性指数 (Jain's index >0.9)

EOF
}

# BBR调优参数
show_bbr_tuning() {
    echo -e "\n========== BBR调优参数 =========="
    
    cat << 'EOF'

BBRv3 推荐配置
-------------
# 基础BBR配置
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# BBRv3 特定优化
net.ipv4.tcp_ecn = 1                    # 启用ECN
net.ipv4.tcp_ecn_fallback = 1           # ECN回退
net.ipv4.tcp_pacing_ss_ratio = 200      # 慢启动pacing比率
net.ipv4.tcp_pacing_ca_ratio = 120      # 拥塞避免pacing比率
net.ipv4.tcp_bbr_startup_probe_rtt = 0  # 启动时RTT探测
net.ipv4.tcp_bbr_drain_to_target = 1    # 排空到目标

# 缓冲区优化 (配合BBR)
net.core.rmem_max = 134217728           # 128MB
net.core.wmem_max = 134217728           # 128MB
net.ipv4.tcp_rmem = 4096 131072 134217728
net.ipv4.tcp_wmem = 4096 131072 134217728

# 队列管理
net.core.netdev_max_backlog = 30000
net.ipv4.tcp_max_syn_backlog = 16384
net.core.somaxconn = 32768

# WiFi/4G优化 (BBRv3特别优化)
net.ipv4.tcp_no_delay_ack = 1           # 减少ACK延迟
net.ipv4.tcp_early_retrans = 3          # 早期重传
net.ipv4.tcp_thin_linear_timeouts = 1   # 薄流优化

场景化配置
---------
1. 数据中心 (低延迟)
   - 使用默认BBRv3配置
   - 调小缓冲区 (16-32MB)

2. 跨国链路 (高延迟)
   - 增大缓冲区 (128-256MB)
   - 启用tcp_westwood备选

3. 移动网络 (高丢包)
   - 启用ECN
   - 降低pacing比率
   - 启用薄流优化

4. 混合场景
   - 使用BBRv3默认值
   - 动态调整为主

EOF
}

# 主菜单
main_menu() {
    while true; do
        echo -e "\n========== BBR版本检测和优化工具 =========="
        echo "1. 检查当前BBR版本和状态"
        echo "2. 显示BBR版本对比"
        echo "3. 查看BBRv3安装方法"
        echo "4. BBR性能测试建议"
        echo "5. BBR调优参数说明"
        echo "6. 退出"
        echo "请选择操作 [1-6]: "
        read -r choice
        
        case $choice in
            1)
                check_kernel_version
                check_bbr_version
                ;;
            2)
                show_bbr_comparison
                ;;
            3)
                show_bbr_v3_installation
                ;;
            4)
                test_bbr_performance
                ;;
            5)
                show_bbr_tuning
                ;;
            6)
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
        --check)
            check_kernel_version
            check_bbr_version
            ;;
        --compare)
            show_bbr_comparison
            ;;
        --install)
            show_bbr_v3_installation
            ;;
        --test)
            test_bbr_performance
            ;;
        --tune)
            show_bbr_tuning
            ;;
        --help)
            echo "BBR版本检测和优化工具"
            echo ""
            echo "用法: $0 [选项]"
            echo ""
            echo "选项:"
            echo "  --check    检查BBR版本"
            echo "  --compare  版本对比"
            echo "  --install  安装指南"
            echo "  --test     测试建议"
            echo "  --tune     调优参数"
            echo "  --help     显示帮助"
            ;;
        *)
            echo "未知参数: $1"
            exit 1
            ;;
    esac
fi