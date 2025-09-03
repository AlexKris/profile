#!/bin/bash

# 检查当前系统NTP服务状态

echo "=== 系统NTP服务检查 ==="
echo ""

# 检查systemd-timesyncd
echo "1. systemd-timesyncd 状态:"
if systemctl is-active systemd-timesyncd &>/dev/null; then
    echo "   ✓ 运行中"
    echo "   配置文件: /etc/systemd/timesyncd.conf"
    if [ -f /etc/systemd/timesyncd.conf ]; then
        echo "   当前NTP服务器:"
        grep "^NTP=" /etc/systemd/timesyncd.conf 2>/dev/null || echo "   (使用默认)"
    fi
    echo ""
    echo "   同步状态:"
    timedatectl show-timesync --no-pager | grep -E "ServerName|Frequency|Stratum" | sed 's/^/   /'
else
    echo "   ✗ 未运行"
fi

echo ""

# 检查chrony
echo "2. chrony 状态:"
if systemctl is-active chrony &>/dev/null || systemctl is-active chronyd &>/dev/null; then
    echo "   ✓ 运行中"
    echo "   配置文件: /etc/chrony/chrony.conf 或 /etc/chrony.conf"
    if command -v chronyc &>/dev/null; then
        echo ""
        echo "   时间源:"
        chronyc sources | head -10 | sed 's/^/   /'
        echo ""
        echo "   同步状态:"
        chronyc tracking | grep -E "Reference ID|Stratum|Last offset|Frequency" | sed 's/^/   /'
    fi
else
    echo "   ✗ 未运行"
fi

echo ""

# 检查ntpd（传统NTP）
echo "3. ntpd (传统NTP) 状态:"
if systemctl is-active ntp &>/dev/null || systemctl is-active ntpd &>/dev/null; then
    echo "   ✓ 运行中"
else
    echo "   ✗ 未运行"
fi

echo ""
echo "=== 系统时间信息 ==="
echo "时区: $(timedatectl | grep "Time zone" | awk '{print $3}')"
echo "NTP同步: $(timedatectl | grep "NTP synchronized" | awk '{print $3}')"
echo "系统时间: $(date)"

echo ""
echo "=== 建议 ==="
active_count=0
[ $(systemctl is-active systemd-timesyncd 2>/dev/null) = "active" ] && ((active_count++))
[ $(systemctl is-active chrony 2>/dev/null) = "active" ] && ((active_count++))
[ $(systemctl is-active chronyd 2>/dev/null) = "active" ] && ((active_count++))

if [ $active_count -gt 1 ]; then
    echo "⚠️  检测到多个NTP服务同时运行，建议只保留一个"
elif [ $active_count -eq 0 ]; then
    echo "⚠️  未检测到活跃的NTP服务，建议启用一个"
else
    echo "✓ NTP服务配置正常"
fi

# 性能对比（如果两个服务都安装了）
if command -v chronyd &>/dev/null && command -v timedatectl &>/dev/null; then
    echo ""
    echo "=== 参考信息 ==="
    echo "• systemd-timesyncd: 轻量级，适合客户端使用"
    echo "• chrony: 功能丰富，精度更高，适合服务器使用"
    echo "• 生产环境推荐使用 chrony"
fi 