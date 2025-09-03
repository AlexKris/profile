#!/bin/bash

# 防火墙规则诊断脚本
echo "========== 防火墙规则诊断 =========="
echo "时间: $(date)"
echo ""

# 检查是否有root权限
if [ "$EUID" -ne 0 ]; then
    echo "错误: 此脚本需要root权限运行"
    exit 1
fi

# 检查INPUT链规则
echo "=== INPUT链规则 ==="
echo "Web端口规则（80/443）："
iptables -L INPUT -n --line-numbers | grep -E "tcp dpt:(80|443)" | nl
echo ""

# 检查DOCKER-USER链
if iptables -L DOCKER-USER -n &>/dev/null 2>&1; then
    echo "=== DOCKER-USER链规则 ==="
    echo "Web端口规则（80/443）："
    iptables -L DOCKER-USER -n --line-numbers | grep -E "dpt:(80|443)" | nl
    echo ""
else
    echo "=== DOCKER-USER链不存在 ==="
    echo ""
fi

# 统计规则
echo "=== 规则统计 ==="
input_internal=$(iptables -L INPUT -n | grep -c "internal-network" || echo 0)
input_cloudflare=$(iptables -L INPUT -n | grep -c "cloudflare-auto" || echo 0)
input_drop=$(iptables -L INPUT -n | grep -cE "tcp dpt:(80|443).*DROP" || echo 0)

echo "INPUT链："
echo "  内网规则: $input_internal 条"
echo "  Cloudflare规则: $input_cloudflare 条"
echo "  DROP规则: $input_drop 条"

if iptables -L DOCKER-USER -n &>/dev/null 2>&1; then
    docker_internal=$(iptables -L DOCKER-USER -n | grep -c "internal-network" || echo 0)
    docker_cloudflare=$(iptables -L DOCKER-USER -n | grep -c "cloudflare-auto" || echo 0)
    docker_drop=$(iptables -L DOCKER-USER -n | grep -cE "dpt:(80|443).*DROP" || echo 0)
    docker_return=$(iptables -L DOCKER-USER -n | grep -c "RETURN.*all" || echo 0)
    
    echo ""
    echo "DOCKER-USER链："
    echo "  内网规则: $docker_internal 条"
    echo "  Cloudflare规则: $docker_cloudflare 条"
    echo "  DROP规则: $docker_drop 条"
    echo "  RETURN规则: $docker_return 条"
fi
echo ""

# 检查规则顺序
echo "=== 规则顺序检查 ==="
first_drop=$(iptables -L INPUT -n --line-numbers | grep -E "tcp dpt:(80|443).*DROP" | head -1 | awk '{print $1}')
last_accept=$(iptables -L INPUT -n --line-numbers | grep -E "tcp dpt:(80|443).*ACCEPT" | tail -1 | awk '{print $1}')

if [ -n "$first_drop" ] && [ -n "$last_accept" ]; then
    if [ "$last_accept" -gt "$first_drop" ]; then
        echo "警告: 发现ACCEPT规则（行$last_accept）在DROP规则（行$first_drop）之后！"
        echo "      这可能导致防火墙规则无效！"
    else
        echo "✓ INPUT链规则顺序正确"
    fi
else
    echo "✓ INPUT链规则顺序检查通过"
fi

if iptables -L DOCKER-USER -n &>/dev/null 2>&1; then
    docker_first_drop=$(iptables -L DOCKER-USER -n --line-numbers | grep -E "dpt:(80|443).*DROP" | head -1 | awk '{print $1}')
    docker_last_return=$(iptables -L DOCKER-USER -n --line-numbers | grep -E "dpt:(80|443).*RETURN" | tail -1 | awk '{print $1}')
    
    if [ -n "$docker_first_drop" ] && [ -n "$docker_last_return" ]; then
        if [ "$docker_last_return" -gt "$docker_first_drop" ]; then
            echo "警告: DOCKER-USER链中发现RETURN规则（行$docker_last_return）在DROP规则（行$docker_first_drop）之后！"
        else
            echo "✓ DOCKER-USER链规则顺序正确"
        fi
    else
        echo "✓ DOCKER-USER链规则顺序检查通过"
    fi
fi
echo ""

# 检查Cloudflare IP更新脚本
echo "=== Cloudflare IP更新配置 ==="
if [ -f "/usr/local/bin/update-cloudflare-ips.sh" ]; then
    echo "✓ 更新脚本存在"
    if [ -x "/usr/local/bin/update-cloudflare-ips.sh" ]; then
        echo "✓ 更新脚本可执行"
    else
        echo "✗ 更新脚本不可执行"
    fi
else
    echo "✗ 更新脚本不存在"
fi

if [ -f "/etc/cron.d/cloudflare-ip-update" ]; then
    echo "✓ 定时任务已配置"
    echo "  内容: $(cat /etc/cron.d/cloudflare-ip-update | grep -v '^#')"
else
    echo "✗ 定时任务未配置"
fi

if [ -f "/var/log/cloudflare-ip-update.log" ]; then
    echo ""
    echo "最近的更新日志："
    tail -5 /var/log/cloudflare-ip-update.log | sed 's/^/  /'
fi
echo ""

# 测试连接性
echo "=== 连接测试 ==="
echo -n "测试从本机访问80端口... "
if nc -zv -w2 127.0.0.1 80 &>/dev/null 2>&1; then
    echo "✓ 成功"
else
    echo "✗ 失败（可能没有运行Web服务）"
fi

echo -n "测试从本机访问443端口... "
if nc -zv -w2 127.0.0.1 443 &>/dev/null 2>&1; then
    echo "✓ 成功"
else
    echo "✗ 失败（可能没有运行Web服务）"
fi

echo ""
echo "========== 诊断完成 =========="