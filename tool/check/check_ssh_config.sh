#!/bin/bash

# SSH配置诊断脚本

echo "========== SSH配置诊断 =========="
echo "时间: $(date)"
echo ""

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 1. 显示配置文件加载顺序
echo "=== SSH配置文件加载顺序 ==="
echo "1. /etc/ssh/sshd_config (主配置文件)"
if [ -d /etc/ssh/sshd_config.d ]; then
    echo "2. /etc/ssh/sshd_config.d/*.conf (按字母顺序):"
    for conf in /etc/ssh/sshd_config.d/*.conf; do
        if [ -f "$conf" ]; then
            echo "   - $(basename "$conf")"
        fi
    done
fi
echo ""

# 2. 检查配置冲突
echo "=== 配置冲突检查 ==="
check_config() {
    local param="$1"
    local found_in=""
    
    # 检查主配置文件
    if grep -q "^$param" /etc/ssh/sshd_config 2>/dev/null; then
        found_in="$found_in/etc/ssh/sshd_config "
    fi
    
    # 检查sshd_config.d目录
    if [ -d /etc/ssh/sshd_config.d ]; then
        for conf in /etc/ssh/sshd_config.d/*.conf; do
            if [ -f "$conf" ] && grep -q "^$param" "$conf" 2>/dev/null; then
                found_in="$found_in$(basename "$conf") "
            fi
        done
    fi
    
    if [ -n "$found_in" ]; then
        local count=$(echo "$found_in" | wc -w)
        if [ "$count" -gt 1 ]; then
            echo -e "${YELLOW}⚠ $param 在多个文件中定义:${NC} $found_in"
        else
            echo -e "${GREEN}✓ $param 定义在:${NC} $found_in"
        fi
    fi
}

# 检查关键参数
for param in Port PasswordAuthentication PermitRootLogin PubkeyAuthentication; do
    check_config "$param"
done
echo ""

# 3. 显示实际生效的配置
echo "=== 实际生效的SSH配置 ==="
echo "(使用 sshd -T 获取)"
echo ""

if command -v sshd &>/dev/null; then
    echo "关键配置项："
    sshd -T 2>/dev/null | grep -E "^(port|passwordauthentication|permitrootlogin|pubkeyauthentication|protocol|x11forwarding|clientaliveinterval|usepam)" | sort | while read line; do
        key=$(echo "$line" | awk '{print $1}')
        value=$(echo "$line" | cut -d' ' -f2-)
        printf "  %-25s : %s\n" "$key" "$value"
    done
else
    echo -e "${RED}错误: sshd命令不可用${NC}"
fi
echo ""

# 4. 验证SSH服务状态
echo "=== SSH服务状态 ==="
if systemctl is-active ssh &>/dev/null 2>&1; then
    echo -e "${GREEN}✓ SSH服务 (ssh.service) 运行中${NC}"
    ssh_port=$(sudo ss -tlnp | grep sshd | head -1 | sed 's/.*:\([0-9]\+\) .*/\1/' 2>/dev/null || echo "未知")
    echo "  监听端口: $ssh_port"
elif systemctl is-active sshd &>/dev/null 2>&1; then
    echo -e "${GREEN}✓ SSH服务 (sshd.service) 运行中${NC}"
    ssh_port=$(sudo ss -tlnp | grep sshd | head -1 | sed 's/.*:\([0-9]\+\) .*/\1/' 2>/dev/null || echo "未知")
    echo "  监听端口: $ssh_port"
else
    echo -e "${RED}✗ SSH服务未运行${NC}"
fi
echo ""

# 5. Cloud-init状态
echo "=== Cloud-init状态 ==="
if [ -f /etc/ssh/sshd_config.d/50-cloud-init.conf ]; then
    echo -e "${YELLOW}⚠ 检测到cloud-init SSH配置文件${NC}"
    echo "  文件: /etc/ssh/sshd_config.d/50-cloud-init.conf"
    echo "  内容预览:"
    head -5 /etc/ssh/sshd_config.d/50-cloud-init.conf | sed 's/^/    /'
    if [ -f /etc/ssh/sshd_config.d/99-security.conf ]; then
        echo -e "${GREEN}✓ 但是99-security.conf会覆盖其设置${NC}"
    fi
else
    echo "✓ 未检测到cloud-init SSH配置"
fi

if systemctl is-enabled cloud-init &>/dev/null 2>&1; then
    echo "  Cloud-init服务: 已启用"
else
    echo "  Cloud-init服务: 未启用"
fi
echo ""

# 6. 建议
echo "=== 建议 ==="
if grep -q "^Port" /etc/ssh/sshd_config 2>/dev/null && [ -f /etc/ssh/sshd_config.d/99-security.conf ] && grep -q "^Port" /etc/ssh/sshd_config.d/99-security.conf 2>/dev/null; then
    echo -e "${YELLOW}建议：${NC}"
    echo "  发现Port在多个文件中定义，建议在主配置文件中注释掉Port设置"
    echo "  运行: sudo sed -i 's/^Port/#Port/' /etc/ssh/sshd_config"
fi

# 测试配置
echo ""
echo "=== 配置语法检查 ==="
if sudo sshd -t 2>&1; then
    echo -e "${GREEN}✓ SSH配置语法正确${NC}"
else
    echo -e "${RED}✗ SSH配置存在语法错误${NC}"
fi

echo ""
echo "========== 诊断完成 =========="