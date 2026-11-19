#!/bin/bash

# SSH配置诊断脚本
set -uo pipefail

as_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    else
        sudo "$@"
    fi
}

SSHD_BIN=""
if [ -x /usr/sbin/sshd ]; then
    SSHD_BIN="/usr/sbin/sshd"
elif command -v sshd >/dev/null 2>&1; then
    SSHD_BIN=$(command -v sshd)
fi

echo "========== SSH配置诊断 =========="
echo "时间: $(date)"
echo ""

# 1. 显示配置文件加载顺序（OpenSSH 采用 First-Match-Wins，Debian/Ubuntu 顶部先 Include sshd_config.d）
echo "=== SSH配置文件加载顺序（先匹配先生效）==="
if grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config 2>/dev/null; then
    echo "1. /etc/ssh/sshd_config.d/*.conf (按字母顺序，优先于主配置剩余项):"
    if [ -d /etc/ssh/sshd_config.d ]; then
        for conf in /etc/ssh/sshd_config.d/*.conf; do
            [ -f "$conf" ] && echo "   - $(basename "$conf")"
        done
    fi
    echo "2. /etc/ssh/sshd_config (主配置文件)"
else
    echo "1. /etc/ssh/sshd_config (主配置文件，未检测到 Include sshd_config.d/*.conf)"
fi
echo ""

# 2. 检查配置冲突
echo "=== 配置冲突检查 ==="
check_config() {
    local param="$1"
    local found_in=""

    if grep -iqE "^[[:space:]]*${param}([[:space:]]|=)" /etc/ssh/sshd_config 2>/dev/null; then
        found_in="${found_in}/etc/ssh/sshd_config "
    fi

    if [ -d /etc/ssh/sshd_config.d ]; then
        for conf in /etc/ssh/sshd_config.d/*.conf; do
            if [ -f "$conf" ] && grep -iqE "^[[:space:]]*${param}([[:space:]]|=)" "$conf" 2>/dev/null; then
                found_in="${found_in}$(basename "$conf") "
            fi
        done
    fi

    if [ -n "$found_in" ]; then
        local count
        count=$(echo "$found_in" | wc -w | tr -d ' ')
        if [ "$count" -gt 1 ]; then
            echo "⚠ $param 在多个文件中定义: $found_in"
        else
            echo "✓ $param 定义在: $found_in"
        fi
    fi
}

for param in Port PasswordAuthentication PermitRootLogin PubkeyAuthentication; do
    check_config "$param"
done
echo ""

# 3. 显示实际生效的配置
echo "=== 实际生效的SSH配置 ==="
echo "(使用 sshd -T 获取)"
echo ""

if [ -n "$SSHD_BIN" ]; then
    [ ! -d /run/sshd ] && as_root mkdir -p /run/sshd 2>/dev/null && as_root chmod 0755 /run/sshd 2>/dev/null || true
    echo "关键配置项："
    sshd_dump=$(as_root "$SSHD_BIN" -T -C user=root,host=localhost,addr=127.0.0.1 2>/dev/null || as_root "$SSHD_BIN" -T 2>/dev/null || true)
    if [ -n "$sshd_dump" ]; then
        echo "$sshd_dump" | grep -E "^(port|passwordauthentication|permitrootlogin|pubkeyauthentication|permitemptypasswords|kbdinteractiveauthentication|challengeresponseauthentication|x11forwarding|usedns|clientaliveinterval|clientalivecountmax|usepam) " | sort | while IFS= read -r line; do
            key=$(echo "$line" | awk '{print $1}')
            value=$(echo "$line" | cut -d' ' -f2-)
            printf "  %-32s : %s\n" "$key" "$value"
        done
    else
        echo "  无法读取 sshd -T 输出（请检查权限或配置语法）"
    fi
else
    echo "错误: sshd命令不可用"
fi
echo ""

# 4. 验证SSH服务状态
echo "=== SSH服务状态 ==="
list_ssh_ports() {
    local pattern="$1"
    as_root ss -tlnp 2>/dev/null | grep -E "$pattern" | awk '{print $4}' | sed 's/.*://' | sort -nu | tr '\n' ' ' | sed 's/[[:space:]]*$//'
}

if systemctl is-active --quiet ssh 2>/dev/null; then
    echo "✓ SSH服务 (ssh.service) 运行中"
    ssh_ports=$(list_ssh_ports '"sshd"')
    echo "  监听端口: ${ssh_ports:-未知}"
elif systemctl is-active --quiet sshd 2>/dev/null; then
    echo "✓ SSH服务 (sshd.service) 运行中"
    ssh_ports=$(list_ssh_ports '"sshd"')
    echo "  监听端口: ${ssh_ports:-未知}"
elif systemctl is-active --quiet ssh.socket 2>/dev/null; then
    echo "✓ SSH服务 (ssh.socket 监听模式) 运行中"
    ssh_ports=$(list_ssh_ports '"systemd"')
    echo "  监听端口: ${ssh_ports:-未知}"
else
    echo "✗ SSH服务未运行"
fi
echo ""

# 5. Cloud-init / 云镜像默认配置状态
echo "=== 云镜像 SSH 配置状态 ==="
cloud_found=0
for cloud_conf in /etc/ssh/sshd_config.d/50-cloud-init.conf /etc/ssh/sshd_config.d/60-cloudimg-settings.conf; do
    if [ -f "$cloud_conf" ]; then
        cloud_found=1
        echo "⚠ 检测到云镜像 SSH 配置文件: $cloud_conf"
        head -5 "$cloud_conf" | sed 's/^/    /'
    fi
done
if [ "$cloud_found" -eq 1 ]; then
    if [ -f /etc/ssh/sshd_config.d/00-setup-security.conf ]; then
        echo "✓ 00-setup-security.conf 按顺序优先于云镜像配置生效"
    elif [ -f /etc/ssh/sshd_config.d/99-security.conf ]; then
        echo "⚠ 旧版 99-security.conf 排在 50-cloud-init.conf / 60-cloudimg-settings.conf 之后，可能被覆盖"
    fi
else
    echo "✓ 未检测到 50-cloud-init.conf / 60-cloudimg-settings.conf"
fi

if systemctl is-enabled --quiet cloud-init 2>/dev/null; then
    echo "  Cloud-init服务: 已启用"
else
    echo "  Cloud-init服务: 未启用"
fi
echo ""

# 6. 建议
echo "=== 建议 ==="
SSH_SECURITY_CONF="/etc/ssh/sshd_config.d/00-setup-security.conf"
[ ! -f "$SSH_SECURITY_CONF" ] && SSH_SECURITY_CONF="/etc/ssh/sshd_config.d/99-security.conf"
if grep -iqE "^[[:space:]]*Port([[:space:]]|=)" /etc/ssh/sshd_config 2>/dev/null \
    && [ -f "$SSH_SECURITY_CONF" ] \
    && grep -iqE "^[[:space:]]*Port([[:space:]]|=)" "$SSH_SECURITY_CONF" 2>/dev/null; then
    echo "建议："
    echo "  发现Port在多个文件中定义，建议在主配置文件中注释掉Port设置"
    echo "  运行: sudo sed -i -E 's/^[[:space:]]*Port([[:space:]]|=)/#&/I' /etc/ssh/sshd_config"
fi

# 测试配置
echo ""
echo "=== 配置语法检查 ==="
if [ -n "$SSHD_BIN" ] && as_root "$SSHD_BIN" -t 2>&1; then
    echo "✓ SSH配置语法正确"
else
    echo "✗ SSH配置存在语法错误"
fi

echo ""
echo "========== 诊断完成 =========="
