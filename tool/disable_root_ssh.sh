#!/bin/bash

# 禁用root SSH登录脚本
# 彻底禁用root用户通过SSH登录（包括密钥登录）

set -euo pipefail

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

# 检查是否为root用户
check_root() {
    if [ "$(id -u)" != "0" ]; then
        log_error "此脚本需要root权限运行"
        exit 1
    fi
}

# 备份SSH配置
backup_ssh_config() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_dir="/root/ssh_disable_root_backup_$timestamp"
    
    log_info "创建SSH配置备份到 $backup_dir"
    mkdir -p "$backup_dir"
    
    # 备份主配置文件
    cp /etc/ssh/sshd_config "$backup_dir/sshd_config.bak"
    
    # 备份模块化配置目录
    if [ -d /etc/ssh/sshd_config.d ]; then
        cp -r /etc/ssh/sshd_config.d "$backup_dir/"
    fi
    
    # 创建还原脚本
    cat > "$backup_dir/restore.sh" << 'EOF'
#!/bin/bash
echo "还原SSH配置..."
cp sshd_config.bak /etc/ssh/sshd_config
if [ -d sshd_config.d ]; then
    rm -rf /etc/ssh/sshd_config.d
    cp -r sshd_config.d /etc/ssh/
fi
systemctl restart ssh
echo "SSH配置已还原，请测试登录功能"
EOF
    chmod +x "$backup_dir/restore.sh"
    
    log_info "备份完成，还原脚本: $backup_dir/restore.sh"
}

# 检查当前SSH配置
check_current_config() {
    log_info "检查当前SSH配置..."
    
    echo "主配置文件 (/etc/ssh/sshd_config):"
    if grep -E "^\s*PermitRootLogin" /etc/ssh/sshd_config; then
        echo "  $(grep -E "^\s*PermitRootLogin" /etc/ssh/sshd_config)"
    else
        echo "  未找到 PermitRootLogin 配置（默认值可能是 prohibit-password）"
    fi
    
    # 检查模块化配置
    if [ -d /etc/ssh/sshd_config.d ]; then
        echo ""
        echo "模块化配置文件 (/etc/ssh/sshd_config.d/):"
        for conf_file in /etc/ssh/sshd_config.d/*.conf; do
            if [ -f "$conf_file" ] && grep -E "^\s*PermitRootLogin" "$conf_file" &>/dev/null; then
                echo "  $conf_file: $(grep -E "^\s*PermitRootLogin" "$conf_file")"
            fi
        done
    fi
    
    echo ""
}

# 禁用root SSH登录
disable_root_ssh() {
    log_info "开始禁用root SSH登录..."
    
    # 处理主配置文件
    if grep -E "^\s*PermitRootLogin\s+(yes|prohibit-password)" /etc/ssh/sshd_config > /dev/null; then
        log_info "更新主配置文件中的 PermitRootLogin 设置..."
        sed -i 's/^\s*PermitRootLogin\s\+\(yes\|prohibit-password\)/PermitRootLogin no/' /etc/ssh/sshd_config
    elif grep -E "^\s*PermitRootLogin" /etc/ssh/sshd_config > /dev/null; then
        if ! grep -q "PermitRootLogin no" /etc/ssh/sshd_config; then
            log_info "强制更新主配置文件中的 PermitRootLogin 为 no..."
            sed -i 's/^\s*PermitRootLogin\s\+.*/PermitRootLogin no/' /etc/ssh/sshd_config
        fi
    else
        log_info "在主配置文件中添加 PermitRootLogin no..."
        echo "PermitRootLogin no" >> /etc/ssh/sshd_config
    fi
    
    # 处理模块化配置文件
    if [ -d /etc/ssh/sshd_config.d ]; then
        for conf_file in /etc/ssh/sshd_config.d/*.conf; do
            if [ -f "$conf_file" ] && grep -E "^\s*PermitRootLogin" "$conf_file" > /dev/null; then
                log_info "处理模块化配置文件: $conf_file"
                
                # 备份原文件
                cp "$conf_file" "${conf_file}.bak"
                
                if grep -E "^\s*PermitRootLogin\s+(yes|prohibit-password)" "$conf_file" > /dev/null; then
                    sed -i 's/^\s*PermitRootLogin\s\+\(yes\|prohibit-password\)/PermitRootLogin no/' "$conf_file"
                elif ! grep -q "PermitRootLogin no" "$conf_file"; then
                    sed -i 's/^\s*PermitRootLogin\s\+.*/PermitRootLogin no/' "$conf_file"
                fi
            fi
        done
    fi
}

# 验证SSH配置语法
verify_ssh_config() {
    log_info "验证SSH配置语法..."
    if sshd -t; then
        log_info "SSH配置语法正确"
        return 0
    else
        log_error "SSH配置语法错误！"
        return 1
    fi
}

# 重启SSH服务
restart_ssh_service() {
    log_info "重启SSH服务..."
    if systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null; then
        log_info "SSH服务重启成功"
    else
        log_error "SSH服务重启失败"
        return 1
    fi
}

# 测试SSH配置
test_ssh_config() {
    log_info "测试新的SSH配置..."
    
    # 显示当前监听端口
    local ssh_port=$(ss -tlnp | grep sshd | awk '{print $4}' | cut -d: -f2 | head -1)
    if [ -n "$ssh_port" ]; then
        log_info "SSH服务正在端口 $ssh_port 上监听"
    fi
    
    # 检查配置是否生效
    if sshd -T | grep -q "permitrootlogin no"; then
        log_info "✓ root SSH登录已成功禁用"
    else
        log_warn "⚠ root SSH登录配置可能未完全生效"
        log_warn "当前有效配置: $(sshd -T | grep permitrootlogin)"
    fi
}

# 显示后续建议
show_recommendations() {
    echo ""
    log_info "=== 操作完成 ==="
    echo ""
    log_warn "重要提醒："
    echo "1. root用户的SSH登录（包括密钥登录）已被禁用"
    echo "2. 请确保您有其他方式访问系统（如普通用户+sudo）"
    echo "3. 建议在关闭当前会话前测试新的登录方式"
    echo ""
    log_info "建议的登录方式："
    echo "- 使用具有sudo权限的普通用户登录"
    echo "- 登录后使用 'sudo su -' 切换到root"
    echo ""
    log_info "如需紧急还原，使用备份目录中的 restore.sh 脚本"
}

# 主函数
main() {
    echo -e "${BLUE}=== 禁用root SSH登录脚本 ===${NC}"
    echo ""
    
    check_root
    
    # 显示当前配置
    check_current_config
    
    # 询问用户确认
    read -p "是否继续禁用root SSH登录？(y/N): " -r
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "操作已取消"
        exit 0
    fi
    
    # 备份配置
    backup_ssh_config
    
    # 禁用root SSH登录
    disable_root_ssh
    
    # 验证配置
    if ! verify_ssh_config; then
        log_error "配置验证失败，请检查语法错误"
        exit 1
    fi
    
    # 重启SSH服务
    if ! restart_ssh_service; then
        log_error "SSH服务重启失败"
        exit 1
    fi
    
    # 测试配置
    test_ssh_config
    
    # 显示建议
    show_recommendations
}

# 支持命令行参数
case "${1:-}" in
    --check)
        check_current_config
        exit 0
        ;;
    --force)
        check_root
        backup_ssh_config
        disable_root_ssh
        verify_ssh_config && restart_ssh_service
        test_ssh_config
        show_recommendations
        ;;
    --help|-h)
        echo "用法: $0 [选项]"
        echo ""
        echo "选项:"
        echo "  --check     只检查当前配置，不做修改"
        echo "  --force     跳过确认，直接执行"
        echo "  --help      显示此帮助信息"
        echo ""
        exit 0
        ;;
    *)
        main
        ;;
esac