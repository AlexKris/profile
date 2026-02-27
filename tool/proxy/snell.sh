#!/bin/bash
#########################################################
# Snell Server Management Script
# Description: Install, configure and manage Snell proxy server
# Author: Updated with best practices
# License: MIT
#########################################################

# Exit on error, undefined vars, and pipe failures
set -euo pipefail

# Global variables
SCRIPT_NAME=$(basename "$0")
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
LOG_PREFIX="[Snell]"

# 日志函数
log_info() {
    echo -e "${LOG_PREFIX} [信息] $*"
}

log_warn() {
    echo -e "${LOG_PREFIX} [警告] $*" >&2
}

log_error() {
    echo -e "${LOG_PREFIX} [错误] $*" >&2
}

# 检查是否具有root权限
check_root() {
    if [ "$(id -u)" -ne 0 ] && ! sudo -v &>/dev/null; then
        log_error "此脚本需要root权限执行，请使用root用户或确保当前用户可以使用sudo"
        exit 1
    fi
}

# 清理临时文件
cleanup() {
    local exit_code=$?
    if [ -n "${TEMP_DIR:-}" ] && [ -d "$TEMP_DIR" ]; then
        log_info "清理临时文件..."
        rm -rf "$TEMP_DIR"
    fi
    if [ $exit_code -ne 0 ]; then
        log_error "脚本执行失败，退出码: $exit_code"
    fi
    exit $exit_code
}

# 设置清理陷阱
trap cleanup EXIT INT TERM

# 执行命令并检查结果
execute_cmd() {
    local cmd_desc="$1"
    shift
    log_info "正在${cmd_desc}..."
    
    if ! "$@"; then
        log_error "${cmd_desc}失败，退出码: $?"
        return 1
    fi
    return 0
}

# 验证下载文件
verify_download() {
    local file="$1"
    local min_size="$2"
    
    if [ ! -f "$file" ]; then
        log_error "下载的文件不存在: $file"
        return 1
    fi
    
    local file_size
    file_size=$(stat -c %s "$file" 2>/dev/null || stat -f %z "$file" 2>/dev/null)
    
    if [ "$file_size" -lt "$min_size" ]; then
        log_error "下载的文件过小 (${file_size} bytes)，可能不完整或下载失败"
        return 1
    fi
    
    return 0
}

# 下载 Snell 服务
download_snell() {
    check_root
    
    log_info "正在检查 Snell 是否已安装..."
    if [ -f /usr/local/bin/snell-server ]; then
        log_info "Snell 已经安装，将进行覆盖安装。"
    fi

    log_info "正在下载并安装 Snell 服务..."

    local snell_url="https://dl.nssurge.com/snell/snell-server-${SNELL_VERSION}-linux-${SNELL_ARCH}.zip"
    
    # 创建临时目录
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR" || {
        log_error "无法进入临时目录"
        exit 1
    }

    log_info "下载 Snell 到临时目录: $TEMP_DIR"
    
    if ! wget -O snell-server.zip "${snell_url}"; then
        log_error "下载 Snell 失败，请检查网络连接和版本参数。"
        return 1
    fi

    # 验证文件大小确保下载完整
    if ! verify_download "snell-server.zip" 1000; then
        return 1
    fi

    if ! unzip snell-server.zip; then
        log_error "解压 Snell 失败。"
        return 1
    fi

    if [ ! -f snell-server ]; then
        log_error "解压后未找到 snell-server 文件。"
        return 1
    fi

    execute_cmd "移动 snell-server 到 /usr/local/bin" sudo mv snell-server /usr/local/bin/
    execute_cmd "设置执行权限" sudo chmod +x /usr/local/bin/snell-server
    
    # 返回原始目录
    cd - >/dev/null || true
    
    log_info "Snell 服务已安装。"
    return 0
}

# 检查端口是否可用
check_port_available() {
    local port="$1"
    local port_check=""
    local cmd_prefix=""

    # 使用带进程信息的端口检查，若已由 Snell 占用则视为正常升级
    if [ "$(id -u)" -ne 0 ] && command -v sudo &>/dev/null; then
        cmd_prefix="sudo"
    fi
    
    if command -v ss &>/dev/null; then
        port_check=$($cmd_prefix ss -tulnp 2>/dev/null | grep -E "[.:]${port}\\b" || true)
    elif command -v netstat &>/dev/null; then
        port_check=$($cmd_prefix netstat -tulnp 2>/dev/null | grep -E "[.:]${port}\\b" || true)
    else
        log_warn "未找到 ss 或 netstat 命令，无法检查端口占用情况"
        return 0
    fi
    
    if [ -z "$port_check" ]; then
        return 0
    fi

    if echo "$port_check" | grep -qi "snell"; then
        log_info "端口 ${port} 当前由 Snell 使用，视为覆盖升级将继续安装。"
        return 0
    fi
    
    log_warn "端口 ${port} 已被占用，可能导致服务无法启动:"
    echo "$port_check"
    return 1
}

# 配置 systemd 服务
configure_systemd_service() {
    check_root
    
    log_info "正在配置 Snell 的 systemd 服务..."
    
    # 确保文件所有者和权限正确
    cat > /tmp/snell.service <<EOF
[Unit]
Description=Snell Proxy Service
After=network.target

[Service]
Type=simple
DynamicUser=yes
LimitNOFILE=32768
ExecStart=/usr/local/bin/snell-server -c /etc/snell/snell-server.conf
AmbientCapabilities=CAP_NET_BIND_SERVICE
StandardOutput=journal
StandardError=journal
SyslogIdentifier=snell-server
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

    execute_cmd "移动服务文件到systemd目录" sudo mv /tmp/snell.service /etc/systemd/system/snell.service
    execute_cmd "重新加载systemd配置" sudo systemctl daemon-reload
    
    log_info "Snell 的 systemd 服务已配置。"
    return 0
}

# 配置 Snell 服务
configure_snell() {
    check_root
    
    log_info "正在配置 Snell 服务..."

    # 检查端口是否被占用
    check_port_available "$SNELL_PORT" || log_warn "继续安装，但服务可能无法启动"

    # 创建配置目录
    execute_cmd "创建配置目录" sudo mkdir -p /etc/snell

    # 创建配置文件
    sudo tee /etc/snell/snell-server.conf > /dev/null <<EOF
[snell-server]
listen = 0.0.0.0:${SNELL_PORT}
psk = ${SNELL_PSK}
ipv6 = false
EOF
    
    log_info "Snell 配置文件已生成。"
    log_info "请保存以下信息："
    log_info "端口: ${SNELL_PORT}"
    log_info "密钥: ${SNELL_PSK}"
    
    return 0
}

# 验证安装参数
validate_install_params() {
    # 验证版本号格式
    if ! [[ "$SNELL_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log_error "版本号格式不正确，应为 vX.Y.Z 格式，如 v4.0.1"
        return 1
    fi
    
    # 验证架构
    if [ "$SNELL_ARCH" != "amd64" ] && [ "$SNELL_ARCH" != "aarch64" ]; then
        log_error "不支持的架构，只支持 amd64 或 aarch64"
        return 1
    fi
    
    # 验证端口号
    if ! [[ "$SNELL_PORT" =~ ^[0-9]+$ ]] || [ "$SNELL_PORT" -lt 1 ] || [ "$SNELL_PORT" -gt 65535 ]; then
        log_error "端口号必须是1-65535之间的数字"
        return 1
    fi
    
    # 验证PSK长度和安全性
    if [ ${#SNELL_PSK} -lt 8 ]; then
        log_warn "PSK长度小于8个字符，建议使用更长的密钥以提高安全性"
    fi
    
    # 检查是否包含常见弱密码特征
    if [[ "$SNELL_PSK" =~ ^(password|123|admin)$ ]]; then
        log_warn "检测到常见弱密码模式，建议使用更安全的随机密钥"
    fi
    
    return 0
}

# 启动 Snell 服务
start_snell() {
    check_root
    
    log_info "正在启动 Snell 服务..."
    
    execute_cmd "启用 Snell 服务自启动" sudo systemctl enable snell
    
    if ! execute_cmd "重启 Snell 服务" sudo systemctl restart snell; then
        log_error "无法启动 Snell 服务，请检查配置或端口是否被占用。"
        return 1
    fi
    
    # 给服务一点时间启动
    sleep 2
    
    # 检查服务是否成功启动
    if sudo systemctl is-active snell >/dev/null 2>&1; then
        log_info "Snell 服务已成功启动。"
        sudo systemctl status snell --no-pager
    else
        log_error "Snell 服务启动失败，请检查日志。"
        sudo systemctl status snell --no-pager
        return 1
    fi
    
    return 0
}

# 安装 Snell
install_snell() {
    # 验证参数
    validate_install_params || {
        log_error "参数验证失败，无法继续安装。"
        return 1
    }
    
    download_snell && 
    configure_systemd_service && 
    configure_snell || {
        log_error "安装过程失败"
        return 1
    }
    
    if ! start_snell; then
        log_warn "Snell 服务启动失败，但安装过程已完成。"
        log_warn "请检查配置文件和系统日志，然后尝试手动启动服务。"
        return 1
    fi
    
    log_info "Snell 安装成功！"
    return 0
}

# 停止 Snell 服务
stop_snell() {
    check_root
    log_info "停止 Snell 服务..."
    execute_cmd "停止服务" sudo systemctl stop snell
}

# 重启 Snell 服务
restart_snell() {
    check_root
    log_info "重启 Snell 服务..."
    execute_cmd "重启服务" sudo systemctl restart snell
    sleep 2
    sudo systemctl status snell --no-pager
}

# 查看 Snell 服务状态
status_snell() {
    check_root
    log_info "获取 Snell 服务状态..."
    sudo systemctl status snell --no-pager
}

# 卸载 Snell 服务
uninstall_snell() {
    check_root
    log_info "卸载 Snell 服务..."
    
    execute_cmd "停止服务" sudo systemctl stop snell || true
    execute_cmd "禁用服务" sudo systemctl disable snell || true
    
    if [ -f /usr/local/bin/snell-server ]; then
        execute_cmd "删除可执行文件" sudo rm -f /usr/local/bin/snell-server
    fi
    
    if [ -f /etc/systemd/system/snell.service ]; then
        execute_cmd "删除服务文件" sudo rm -f /etc/systemd/system/snell.service
    fi
    
    if [ -d /etc/snell ]; then
        log_info "发现配置目录，将创建备份..."
        local backup_dir="/etc/snell.bak.$(date +%Y%m%d%H%M%S)"
        execute_cmd "备份配置目录" sudo mv /etc/snell "$backup_dir"
        log_info "配置已备份到: $backup_dir"
    fi
    
    execute_cmd "重新加载systemd配置" sudo systemctl daemon-reload
    log_info "Snell 服务已卸载。"
}

# 显示使用帮助
show_help() {
    cat <<EOF
用法: $SCRIPT_NAME {update|install|restart|stop|status|uninstall}

命令:
  install <版本> <架构> <端口> <密钥>  安装Snell服务
  restart                  重启Snell服务
  stop                     停止Snell服务
  status                   查看Snell服务状态
  uninstall                卸载Snell服务

参数说明:
  <版本>                   Snell版本号，格式为vX.Y.Z，如v4.0.1
  <架构>                   系统架构，可选值为amd64或aarch64
  <端口>                   服务端口，1-65535之间的数字
  <密钥>                   预共享密钥，建议长度不少于8个字符

示例: 
  $SCRIPT_NAME install v4.0.1 amd64 8388 YourPassword123
EOF
}

# 根据命令行参数执行不同功能
case "${1:-}" in
    install)
        SNELL_VERSION="${2:-}"
        SNELL_ARCH="${3:-}"
        SNELL_PORT="${4:-}"
        SNELL_PSK="${5:-}"
        
        if [ -z "${SNELL_VERSION:-}" ] || [ -z "${SNELL_ARCH:-}" ] || [ -z "${SNELL_PORT:-}" ] || [ -z "${SNELL_PSK:-}" ]; then
            log_error "安装Snell需要提供所有参数: SNELL_VERSION, SNELL_ARCH, SNELL_PORT, SNELL_PSK"
            show_help
            exit 1
        fi
        install_snell
        ;;
    restart)
        restart_snell
        ;;
    stop)
        stop_snell
        ;;
    status)
        status_snell
        ;;
    uninstall)
        uninstall_snell
        ;;
    *)
        show_help
        exit 1
        ;;
esac

exit 0
