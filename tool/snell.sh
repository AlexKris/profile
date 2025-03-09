#!/bin/bash

# 参数赋值
SNELL_VERSION="$2"
SNELL_ARCH="$3"
SNELL_PORT="$4"
SNELL_PSK="$5"

# 更新系统包
update_system(){
    if [ -f /etc/debian_version ]; then
        echo -e "[信息] 检测到 Debian/Ubuntu 系统..."
        sudo apt update && sudo apt upgrade -y && sudo apt full-upgrade -y && sudo apt autoclean -y && sudo apt autoremove -y
        
        echo -e "[信息] 正在安装 wget 和 unzip..."
        sudo apt install -y wget unzip
    elif [ -f /etc/redhat-release ]; then
        echo -e "[信息] 检测到 RHEL/CentOS 系统..."
        
        # 检查是否有 dnf（CentOS/RHEL 8+）
        if command -v dnf &> /dev/null; then
            echo -e "[信息] 使用 dnf 包管理器进行更新..."
            sudo dnf update -y
            
            echo -e "[信息] 正在安装 wget unzip..."
            sudo dnf install -y wget unzip
        else
            echo -e "[信息] 使用 yum 包管理器进行更新..."
            sudo yum update -y
            
            echo -e "[信息] 正在安装 wget unzip..."
            sudo yum install -y wget unzip
        fi
    else
        echo -e "[错误] 不支持的操作系统，只支持Debian/Ubuntu和CentOS/RHEL。"
        exit 1
    fi
    if [ $? -ne 0 ]; then
        echo -e "[错误] 系统更新或安装软件包失败，请检查网络连接。"
        exit 1
    fi
    echo -e "[信息] 系统更新完成。"
    echo -e "[信息] wget 和 unzip 安装完成。"
}

# 下载 Snell 服务
download_snell(){
    echo -e "[信息] 正在检查 Snell 是否已安装..."
    if [ -f /usr/local/bin/snell-server ]; then
        echo -e "[信息] Snell 已经安装，将进行覆盖安装。"
    fi

    echo -e "[信息] 正在下载并安装 Snell 服务..."

    SNELL_URL="https://dl.nssurge.com/snell/snell-server-${SNELL_VERSION}-linux-${SNELL_ARCH}.zip"
    
    # 创建临时目录
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"

    echo -e "[信息] 下载 Snell 到临时目录: $TEMP_DIR"
    wget -O snell-server.zip "${SNELL_URL}"
    if [ $? -ne 0 ]; then
        echo -e "[错误] 下载 Snell 失败，请检查网络连接和版本参数。"
        cd - > /dev/null
        rm -rf "$TEMP_DIR"
        exit 1
    fi

    # 验证文件大小确保下载完整
    FILE_SIZE=$(du -b snell-server.zip | cut -f1)
    if [ "$FILE_SIZE" -lt 1000 ]; then
        echo -e "[错误] 下载的文件过小，可能不完整或版本号错误。"
        cd - > /dev/null
        rm -rf "$TEMP_DIR"
        exit 1
    fi

    unzip snell-server.zip
    if [ $? -ne 0 ]; then
        echo -e "[错误] 解压 Snell 失败。"
        cd - > /dev/null
        rm -rf "$TEMP_DIR"
        exit 1
    fi

    if [ ! -f snell-server ]; then
        echo -e "[错误] 解压后未找到 snell-server 文件。"
        cd - > /dev/null
        rm -rf "$TEMP_DIR"
        exit 1
    fi

    sudo mv snell-server /usr/local/bin/
    sudo chmod +x /usr/local/bin/snell-server
    cd - > /dev/null
    rm -rf "$TEMP_DIR"
    echo -e "[信息] Snell 服务已安装。"
}

# 配置 systemd 服务
configure_systemd_service(){
    echo -e "[信息] 正在配置 Snell 的 systemd 服务..."
    sudo bash -c 'cat > /etc/systemd/system/snell.service <<EOF
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

[Install]
WantedBy=multi-user.target
EOF
'
    sudo systemctl daemon-reload
    echo -e "[信息] Snell 的 systemd 服务已配置。"
}

# 配置 Snell 服务
configure_snell(){
    echo -e "[信息] 正在配置 Snell 服务..."

    # 检查端口是否被占用
    if command -v netstat > /dev/null; then
        PORT_CHECK=$(netstat -tuln | grep ":${SNELL_PORT} ")
    elif command -v ss > /dev/null; then
        PORT_CHECK=$(ss -tuln | grep ":${SNELL_PORT} ")
    fi
    
    if [ -n "$PORT_CHECK" ]; then
        echo -e "[警告] 端口 ${SNELL_PORT} 已被占用，可能导致服务无法启动。"
        echo -e "$PORT_CHECK"
    fi

    # 创建配置目录
    sudo mkdir -p /etc/snell

    # 备份现有配置
    if [ -f /etc/snell/snell-server.conf ]; then
        BACKUP_FILE="/etc/snell/snell-server.conf.bak.$(date +%Y%m%d%H%M%S)"
        sudo cp /etc/snell/snell-server.conf "$BACKUP_FILE"
        echo -e "[信息] 已备份原配置文件到 $BACKUP_FILE"
    fi

    sudo bash -c "cat > /etc/snell/snell-server.conf <<EOF
[snell-server]
listen = 0.0.0.0:${SNELL_PORT}
psk = ${SNELL_PSK}
ipv6 = false
EOF
"
    echo -e "[信息] Snell 配置文件已生成。"
    echo -e "[信息] 请保存以下信息："
    echo -e "[信息] 端口: ${SNELL_PORT}"
    echo -e "[信息] 密钥: ${SNELL_PSK}"
}

# 验证安装参数
validate_install_params() {
    # 验证版本号格式
    if ! [[ "$SNELL_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "[错误] 版本号格式不正确，应为 vX.Y.Z 格式，如 v4.0.1"
        return 1
    fi
    
    # 验证架构
    if [ "$SNELL_ARCH" != "amd64" ] && [ "$SNELL_ARCH" != "aarch64" ]; then
        echo "[错误] 不支持的架构，只支持 amd64 或 aarch64"
        return 1
    fi
    
    # 验证端口号
    if ! [[ "$SNELL_PORT" =~ ^[0-9]+$ ]] || [ "$SNELL_PORT" -lt 1 ] || [ "$SNELL_PORT" -gt 65535 ]; then
        echo "[错误] 端口号必须是1-65535之间的数字"
        return 1
    fi
    
    # 验证PSK长度
    if [ ${#SNELL_PSK} -lt 8 ]; then
        echo "[警告] PSK长度小于8个字符，建议使用更长的密钥以提高安全性"
    fi
    
    return 0
}

# 启动 Snell 服务
start_snell(){
    echo -e "[信息] 正在启动 Snell 服务..."
    sudo systemctl enable snell
    if [ $? -ne 0 ]; then
        echo -e "[错误] 无法启用 Snell 服务。"
        return 1
    fi
    
    sudo systemctl restart snell
    if [ $? -ne 0 ]; then
        echo -e "[错误] 无法启动 Snell 服务，请检查配置或端口是否被占用。"
        return 1
    fi
    
    sleep 2
    # 检查服务是否成功启动
    if sudo systemctl is-active snell >/dev/null 2>&1; then
        echo -e "[信息] Snell 服务已成功启动。"
        sudo systemctl status snell --no-pager
    else
        echo -e "[错误] Snell 服务启动失败，请检查日志。"
        sudo systemctl status snell --no-pager
        return 1
    fi
    
    return 0
}

install_snell(){
    # 验证参数
    validate_install_params
    if [ $? -ne 0 ]; then
        echo "[错误] 参数验证失败，无法继续安装。"
        exit 1
    fi
    
    download_snell
    configure_systemd_service
    configure_snell
    if ! start_snell; then
        echo -e "[警告] Snell 服务启动失败，但安装过程已完成。"
        echo -e "[警告] 请检查配置文件和系统日志，然后尝试手动启动服务。"
    fi
}

# 停止 Snell 服务
stop_snell(){
    echo -e "[信息] 停止 Snell 服务..."
    sudo systemctl stop snell
}

# 重启 Snell 服务
restart_snell(){
    echo -e "[信息] 重启 Snell 服务..."
    sudo systemctl restart snell
    sleep 2
    sudo systemctl status snell --no-pager
}

# 查看 Snell 服务状态
status_snell(){
    echo -e "[信息] 获取 Snell 服务状态..."
    sudo systemctl status snell --no-pager
}

# 卸载 Snell 服务
uninstall_snell(){
    echo -e "[信息] 卸载 Snell 服务..."
    sudo systemctl stop snell
    sudo systemctl disable snell
    sudo rm -f /usr/local/bin/snell-server
    sudo rm -f /etc/systemd/system/snell.service
    sudo rm -rf /etc/snell
    sudo systemctl daemon-reload
    echo -e "[信息] Snell 服务已卸载。"
}

# 根据命令行参数执行不同功能
case "$1" in
    update)
        update_system
        ;;
    install)
        if [ -z "$SNELL_VERSION" ] || [ -z "$SNELL_ARCH" ] || [ -z "$SNELL_PORT" ] || [ -z "$SNELL_PSK" ]; then
            echo "[错误] 安装Snell需要提供所有参数: SNELL_VERSION, SNELL_ARCH, SNELL_PORT, SNELL_PSK"
            echo "用法: $0 install <SNELL_VERSION> <SNELL_ARCH> <SNELL_PORT> <SNELL_PSK>"
            echo ""
            echo "参数说明:"
            echo "  SNELL_VERSION: Snell版本号，格式为vX.Y.Z，如v4.0.1"
            echo "  SNELL_ARCH: 系统架构，可选值为amd64或aarch64"
            echo "  SNELL_PORT: 服务端口，1-65535之间的数字"
            echo "  SNELL_PSK: 预共享密钥，建议长度不少于8个字符"
            echo ""
            echo "示例: $0 install v4.0.1 amd64 8388 YourPassword123"
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
        echo "用法: $0 {update|install|restart|stop|status|uninstall}"
        echo " - 更新系统 update"
        echo " - 安装Snell install <SNELL_VERSION> <SNELL_ARCH> <SNELL_PORT> <SNELL_PSK>"
        echo " - 重启Snell restart"
        echo " - 停止Snell stop"
        echo " - 查看Snell状态 status"
        echo " - 卸载Snell uninstall"
        exit 1
        ;;
esac

exit 0