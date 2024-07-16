#!/bin/bash

# 更新系统包并安装必要的软件
echo "更新系统包..."
sudo apt update && sudo apt upgrade -y

# 安装 Docker
install_docker() {
    echo "正在检查 Docker 是否已安装..."
    if ! command -v docker &> /dev/null; then
        echo "Docker 未安装，开始安装 Docker..."
        sudo apt install docker.io -y
    else
        echo "Docker 已安装."
    fi
}

# 安装 Docker Compose
install_docker_compose() {
    echo "正在检查 Docker Compose 是否已安装..."
    if ! command -v docker-compose &> /dev/null; then
        echo "Docker Compose 未安装，开始安装 Docker Compose..."
        sudo apt install docker-compose -y
    else
        echo "Docker Compose 已安装."
    fi
}

# 配置和启动 Sing-box
configure_and_start_singbox() {
    echo "开始配置 Sing-box..."
    mkdir -p /root/sing-box/conf
    mkdir -p /root/sing-box/docker

    read -p "请输入 Shadowsocks 监听端口: " port
    read -p "请输入 Shadowsocks 密码: " password
    read -p "请输入 docker-compose 版本: " docker_compose_version

    # 创建 Sing-box 配置文件
    cat > /root/sing-box/conf/config.json << EOF
{
    "log": {
        "level": "error",
        "timestamp": true
    },
    "inbounds": [
        {
            "type": "shadowsocks",
            "listen": "::",
            "listen_port": $port,
            "method": "aes-256-gcm",
            "password": "$password",
            "multiplex": {
                "enabled": true
            }
        }
    ],
    "outbounds": [
        {
            "type": "direct",
            "tag": "direct-out"
        }
    ]
}
EOF

    # 创建 Docker Compose 文件
    cat > /root/sing-box/docker/docker-compose.yml << EOF
version: "$docker_compose_version"
services:
  sing-box:
    image: ghcr.io/sagernet/sing-box
    container_name: sing-box
    restart: always
    ports:
      - "$port:$port"
      - "$port:$port/udp"
    volumes:
      - /root/sing-box/conf:/etc/sing-box/
    command: -D /var/lib/sing-box -C /etc/sing-box/ run
EOF

    # 启动 Sing-box 服务
    echo "正在启动 Sing-box 服务..."
    cd /root/sing-box/docker
    docker-compose down && docker-compose up -d
    echo "Sing-box 配置并启动完成."
}

# 卸载 Docker 和 Docker Compose
uninstall_docker_and_compose() {
    echo "卸载 Docker 和 Docker Compose..."
    sudo apt-get remove --auto-remove docker docker-engine docker.io containerd runc docker-compose -y
    echo "Docker 和 Docker Compose 卸载完成."
}

# 清理 Sing-box 配置
cleanup_singbox() {
    echo "清理 Sing-box 配置..."
    rm -rf /root/sing-box
    echo "Sing-box 配置已清理."
}

start_snell() {
    echo "开始启动 Snell..."
    systemctl start snell && systemctl enable snell
    echo "Snell 启动完成."
}

# 主逻辑
echo "1. 安装 Docker 和 Docker Compose, 配置和启动 Sing-box"
echo "2. 安装 Docker 和 Docker Compose"
echo "3. 配置和启动 Sing-box"
echo "4. 卸载 Docker 和 Docker Compose"
echo "5. 清理 Sing-box 配置"
echo "5. 启动 Snell"
read -p "请选择一个操作: " action

case $action in
    1)
        install_docker
        install_docker_compose
        configure_and_start_singbox
        ;;
    2)
        install_docker
        install_docker_compose
        ;;
    3)
        configure_and_start_singbox
        ;;
    4)
        uninstall_docker_and_compose
        ;;
    5)
        cleanup_singbox
        ;;
    6)
        start_snell
        ;;
    *)
        echo "无效的输入，退出..."
        exit 1
        ;;
esac