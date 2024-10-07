#!/bin/bash

# 更新系统包并安装必要的软件
echo "正在更新系统包..."
sudo apt update && sudo apt upgrade -y && apt full-upgrade -y && apt autoclean -y && apt autoremove -y

Update_Shell(){
    wget -N "https://raw.githubusercontent.com/AlexKris/profile/main/tool/ssrust.sh" -O ssrust.sh && bash ssrust.sh
}

# 安装 Docker
install_docker() {
    echo "正在检查 Docker 是否已安装..."
    if ! command -v docker &> /dev/null; then
        echo "Docker 未安装，开始安装 Docker..."
        sudo apt install docker.io -y
        if [ $? -ne 0 ]; then
            echo "Docker 安装失败，退出..."
            exit 1
        fi
    else
        echo "Docker 已经安装."
    fi
}

# 安装 Docker Compose
install_docker_compose() {
    echo "正在检查 Docker Compose 是否已安装..."
    if ! command -v docker-compose &> /dev/null; then
        echo "Docker Compose 未安装，开始安装 Docker Compose..."
        sudo apt install docker-compose -y
        if [ $? -ne 0 ]; then
            echo "Docker Compose 安装失败，退出..."
            exit 1
        fi
    else
        echo "Docker Compose 已经安装."
    fi
}

# 配置和启动 shadowsocks-rust
configure_and_start_ssrust() {
    echo "开始配置 shadowsocks-rust"
    mkdir -p /root/ssrust/conf
    mkdir -p /root/ssrust/docker

    read -p "请输入 Shadowsocks 监听端口: " port
    read -sp "请输入 Shadowsocks 密码: " password
    echo # 新行
    read -p "请输入 docker-compose 版本: " docker_compose_version
    echo "请选择网络模式：1) bridge（默认） 2) host"
    read -p "输入选择（默认为 1）: " network_mode_choice

    network_mode="bridge"
    if [ "$network_mode_choice" == "2" ]; then
        network_mode="host"
    fi

    # 创建 shadowsocks-rust 配置文件
    cat > /root/ssrust/conf/config.json <<EOF
{
    "servers": [
        {
            "server": "0.0.0.0",
            "server_port": $port,
            "method": "aes-128-gcm",
            "password": "$password",
            "timeout": 300,
            "nameserver": "8.8.8.8,1.1.1.1",
            "mode": "tcp_and_udp",
            "fast_open": true
        }
    ]
}
EOF

    # 创建 Docker Compose 文件
    if [ "$network_mode" == "host" ]; then
        cat > /root/ssrust/docker/docker-compose.yml <<EOF
version: "$docker_compose_version"
services:
  shadowsocks:
    image: teddysun/shadowsocks-rust:latest
    container_name: ss-rust
    restart: always
    network_mode: host
    volumes:
      - /root/ssrust/conf:/etc/shadowsocks-rust
EOF
    else
        cat > /root/ssrust/docker/docker-compose.yml <<EOF
version: "$docker_compose_version"
services:
  shadowsocks:
    image: teddysun/shadowsocks-rust:latest
    container_name: ss-rust
    restart: always
    network_mode: bridge
    ports:
      - "$port:$port"
      - "$port:$port/udp"
    volumes:
      - /root/ssrust/conf:/etc/shadowsocks-rust
EOF
    fi

    # 启动 shadowsocks-rust 服务
    echo "正在启动 shadowsocks-rust 服务"
    cd /root/ssrust/docker
    docker-compose down && docker-compose up -d
    if [ $? -eq 0 ]; then
        echo "shadowsocks-rust 配置并启动完成."
    else
        echo "服务启动失败，请检查日志."
    fi
}

# 停止 shadowsocks-rust
stop_ssrust() {
    echo "正在停止 shadowsocks-rust"
    cd /root/ssrust/docker
    docker-compose down
    echo "shadowsocks-rust 已停止."
}

# 卸载 Docker 和 Docker Compose
uninstall_docker_and_compose() {
    echo "正在卸载 Docker 和 Docker Compose..."
    sudo apt purge docker-compose -y && sudo apt autoremove --purge docker-compose -y
    sudo apt purge docker.io -y && sudo apt autoremove --purge docker.io -y
    echo "Docker 和 Docker Compose 已卸载完成."
}

# 清理 shadowsocks-rust 配置
cleanup_ssrust() {
    echo "正在清理 shadowsocks-rust 配置..."
    rm -rf /root/ssrust
    echo "shadowsocks-rust 配置已清理完成."
}

# 主逻辑
echo "1. 更新脚本"
echo "2. 安装 Docker 和 Docker Compose, 配置和启动 shadowsocks-rust"
echo "3. 安装 Docker 和 Docker Compose"
echo "4. 配置和启动 shadowsocks-rust"
echo "5. 停止 shadowsocks-rust"
echo "6. 卸载 Docker 和 Docker Compose"
echo "7. 清理 shadowsocks-rust 配置"
read -p "请选择一个操作: " action

case $action in
    1)
        Update_Shell
        ;;
    2)
        install_docker
        install_docker_compose
        configure_and_start_ssrust
        ;;
    3)
        install_docker
        install_docker_compose
        ;;
    4)
        configure_and_start_ssrust
        ;;
    5)
        stop_ssrust
        ;;
    6)
        uninstall_docker_and_compose
        ;;
    7)
        cleanup_ssrust
        ;;
    *)
        echo "输入无效，退出..."
        exit 1
        ;;
esac