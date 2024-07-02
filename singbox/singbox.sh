#!/bin/bash

# 更新系统包并安装必要的软件
echo "更新系统包..."
sudo apt update && sudo apt upgrade -y
# sudo apt install -y apt-transport-https ca-certificates curl software-properties-common

# 安装 Docker
install_docker() {
    echo "正在检查 Docker 是否已安装..."
    if ! command -v docker &> /dev/null; then
        echo "Docker 未安装，开始安装 Docker..."
        curl -fsSL https://download.docker.com/linux/debian/gpg | sudo apt-key add -
        sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/debian $(lsb_release -cs) stable"
        sudo apt update
        sudo apt install -y docker-ce docker-ce-cli containerd.io
        sudo systemctl start docker
        sudo systemctl enable docker
    else
        echo "Docker 已安装."
    fi
}

# 安装 Docker Compose
install_docker_compose() {
    echo "正在检查 Docker Compose 是否已安装..."
    if ! command -v docker-compose &> /dev/null; then
        echo "Docker Compose 未安装，开始安装 Docker Compose..."
        sudo curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        sudo chmod +x /usr/local/bin/docker-compose
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

    # 创建 Sing-box 配置文件
    cat > /root/sing-box/conf/config.json << EOF
{
    "log": {
        "level": "info",
        "timestamp": true
    },
    "inbounds": [
        {
            "type": "shadowsocks",
            "listen": "::",
            "listen_port": $port,
            "method": "aes-256-gcm",
            "password": "$password"
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
version: "3.8"
services:
  sing-box:
    image: ghcr.io/sagernet/sing-box
    container_name: sing-box
    restart: always
    ports:
      - "$port:$port"
    volumes:
      - /root/sing-box/conf:/etc/sing-box/
    command: -D /var/lib/sing-box -C /etc/sing-box/ run
EOF

    # 启动 Sing-box 服务
    echo "正在启动 Sing-box 服务..."
    cd /root/sing-box/docker
    docker-compose up -d
    echo "Sing-box 配置并启动完成."
}

# 主逻辑
install_docker
install_docker_compose
configure_and_start_singbox
