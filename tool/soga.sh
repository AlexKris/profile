#!/bin/bash

# 判断是否传入足够的参数（现在只需传入 PANEL_URL 和 PANEL_KEY）
if [ "$#" -ne 2 ]; then
    echo "用法: $0 <PANEL_URL> <PANEL_KEY>"
    exit 1
fi

# 参数赋值
PANEL_URL="$1"
PANEL_KEY="$2"
CONTAINER_NAME="sogass"

# 运行时输入 NODE_ID
read -p "请输入 NODE_ID: " NODE_ID

# 更新系统包并安装必要的软件
update_system() {
    echo -e "[信息] 正在更新系统包..."
    sudo apt update && sudo apt upgrade -y && sudo apt full-upgrade -y && sudo apt autoclean -y && sudo apt autoremove -y
}

# 安装 Docker
install_docker(){
    echo -e "[信息] 正在安装 Docker..."
    curl -fsSL https://get.docker.com | bash
    echo -e "[信息] Docker 已经安装..."
}

# 检查并删除已存在的容器
check_remove_container() {
    echo -e "[信息] 检查是否存在旧的 $CONTAINER_NAME 容器..."
    if docker ps -a | grep -q "$CONTAINER_NAME"; then
        echo -e "[信息] 发现已存在的 $CONTAINER_NAME 容器，正在停止并删除..."
        docker stop "$CONTAINER_NAME" >/dev/null 2>&1
        docker rm "$CONTAINER_NAME" >/dev/null 2>&1
        echo -e "[信息] 已删除旧的 $CONTAINER_NAME 容器"
    else
        echo -e "[信息] 未发现已存在的 $CONTAINER_NAME 容器"
    fi
}

# 配置并运行 soga
config_run_soga(){
    echo -e "[信息] 正在安装 soga..."
    docker run --restart=always --name "$CONTAINER_NAME" -d \
    -v /etc/soga/:/etc/soga/ --network host \
    -e type=v2board \
    -e server_type=ss \
    -e node_id="$NODE_ID" \
    -e api=webapi \
    -e webapi_url="$PANEL_URL" \
    -e webapi_key="$PANEL_KEY" \
    -e forbidden_bit_torrent=true \
    -e log_level=info \
    vaxilu/soga
    echo -e "[信息] soga 已经安装..."
}

update_system
install_docker
check_remove_container
config_run_soga