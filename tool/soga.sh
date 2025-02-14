#!/bin/bash

# 判断是否传入足够的参数
if [ "$#" -ne 3 ]; then
    echo "用法: $0 <PANEL_URL> <PANEL_KEY> <NODE_ID>"
    exit 1
fi

# 参数赋值
PANEL_URL="$1"
PANEL_KEY="$2"
NODE_ID="$3"

# 更新脚本函数
update_shell(){
    wget -N "https://raw.githubusercontent.com/AlexKris/profile/main/tool/soga.sh" -O soga.sh && bash soga.sh
}

# 更新系统包并安装必要的软件
update_system() {
    echo -e "[信息] 正在更新系统包..."
    sudo apt update && sudo apt upgrade -y && sudo apt full-upgrade -y && sudo apt autoclean -y && sudo apt autoremove -y
}

# 安装Docker
install_docker(){
    echo -e "[信息] 正在安装 Docker..."
    curl -fsSL https://get.docker.com | bash
    echo -e "[信息] Docker 已经安装..."
}

# 配置并运行soga
config_run_soga(){
    echo -e "[信息] 正在安装 soga..."
    docker run --restart=always --name sogass -d \
    -v /etc/soga/:/etc/soga/ --network host \
    -e type=v2board \
    -e server_type=ss \
    -e node_id=$3 \
    -e api=webapi \
    -e webapi_url=$1 \
    -e webapi_key=$2 \
    -e forbidden_bit_torrent=true \
    -e log_level=info \
    vaxilu/soga
    echo -e "[信息] soga 已经安装..."
}

update_system
install_docker
config_run_soga "$PANEL_URL" "$PANEL_KEY" "$NODE_ID"
