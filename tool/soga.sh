#!/bin/bash

# 参数赋值
PANEL_URL="$2"
PANEL_KEY="$3"
CONTAINER_NAME="$4"
NODE_ID="$5"

# 更新系统包
update_system(){
    if [ -f /etc/debian_version ]; then
        echo -e "[信息] 正在更新系统包..."
        sudo apt update && sudo apt upgrade -y && sudo apt full-upgrade -y && sudo apt autoclean -y && sudo apt autoremove -y
    elif [ -f /etc/redhat-release ]; then
        echo -e "[信息] 正在更新系统包..."
        sudo yum update -y
    else
        echo -e "[错误] 不支持的操作系统，只支持Debian/Ubuntu和CentOS/RHEL。"
        exit 1
    fi
    if [ $? -ne 0 ]; then
        echo -e "[错误] 系统更新失败，请检查网络连接。"
        exit 1
    fi
    echo -e "[信息] 系统更新完成。"
}

# 安装 Docker
install_docker(){
    if command -v docker &> /dev/null; then
        echo -e "[信息] Docker 已经安装，跳过安装步骤..."
        return
    fi
    echo -e "[信息] 正在安装 Docker..."
    curl -fsSL https://get.docker.com | bash
    if [ $? -ne 0 ]; then
        echo -e "[错误] 安装 Docker 失败，请检查网络连接。"
        exit 1
    fi
    echo -e "[信息] Docker 已经安装..."
}

# 检查并删除已存在的容器
check_remove_container(){
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

# 安装 soga
install_soga(){
    install_docker
    check_remove_container
    config_run_soga
}

# 重启 soga
restart_soga(){
    echo -e "[信息] 正在重启 soga..."
    docker restart "$CONTAINER_NAME"
    echo -e "[信息] soga 已经重启..."
}

# 根据命令行参数执行不同功能
case "$1" in
    update)
        update_system
        ;;
    install)
        if [ -z "$PANEL_URL" ] || [ -z "$PANEL_KEY" ] || [ -z "$CONTAINER_NAME" ] || [ -z "$NODE_ID" ]; then
            echo "[错误] 安装soga需要提供所有参数: PANEL_URL, PANEL_KEY, CONTAINER_NAME, NODE_ID"
            echo "用法: $0 install <PANEL_URL> <PANEL_KEY> <CONTAINER_NAME> <NODE_ID>"
            exit 1
        fi
        install_soga
        ;;
    restart)
        CONTAINER_NAME="$2"
        if [ -z "$CONTAINER_NAME" ]; then
            echo "[错误] 重启soga需要提供容器名"
            echo "用法: $0 restart <CONTAINER_NAME>"
            exit 1
        fi
        restart_soga
        ;;
    *)
        echo "用法: $0 {update|install|restart}"
        echo " - 更新系统 update"
        echo " - 安装soga install <PANEL_URL> <PANEL_KEY> <CONTAINER_NAME> <NODE_ID>"
        echo " - 重启soga restart <CONTAINER_NAME>"
        exit 1
        ;;
esac

exit 0