#!/bin/bash

# 启用错误处理
set -euo pipefail

# 更新系统包
update_system(){
    if [ -f /etc/debian_version ]; then
        echo -e "[信息] 检测到 Debian/Ubuntu 系统..."
        sudo apt update && sudo apt upgrade -y && sudo apt full-upgrade -y && sudo apt autoclean -y && sudo apt autoremove -y
    elif [ -f /etc/redhat-release ]; then
        echo -e "[信息] 检测到 RHEL/CentOS 系统..."
        
        # 检查是否有 dnf（CentOS/RHEL 8+）
        if command -v dnf &> /dev/null; then
            echo -e "[信息] 使用 dnf 包管理器进行更新..."
            sudo dnf update -y
        else
            echo -e "[信息] 使用 yum 包管理器进行更新..."
            sudo yum update -y
        fi
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

# 检查并安装 Docker
install_docker(){
    if command -v docker &> /dev/null; then
        echo -e "[信息] Docker 已经安装，检查 Docker 服务状态..."
        if ! systemctl is-active --quiet docker; then
            echo -e "[信息] Docker 服务未运行，正在启动..."
            sudo systemctl start docker
            sudo systemctl enable docker
        fi
        return
    fi
    echo -e "[信息] 正在安装 Docker..."
    curl -fsSL https://get.docker.com | bash
    if [ $? -ne 0 ]; then
        echo -e "[错误] 安装 Docker 失败，请检查网络连接。"
        exit 1
    fi
    sudo systemctl enable docker
    sudo systemctl start docker
    echo -e "[信息] Docker 已安装并启动..."
}

# 检查并删除已存在的容器
check_remove_container(){
    local CONTAINER_NAME="$1"
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

# 验证输入参数格式
validate_params() {
    local PANEL_URL="$1"
    local NODE_ID="$2"
    
    # 验证PANEL_URL格式
    if [[ ! "$PANEL_URL" =~ ^https?:// ]]; then
        echo -e "[错误] PANEL_URL 格式错误，必须以 http:// 或 https:// 开头"
        exit 1
    fi
    
    # 验证NODE_ID是否为数字
    if ! [[ "$NODE_ID" =~ ^[0-9]+$ ]]; then
        echo -e "[错误] NODE_ID 必须为数字"
        exit 1
    fi
}

# 配置并运行 soga
config_run_soga(){
    local CONTAINER_NAME="$1"
    local PANEL_URL="$2"
    local PANEL_KEY="$3"
    local NODE_ID="$4"
    
    echo -e "[信息] 正在安装 soga..."
    docker run --restart=always --name "$CONTAINER_NAME" -d \
    -v /etc/soga/:/etc/soga/ \
    --network host \
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
    local CONTAINER_NAME="$1"
    local PANEL_URL="$2"
    local PANEL_KEY="$3"
    local NODE_ID="$4"
    
    validate_params "$PANEL_URL" "$NODE_ID"
    install_docker
    check_remove_container "$CONTAINER_NAME"
    config_run_soga "$CONTAINER_NAME" "$PANEL_URL" "$PANEL_KEY" "$NODE_ID"
}

# 重启 soga
restart_soga(){
    local CONTAINER_NAME="$1"
    echo -e "[信息] 正在重启 soga..."
    docker restart "$CONTAINER_NAME"
    if [ $? -ne 0 ]; then
        echo -e "[错误] 重启 soga 失败，请检查容器是否存在。"
        exit 1
    fi
    echo -e "[信息] soga 已经重启..."
}

# 停止并删除 soga 容器
stop_soga(){
    local CONTAINER_NAME="$1"
    echo -e "[信息] 检查是否存在 $CONTAINER_NAME 容器..."
    if docker ps -a | grep -q "$CONTAINER_NAME"; then
        echo -e "[信息] 发现已存在的 $CONTAINER_NAME 容器，正在停止并删除..."
        docker stop "$CONTAINER_NAME" >/dev/null 2>&1
        docker rm "$CONTAINER_NAME" >/dev/null 2>&1
        echo -e "[信息] 已删除旧的 $CONTAINER_NAME 容器"
    else
        echo -e "[信息] 未发现已存在的 $CONTAINER_NAME 容器"
    fi
}

# 根据命令行参数执行不同功能
case "$1" in
    update)
        update_system
        ;;
    install)
        if [ -z "${2:-}" ] || [ -z "${3:-}" ] || [ -z "${4:-}" ] || [ -z "${5:-}" ]; then
            echo "[错误] 安装soga需要提供所有参数: CONTAINER_NAME, PANEL_URL, PANEL_KEY, NODE_ID"
            echo "用法: $0 install <CONTAINER_NAME> <PANEL_URL> <PANEL_KEY> <NODE_ID>"
            exit 1
        fi
        install_soga "$2" "$3" "$4" "$5"
        ;;
    restart)
        if [ -z "${2:-}" ]; then
            echo "[错误] 重启soga需要提供容器名"
            echo "用法: $0 restart <CONTAINER_NAME>"
            exit 1
        fi
        restart_soga "$2"
        ;;
    stop)
        if [ -z "${2:-}" ]; then
            echo "[错误] 停止soga需要提供容器名"
            echo "用法: $0 stop <CONTAINER_NAME>"
            exit 1
        fi
        stop_soga "$2"
        ;;
    *)
        echo "用法: $0 {update|install|restart|stop}"
        echo " - 更新系统 update"
        echo " - 安装soga install <CONTAINER_NAME> <PANEL_URL> <PANEL_KEY> <NODE_ID>"
        echo " - 重启soga restart <CONTAINER_NAME>"
        echo " - 停止soga stop <CONTAINER_NAME>"
        exit 1
        ;;
esac

exit 0