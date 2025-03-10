#!/bin/bash

# 参数赋值
CONTAINER_NAME="$2"
PORT="$3"
PASSWORD="$4"
ENC_METHOD="$5"

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
        echo -e "[错误] 系统更新或安装软件包失败，请检查网络连接。"
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

# 配置并运行 ssrust
config_run_ssrust(){
    echo -e "[信息] 正在安装 ssrust..."
    docker run --restart=always --name "$CONTAINER_NAME" -d \
    --net=host \
    --log-driver json-file \
    --log-opt max-size=10m \
    --log-opt max-file=3 \
    ghcr.io/shadowsocks/ssserver-rust \
    -s "[::]:$PORT" -m "$ENC_METHOD" -k "$PASSWORD" -U
    echo -e "[信息] ssrust 已经安装..."
}

# 安装 ssrust
install_ssrust(){
    install_docker
    check_remove_container
    config_run_ssrust
}

# 重启 ssrust
restart_ssrust(){
    echo -e "[信息] 正在重启 ssrust..."
    docker restart "$CONTAINER_NAME"
    echo -e "[信息] ssrust 已经重启..."
}

stop_ssrust(){
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
        if [ -z "$CONTAINER_NAME" ] || [ -z "$PORT" ] || [ -z "$PASSWORD" ] || [ -z "$ENC_METHOD" ]; then
            echo "[错误] 安装ssrust需要提供所有参数: CONTAINER_NAME, PORT, PASSWORD, ENC_METHOD"
            echo "用法: $0 install <CONTAINER_NAME> <PORT> <PASSWORD> <ENC_METHOD>"
            exit 1
        fi
        install_ssrust
        ;;
    restart)
        CONTAINER_NAME="$2"
        if [ -z "$CONTAINER_NAME" ]; then
            echo "[错误] 重启ssrust需要提供容器名"
            echo "用法: $0 restart <CONTAINER_NAME>"
            exit 1
        fi
        restart_ssrust
        ;;
    stop)
        CONTAINER_NAME="$2"
        if [ -z "$CONTAINER_NAME" ]; then
            echo "[错误] 停止ssrust需要提供容器名"
            echo "用法: $0 stop <CONTAINER_NAME>"
            exit 1
        fi
        stop_ssrust
        ;;
    *)
        echo "用法: $0 {update|install|restart|stop}"
        echo " - 更新系统 update"
        echo " - 安装ssrust install <CONTAINER_NAME> <PORT> <PASSWORD> <ENC_METHOD>"
        echo " - 重启ssrust restart <CONTAINER_NAME>"
        echo " - 停止ssrust stop <CONTAINER_NAME>"
        exit 1
        ;;
esac

exit 0