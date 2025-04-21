#!/bin/bash
# ssrust.sh - Shadowsocks Rust Server Management Script
# This script manages installation and operations of Shadowsocks Rust server in Docker

# Exit on error, undefined variables, and pipe failures
set -euo pipefail

SSRUST_BASE_DIR="/root/ssrust"
SSRUST_CONFIG_DIR="${SSRUST_BASE_DIR}/conf"
DOCKER_IMAGE="ghcr.io/shadowsocks/ssserver-rust:latest"
DOCKER_COMPOSE_CMD="docker compose"

# Function for logging
log() {
    local level="$1"
    local message="$2"
    case "$level" in
        "info")  echo "[INFO] $message" ;;
        "warn")  echo "[WARN] $message" ;;
        "error") echo "[ERROR] $message" ;;
    esac
}

# Check if running as root or with sudo
check_privileges() {
    if [ "$(id -u)" -ne 0 ]; then
        log "error" "This script must be run as root or with sudo"
        exit 1
    fi
}

# Handle cleanup on script interruption
cleanup() {
    log "info" "Script interrupted, cleaning up..."
    exit 1
}

trap cleanup SIGINT SIGTERM

# 参数赋值 - Remove global parameter assignment
# CONTAINER_NAME="$2"
# PORT="$3"
# PASSWORD="$4"
# ENC_METHOD="$5"

# 更新系统包
update_system() {
    if [ -f /etc/debian_version ]; then
        log "info" "检测到 Debian/Ubuntu 系统..."
        apt update && apt upgrade -y && apt full-upgrade -y && apt autoclean -y && apt autoremove -y
    elif [ -f /etc/redhat-release ]; then
        log "info" "检测到 RHEL/CentOS 系统..."
        
        # 检查是否有 dnf（CentOS/RHEL 8+）
        if command -v dnf &> /dev/null; then
            log "info" "使用 dnf 包管理器进行更新..."
            dnf update -y
        else
            log "info" "使用 yum 包管理器进行更新..."
            yum update -y
        fi
    else
        log "error" "不支持的操作系统，只支持Debian/Ubuntu和CentOS/RHEL。"
        exit 1
    fi
    if [ $? -ne 0 ]; then
        log "error" "系统更新或安装软件包失败，请检查网络连接。"
        exit 1
    fi
    log "info" "系统更新完成。"
}

# 安装 Docker
install_docker() {
    if command -v docker &> /dev/null; then
        log "info" "Docker 已经安装，跳过安装步骤..."
        # Check Docker version
        docker_version=$(docker --version | cut -d ' ' -f3 | cut -d ',' -f1)
        log "info" "当前 Docker 版本: $docker_version"
        return
    fi
    
    log "info" "正在安装 Docker..."
    if ! command -v curl &> /dev/null; then
        log "error" "未找到 curl 命令，请先安装 curl"
        exit 1
    fi
    
    curl -fsSL https://get.docker.com | bash
    if [ $? -ne 0 ]; then
        log "error" "安装 Docker 失败，请检查网络连接。"
        exit 1
    fi
    
    # Enable and start Docker service
    systemctl enable docker
    systemctl start docker
    
    log "info" "Docker 已经安装完成。"
}

# 检查并删除已存在的容器
check_remove_container() {
    log "info" "检查是否存在通过docker run方式启动的旧容器..."

    # 检查是否存在直接通过docker run启动的容器
    # 使用inspect检查容器是否由docker-compose启动
    if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        # 检查容器是否有docker-compose标签
        if ! docker inspect "${CONTAINER_NAME}" 2>/dev/null | grep -q "com.docker.compose"; then
            log "info" "发现通过docker run直接启动的 ${CONTAINER_NAME} 容器，正在停止并删除..."
            if ! docker stop "${CONTAINER_NAME}" >/dev/null 2>&1; then
                log "warn" "停止容器 ${CONTAINER_NAME} 失败"
            fi
            if ! docker rm "${CONTAINER_NAME}" >/dev/null 2>&1; then
                log "warn" "删除容器 ${CONTAINER_NAME} 失败"
            fi
            log "info" "已删除通过docker run启动的旧容器"
        else
            log "info" "发现通过docker compose启动的 ${CONTAINER_NAME} 容器，不进行处理"
        fi
    else
        log "info" "未发现名为 ${CONTAINER_NAME} 的容器"
    fi
}

# 配置并运行 ssrust
config_run_ssrust() {
    log "info" "正在拉取 ssrust 镜像..."
    docker pull ghcr.io/shadowsocks/ssserver-rust

    log "info" "正在启动 ssrust 容器..."
    docker run --entrypoint ssserver --restart=always --name "${CONTAINER_NAME}" -d \
    --net=host \
    --log-driver json-file \
    --log-opt max-size=10m \
    --log-opt max-file=3 \
    ghcr.io/shadowsocks/ssserver-rust \
    -s "[::]:${PORT}" -m "${ENC_METHOD}" -k "${PASSWORD}" -U

    if [ $? -ne 0 ]; then
        log "error" "启动 ssrust 容器失败"
        exit 1
    fi

    log "info" "检查容器是否正常运行..."
    sleep 2
    if ! docker ps | grep -q "${CONTAINER_NAME}"; then
        log "error" "容器没有正常运行，请检查日志"
        docker logs "${CONTAINER_NAME}"
        exit 1
    fi

    log "info" "ssrust 已经成功安装并启动"
    log "info" "服务信息:"
    log "info" "端口: ${PORT}"
    log "info" "加密方式: ${ENC_METHOD}"
}

config_run_ssrust_compose() {
    log "info" "开始配置 shadowsocks-rust..."
    mkdir -p "$SSRUST_CONFIG_DIR"

    cat > "$SSRUST_CONFIG_DIR/config.json" <<EOF
{
    "servers": [
        {
            "server": "0.0.0.0",
            "server_port": $PORT,
            "method": "$ENC_METHOD",
            "password": "$PASSWORD",
            "timeout": 300,
            "mode": "tcp_and_udp",
            "fast_open": true
        }
    ]
}
EOF

    cat > "$SSRUST_BASE_DIR/docker-compose.yml" <<EOF
services:
  shadowsocks:
    image: $DOCKER_IMAGE
    container_name: ${CONTAINER_NAME}
    restart: always
    network_mode: host
    volumes:
      - $SSRUST_CONFIG_DIR:/etc/shadowsocks-rust
EOF

    log "info" "正在启动 shadowsocks-rust ..."
    cd "$SSRUST_BASE_DIR"
    $DOCKER_COMPOSE_CMD down
    $DOCKER_COMPOSE_CMD up -d

    if [ $? -eq 0 ]; then
        log "info" "ssrust 已经成功安装并启动"
        log "info" "服务信息:"
        log "info" "端口: ${PORT}"
        log "info" "加密方式: ${ENC_METHOD}"
    else
        log "error" "服务启动失败，请检查日志."
    fi
}

# 安装 ssrust
install_ssrust() {
    check_privileges
    install_docker
    check_remove_container
    config_run_ssrust_compose
}

# 重启 ssrust
restart_ssrust() {
    log "info" "正在重启 shadowsocks-rust..."
    cd "$SSRUST_BASE_DIR"
    if ! $DOCKER_COMPOSE_CMD restart; then
        log "error" "重启 shadowsocks-rust 失败"
        exit 1
    fi
    log "info" "shadowsocks-rust 已经重启成功"
}

stop_ssrust() {
    log "info" "正在停止 shadowsocks-rust..."
    cd "$SSRUST_BASE_DIR"
    if ! $DOCKER_COMPOSE_CMD down; then
        log "error" "停止 shadowsocks-rust 失败"
        exit 1
    fi
    log "info" "shadowsocks-rust 已经停止成功"
}

# 显示使用帮助
show_help() {
    echo "用法: $0 {update|install|restart|stop}"
    echo " - 更新系统:  $0 update"
    echo " - 安装ssrust: $0 install <CONTAINER_NAME> <PORT> <PASSWORD> <ENC_METHOD>"
    echo " - 重启ssrust: $0 restart"
    echo " - 停止ssrust: $0 stop"
}

# 根据命令行参数执行不同功能
case "$1" in
    update)
        check_privileges
        update_system
        ;;
    install)
        # Moved parameter assignment here
        CONTAINER_NAME="${2:-}"
        PORT="${3:-}"
        PASSWORD="${4:-}"
        ENC_METHOD="${5:-}"
        
        if [ -z "${CONTAINER_NAME}" ] || [ -z "${PORT}" ] || [ -z "${PASSWORD}" ] || [ -z "${ENC_METHOD}" ]; then
            log "error" "安装ssrust需要提供所有参数: CONTAINER_NAME, PORT, PASSWORD, ENC_METHOD"
            show_help
            exit 1
        fi
        install_ssrust
        ;;
    restart)
        check_privileges
        restart_ssrust
        ;;
    stop)
        check_privileges
        stop_ssrust
        ;;
    *)
        show_help
        exit 1
        ;;
esac

exit 0