#!/bin/bash

# 启用错误处理
set -euo pipefail

SOGA_BASE_DIR="/root/soga"
SOGA_CONFIG_DIR="/etc/soga"
DOCKER_IMAGE="vaxilu/soga:latest"
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
            cd "$SOGA_BASE_DIR"
            $DOCKER_COMPOSE_CMD down
        fi
    else
        log "info" "未发现名为 ${CONTAINER_NAME} 的容器"
    fi
}

# 验证输入参数格式
validate_params() {
    local PANEL_URL="$1"
    local NODE_ID="$2"
    
    # 验证PANEL_URL格式
    if [[ ! "$PANEL_URL" =~ ^https?:// ]]; then
        log "error" "PANEL_URL 格式错误，必须以 http:// 或 https:// 开头"
        exit 1
    fi
    
    # 验证NODE_ID是否为数字
    if ! [[ "$NODE_ID" =~ ^[0-9]+$ ]]; then
        log "error" "NODE_ID 必须为数字"
        exit 1
    fi
}

# 配置并运行 soga
config_run_soga(){
    local CONTAINER_NAME="$1"
    local PANEL_URL="$2"
    local PANEL_KEY="$3"
    local NODE_ID="$4"

    log "info" "正在安装 soga..."
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
    log "info" "soga 已经安装..."
}

# 配置并运行 soga_compose
config_run_soga_compose() {
    log "info" "开始配置 soga..."
    mkdir -p "$SOGA_BASE_DIR"
    mkdir -p "$SOGA_CONFIG_DIR"

    cat > "$SOGA_BASE_DIR/docker-compose.yml" <<EOF
services:
  soga:
    image: $DOCKER_IMAGE
    container_name: ${CONTAINER_NAME}
    restart: always
    network_mode: host
    environment:
      type: xboard
      server_type: ss
      node_id: ${NODE_ID}
      api: webapi
      webapi_url: ${PANEL_URL}
      webapi_key: ${PANEL_KEY}
      forbidden_bit_torrent: 'true'
      log_level: info
    volumes:
      - $SOGA_CONFIG_DIR:/etc/soga
EOF

    log "info" "正在启动 soga ..."
    cd "$SOGA_BASE_DIR"
    $DOCKER_COMPOSE_CMD down
    $DOCKER_COMPOSE_CMD up -d

    if [ $? -eq 0 ]; then
        log "info" "soga 已经成功安装并启动"
    else
        log "error" "服务启动失败，请检查日志."
    fi
}

# 安装 soga
install_soga() {
    check_privileges
    install_docker
    validate_params "$PANEL_URL" "$NODE_ID"
    check_remove_container
    config_run_soga_compose
}

# 重启 soga
restart_soga() {
    log "info" "正在重启 soga..."
    cd "$SOGA_BASE_DIR"
    if ! $DOCKER_COMPOSE_CMD restart; then
        log "error" "重启 soga 失败"
        exit 1
    fi
    log "info" "soga 已经重启成功"
}

# 停止 soga
stop_soga() {
    log "info" "正在停止 soga..."
    cd "$SOGA_BASE_DIR"
    if ! $DOCKER_COMPOSE_CMD down; then
        log "error" "停止 soga 失败"
        exit 1
    fi
    log "info" "soga 已经停止成功"
}

# 显示使用帮助
show_help() {
    echo "用法: $0 {update|install|restart|stop}"
    echo " - 更新系统:  $0 update"
    echo " - 安装soga: $0 install <CONTAINER_NAME> <PANEL_URL> <PANEL_KEY> <NODE_ID>"
    echo " - 重启soga: $0 restart"
    echo " - 停止soga: $0 stop"
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
        PANEL_URL="${3:-}"
        PANEL_KEY="${4:-}"
        NODE_ID="${5:-}"

        if [ -z "${CONTAINER_NAME}" ] || [ -z "${PANEL_URL}" ] || [ -z "${PANEL_KEY}" ] || [ -z "${NODE_ID}" ]; then
            log "error" "安装soga需要提供所有参数: CONTAINER_NAME, PANEL_URL, PANEL_KEY, NODE_ID"
            show_help
            exit 1
        fi
        install_soga
        ;;
    restart)
        check_privileges
        restart_soga
        ;;
    stop)
        check_privileges
        stop_soga
        ;;
    *)
        show_help
        exit 1
        ;;
esac

exit 0