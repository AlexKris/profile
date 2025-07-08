#!/bin/bash

# 启用错误处理
set -euo pipefail

BASE_DIR="/root/soga"
CONFIG_DIR="/etc/soga"
DOCKER_IMAGE="vaxilu/soga"
IMAGE_TAG="latest"
DOCKER_COMPOSE_CMD="docker compose"

# 默认参数值
CONTAINER_NAME=""
PANEL_URL=""
PANEL_KEY=""
NODE_ID=""
ACTION=""

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
        if ! docker inspect "${CONTAINER_NAME}" --format '{{index .Config.Labels "com.docker.compose.project"}}' 2>/dev/null | grep -q .; then
            log "info" "发现通过docker run直接启动的 ${CONTAINER_NAME} 容器，正在停止并删除..."
            if ! docker stop "${CONTAINER_NAME}" >/dev/null 2>&1; then
                log "warn" "停止容器 ${CONTAINER_NAME} 失败"
            fi
            if ! docker rm "${CONTAINER_NAME}" >/dev/null 2>&1; then
                log "warn" "删除容器 ${CONTAINER_NAME} 失败"
            fi
            log "info" "已删除通过docker run启动的旧容器"
        else
            log "info" "发现通过docker compose启动的 ${CONTAINER_NAME} 容器，正在停止并删除..."
            cd "$BASE_DIR"
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
    log "info" "使用镜像标签: $IMAGE_TAG"
    mkdir -p "$BASE_DIR"
    mkdir -p "$CONFIG_DIR"

    cat > "$BASE_DIR/docker-compose.yml" <<EOF
services:
  ${CONTAINER_NAME}:
    image: $DOCKER_IMAGE:$IMAGE_TAG
    container_name: ${CONTAINER_NAME}
    restart: unless-stopped
    network_mode: host
    environment:
      TZ: Asia/Hong_Kong
      type: xboard
      server_type: ss
      node_id: ${NODE_ID}
      api: webapi
      webapi_url: ${PANEL_URL}
      webapi_key: ${PANEL_KEY}
      log_level: info
    volumes:
      - $CONFIG_DIR:/etc/soga
EOF

    log "info" "正在启动 soga ..."
    cd "$BASE_DIR"
    $DOCKER_COMPOSE_CMD down
    $DOCKER_COMPOSE_CMD up -d

    if [ $? -eq 0 ]; then
        log "info" "soga 已经成功安装并启动"
        log "info" "容器名称: $CONTAINER_NAME"
        log "info" "镜像版本: $DOCKER_IMAGE:$IMAGE_TAG"
        log "info" "节点ID: $NODE_ID"
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
    cd "$BASE_DIR"
    if ! $DOCKER_COMPOSE_CMD restart; then
        log "error" "重启 soga 失败"
        exit 1
    fi
    log "info" "soga 已经重启成功"
}

# 停止 soga
stop_soga() {
    log "info" "正在停止 soga..."
    cd "$BASE_DIR"
    if ! $DOCKER_COMPOSE_CMD down; then
        log "error" "停止 soga 失败"
        exit 1
    fi
    log "info" "soga 已经停止成功"
}

# 显示使用帮助
show_help() {
    cat << EOF
用法: $0 [操作] [选项]

操作:
  --update              更新系统
  --install             安装soga
  --restart             重启soga
  --stop                停止soga
  --help                显示此帮助信息

安装选项:
  --container-name NAME 容器名称 (必需)
  --panel-url URL       面板URL地址 (必需)
  --panel-key KEY       面板API密钥 (必需)
  --node-id ID          节点ID (必需)
  --image-tag TAG       Docker镜像标签 (默认: latest)

示例:
  $0 --update
  $0 --install --container-name soga1 --panel-url https://example.com --panel-key your_key --node-id 1
  $0 --install --container-name soga1 --panel-url https://example.com --panel-key your_key --node-id 1 --image-tag v1.7.11
  $0 --restart
  $0 --stop
EOF
}

# 解析命令行参数
parse_arguments() {
    if [ $# -eq 0 ]; then
        show_help
        exit 1
    fi

    while [[ $# -gt 0 ]]; do
        case $1 in
            --update)
                ACTION="update"
                shift
                ;;
            --install)
                ACTION="install"
                shift
                ;;
            --restart)
                ACTION="restart"
                shift
                ;;
            --stop)
                ACTION="stop"
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            --container-name)
                if [[ -n "${2:-}" && ! "$2" =~ ^-- ]]; then
                    CONTAINER_NAME="$2"
                    shift 2
                else
                    log "error" "--container-name 需要提供容器名称"
                    exit 1
                fi
                ;;
            --panel-url)
                if [[ -n "${2:-}" && ! "$2" =~ ^-- ]]; then
                    PANEL_URL="$2"
                    shift 2
                else
                    log "error" "--panel-url 需要提供面板URL"
                    exit 1
                fi
                ;;
            --panel-key)
                if [[ -n "${2:-}" && ! "$2" =~ ^-- ]]; then
                    PANEL_KEY="$2"
                    shift 2
                else
                    log "error" "--panel-key 需要提供面板密钥"
                    exit 1
                fi
                ;;
            --node-id)
                if [[ -n "${2:-}" && ! "$2" =~ ^-- ]]; then
                    NODE_ID="$2"
                    shift 2
                else
                    log "error" "--node-id 需要提供节点ID"
                    exit 1
                fi
                ;;
            --image-tag)
                if [[ -n "${2:-}" && ! "$2" =~ ^-- ]]; then
                    IMAGE_TAG="$2"
                    shift 2
                else
                    log "error" "--image-tag 需要提供镜像标签"
                    exit 1
                fi
                ;;
            *)
                log "error" "未知参数: $1"
                show_help
                exit 1
                ;;
        esac
    done

    # 验证必需的操作参数
    if [[ -z "$ACTION" ]]; then
        log "error" "必须指定一个操作 (--update, --install, --restart, --stop)"
        show_help
        exit 1
    fi

    # 如果是安装操作，验证必需的参数
    if [[ "$ACTION" == "install" ]]; then
        if [[ -z "$CONTAINER_NAME" || -z "$PANEL_URL" || -z "$PANEL_KEY" || -z "$NODE_ID" ]]; then
            log "error" "安装操作需要提供所有必需参数: --container-name, --panel-url, --panel-key, --node-id"
            show_help
            exit 1
        fi
    fi
}

# 主程序入口
main() {
    # 解析命令行参数
    parse_arguments "$@"

    # 根据操作执行相应功能
    case "$ACTION" in
        update)
            check_privileges
            update_system
            ;;
        install)
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
    esac
}

# 调用主程序
main "$@"

exit 0