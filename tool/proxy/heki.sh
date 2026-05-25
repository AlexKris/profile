#!/bin/bash

# 启用错误处理
set -euo pipefail

HEKI_ROOT="/root/heki"
CONFIG_ROOT="/etc/heki"
DOCKER_IMAGE="hekicore/heki"
IMAGE_TAG="latest"
DOCKER_COMPOSE_CMD="docker compose"

# 实例级路径（参数解析完成后赋值）
BASE_DIR=""
CONFIG_DIR=""

# 默认参数值
CONTAINER_NAME=""
PANEL_URL=""
PANEL_KEY=""
NODE_ID=""
HEKI_KEY=""
LOG_LEVEL="info"
ACTION=""

PANEL_TYPE="xboard"
SERVER_TYPE=""
CERT_MODE=""
CERT_FILE=""
KEY_FILE=""
CERT_DOMAIN=""
CERT_KEY_LENGTH=""
DNS_PROVIDER=""
DNS_ENVS=()

ALLOWED_SERVER_TYPES="v2ray vmess vless ss ssr trojan hysteria tuic anytls naive mieru"
ALLOWED_PANEL_TYPES="sspanel-uim metron xboard v2board xiaov2board ppanel heki-v1"
ALLOWED_CERT_MODES="file http dns self"

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

# 在允许的枚举集中检查值
in_set() {
    local needle="$1"
    local haystack="$2"
    local item
    for item in $haystack; do
        [[ "$item" == "$needle" ]] && return 0
    done
    return 1
}

# 给 YAML 单引号字符串里的值做转义
yaml_escape() {
    local s="$1"
    # 单引号在 YAML 单引号字符串中用两个连续单引号表示
    printf '%s' "$s" | sed "s/'/''/g"
}

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
    log "info" "系统更新完成。"
}

# 安装 Docker
install_docker() {
    if command -v docker &> /dev/null; then
        log "info" "Docker 已经安装，跳过安装步骤..."
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

    systemctl enable docker
    systemctl start docker

    log "info" "Docker 已经安装完成。"
}

# 从 compose 文件解析 container_name
parse_compose_container_name() {
    local compose_file="$1"
    grep -E '^[[:space:]]*container_name:' "$compose_file" 2>/dev/null | head -n1 | awk '{print $2}' | tr -d '"'"'"
}

# 参数枚举与证书校验
validate_install_params() {
    # 基础必填
    if [[ -z "$CONTAINER_NAME" || -z "$PANEL_URL" || -z "$PANEL_KEY" || -z "$NODE_ID" ]]; then
        log "error" "安装操作需要: --container-name, --panel-url, --panel-key, --node-id"
        exit 1
    fi

    # container-name 字符集
    if [[ ! "$CONTAINER_NAME" =~ ^[A-Za-z0-9_-]+$ ]]; then
        log "error" "--container-name 只允许字母数字、下划线与连字符: $CONTAINER_NAME"
        exit 1
    fi

    # PANEL_URL 格式
    if [[ ! "$PANEL_URL" =~ ^https?:// ]]; then
        log "error" "--panel-url 必须以 http:// 或 https:// 开头"
        exit 1
    fi

    # NODE_ID 数字，多个以逗号分隔
    if ! [[ "$NODE_ID" =~ ^[0-9]+(,[0-9]+)*$ ]]; then
        log "error" "--node-id 必须为数字，多个以逗号分隔 (如 1 或 1,2,3)"
        exit 1
    fi

    # 枚举（server_type 可选：协议由面板按节点下发，仅在显式指定时校验）
    if [[ -n "$SERVER_TYPE" ]] && ! in_set "$SERVER_TYPE" "$ALLOWED_SERVER_TYPES"; then
        log "error" "--server-type 非法: ${SERVER_TYPE}，允许: $ALLOWED_SERVER_TYPES"
        exit 1
    fi
    if ! in_set "$PANEL_TYPE" "$ALLOWED_PANEL_TYPES"; then
        log "error" "--panel-type 非法: ${PANEL_TYPE}，允许: $ALLOWED_PANEL_TYPES"
        exit 1
    fi
    if [[ -n "$CERT_MODE" ]] && ! in_set "$CERT_MODE" "$ALLOWED_CERT_MODES"; then
        log "error" "--cert-mode 非法: ${CERT_MODE}，允许: $ALLOWED_CERT_MODES"
        exit 1
    fi

    local dns_env_count=0
    if [[ ${DNS_ENVS+x} ]]; then
        dns_env_count=${#DNS_ENVS[@]}
    fi

    # 证书为实例级、可选：需 TLS/QUIC 的节点才传 --cert-mode（协议由面板下发）
    if [[ -n "$CERT_MODE" ]]; then
        case "$CERT_MODE" in
            file)
                if [[ -z "$CERT_FILE" || -z "$KEY_FILE" ]]; then
                    log "error" "--cert-mode file 要求 --cert-file 与 --key-file"
                    exit 1
                fi
                ;;
            http)
                if [[ -z "$CERT_DOMAIN" ]]; then
                    log "error" "--cert-mode http 要求 --cert-domain"
                    exit 1
                fi
                ;;
            self)
                if [[ -z "$CERT_DOMAIN" ]]; then
                    log "error" "--cert-mode self 要求 --cert-domain"
                    exit 1
                fi
                ;;
            dns)
                if [[ -z "$CERT_DOMAIN" ]]; then
                    log "error" "--cert-mode dns 要求 --cert-domain"
                    exit 1
                fi
                if [[ -z "$DNS_PROVIDER" ]]; then
                    log "error" "--cert-mode dns 要求 --dns-provider"
                    exit 1
                fi
                if [[ $dns_env_count -eq 0 ]]; then
                    log "error" "--cert-mode dns 至少需要一个 --dns-env KEY=VALUE"
                    exit 1
                fi
                ;;
        esac
    fi

    # --dns-env 格式
    if [[ $dns_env_count -gt 0 ]]; then
        local env_item
        for env_item in "${DNS_ENVS[@]}"; do
            if [[ ! "$env_item" =~ ^[A-Za-z_][A-Za-z0-9_]*=.+ ]]; then
                log "error" "--dns-env 格式错误: $env_item (需 KEY=VALUE)"
                exit 1
            fi
        done
    fi
}

# 检查并清理同名容器（仅当前实例）
check_remove_container() {
    log "info" "检查是否存在名为 ${CONTAINER_NAME} 的旧容器..."

    if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        if ! docker inspect "${CONTAINER_NAME}" --format '{{index .Config.Labels "com.docker.compose.project"}}' 2>/dev/null | grep -q .; then
            log "info" "发现 docker run 启动的 ${CONTAINER_NAME}，停止并删除..."
            docker stop "${CONTAINER_NAME}" >/dev/null 2>&1 || log "warn" "停止容器 ${CONTAINER_NAME} 失败"
            docker rm "${CONTAINER_NAME}" >/dev/null 2>&1 || log "warn" "删除容器 ${CONTAINER_NAME} 失败"
        else
            if [[ -f "${BASE_DIR}/docker-compose.yml" ]]; then
                log "info" "发现 compose 启动的 ${CONTAINER_NAME}，在 ${BASE_DIR} 执行 down"
                (cd "$BASE_DIR" && $DOCKER_COMPOSE_CMD down)
            else
                log "error" "容器 ${CONTAINER_NAME} 由 compose 启动，但本地无对应 compose 文件: ${BASE_DIR}/docker-compose.yml"
                exit 1
            fi
        fi
    else
        log "info" "未发现名为 ${CONTAINER_NAME} 的容器"
    fi
}

# 生成 docker-compose.yml
write_compose_file() {
    mkdir -p "$BASE_DIR"
    mkdir -p "$CONFIG_DIR"

    local esc_panel_url esc_panel_key esc_log_level esc_panel_type
    esc_panel_url=$(yaml_escape "$PANEL_URL")
    esc_panel_key=$(yaml_escape "$PANEL_KEY")
    esc_log_level=$(yaml_escape "$LOG_LEVEL")
    esc_panel_type=$(yaml_escape "$PANEL_TYPE")

    {
        cat <<EOF
services:
  ${CONTAINER_NAME}:
    image: ${DOCKER_IMAGE}:${IMAGE_TAG}
    container_name: ${CONTAINER_NAME}
    restart: unless-stopped
    network_mode: host
    environment:
      TZ: Asia/Hong_Kong
      type: '${esc_panel_type}'
      node_id: '${NODE_ID}'
      panel_url: '${esc_panel_url}'
      panel_key: '${esc_panel_key}'
      log_level: '${esc_log_level}'
      log_file_dir: /etc/heki/
EOF

        # server_type 可选：仅在显式指定时写入（否则由面板按节点下发）
        if [[ -n "$SERVER_TYPE" ]]; then
            printf "      server_type: '%s'\n" "$(yaml_escape "$SERVER_TYPE")"
        fi

        if [[ -n "$HEKI_KEY" ]]; then
            printf "      heki_key: '%s'\n" "$(yaml_escape "$HEKI_KEY")"
        fi

        if [[ -n "$CERT_MODE" ]]; then
            case "$CERT_MODE" in
                file)
                    printf "      cert_file: '%s'\n" "$(yaml_escape "$CERT_FILE")"
                    printf "      key_file: '%s'\n" "$(yaml_escape "$KEY_FILE")"
                    ;;
                http)
                    echo "      cert_mode: http"
                    printf "      cert_domain: '%s'\n" "$(yaml_escape "$CERT_DOMAIN")"
                    if [[ -n "$CERT_KEY_LENGTH" ]]; then
                        printf "      cert_key_length: '%s'\n" "$(yaml_escape "$CERT_KEY_LENGTH")"
                    fi
                    ;;
                self)
                    echo "      cert_mode: self"
                    printf "      cert_domain: '%s'\n" "$(yaml_escape "$CERT_DOMAIN")"
                    ;;
                dns)
                    echo "      cert_mode: dns"
                    printf "      cert_domain: '%s'\n" "$(yaml_escape "$CERT_DOMAIN")"
                    printf "      dns_provider: '%s'\n" "$(yaml_escape "$DNS_PROVIDER")"
                    if [[ -n "$CERT_KEY_LENGTH" ]]; then
                        printf "      cert_key_length: '%s'\n" "$(yaml_escape "$CERT_KEY_LENGTH")"
                    fi
                    if [[ ${DNS_ENVS+x} && ${#DNS_ENVS[@]} -gt 0 ]]; then
                        local item k v
                        for item in "${DNS_ENVS[@]}"; do
                            k="${item%%=*}"
                            v="${item#*=}"
                            printf "      %s: '%s'\n" "$k" "$(yaml_escape "$v")"
                        done
                    fi
                    ;;
            esac
        fi

        cat <<EOF
    volumes:
      - ${CONFIG_DIR}:/etc/heki
EOF
    } > "${BASE_DIR}/docker-compose.yml"
}

# 安装摘要输出
print_install_summary() {
    local mode_display="${CERT_MODE:-none}"
    local key_display="免费版(无 key)"
    [[ -n "$HEKI_KEY" ]] && key_display="已配置授权码"
    log "info" "配置摘要:"
    log "info" "  container-name : ${CONTAINER_NAME}"
    log "info" "  panel-type     : ${PANEL_TYPE}"
    log "info" "  server-type    : ${SERVER_TYPE:-面板下发}"
    log "info" "  node-id        : ${NODE_ID}"
    log "info" "  cert-mode      : ${mode_display}"
    log "info" "  heki-key       : ${key_display}"
    log "info" "  base-dir       : ${BASE_DIR}"
    log "info" "  config-dir     : ${CONFIG_DIR}"
}

# 配置并启动
config_run_heki_compose() {
    log "info" "开始配置 heki..."
    log "info" "使用镜像标签: $IMAGE_TAG"

    write_compose_file

    log "info" "正在启动 heki ..."
    (cd "$BASE_DIR" && $DOCKER_COMPOSE_CMD up -d)

    log "info" "heki 已经成功安装并启动"
    log "info" "容器名称: $CONTAINER_NAME"
    log "info" "镜像版本: $DOCKER_IMAGE:$IMAGE_TAG"
    log "info" "节点ID: $NODE_ID"
    log "info" "协议: ${SERVER_TYPE:-面板下发} ($PANEL_TYPE)"
}

# 安装 heki
install_heki() {
    check_privileges
    install_docker
    validate_install_params

    BASE_DIR="${HEKI_ROOT}/${CONTAINER_NAME}"
    CONFIG_DIR="${CONFIG_ROOT}/${CONTAINER_NAME}"

    # 同名重装校验
    if [[ -f "${BASE_DIR}/docker-compose.yml" ]]; then
        local existing_name
        existing_name=$(parse_compose_container_name "${BASE_DIR}/docker-compose.yml")
        if [[ -z "$existing_name" ]]; then
            log "error" "${BASE_DIR}/docker-compose.yml 无法解析 container_name，请手工处理"
            exit 1
        fi
        if [[ "$existing_name" != "$CONTAINER_NAME" ]]; then
            log "error" "目录 ${BASE_DIR} 中已有 compose，container_name=${existing_name}，与本次 --container-name=${CONTAINER_NAME} 不一致"
            exit 1
        fi
        log "info" "检测到同名实例，执行覆盖更新（保留 ${CONFIG_DIR} 数据）"
    elif [[ -d "$BASE_DIR" ]] && [[ -n "$(ls -A "$BASE_DIR" 2>/dev/null || true)" ]]; then
        log "error" "目录 ${BASE_DIR} 已存在但无 docker-compose.yml，请手工处理"
        exit 1
    fi

    print_install_summary
    check_remove_container
    config_run_heki_compose
}

# 设置实例路径（用于 restart/stop）
set_instance_paths() {
    if [[ -z "$CONTAINER_NAME" ]]; then
        log "error" "该操作必须指定 --container-name"
        exit 1
    fi
    if [[ ! "$CONTAINER_NAME" =~ ^[A-Za-z0-9_-]+$ ]]; then
        log "error" "--container-name 只允许字母数字、下划线与连字符"
        exit 1
    fi
    BASE_DIR="${HEKI_ROOT}/${CONTAINER_NAME}"
    CONFIG_DIR="${CONFIG_ROOT}/${CONTAINER_NAME}"
    if [[ ! -f "${BASE_DIR}/docker-compose.yml" ]]; then
        log "error" "实例 ${CONTAINER_NAME} 不存在: ${BASE_DIR}/docker-compose.yml"
        exit 1
    fi
}

# 重启 heki
restart_heki() {
    set_instance_paths
    log "info" "正在重启 heki (${CONTAINER_NAME})..."
    if ! (cd "$BASE_DIR" && $DOCKER_COMPOSE_CMD restart); then
        log "error" "重启 heki 失败"
        exit 1
    fi
    log "info" "heki 已经重启成功"
}

# 停止 heki
stop_heki() {
    set_instance_paths
    log "info" "正在停止 heki (${CONTAINER_NAME})..."
    if ! (cd "$BASE_DIR" && $DOCKER_COMPOSE_CMD down); then
        log "error" "停止 heki 失败"
        exit 1
    fi
    log "info" "heki 已经停止成功"
}

# 显示使用帮助
show_help() {
    cat <<EOF
用法: $0 [操作] [选项]

操作:
  --update              更新系统
  --install             安装/覆盖更新 heki 实例
  --restart             重启指定实例 (必须 --container-name)
  --stop                停止指定实例 (必须 --container-name)
  --help                显示此帮助信息

通用选项:
  --container-name NAME 容器名称 (所有操作必需)

安装选项:
  --panel-url URL            面板 URL (必需)
  --panel-key KEY            面板 API 密钥 (必需)
  --node-id ID               节点 ID (必需，数字，多个用逗号分隔 如 1,2,3)
  --heki-key KEY             授权码 (可选，留空即免费版)
  --image-tag TAG            镜像标签 (默认: latest)
  --log-level LEVEL          debug/info/warn/error (默认: info)
  --server-type TYPE         可选; 协议默认由面板按节点自动下发, 单实例可混跑
                             多协议。仅在需本地强制指定时填: v2ray|vmess|vless|
                             ss|ssr|trojan|hysteria|tuic|anytls|naive|mieru
  --panel-type TYPE          sspanel-uim|metron|xboard|v2board|xiaov2board|
                             ppanel|heki-v1 (默认: xboard)
  --cert-mode MODE           file|http|dns|self
  --cert-file PATH           证书文件路径 (cert-mode=file)
  --key-file PATH            密钥文件路径 (cert-mode=file)
  --cert-domain DOMAIN       域名 (cert-mode=http/dns/self)
  --cert-key-length VALUE    证书长度: 留空=RSA, ec-256/ec-384 (可选)
  --dns-provider NAME        DNS 服务商, 如 dns_cf (cert-mode=dns)
  --dns-env KEY=VALUE        DNS 验证凭据, 可重复多次 (cert-mode=dns)

证书说明:
  协议由面板下发, 证书为实例级、可选。需要 TLS/QUIC 的节点
  (trojan/hysteria/tuic/anytls/naive) 才需 --cert-mode; 用通配证书
  (*.example.com) 时一份证书即可供该实例所有节点共用。
  file 模式的 --cert-file/--key-file 填容器内路径: 把证书放进
  /root/heki/<name>/ (映射为容器内 /etc/heki/), 再引用 /etc/heki/xxx.pem。

示例:
  # 单实例多协议混跑 (协议由面板下发, 不要证书的协议无需 cert 参数)
  $0 --install --container-name heki1 --panel-url https://panel.example.com \\
     --panel-key KEY --node-id 1,2,3

  # 多节点共用一张通配证书 (手动上传到 /root/heki/heki1/)
  $0 --install --container-name heki1 --panel-url https://panel.example.com \\
     --panel-key KEY --node-id 1,2,3 \\
     --cert-mode file --cert-file /etc/heki/fullchain.pem --key-file /etc/heki/privkey.pem

  # 通配证书 DNS 自动签发 (通配只能走 dns 验证)
  $0 --install --container-name heki1 --panel-url https://panel.example.com \\
     --panel-key KEY --node-id 1,2,3 \\
     --cert-mode dns --cert-domain '*.example.com' --dns-provider dns_cf \\
     --dns-env DNS_CF_Email=me@example.com --dns-env DNS_CF_Key=xxxxx

  $0 --restart --container-name heki1
  $0 --stop    --container-name heki1

注意:
  --restart 与 --stop 必须显式指定 --container-name。
  实例按容器名隔离: /root/heki/<name>/ 与 /etc/heki/<name>/。
  免费版无需 --heki-key (88 用户、全协议、无需联网验证)。
EOF
}

# 读取下一个参数值并防止误吃标志位
require_value() {
    local flag="$1"
    local value="${2:-}"
    if [[ -z "$value" || "$value" =~ ^-- ]]; then
        log "error" "$flag 需要提供值"
        exit 1
    fi
    printf "%s" "$value"
}

# 解析命令行参数
parse_arguments() {
    if [ $# -eq 0 ]; then
        show_help
        exit 1
    fi

    while [[ $# -gt 0 ]]; do
        case $1 in
            --update)  ACTION="update"; shift ;;
            --install) ACTION="install"; shift ;;
            --restart) ACTION="restart"; shift ;;
            --stop)    ACTION="stop"; shift ;;
            --help|-h) show_help; exit 0 ;;
            --container-name)
                CONTAINER_NAME=$(require_value "$1" "${2:-}"); shift 2 ;;
            --panel-url)
                PANEL_URL=$(require_value "$1" "${2:-}"); shift 2 ;;
            --panel-key)
                PANEL_KEY=$(require_value "$1" "${2:-}"); shift 2 ;;
            --node-id)
                NODE_ID=$(require_value "$1" "${2:-}"); shift 2 ;;
            --heki-key)
                HEKI_KEY=$(require_value "$1" "${2:-}"); shift 2 ;;
            --image-tag)
                IMAGE_TAG=$(require_value "$1" "${2:-}"); shift 2 ;;
            --log-level)
                LOG_LEVEL=$(require_value "$1" "${2:-}")
                if [[ ! "$LOG_LEVEL" =~ ^(debug|info|warn|error)$ ]]; then
                    log "error" "--log-level 非法: $LOG_LEVEL"
                    exit 1
                fi
                shift 2 ;;
            --server-type)
                SERVER_TYPE=$(require_value "$1" "${2:-}"); shift 2 ;;
            --panel-type)
                PANEL_TYPE=$(require_value "$1" "${2:-}"); shift 2 ;;
            --cert-mode)
                CERT_MODE=$(require_value "$1" "${2:-}"); shift 2 ;;
            --cert-file)
                CERT_FILE=$(require_value "$1" "${2:-}"); shift 2 ;;
            --key-file)
                KEY_FILE=$(require_value "$1" "${2:-}"); shift 2 ;;
            --cert-domain)
                CERT_DOMAIN=$(require_value "$1" "${2:-}"); shift 2 ;;
            --cert-key-length)
                CERT_KEY_LENGTH=$(require_value "$1" "${2:-}"); shift 2 ;;
            --dns-provider)
                DNS_PROVIDER=$(require_value "$1" "${2:-}"); shift 2 ;;
            --dns-env)
                DNS_ENVS+=("$(require_value "$1" "${2:-}")"); shift 2 ;;
            *)
                log "error" "未知参数: $1"
                show_help
                exit 1 ;;
        esac
    done

    if [[ -z "$ACTION" ]]; then
        log "error" "必须指定一个操作 (--update, --install, --restart, --stop)"
        show_help
        exit 1
    fi
}

# 主程序入口
main() {
    parse_arguments "$@"

    case "$ACTION" in
        update)
            check_privileges
            update_system
            ;;
        install)
            install_heki
            ;;
        restart)
            check_privileges
            restart_heki
            ;;
        stop)
            check_privileges
            stop_heki
            ;;
    esac
}

main "$@"

exit 0
