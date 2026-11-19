#!/bin/bash

# 启用错误处理
set -euo pipefail

SOGA_ROOT="/root/soga"
CONFIG_ROOT="/etc/soga"
DOCKER_IMAGE="vaxilu/soga"
IMAGE_TAG="latest"
DOCKER_COMPOSE_CMD="docker compose"

# 实例级路径（参数解析完成后赋值）
BASE_DIR=""
CONFIG_DIR=""
TMP_COMPOSE_FILE=""
EXISTING_CONTAINER_MODE="none"

# 默认参数值
CONTAINER_NAME=""
PANEL_URL=""
PANEL_KEY=""
SOGA_KEY=""
NODE_ID=""
LOG_LEVEL="info"
ACTION=""
HAS_INSTALL_OPT="false"

PANEL_TYPE="xboard"
SERVER_TYPE="ss"
CERT_MODE=""
CERT_FILE=""
KEY_FILE=""
CERT_DOMAIN=""
CERT_KEY_LENGTH=""
DNS_PROVIDER=""
DNS_ENVS=()
EXTRA_ENVS=()

ALLOWED_SERVER_TYPES="v2ray vless ss ssr trojan hysteria anytls mieru"
ALLOWED_PANEL_TYPES="sspanel-uim xboard v2board xiaov2board whmcs proxypanel ppanel v2raysocks soga-v1"
ALLOWED_CERT_MODES="file http dns"
ALLOWED_CERT_KEY_LENGTHS="ec-256 ec-384"

log() {
    local level="$1"
    local message="$2"
    case "$level" in
        "info")  echo "[INFO] $message" ;;
        "warn")  echo "[WARN] $message" ;;
        "error") echo "[ERROR] $message" >&2 ;;
    esac
}

check_privileges() {
    if [ "$(id -u)" -ne 0 ]; then
        log "error" "请使用 root 用户或 sudo 运行此脚本"
        exit 1
    fi
}

cleanup_tmp_file() {
    if [[ -n "${TMP_COMPOSE_FILE:-}" && -e "$TMP_COMPOSE_FILE" ]]; then
        rm -f "$TMP_COMPOSE_FILE"
    fi
}

cleanup() {
    cleanup_tmp_file
    log "info" "脚本中断，退出..."
    exit 130
}

trap cleanup_tmp_file EXIT
trap cleanup SIGINT SIGTERM

in_set() {
    local needle="$1"
    local haystack="$2"
    local item
    for item in $haystack; do
        [[ "$item" == "$needle" ]] && return 0
    done
    return 1
}

has_control_char() {
    local s="$1"
    [[ "$s" == *$'\n'* || "$s" == *$'\r'* ]]
}

# 给 Docker Compose YAML 单引号字符串做转义（' -> ''，同时转义 Compose 变量插值符 $ -> $$）
yaml_escape() {
    local s="$1"
    printf '%s\n' "$s" | sed -e "s/'/''/g" -e 's/\$/$$/g'
}

# 防止 --env / --dns-env 覆盖脚本有显式选项（或固定）的配置，避免 compose 出现重复 key
is_managed_env_key() {
    local key="$1"
    case "$key" in
        type|server_type|node_id|soga_key|api|webapi_url|webapi_key|log_level|\
        cert_file|key_file|cert_mode|cert_domain|cert_key_length|dns_provider)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# 默认写入、允许通过 --env 覆盖的配置键（--dns-env 不可占用）
is_default_env_key() {
    local key="$1"
    case "$key" in
        TZ|log_file_dir|forbidden_bit_torrent|geo_update_enable)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# 查询 EXTRA_ENVS 中是否存在指定 key
has_extra_env_key() {
    local target="$1"
    local item
    if [[ ${EXTRA_ENVS+x} && ${#EXTRA_ENVS[@]} -gt 0 ]]; then
        for item in "${EXTRA_ENVS[@]}"; do
            [[ "${item%%=*}" == "$target" ]] && return 0
        done
    fi
    return 1
}

# 查询 EXTRA_ENVS 中指定布尔项是否为 true
is_extra_env_true() {
    local target="$1"
    local item val
    if [[ ${EXTRA_ENVS+x} && ${#EXTRA_ENVS[@]} -gt 0 ]]; then
        for item in "${EXTRA_ENVS[@]}"; do
            if [[ "${item%%=*}" == "$target" ]]; then
                val="${item#*=}"
                case "$val" in
                    true|TRUE|True|1) return 0 ;;
                esac
            fi
        done
    fi
    return 1
}

# 更新系统包
update_system() {
    if [ -f /etc/debian_version ]; then
        log "info" "检测到 Debian/Ubuntu 系统..."
        DEBIAN_FRONTEND=noninteractive apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get upgrade -y \
            -o Dpkg::Options::="--force-confdef" \
            -o Dpkg::Options::="--force-confold"
        DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y \
            -o Dpkg::Options::="--force-confdef" \
            -o Dpkg::Options::="--force-confold"
        apt-get autoclean -y
        DEBIAN_FRONTEND=noninteractive apt-get autoremove -y
    elif [ -f /etc/redhat-release ]; then
        log "info" "检测到 RHEL/CentOS 系统..."
        if command -v dnf &> /dev/null; then
            log "info" "使用 dnf 包管理器进行更新..."
            dnf update -y
        else
            log "info" "使用 yum 包管理器进行更新..."
            yum update -y
        fi
    else
        log "error" "不支持的操作系统，只支持 Debian/Ubuntu 和 CentOS/RHEL。"
        exit 1
    fi
    log "info" "系统更新完成。"
}

# 确保 Docker 守护进程与 docker compose 可用
ensure_docker() {
    if ! command -v docker &> /dev/null; then
        log "info" "正在安装 Docker..."
        if ! command -v curl &> /dev/null; then
            log "error" "未找到 curl 命令，请先安装 curl"
            exit 1
        fi
        if ! curl -fsSL https://get.docker.com | bash; then
            log "error" "安装 Docker 失败，请检查网络连接。"
            exit 1
        fi
        if command -v systemctl &> /dev/null; then
            systemctl enable docker || true
            systemctl start docker || true
        fi
        log "info" "Docker 安装完成。"
    else
        local docker_version
        docker_version=$(docker --version | cut -d ' ' -f3 | cut -d ',' -f1)
        log "info" "检测到已安装 Docker (版本: ${docker_version})"
    fi

    if ! docker info &> /dev/null; then
        if command -v systemctl &> /dev/null; then
            log "info" "Docker 守护进程未就绪，尝试启动服务..."
            systemctl start docker || true
        fi
        if ! docker info &> /dev/null; then
            log "error" "无法连接 Docker 守护进程，请检查 Docker 服务状态"
            exit 1
        fi
    fi

    if ! $DOCKER_COMPOSE_CMD version &> /dev/null; then
        log "error" "未检测到 'docker compose' 插件，请安装 docker-compose-plugin 后重试"
        exit 1
    fi
}

# 从 compose 文件解析 container_name（兼容引号、行尾注释、CRLF，兼容 mawk 且不触发 pipefail）
parse_compose_container_name() {
    local compose_file="$1"
    awk '
        /^[ \t]*container_name:[ \t]*/ {
            sub(/^[ \t]*container_name:[ \t]*/, "")
            sub(/#.*$/, "")
            gsub(/["\047\r \t]/, "")
            print
            exit
        }
    ' "$compose_file" 2>/dev/null || true
}

# 参数枚举与证书校验
validate_install_params() {
    if [[ -z "$CONTAINER_NAME" || -z "$PANEL_URL" || -z "$PANEL_KEY" || -z "$NODE_ID" ]]; then
        log "error" "安装操作需要: --container-name, --panel-url, --panel-key, --node-id"
        exit 1
    fi

    if [[ ! "$CONTAINER_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9_-]*$ ]]; then
        log "error" "--container-name 必须以字母或数字开头，且只允许字母数字、下划线与连字符: ${CONTAINER_NAME}"
        exit 1
    fi

    if [[ ! "$IMAGE_TAG" =~ ^[A-Za-z0-9_][A-Za-z0-9._-]*$ ]]; then
        log "error" "--image-tag 包含非法字符或首字符不合法: ${IMAGE_TAG}"
        exit 1
    fi

    if [[ ! "$PANEL_URL" =~ ^https?://[^/[:space:]]+[^[:space:]]*$ ]]; then
        log "error" "--panel-url 必须以 http:// 或 https:// 开头且不含空白字符"
        exit 1
    fi

    if ! [[ "$NODE_ID" =~ ^[0-9]+(,[0-9]+)*$ ]]; then
        log "error" "--node-id 必须为数字，多个以逗号分隔 (如 1 或 1,2,3)"
        exit 1
    fi

    if ! in_set "$SERVER_TYPE" "$ALLOWED_SERVER_TYPES"; then
        log "error" "--server-type 非法: ${SERVER_TYPE}，允许: ${ALLOWED_SERVER_TYPES}"
        exit 1
    fi
    if ! in_set "$PANEL_TYPE" "$ALLOWED_PANEL_TYPES"; then
        log "error" "--panel-type 非法: ${PANEL_TYPE}，允许: ${ALLOWED_PANEL_TYPES}"
        exit 1
    fi
    if [[ -n "$CERT_MODE" ]] && ! in_set "$CERT_MODE" "$ALLOWED_CERT_MODES"; then
        log "error" "--cert-mode 非法: ${CERT_MODE}，允许: ${ALLOWED_CERT_MODES}"
        exit 1
    fi
    if [[ -n "$CERT_KEY_LENGTH" ]] && ! in_set "$CERT_KEY_LENGTH" "$ALLOWED_CERT_KEY_LENGTHS"; then
        log "error" "--cert-key-length 非法: ${CERT_KEY_LENGTH}，允许: ${ALLOWED_CERT_KEY_LENGTHS} (或留空使用默认 RSA)"
        exit 1
    fi

    local dns_env_count=0
    if [[ ${DNS_ENVS+x} ]]; then
        dns_env_count=${#DNS_ENVS[@]}
    fi

    local extra_env_count=0
    if [[ ${EXTRA_ENVS+x} ]]; then
        extra_env_count=${#EXTRA_ENVS[@]}
    fi

    # 校验 --dns-env 与 --env 的格式、内置键冲突及重复 key
    local seen_keys=()
    local item key existing
    if [[ $dns_env_count -gt 0 ]]; then
        for item in "${DNS_ENVS[@]}"; do
            if [[ ! "$item" =~ ^[A-Za-z_][A-Za-z0-9_]*=.+ ]]; then
                log "error" "--dns-env 格式错误: ${item} (需 KEY=VALUE)"
                exit 1
            fi
            key="${item%%=*}"
            if [[ ! "$key" =~ ^DNS_[A-Za-z0-9_]+$ ]]; then
                log "error" "--dns-env 键名必须以 DNS_ 开头 (如 DNS_CF_Token=...)，Soga 仅识别 DNS_ 前缀的 acme.sh 凭据: ${key}"
                exit 1
            fi
            if [[ ${seen_keys+x} && ${#seen_keys[@]} -gt 0 ]]; then
                for existing in "${seen_keys[@]}"; do
                    if [[ "$existing" == "$key" ]]; then
                        log "error" "--dns-env 存在重复键: ${key}"
                        exit 1
                    fi
                done
            fi
            seen_keys+=("$key")
        done
    fi

    if [[ $extra_env_count -gt 0 ]]; then
        for item in "${EXTRA_ENVS[@]}"; do
            if [[ ! "$item" =~ ^[A-Za-z_][A-Za-z0-9_]*=.+ ]]; then
                log "error" "--env 格式错误: ${item} (需 KEY=VALUE)"
                exit 1
            fi
            key="${item%%=*}"
            if is_managed_env_key "$key"; then
                log "error" "--env ${key}=... 会覆盖脚本内置参数，请使用对应显式选项"
                exit 1
            fi
            if [[ ${seen_keys+x} && ${#seen_keys[@]} -gt 0 ]]; then
                for existing in "${seen_keys[@]}"; do
                    if [[ "$existing" == "$key" ]]; then
                        log "error" "--env 存在重复键或与 --dns-env 冲突: ${key}"
                        exit 1
                    fi
                done
            fi
            seen_keys+=("$key")
        done
    fi

    local has_cert_subparam="no"
    if [[ -n "$CERT_FILE" || -n "$KEY_FILE" || -n "$CERT_DOMAIN" \
          || -n "$CERT_KEY_LENGTH" || -n "$DNS_PROVIDER" || $dns_env_count -gt 0 ]]; then
        has_cert_subparam="yes"
    fi

    # 协议与证书关系校验
    case "$SERVER_TYPE" in
        ss|ssr|mieru)
            if [[ -n "$CERT_MODE" || "$has_cert_subparam" == "yes" ]]; then
                log "error" "${SERVER_TYPE} 协议不接受任何证书相关参数"
                exit 1
            fi
            ;;
        hysteria)
            if [[ -z "$CERT_MODE" ]]; then
                log "error" "hysteria 必须提供 --cert-mode (file|http|dns)"
                exit 1
            fi
            ;;
        trojan)
            if [[ -z "$CERT_MODE" ]] && ! is_extra_env_true "force_close_ssl"; then
                log "error" "trojan 必须提供 --cert-mode (file|http|dns)；若由前置反代卸载 TLS 请传 --env force_close_ssl=true"
                exit 1
            fi
            ;;
        anytls)
            if [[ -z "$CERT_MODE" && "$PANEL_TYPE" != "soga-v1" ]] && ! is_extra_env_true "force_close_ssl"; then
                log "error" "anytls 必须提供 --cert-mode (file|http|dns)"
                exit 1
            fi
            ;;
        v2ray|vless)
            # TLS / Reality 由面板节点配置决定，证书可选
            ;;
    esac

    # 证书模式与子参数互斥校验
    if [[ -z "$CERT_MODE" ]]; then
        if [[ "$has_cert_subparam" == "yes" ]]; then
            log "error" "提供了证书子参数但未指定 --cert-mode (file|http|dns)"
            exit 1
        fi
        return 0
    fi

    case "$CERT_MODE" in
        file)
            if [[ -z "$CERT_FILE" || -z "$KEY_FILE" ]]; then
                log "error" "--cert-mode file 要求同时提供 --cert-file 与 --key-file"
                exit 1
            fi
            if [[ "$CERT_FILE" != /* || "$KEY_FILE" != /* ]]; then
                log "error" "--cert-file 与 --key-file 必须为绝对路径"
                exit 1
            fi
            if [[ "$CERT_FILE" == */ || "$KEY_FILE" == */ ]]; then
                log "error" "--cert-file 与 --key-file 不能为目录路径"
                exit 1
            fi
            if [[ "$CERT_FILE" =~ (^|/)\.\.(/|$) || "$KEY_FILE" =~ (^|/)\.\.(/|$) ]]; then
                log "error" "--cert-file 与 --key-file 路径不能包含 .."
                exit 1
            fi
            if [[ "$CERT_FILE" == *:* || "$KEY_FILE" == *:* ]]; then
                log "error" "--cert-file 与 --key-file 路径不能包含冒号"
                exit 1
            fi
            if [[ -n "$CERT_DOMAIN" || -n "$CERT_KEY_LENGTH" || -n "$DNS_PROVIDER" || $dns_env_count -gt 0 ]]; then
                log "error" "--cert-mode file 不接受 --cert-domain / --cert-key-length / --dns-provider / --dns-env"
                exit 1
            fi
            ;;
        http)
            if [[ -z "$CERT_DOMAIN" ]]; then
                log "error" "--cert-mode http 要求 --cert-domain"
                exit 1
            fi
            if [[ "$CERT_DOMAIN" =~ [[:space:]/] || "$CERT_DOMAIN" == *:* ]]; then
                log "error" "--cert-domain 只需填写纯域名 (如 node.example.com)，不要包含协议头、端口或路径"
                exit 1
            fi
            if [[ "$CERT_DOMAIN" == *'*'* ]]; then
                log "error" "通配符证书不能使用 http 验证，请改用 --cert-mode dns"
                exit 1
            fi
            if [[ -n "$CERT_FILE" || -n "$KEY_FILE" || -n "$DNS_PROVIDER" || $dns_env_count -gt 0 ]]; then
                log "error" "--cert-mode http 不接受 --cert-file / --key-file / --dns-provider / --dns-env"
                exit 1
            fi
            ;;
        dns)
            if [[ -z "$CERT_DOMAIN" ]]; then
                log "error" "--cert-mode dns 要求 --cert-domain"
                exit 1
            fi
            if [[ "$CERT_DOMAIN" =~ [[:space:]/] || "$CERT_DOMAIN" == *:* ]]; then
                log "error" "--cert-domain 只需填写纯域名 (如 node.example.com 或 *.example.com)，不要包含协议头、端口或路径"
                exit 1
            fi
            if [[ -z "$DNS_PROVIDER" ]]; then
                log "error" "--cert-mode dns 要求 --dns-provider"
                exit 1
            fi
            if [[ ! "$DNS_PROVIDER" =~ ^[A-Za-z0-9._-]+$ ]]; then
                log "error" "--dns-provider 格式非法: ${DNS_PROVIDER}"
                exit 1
            fi
            if [[ $dns_env_count -eq 0 ]]; then
                log "error" "--cert-mode dns 至少需要一个 --dns-env KEY=VALUE"
                exit 1
            fi
            if [[ -n "$CERT_FILE" || -n "$KEY_FILE" ]]; then
                log "error" "--cert-mode dns 不接受 --cert-file / --key-file"
                exit 1
            fi
            ;;
    esac
}

# 归一化并校验宿主机证书文件存在性（在 CONFIG_DIR 确定且 check_privileges 之后调用）
validate_cert_files_on_host() {
    [[ "$CERT_MODE" == "file" ]] || return 0

    # 若用户传入宿主机实例配置目录路径 (/etc/soga/<name>/xxx)，且非容器内同名子目录文件，自动转换为容器内路径 (/etc/soga/xxx)
    if [[ "$CERT_FILE" == "${CONFIG_DIR}/"* && ! -f "${CONFIG_DIR}/${CERT_FILE#/etc/soga/}" ]]; then
        CERT_FILE="/etc/soga/${CERT_FILE#"${CONFIG_DIR}/"}"
        log "info" "已将 --cert-file 映射为容器内路径: ${CERT_FILE}"
    fi
    if [[ "$KEY_FILE" == "${CONFIG_DIR}/"* && ! -f "${CONFIG_DIR}/${KEY_FILE#/etc/soga/}" ]]; then
        KEY_FILE="/etc/soga/${KEY_FILE#"${CONFIG_DIR}/"}"
        log "info" "已将 --key-file 映射为容器内路径: ${KEY_FILE}"
    fi

    local path host_rel
    for path in "$CERT_FILE" "$KEY_FILE"; do
        if [[ "$path" == /etc/soga/* ]]; then
            host_rel="${path#/etc/soga/}"
            if [[ -z "$host_rel" || -d "${CONFIG_DIR}/${host_rel}" ]]; then
                log "error" "证书路径不能为目录: ${path}"
                exit 1
            fi
            if [[ ! -f "${CONFIG_DIR}/${host_rel}" ]]; then
                if [[ -f "${CONFIG_ROOT}/${host_rel}" ]]; then
                    log "error" "检测到证书位于 ${CONFIG_ROOT}/${host_rel}，但实例挂载目录为 ${CONFIG_DIR}:/etc/soga；请将证书移入 ${CONFIG_DIR}/，或放到 /etc/ssl/ 等独立目录后传入宿主机路径"
                    exit 1
                fi
                log "warn" "宿主机尚未检测到 ${CONFIG_DIR}/${host_rel}（对应容器内 ${path}），请确保证书文件已就位"
            fi
        else
            if [[ ! -f "$path" ]]; then
                log "error" "宿主机证书文件不存在: ${path}（推荐放入 ${CONFIG_DIR}/ 并使用 /etc/soga/文件名）"
                exit 1
            fi
        fi
    done
}

# 预先检查同名容器归属（不停止运行中容器，避免镜像拉取失败导致线上中断）
inspect_existing_container() {
    log "info" "检查是否存在名为 ${CONTAINER_NAME} 的旧容器..."
    EXISTING_CONTAINER_MODE="none"

    local lower_name
    lower_name=$(printf '%s' "$CONTAINER_NAME" | tr '[:upper:]' '[:lower:]')

    local all_containers cname cname_lower
    all_containers=$(docker ps -a --format '{{.Names}}' || true)
    if [[ -n "$all_containers" ]]; then
        while IFS= read -r cname; do
            [[ -n "$cname" ]] || continue
            cname_lower=$(printf '%s' "$cname" | tr '[:upper:]' '[:lower:]')
            if [[ "$cname_lower" == "$lower_name" && "$cname" != "$CONTAINER_NAME" ]]; then
                log "error" "已存在仅大小写不同的容器 ${cname}，与 ${CONTAINER_NAME} 存在 Docker Compose 项目名冲突"
                exit 1
            fi
        done <<< "$all_containers"
    fi

    if [[ -d "$SOGA_ROOT" ]]; then
        local entry entry_name entry_lower
        for entry in "$SOGA_ROOT"/*; do
            [[ -e "$entry" ]] || continue
            entry_name="${entry##*/}"
            entry_lower=$(printf '%s' "$entry_name" | tr '[:upper:]' '[:lower:]')
            if [[ "$entry_lower" == "$lower_name" && "$entry_name" != "$CONTAINER_NAME" ]]; then
                log "error" "已存在仅大小写不同的实例目录 ${entry}，与 ${CONTAINER_NAME} 存在冲突"
                exit 1
            fi
        done
    fi

    local matched
    matched=$(docker ps -a --filter "name=^/${CONTAINER_NAME}$" --format '{{.Names}}')
    if [[ -z "$matched" ]]; then
        log "info" "未发现名为 ${CONTAINER_NAME} 的容器"
        return 0
    fi

    local compose_project compose_workdir
    compose_project=$(docker container inspect "${CONTAINER_NAME}" \
        --format '{{index .Config.Labels "com.docker.compose.project"}}' 2>/dev/null || true)
    compose_workdir=$(docker container inspect "${CONTAINER_NAME}" \
        --format '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' 2>/dev/null || true)

    if [[ -z "$compose_project" ]]; then
        EXISTING_CONTAINER_MODE="docker_run"
        return 0
    fi

    if [[ -n "$compose_workdir" && "$compose_workdir" != "$BASE_DIR" ]]; then
        log "error" "容器 ${CONTAINER_NAME} 由其他目录 (${compose_workdir}) 的 compose 管理，请先前往该目录停止或更换 --container-name"
        exit 1
    fi

    if [[ ! -f "${BASE_DIR}/docker-compose.yml" ]]; then
        log "error" "容器 ${CONTAINER_NAME} 由 compose 启动，但本地无对应 compose 文件: ${BASE_DIR}/docker-compose.yml"
        exit 1
    fi

    EXISTING_CONTAINER_MODE="compose"
}

# 拉取目标镜像（在停止旧容器和覆盖 compose 文件前完成）
pull_soga_image() {
    log "info" "正在拉取镜像 ${DOCKER_IMAGE}:${IMAGE_TAG}..."
    if ! docker pull "${DOCKER_IMAGE}:${IMAGE_TAG}"; then
        if docker image inspect "${DOCKER_IMAGE}:${IMAGE_TAG}" >/dev/null 2>&1; then
            log "warn" "拉取最新镜像失败，回退使用本地缓存镜像 ${DOCKER_IMAGE}:${IMAGE_TAG}"
        else
            log "error" "拉取镜像 ${DOCKER_IMAGE}:${IMAGE_TAG} 失败且本地无缓存（现有实例未被修改）"
            exit 1
        fi
    fi
}

# 清理同名旧容器（仅在镜像就绪后执行）
remove_existing_container() {
    case "$EXISTING_CONTAINER_MODE" in
        none)
            return 0
            ;;
        docker_run)
            log "info" "发现 docker run 启动的 ${CONTAINER_NAME}，停止并删除..."
            docker stop "${CONTAINER_NAME}" >/dev/null 2>&1 || true
            if ! docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1; then
                log "error" "删除旧容器 ${CONTAINER_NAME} 失败"
                exit 1
            fi
            ;;
        compose)
            log "info" "发现 compose 启动的 ${CONTAINER_NAME}，在 ${BASE_DIR} 执行 down"
            (cd "$BASE_DIR" && $DOCKER_COMPOSE_CMD down)
            ;;
    esac
}

# 原子生成 docker-compose.yml（权限 600）
write_compose_file() {
    mkdir -p "$BASE_DIR"
    mkdir -p "$CONFIG_DIR"

    local esc_panel_url esc_panel_key esc_log_level esc_panel_type esc_server_type
    esc_panel_url=$(yaml_escape "$PANEL_URL")
    esc_panel_key=$(yaml_escape "$PANEL_KEY")
    esc_log_level=$(yaml_escape "$LOG_LEVEL")
    esc_panel_type=$(yaml_escape "$PANEL_TYPE")
    esc_server_type=$(yaml_escape "$SERVER_TYPE")

    local project_name
    project_name="soga-$(printf '%s' "$CONTAINER_NAME" | tr '[:upper:]' '[:lower:]')"

    TMP_COMPOSE_FILE="${BASE_DIR}/docker-compose.yml.tmp.$$"
    (
        umask 077
        {
            cat <<EOF
name: '${project_name}'
services:
  '${CONTAINER_NAME}':
    image: '${DOCKER_IMAGE}:${IMAGE_TAG}'
    container_name: '${CONTAINER_NAME}'
    restart: unless-stopped
    network_mode: host
    environment:
EOF
            if ! has_extra_env_key "TZ"; then
                echo "      TZ: Asia/Hong_Kong"
            fi

            cat <<EOF
      type: '${esc_panel_type}'
      server_type: '${esc_server_type}'
      node_id: '${NODE_ID}'
      api: webapi
      webapi_url: '${esc_panel_url}'
      webapi_key: '${esc_panel_key}'
EOF

            if [[ -n "$SOGA_KEY" ]]; then
                printf "      soga_key: '%s'\n" "$(yaml_escape "$SOGA_KEY")"
            fi

            if ! has_extra_env_key "forbidden_bit_torrent"; then
                echo "      forbidden_bit_torrent: 'true'"
            fi
            if ! has_extra_env_key "geo_update_enable"; then
                echo "      geo_update_enable: 'true'"
            fi

            printf "      log_level: '%s'\n" "$esc_log_level"
            if ! has_extra_env_key "log_file_dir"; then
                echo "      log_file_dir: /etc/soga/"
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

            if [[ ${EXTRA_ENVS+x} && ${#EXTRA_ENVS[@]} -gt 0 ]]; then
                local extra_item extra_key extra_value
                for extra_item in "${EXTRA_ENVS[@]}"; do
                    extra_key="${extra_item%%=*}"
                    extra_value="${extra_item#*=}"
                    printf "      %s: '%s'\n" "$extra_key" "$(yaml_escape "$extra_value")"
                done
            fi

            cat <<EOF
    volumes:
      - '${CONFIG_DIR}:/etc/soga'
EOF
            if [[ "$CERT_MODE" == "file" ]]; then
                if [[ "$CERT_FILE" != /etc/soga/* ]]; then
                    printf "      - '%s:%s:ro'\n" "$(yaml_escape "$CERT_FILE")" "$(yaml_escape "$CERT_FILE")"
                fi
                if [[ "$KEY_FILE" != /etc/soga/* && "$KEY_FILE" != "$CERT_FILE" ]]; then
                    printf "      - '%s:%s:ro'\n" "$(yaml_escape "$KEY_FILE")" "$(yaml_escape "$KEY_FILE")"
                fi
            fi
        } > "$TMP_COMPOSE_FILE"
    )
    chmod 600 "$TMP_COMPOSE_FILE"
    mv -f "$TMP_COMPOSE_FILE" "${BASE_DIR}/docker-compose.yml"
    TMP_COMPOSE_FILE=""
}

# 安装摘要输出
print_install_summary() {
    local mode_display="${CERT_MODE:-none}"
    local key_display="未配置(免费额度)"
    [[ -n "$SOGA_KEY" ]] && key_display="已配置授权码"

    log "info" "配置摘要:"
    log "info" "  container-name : ${CONTAINER_NAME}"
    log "info" "  panel-type     : ${PANEL_TYPE}"
    log "info" "  server-type    : ${SERVER_TYPE}"
    log "info" "  node-id        : ${NODE_ID}"
    log "info" "  cert-mode      : ${mode_display}"
    log "info" "  soga-key       : ${key_display}"
    if [[ ${EXTRA_ENVS+x} && ${#EXTRA_ENVS[@]} -gt 0 ]]; then
        log "info" "  extra-env      : ${#EXTRA_ENVS[@]} 项"
    fi
    log "info" "  base-dir       : ${BASE_DIR}"
    log "info" "  config-dir     : ${CONFIG_DIR}"
}

# 写入配置并启动
config_run_soga_compose() {
    log "info" "开始配置 soga..."
    log "info" "使用镜像: ${DOCKER_IMAGE}:${IMAGE_TAG}"

    write_compose_file

    log "info" "正在启动 soga..."
    (cd "$BASE_DIR" && $DOCKER_COMPOSE_CMD up -d)

    log "info" "soga 已成功安装并启动"
    log "info" "容器名称: ${CONTAINER_NAME}"
    log "info" "镜像版本: ${DOCKER_IMAGE}:${IMAGE_TAG}"
    log "info" "节点ID: ${NODE_ID}"
    log "info" "协议: ${SERVER_TYPE} (${PANEL_TYPE})"
}

# 安装 soga
install_soga() {
    validate_install_params
    check_privileges

    BASE_DIR="${SOGA_ROOT}/${CONTAINER_NAME}"
    CONFIG_DIR="${CONFIG_ROOT}/${CONTAINER_NAME}"

    ensure_docker
    validate_cert_files_on_host

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

    inspect_existing_container
    pull_soga_image
    print_install_summary
    remove_existing_container
    config_run_soga_compose
}

# 校验并设置实例路径（用于 start/stop/restart/uninstall；先校验名称与 root 权限再探测 /root 路径）
set_instance_paths() {
    if [[ -z "$CONTAINER_NAME" ]]; then
        log "error" "该操作必须指定 --container-name"
        exit 1
    fi
    if [[ ! "$CONTAINER_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9_-]*$ ]]; then
        log "error" "--container-name 必须以字母或数字开头，且只允许字母数字、下划线与连字符"
        exit 1
    fi
    check_privileges
    BASE_DIR="${SOGA_ROOT}/${CONTAINER_NAME}"
    CONFIG_DIR="${CONFIG_ROOT}/${CONTAINER_NAME}"
    if [[ ! -f "${BASE_DIR}/docker-compose.yml" ]]; then
        log "error" "实例 ${CONTAINER_NAME} 不存在: ${BASE_DIR}/docker-compose.yml"
        exit 1
    fi
}

start_soga() {
    set_instance_paths
    ensure_docker
    log "info" "正在启动 soga (${CONTAINER_NAME})..."
    if ! (cd "$BASE_DIR" && $DOCKER_COMPOSE_CMD up -d); then
        log "error" "启动 soga 失败"
        exit 1
    fi
    log "info" "soga 已启动"
}

restart_soga() {
    set_instance_paths
    ensure_docker
    log "info" "正在重启 soga (${CONTAINER_NAME})..."
    local matched
    matched=$(cd "$BASE_DIR" && $DOCKER_COMPOSE_CMD ps -a -q)
    if [[ -n "$matched" ]]; then
        if ! (cd "$BASE_DIR" && $DOCKER_COMPOSE_CMD restart); then
            log "error" "重启 soga 失败"
            exit 1
        fi
    else
        if ! (cd "$BASE_DIR" && $DOCKER_COMPOSE_CMD up -d); then
            log "error" "拉起 soga 失败"
            exit 1
        fi
    fi
    log "info" "soga 已重启成功"
}

stop_soga() {
    set_instance_paths
    ensure_docker
    log "info" "正在停止 soga (${CONTAINER_NAME})..."
    if ! (cd "$BASE_DIR" && $DOCKER_COMPOSE_CMD stop); then
        log "error" "停止 soga 失败"
        exit 1
    fi
    log "info" "soga 已停止（可使用 --start 或 --restart 恢复）"
}

uninstall_soga() {
    set_instance_paths
    ensure_docker
    log "info" "正在卸载 soga 实例 (${CONTAINER_NAME})..."
    if ! (cd "$BASE_DIR" && $DOCKER_COMPOSE_CMD down); then
        log "error" "移除 soga 容器失败"
        exit 1
    fi
    rm -f "${BASE_DIR}/docker-compose.yml"
    rmdir "$BASE_DIR" 2>/dev/null || true
    log "info" "soga 实例 ${CONTAINER_NAME} 已卸载（证书与配置目录 ${CONFIG_DIR} 已保留）"
}

show_help() {
    cat <<EOF
用法: $0 [操作] [选项]

操作:
  --update              更新系统软件包
  --install             安装/覆盖更新 soga 实例 (自动拉取最新镜像)
  --start               启动已存在的指定实例 (必须 --container-name)
  --stop                停止指定实例 (必须 --container-name)
  --restart             重启指定实例 (必须 --container-name)
  --uninstall           卸载指定实例并移除容器 (必须 --container-name，保留 /etc/soga/<name>)
  --help                显示此帮助信息

通用选项:
  --container-name NAME 容器名称 (--install/--start/--stop/--restart/--uninstall 必需)

安装选项:
  --panel-url URL            面板 URL (必需)
  --panel-key KEY            面板 WebAPI 密钥 (必需)
  --node-id ID               节点 ID (必需，数字，同协议多节点用逗号分隔 如 1,2,3)
  --soga-key KEY             授权码 (可选，留空为免费额度)
  --image-tag TAG            镜像标签 (默认: latest)
  --log-level LEVEL          debug|info|warn|error (默认: info)
  --server-type TYPE         v2ray|vless|ss|ssr|trojan|hysteria|anytls|mieru (默认: ss)
  --panel-type TYPE          sspanel-uim|xboard|v2board|xiaov2board|whmcs|
                             proxypanel|ppanel|v2raysocks|soga-v1 (默认: xboard)
  --cert-mode MODE           file|http|dns (仅支持真实证书)
  --cert-file PATH           证书文件路径 (cert-mode=file)
  --key-file PATH            密钥文件路径 (cert-mode=file)
  --cert-domain DOMAIN       域名 (cert-mode=http/dns)
  --cert-key-length VALUE    证书算法: 留空=RSA, ec-256|ec-384 (可选, cert-mode=http/dns)
  --dns-provider NAME        DNS 服务商, 如 dns_cf (cert-mode=dns)
  --dns-env DNS_KEY=VALUE    DNS 验证凭据 (必须以 DNS_ 开头), 可重复多次 (cert-mode=dns)
  --env KEY=VALUE            透传额外 Soga 配置项, 可重复 (如 sub_type=v2node)

协议与证书说明:
  ss/ssr/mieru        不接受证书参数
  v2ray/vless         证书可选 (Reality 或无 TLS 节点无需 --cert-mode)
  hysteria            必须提供 --cert-mode (file|http|dns)
  trojan/anytls       默认必须提供 --cert-mode (前置反代卸载 TLS 时可传 --env force_close_ssl=true)
  通配符证书 (*.example.com) 只能使用 --cert-mode dns。
  file 模式推荐将证书放入宿主机 /etc/soga/<name>/ 下并传 /etc/soga/xxx.pem；
  若传入其他宿主机绝对路径 (如 /etc/ssl/cert.pem)，脚本校验文件存在后会自动只读挂载进容器。

示例:
  # Shadowsocks / VLESS Reality (无证书)
  $0 --install --container-name sogass --panel-url https://panel.example.com \\
     --panel-key KEY --node-id 1

  $0 --install --container-name sogavless --panel-url https://panel.example.com \\
     --panel-key KEY --node-id 2,3 --server-type vless --soga-key SOGA_KEY

  # 手动证书 (放入宿主机 /etc/soga/sogatrojan/ 后引用容器内 /etc/soga/ 路径)
  $0 --install --container-name sogatrojan --panel-url https://panel.example.com \\
     --panel-key KEY --node-id 4 --server-type trojan \\
     --cert-mode file --cert-file /etc/soga/fullchain.pem --key-file /etc/soga/privkey.pem

  # 通配证书 DNS 自动签发
  $0 --install --container-name sogahy --panel-url https://panel.example.com \\
     --panel-key KEY --node-id 5 --server-type hysteria \\
     --cert-mode dns --cert-domain '*.example.com' --dns-provider dns_cf \\
     --dns-env DNS_CF_Token=xxxxx --dns-env DNS_CF_Account_ID=xxxxx

  # 透传额外参数 (如 xiaov2board 对接 v2node 或开启 proxy_protocol)
  $0 --install --container-name sogav2 --panel-url https://panel.example.com \\
     --panel-key KEY --node-id 6 --panel-type xiaov2board --server-type vless \\
     --env sub_type=v2node --env proxy_protocol=true

  $0 --restart   --container-name sogass
  $0 --stop      --container-name sogass
  $0 --start     --container-name sogass
  $0 --uninstall --container-name sogass
EOF
}

# 读取下一个参数值并防止误吃标志位或换行注入
require_value() {
    local flag="$1"
    if [[ $# -lt 2 || -z "$2" || "$2" =~ ^-- ]]; then
        log "error" "${flag} 需要提供值"
        exit 1
    fi
    if has_control_char "$2"; then
        log "error" "${flag} 的值不能包含换行符"
        exit 1
    fi
    printf "%s" "$2"
}

set_action() {
    local next_action="$1"
    if [[ -n "$ACTION" && "$ACTION" != "$next_action" ]]; then
        log "error" "不能同时指定多个操作 (--${ACTION} 与 --${next_action})"
        exit 1
    fi
    ACTION="$next_action"
}

parse_arguments() {
    if [ $# -eq 0 ]; then
        show_help
        exit 1
    fi

    local val
    while [[ $# -gt 0 ]]; do
        case $1 in
            --update)    set_action "update"; shift ;;
            --install)   set_action "install"; shift ;;
            --start)     set_action "start"; shift ;;
            --restart)   set_action "restart"; shift ;;
            --stop)      set_action "stop"; shift ;;
            --uninstall) set_action "uninstall"; shift ;;
            --help|-h)   show_help; exit 0 ;;
            --container-name)
                CONTAINER_NAME=$(require_value "$1" "${2:-}"); shift 2 ;;
            --panel-url)
                PANEL_URL=$(require_value "$1" "${2:-}"); HAS_INSTALL_OPT="true"; shift 2 ;;
            --panel-key)
                PANEL_KEY=$(require_value "$1" "${2:-}"); HAS_INSTALL_OPT="true"; shift 2 ;;
            --soga-key)
                SOGA_KEY=$(require_value "$1" "${2:-}"); HAS_INSTALL_OPT="true"; shift 2 ;;
            --node-id)
                NODE_ID=$(require_value "$1" "${2:-}"); HAS_INSTALL_OPT="true"; shift 2 ;;
            --image-tag)
                IMAGE_TAG=$(require_value "$1" "${2:-}"); HAS_INSTALL_OPT="true"; shift 2 ;;
            --log-level)
                LOG_LEVEL=$(require_value "$1" "${2:-}")
                if [[ ! "$LOG_LEVEL" =~ ^(debug|info|warn|error)$ ]]; then
                    log "error" "--log-level 非法: ${LOG_LEVEL}，允许: debug|info|warn|error"
                    exit 1
                fi
                HAS_INSTALL_OPT="true"
                shift 2 ;;
            --server-type)
                SERVER_TYPE=$(require_value "$1" "${2:-}"); HAS_INSTALL_OPT="true"; shift 2 ;;
            --panel-type)
                PANEL_TYPE=$(require_value "$1" "${2:-}"); HAS_INSTALL_OPT="true"; shift 2 ;;
            --cert-mode)
                CERT_MODE=$(require_value "$1" "${2:-}"); HAS_INSTALL_OPT="true"; shift 2 ;;
            --cert-file)
                CERT_FILE=$(require_value "$1" "${2:-}"); HAS_INSTALL_OPT="true"; shift 2 ;;
            --key-file)
                KEY_FILE=$(require_value "$1" "${2:-}"); HAS_INSTALL_OPT="true"; shift 2 ;;
            --cert-domain)
                CERT_DOMAIN=$(require_value "$1" "${2:-}"); HAS_INSTALL_OPT="true"; shift 2 ;;
            --cert-key-length)
                CERT_KEY_LENGTH=$(require_value "$1" "${2:-}"); HAS_INSTALL_OPT="true"; shift 2 ;;
            --dns-provider)
                DNS_PROVIDER=$(require_value "$1" "${2:-}"); HAS_INSTALL_OPT="true"; shift 2 ;;
            --dns-env)
                val=$(require_value "$1" "${2:-}"); DNS_ENVS+=("$val"); HAS_INSTALL_OPT="true"; shift 2 ;;
            --env)
                val=$(require_value "$1" "${2:-}"); EXTRA_ENVS+=("$val"); HAS_INSTALL_OPT="true"; shift 2 ;;
            *)
                log "error" "未知参数: $1"
                show_help
                exit 1 ;;
        esac
    done

    if [[ -z "$ACTION" ]]; then
        log "error" "必须指定一个操作 (--update, --install, --start, --stop, --restart, --uninstall)"
        show_help
        exit 1
    fi

    if [[ "$ACTION" != "install" && "$HAS_INSTALL_OPT" == "true" ]]; then
        log "error" "--${ACTION} 不接受安装配置参数；如需修改配置或更新镜像，请使用 --install"
        exit 1
    fi

    if [[ "$ACTION" == "update" && -n "$CONTAINER_NAME" ]]; then
        log "error" "--update 为系统级更新操作，不接受 --container-name"
        exit 1
    fi
}

main() {
    parse_arguments "$@"

    case "$ACTION" in
        update)
            check_privileges
            update_system
            ;;
        install)
            install_soga
            ;;
        start)
            start_soga
            ;;
        restart)
            restart_soga
            ;;
        stop)
            stop_soga
            ;;
        uninstall)
            uninstall_soga
            ;;
    esac
}

main "$@"

exit 0
