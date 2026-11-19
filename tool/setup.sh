#!/bin/bash

# VPS 系统初始化脚本（适用于 Debian 11+ / Ubuntu 20.04+）
# 职责：系统更新与基础工具、用户与 SSH 加固、Fail2ban、时区与 Chrony、BBR 与 IP 转发
set -uo pipefail

readonly SCRIPT_VERSION="3.0.0"
readonly TESTED_DEBIAN_VERSIONS="11 12 13"
readonly MIN_PORT=1024
readonly MAX_PORT=65535

if [ -n "${BASH_SOURCE[0]:-}" ] && [[ "${BASH_SOURCE[0]}" != /dev/fd/* ]] && [[ "${BASH_SOURCE[0]}" != /proc/self/fd/* ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
    if [ -w "${HOME:-}" ] && [ -d "${HOME:-}" ]; then
        SCRIPT_DIR="$HOME"
    else
        SCRIPT_DIR="/tmp"
    fi
fi

readonly TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
readonly CONFIG_BACKUP_DIR="$SCRIPT_DIR/ssh_backups_$TIMESTAMP"
readonly LOG_FILE="$SCRIPT_DIR/setup-script-$TIMESTAMP.log"

readonly SSH_CONFIG="/etc/ssh/sshd_config"
readonly SSH_CONFIG_DIR="/etc/ssh/sshd_config.d"
# OpenSSH 采用 First-Match-Wins，00 前缀确保排在 50-cloud-init.conf / 60-cloudimg-settings.conf 之前生效
readonly SSH_SECURITY_CONF="$SSH_CONFIG_DIR/00-setup-security.conf"
readonly SSH_LEGACY_SECURITY_CONF="$SSH_CONFIG_DIR/99-security.conf"
# Debian 13+ systemd-sysctl 默认不再加载 /etc/sysctl.conf，统一写入 /etc/sysctl.d/
readonly SYSCTL_CUSTOM_CONF="/etc/sysctl.d/99-setup.conf"
readonly APT_FALLBACK_TMP_DIR="/tmp/setup-apt-fallback-official"
readonly APT_FALLBACK_LEGACY_SOURCE="/etc/apt/sources.list.d/00-setup-fallback-official.list"

LOG_ENABLED="false"
DISABLE_SSH_PASSWD="false"
SSH_PORT=""
SSH_KEY=""
SERVER_REGION="asia"
CREATE_DEVOPS_USER="false"
SUDO_USERNAME=""
NTP_SERVICE="chrony"
DISABLE_ROOT_LOGIN="false"

OS_DISTRO=""
OS_VERSION=""
OS_CODENAME=""
OS_PRETTY=""

# ==================== 清理与错误处理 ====================

cleanup() {
    if [ -e "$APT_FALLBACK_TMP_DIR" ]; then
        sudo rm -rf "$APT_FALLBACK_TMP_DIR" 2>/dev/null || true
    fi
    if [ -e "$APT_FALLBACK_LEGACY_SOURCE" ]; then
        sudo rm -f "$APT_FALLBACK_LEGACY_SOURCE" 2>/dev/null || true
    fi
    if [ "$LOG_ENABLED" = "true" ]; then
        log_message "INFO" "清理完成"
    fi
}

on_interrupt() {
    log_message "WARNING" "收到中断信号，正在退出..."
    exit 130
}

die() {
    local msg="${1:-未知致命错误}"
    local exit_code="${2:-1}"

    log_message "ERROR" "致命错误: $msg"
    log_message "ERROR" "脚本终止执行 (退出码: $exit_code)"
    exit "$exit_code"
}

check_error() {
    local exit_code=$1
    local operation="${2:-操作}"
    local context="${3:-}"

    if [ "$exit_code" -ne 0 ]; then
        local error_msg="$operation 失败 (错误码: $exit_code)"
        [ -n "$context" ] && error_msg="$error_msg - $context"
        log_message "WARNING" "$error_msg"
        return 1
    fi
    return 0
}

safe_execute() {
    local description="执行命令"
    local fatal="false"

    while [ $# -gt 0 ] && [ "${1:0:1}" = "-" ]; do
        case "$1" in
            -d) [ $# -lt 2 ] && { log_message "ERROR" "safe_execute: -d 需要参数"; return 1; }
                description="$2"; shift 2 ;;
            -f) fatal="true"; shift ;;
            --) shift; break ;;
            *)  break ;;
        esac
    done

    if [ $# -eq 0 ]; then
        log_message "ERROR" "safe_execute: 未指定命令"
        return 1
    fi

    log_message "DEBUG" "执行: $*"
    "$@"
    local exit_code=$?

    if [ "$exit_code" -ne 0 ]; then
        if [ "$fatal" = "true" ]; then
            die "$description 失败" "$exit_code"
        fi
        check_error "$exit_code" "$description"
        return "$exit_code"
    fi

    log_message "DEBUG" "$description 成功"
    return 0
}

log_message() {
    local level="${1:-INFO}"
    local message="${2:-}"
    [ -z "$message" ] && return 0

    if [[ "$message" =~ (ssh-(ed25519|rsa)|ecdsa-sha2-nistp[0-9]+|sk-(ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)[[:space:]]+[A-Za-z0-9+/]+=* ]]; then
        message="[SSH公钥内容已脱敏]"
    fi

    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    case "$level" in
        ERROR|error|ERR|err)         level="ERROR";   echo "[错误] $message" >&2 ;;
        WARNING|warning|WARN|warn)   level="WARNING"; echo "[警告] $message" ;;
        INFO|info)                   level="INFO";    echo "[信息] $message" ;;
        DEBUG|debug)                 level="DEBUG";   [ "${DEBUG:-}" = "1" ] && echo "[调试] $message" ;;
        SUCCESS|success|OK|ok)       level="SUCCESS"; echo "[成功] $message" ;;
        *)                                            echo "[日志] $message" ;;
    esac

    if [ "$LOG_ENABLED" = "true" ] && [ -n "${LOG_FILE:-}" ]; then
        local log_dir
        log_dir=$(dirname "$LOG_FILE")
        if [ ! -d "$log_dir" ]; then
            mkdir -p "$log_dir" 2>/dev/null || return 0
            chmod 750 "$log_dir" 2>/dev/null || true
        fi
        echo "[$timestamp][$level] $message" >> "$LOG_FILE" 2>/dev/null || true
        chmod 640 "$LOG_FILE" 2>/dev/null || true
    fi

    if [ "$level" = "ERROR" ] && command -v logger >/dev/null 2>&1; then
        logger -t "setup" -p user.err "$message" 2>/dev/null || true
    fi
}

# ==================== 校验与公共辅助函数 ====================

is_valid_ssh_pubkey() {
    local key="${1:-}"
    [ -z "$key" ] && return 1
    [[ "$key" == *$'\n'* ]] || [[ "$key" == *$'\r'* ]] && return 1
    [[ "$key" =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)[[:space:]]+[A-Za-z0-9+/]+={0,3}([[:space:]].*)?$ ]]
}

# 检查 authorized_keys 是否包含真正可用的密钥（排除 cloud-init 禁止 root 登录的 forced-command 占位行）
file_has_usable_ssh_key() {
    local keyfile="$1"
    sudo test -f "$keyfile" || return 1
    sudo awk '
        /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
        /command="[^"]*(Please login as|exit[[:space:]]+[0-9]+)/ { next }
        {
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp(256|384|521)|sk-(ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)$/ &&
                    (i + 1) <= NF && $(i + 1) ~ /^[A-Za-z0-9+\/]+=*$/) {
                    found = 1
                    exit 0
                }
            }
        }
        END { exit(found ? 0 : 1) }
    ' "$keyfile" 2>/dev/null
}

is_reserved_username() {
    local user="$1"
    case "$user" in
        root|daemon|bin|sys|sync|games|man|lp|mail|news|uucp|proxy|www-data|backup|list|irc|gnats|nobody|systemd-*|messagebus|sshd|_apt|chrony|syslog|uuidd|tcpdump|tss|landscape|pollinate|ubuntu-advantage)
            return 0
            ;;
    esac
    if id "$user" &>/dev/null; then
        local uid
        uid=$(id -u "$user" 2>/dev/null || echo 0)
        if [ "$uid" -lt 1000 ]; then
            return 0
        fi
    fi
    return 1
}

get_sshd_bin() {
    if [ -x /usr/sbin/sshd ]; then
        echo "/usr/sbin/sshd"
    elif command -v sshd >/dev/null 2>&1; then
        command -v sshd
    else
        echo ""
    fi
}

ensure_sshd_run_dir() {
    if [ ! -d /run/sshd ]; then
        sudo mkdir -p /run/sshd
        sudo chmod 0755 /run/sshd
    fi
}

read_sshd_effective() {
    local sshd_bin
    sshd_bin=$(get_sshd_bin)
    [ -z "$sshd_bin" ] && return 0
    ensure_sshd_run_dir
    sudo "$sshd_bin" -T -C user=root,host=localhost,addr=127.0.0.1 2>/dev/null \
        || sudo "$sshd_bin" -T 2>/dev/null \
        || true
}

get_effective_ssh_port() {
    if [ -n "$SSH_PORT" ]; then
        echo "$SSH_PORT"
        return 0
    fi
    local cfg port=""
    cfg=$(read_sshd_effective)
    if [ -n "$cfg" ]; then
        port=$(echo "$cfg" | awk '/^port / {print $2; exit}')
    fi
    if [ -z "$port" ] && [ -f "$SSH_SECURITY_CONF" ]; then
        port=$(awk 'tolower($1) == "port" {print $2; exit}' "$SSH_SECURITY_CONF" 2>/dev/null)
    fi
    if [ -z "$port" ] && [ -f "$SSH_CONFIG" ]; then
        port=$(awk 'tolower($1) == "port" {print $2; exit}' "$SSH_CONFIG" 2>/dev/null)
    fi
    echo "${port:-22}"
}

# 管道执行（stdin 非 TTY）时启用非交互防卡死，终端直连时保留原有交互能力
run_apt_get() {
    if [ -t 0 ]; then
        sudo apt-get "$@"
    else
        sudo env DEBIAN_FRONTEND=noninteractive apt-get \
            -o Dpkg::Options::="--force-confdef" \
            -o Dpkg::Options::="--force-confold" \
            "$@"
    fi
}

# ==================== 帮助与参数解析 ====================

usage() {
    cat << EOF
用法: $0 [选项]

选项:
  --help                    显示此帮助信息
  --version                 显示脚本版本
  --disable_ssh_pwd         禁用 SSH 密码登录，仅允许密钥认证
  --port PORT               设置 SSH 端口号（22 或 ${MIN_PORT}-${MAX_PORT}）
  --ssh_key KEY             设置 SSH 公钥（支持 ed25519 / rsa / ecdsa / sk-*）
  --create_user USERNAME    创建具备免密 sudo 权限的管理员用户（必须提供 --ssh_key）
  --disable_root_login      禁用 root 用户 SSH 登录（需存在或新建可用管理员用户）
  --region REGION           服务器地区，用于选择 NTP 源
                            (auto|cn|hk|tw|jp|kr|sg|us|eu|asia，默认: asia)
  --ntp_service SERVICE     NTP 服务（chrony|timesyncd|auto，默认: chrony）

示例:
  $0 --disable_ssh_pwd --port 2222 --ssh_key "ssh-ed25519 AAAA..." --region hk
  $0 --disable_ssh_pwd --ssh_key "ssh-ed25519 AAAA..." --region jp
  $0 --disable_ssh_pwd --port 2222 --ssh_key "ssh-ed25519 AAAA..." --create_user devops --disable_root_login --region sg

支持的系统: Debian 11/12/13, Ubuntu 20.04+
脚本版本: $SCRIPT_VERSION
EOF
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --help|-h)
                usage
                exit 0
                ;;
            --version)
                echo "脚本版本: $SCRIPT_VERSION"
                exit 0
                ;;
            --disable_ssh_pwd)
                DISABLE_SSH_PASSWD="true"
                ;;
            --port)
                if [ $# -lt 2 ] || [ -z "${2:-}" ] || [[ "$2" == --* ]]; then
                    log_message "ERROR" "选项 $1 需要一个有效的端口号参数"
                    exit 1
                fi
                if ! [[ "$2" =~ ^[1-9][0-9]*$ ]] || { [ "$2" -ne 22 ] && { [ "$2" -lt "$MIN_PORT" ] || [ "$2" -gt "$MAX_PORT" ]; }; }; then
                    log_message "ERROR" "无效的端口号: $2（允许 22 或 ${MIN_PORT}-${MAX_PORT}）"
                    exit 1
                fi
                SSH_PORT="$2"
                shift
                ;;
            --ssh_key)
                if [ $# -lt 2 ] || [ -z "${2:-}" ] || [[ "$2" == --* ]]; then
                    log_message "ERROR" "选项 $1 需要一个有效的 SSH 公钥参数"
                    exit 1
                fi
                if ! is_valid_ssh_pubkey "$2"; then
                    log_message "ERROR" "无效的 SSH 公钥格式（需为单行 ssh-ed25519 / ssh-rsa / ecdsa / sk-* 公钥）"
                    exit 1
                fi
                SSH_KEY="$2"
                shift
                ;;
            --region)
                if [ $# -lt 2 ] || [ -z "${2:-}" ] || [[ "$2" == --* ]]; then
                    log_message "ERROR" "选项 $1 需要一个有效的地区参数"
                    exit 1
                fi
                case "$2" in
                    auto|cn|hk|tw|jp|kr|sg|us|eu|asia)
                        SERVER_REGION="$2"
                        ;;
                    *)
                        log_message "ERROR" "无效的地区参数: $2"
                        exit 1
                        ;;
                esac
                shift
                ;;
            --ntp_service)
                if [ $# -lt 2 ] || [ -z "${2:-}" ] || [[ "$2" == --* ]]; then
                    log_message "ERROR" "选项 $1 需要一个有效的 NTP 服务参数"
                    exit 1
                fi
                case "$2" in
                    auto|chrony)
                        NTP_SERVICE="chrony"
                        ;;
                    timesyncd)
                        NTP_SERVICE="timesyncd"
                        ;;
                    *)
                        log_message "ERROR" "无效的 NTP 服务参数: $2（可选: chrony|timesyncd|auto）"
                        exit 1
                        ;;
                esac
                shift
                ;;
            --create_user)
                if [ $# -lt 2 ] || [ -z "${2:-}" ] || [[ "$2" == --* ]]; then
                    log_message "ERROR" "选项 $1 需要一个有效的用户名参数"
                    exit 1
                fi
                if ! [[ "$2" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
                    log_message "ERROR" "无效的用户名格式: $2"
                    exit 1
                fi
                if is_reserved_username "$2"; then
                    log_message "ERROR" "禁止使用系统保留账户名: $2"
                    exit 1
                fi
                CREATE_DEVOPS_USER="true"
                SUDO_USERNAME="$2"
                shift
                ;;
            --disable_root_login)
                DISABLE_ROOT_LOGIN="true"
                ;;
            *)
                log_message "ERROR" "未知选项: $1"
                usage
                exit 1
                ;;
        esac
        shift
    done

    if [ "$CREATE_DEVOPS_USER" = "true" ] && [ -z "$SSH_KEY" ]; then
        log_message "ERROR" "创建管理员用户时必须通过 --ssh_key 提供 SSH 公钥"
        exit 1
    fi
}

# ==================== 系统检查与 APT 包管理 ====================

check_privileges() {
    if [ "$(id -u)" -eq 0 ]; then
        return 0
    fi
    if ! command -v sudo >/dev/null 2>&1; then
        log_message "ERROR" "当前非 root 用户且系统未安装 sudo，请以 root 身份运行"
        return 1
    fi
    if ! sudo -v; then
        log_message "ERROR" "当前用户无可用的 sudo 权限"
        return 1
    fi
    return 0
}

check_compatibility() {
    log_message "INFO" "检查系统兼容性..."

    if [ ! -f /etc/os-release ]; then
        log_message "ERROR" "未找到 /etc/os-release，不支持的操作系统"
        return 1
    fi

    local raw_version=""
    eval "$(
        . /etc/os-release
        printf 'OS_DISTRO=%q\nraw_version=%q\nOS_CODENAME=%q\nOS_PRETTY=%q\n' \
            "${ID:-}" "${VERSION_ID:-}" "${VERSION_CODENAME:-}" "${PRETTY_NAME:-}"
    )"

    case "$OS_DISTRO" in
        debian)
            if [[ "$raw_version" =~ ^([0-9]+) ]]; then
                OS_VERSION="${BASH_REMATCH[1]}"
            elif [ -f /etc/debian_version ]; then
                local deb_ver
                deb_ver=$(cat /etc/debian_version)
                case "$deb_ver" in
                    *trixie*)   OS_VERSION="13"; [ -z "$OS_CODENAME" ] && OS_CODENAME="trixie" ;;
                    *bookworm*) OS_VERSION="12"; [ -z "$OS_CODENAME" ] && OS_CODENAME="bookworm" ;;
                    *bullseye*) OS_VERSION="11"; [ -z "$OS_CODENAME" ] && OS_CODENAME="bullseye" ;;
                    *buster*)   OS_VERSION="10" ;;
                    *)          OS_VERSION="$deb_ver" ;;
                esac
            else
                OS_VERSION="$raw_version"
            fi

            if [[ "$OS_VERSION" =~ ^[0-9]+$ ]] && [ "$OS_VERSION" -lt 11 ]; then
                log_message "ERROR" "不支持 Debian ${OS_VERSION}（最低要求 Debian 11）"
                return 1
            fi
            log_message "INFO" "检测到 Debian 系统 (${OS_PRETTY:-Debian $OS_VERSION})"
            if ! echo "$TESTED_DEBIAN_VERSIONS" | grep -qw "$OS_VERSION"; then
                log_message "WARNING" "Debian $OS_VERSION 尚未在完整测试列表中，将继续执行"
            fi
            ;;
        ubuntu)
            OS_VERSION="$raw_version"
            local ubuntu_major="${raw_version%%.*}"
            if ! [[ "$ubuntu_major" =~ ^[0-9]+$ ]] || [ "$ubuntu_major" -lt 20 ]; then
                log_message "ERROR" "不支持 Ubuntu ${raw_version}（最低要求 Ubuntu 20.04）"
                return 1
            fi
            log_message "INFO" "检测到 Ubuntu 系统 (${OS_PRETTY:-Ubuntu $OS_VERSION})"
            ;;
        *)
            log_message "ERROR" "不支持的发行版: ${OS_PRETTY:-$OS_DISTRO}（仅支持 Debian 11+ 和 Ubuntu 20.04+）"
            return 1
            ;;
    esac

    for cmd in systemctl grep sed awk ss; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            log_message "ERROR" "缺少必要的系统命令: $cmd"
            return 1
        fi
    done

    if [ -z "$(get_sshd_bin)" ]; then
        log_message "ERROR" "未检测到 OpenSSH 服务端 (sshd)"
        return 1
    fi

    return 0
}

wait_for_cloud_init() {
    if command -v cloud-init >/dev/null 2>&1; then
        log_message "INFO" "等待 cloud-init 完成..."
        cloud-init status --wait >/dev/null 2>&1 || true
    fi
}

wait_for_apt_locks() {
    local max_wait=900
    local waited=0
    local check_interval=5
    local first_wait="true"

    if [ -d /var/cache/apt/archives ]; then
        local available_space
        available_space=$(df -Pk /var/cache/apt/archives 2>/dev/null | awk 'NR==2 {print $4}')
        if [[ "${available_space:-0}" =~ ^[0-9]+$ ]] && [ "$available_space" -gt 0 ] && [ "$available_space" -lt 1000000 ]; then
            log_message "WARNING" "磁盘可用空间不足 1GB (${available_space}KB)，清理 apt 缓存..."
            sudo apt-get clean 2>/dev/null || true
        fi
    fi

    while true; do
        local locked="false"
        local lock_sources=()

        if command -v fuser >/dev/null 2>&1; then
            if sudo fuser /var/lib/dpkg/lock /var/lib/dpkg/lock-frontend >/dev/null 2>&1; then
                locked="true"
                lock_sources+=("dpkg-lock")
            fi
            if sudo fuser /var/lib/apt/lists/lock >/dev/null 2>&1; then
                locked="true"
                lock_sources+=("apt-lists-lock")
            fi
            if sudo fuser /var/cache/apt/archives/lock >/dev/null 2>&1; then
                locked="true"
                lock_sources+=("apt-cache-lock")
            fi
        fi

        if pgrep -x "apt|apt-get|dpkg|aptitude" >/dev/null 2>&1; then
            locked="true"
            lock_sources+=("apt-processes")
        fi

        if pgrep -f "/usr/bin/unattended-upgrade" >/dev/null 2>&1; then
            locked="true"
            lock_sources+=("unattended-upgrades")
        fi

        if pgrep -f "cloud-init.*apt" >/dev/null 2>&1; then
            locked="true"
            lock_sources+=("cloud-init-apt")
        fi

        if [ "$locked" = "false" ]; then
            break
        fi

        if [ "$first_wait" = "true" ]; then
            log_message "INFO" "检测到包管理器正在被占用 (${lock_sources[*]})，等待释放..."
            first_wait="false"
        elif [ $((waited % 60)) -eq 0 ]; then
            log_message "INFO" "继续等待 apt 锁释放... ($waited/${max_wait}秒) - 占用源: ${lock_sources[*]}"
        fi

        if [ "$waited" -ge "$max_wait" ]; then
            log_message "ERROR" "等待 apt 锁超时 (${max_wait}秒)，当前占用源: ${lock_sources[*]}"
            return 1
        fi

        sleep "$check_interval"
        waited=$((waited + check_interval))
    done

    if [ "$waited" -gt 0 ]; then
        log_message "INFO" "apt 锁已释放（等待 ${waited} 秒）"
        sleep 2
    fi

    # 锁释放后再检查 dpkg 状态，避免与正在运行的 apt/dpkg 并发冲突
    if ! sudo dpkg --audit >/dev/null 2>&1; then
        log_message "WARNING" "发现未完成配置的软件包，正在执行 dpkg --configure -a..."
        sudo dpkg --configure -a || true
    fi

    return 0
}

fix_sudo_and_hosts() {
    if ! command -v sudo >/dev/null 2>&1; then
        log_message "INFO" "安装 sudo..."
        if ! wait_for_apt_locks; then
            log_message "ERROR" "等待 apt 锁失败，无法安装 sudo"
            return 1
        fi
        if [ -t 0 ]; then
            apt-get update -y && apt-get install -y sudo
        else
            DEBIAN_FRONTEND=noninteractive apt-get update -y && \
                DEBIAN_FRONTEND=noninteractive apt-get install -y sudo
        fi || return 1
    fi

    local current_hostname
    current_hostname=$(hostname | tr -d '\n' | sed 's/[^a-zA-Z0-9.-]//g')
    if [ -n "$current_hostname" ] && ! grep -wq "$current_hostname" /etc/hosts 2>/dev/null; then
        log_message "INFO" "将主机名 $current_hostname 添加到 /etc/hosts..."
        echo "127.0.1.1   $current_hostname" | sudo tee -a /etc/hosts >/dev/null
    fi
    return 0
}

apt_install_with_retry() {
    local packages="$1"
    local max_retries="${2:-3}"
    local retry_delay="${3:-15}"
    local retry_count=0

    while [ "$retry_count" -lt "$max_retries" ]; do
        if ! wait_for_apt_locks; then
            retry_count=$((retry_count + 1))
            if [ "$retry_count" -lt "$max_retries" ]; then
                sleep "$retry_delay"
                continue
            fi
            return 1
        fi

        log_message "INFO" "安装软件包: $packages (尝试 $((retry_count + 1))/$max_retries)"
        # shellcheck disable=SC2086
        if run_apt_get install -y $packages; then
            return 0
        fi

        local exit_code=$?
        retry_count=$((retry_count + 1))
        log_message "WARNING" "软件包安装失败 (退出码: $exit_code): $packages"

        if [ "$retry_count" -lt "$max_retries" ]; then
            log_message "INFO" "等待 ${retry_delay} 秒后重试..."
            sleep "$retry_delay"
            sudo dpkg --configure -a 2>/dev/null || true
            run_apt_get -f install -y 2>/dev/null || true
        else
            log_message "ERROR" "软件包安装失败，已重试 $max_retries 次: $packages"
            return "$exit_code"
        fi
    done

    return 1
}

update_system_install_dependencies() {
    log_message "INFO" "更新系统并安装基础软件..."

    if ! wait_for_apt_locks; then
        log_message "ERROR" "无法获取 apt 锁"
        return 1
    fi

    if ! safe_execute -d "更新软件包索引" run_apt_get update -y; then
        log_message "ERROR" "apt-get update 失败，无法继续安装基础软件"
        return 1
    fi

    safe_execute -d "系统软件包升级" run_apt_get upgrade -y || true
    safe_execute -d "系统完整升级" run_apt_get full-upgrade -y || true
    safe_execute -d "清理过期缓存包" run_apt_get autoclean -y || true
    safe_execute -d "移除无用依赖包" run_apt_get autoremove -y || true

    local base_packages="wget curl vim unzip zip fail2ban rsyslog iptables mtr netcat-openbsd"
    if ! apt_install_with_retry "$base_packages"; then
        log_message "ERROR" "基础软件包安装失败"
        return 1
    fi

    if ! apt_install_with_retry "iperf3" 2 10; then
        log_message "WARNING" "可选工具 iperf3 安装失败，不影响核心功能"
    fi

    local missing_packages=""
    for pkg in wget curl vim; do
        if ! command -v "$pkg" >/dev/null 2>&1; then
            missing_packages="$missing_packages $pkg"
        fi
    done
    if ! command -v fail2ban-client >/dev/null 2>&1; then
        missing_packages="$missing_packages fail2ban"
    fi
    if [ -n "$missing_packages" ]; then
        log_message "WARNING" "以下软件包未检测到可执行命令:$missing_packages"
    fi

    log_message "SUCCESS" "系统更新和基础软件安装完成"
    return 0
}

# ==================== 用户与密钥配置 ====================

configure_ssh_keys() {
    [ -z "$SSH_KEY" ] && return 0

    local current_user current_group target_home
    current_user=$(id -un)
    current_group=$(id -gn)
    target_home=$(getent passwd "$current_user" 2>/dev/null | cut -d: -f6)
    target_home="${target_home:-$HOME}"

    local ssh_dir="$target_home/.ssh"
    local auth_keys="$ssh_dir/authorized_keys"

    sudo mkdir -p "$ssh_dir"
    sudo chmod 700 "$ssh_dir"
    sudo touch "$auth_keys"
    sudo chmod 600 "$auth_keys"
    sudo chown -R "$current_user:$current_group" "$ssh_dir"

    # 清理云镜像在 root authorized_keys 中注入的 forced-command 拦截行，避免同公钥被拦截为禁止登录
    if [ "$current_user" = "root" ] && sudo grep -qE 'command="[^"]*(Please login as|exit[[:space:]]+[0-9]+)' "$auth_keys" 2>/dev/null; then
        log_message "INFO" "清理 root authorized_keys 中的云镜像登录限制占位行"
        sudo sed -i '/command="[^"]*\(Please login as\|exit[[:space:]]\+[0-9]\+\)/d' "$auth_keys"
    fi

    if ! sudo grep -qxF "$SSH_KEY" "$auth_keys"; then
        printf '%s\n' "$SSH_KEY" | sudo tee -a "$auth_keys" >/dev/null
        log_message "INFO" "SSH 公钥已添加到用户 $current_user ($auth_keys)"
    else
        log_message "INFO" "SSH 公钥已存在于用户 $current_user"
    fi

    if ! file_has_usable_ssh_key "$auth_keys"; then
        log_message "ERROR" "验证 $auth_keys 中的可用公钥失败"
        return 1
    fi

    return 0
}

create_admin_user() {
    [ "$CREATE_DEVOPS_USER" != "true" ] && return 0

    log_message "INFO" "配置管理员用户 $SUDO_USERNAME..."

    if id "$SUDO_USERNAME" &>/dev/null; then
        log_message "INFO" "用户 $SUDO_USERNAME 已存在，更新权限和密钥配置"
    else
        if ! sudo adduser --disabled-password --gecos "Administrator" "$SUDO_USERNAME"; then
            log_message "ERROR" "创建用户 $SUDO_USERNAME 失败"
            return 1
        fi
    fi

    if ! sudo usermod -aG sudo "$SUDO_USERNAME"; then
        log_message "ERROR" "将用户 $SUDO_USERNAME 加入 sudo 组失败"
        return 1
    fi

    local user_home user_group
    user_home=$(getent passwd "$SUDO_USERNAME" 2>/dev/null | cut -d: -f6)
    user_home="${user_home:-/home/$SUDO_USERNAME}"
    user_group=$(id -gn "$SUDO_USERNAME")

    local user_ssh_dir="$user_home/.ssh"
    local user_auth_keys="$user_ssh_dir/authorized_keys"

    sudo mkdir -p "$user_ssh_dir"
    sudo touch "$user_auth_keys"

    if ! sudo grep -qxF "$SSH_KEY" "$user_auth_keys"; then
        printf '%s\n' "$SSH_KEY" | sudo tee -a "$user_auth_keys" >/dev/null
    fi

    sudo chown -R "$SUDO_USERNAME:$user_group" "$user_ssh_dir"
    sudo chmod 700 "$user_ssh_dir"
    sudo chmod 600 "$user_auth_keys"

    local sudoers_file="/etc/sudoers.d/$SUDO_USERNAME"
    local sudoers_tmp="/tmp/sudoers.$SUDO_USERNAME.$$"
    printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$SUDO_USERNAME" > "$sudoers_tmp"
    chmod 440 "$sudoers_tmp"

    if command -v visudo >/dev/null 2>&1 && ! sudo visudo -cf "$sudoers_tmp" >/dev/null 2>&1; then
        rm -f "$sudoers_tmp"
        log_message "ERROR" "sudoers 语法校验未通过"
        return 1
    fi
    sudo mv "$sudoers_tmp" "$sudoers_file"
    sudo chown root:root "$sudoers_file"
    sudo chmod 440 "$sudoers_file"

    if ! sudo -u "$SUDO_USERNAME" sudo -n true 2>/dev/null; then
        log_message "ERROR" "验证用户 $SUDO_USERNAME 免密 sudo 权限失败"
        return 1
    fi

    if ! file_has_usable_ssh_key "$user_auth_keys"; then
        log_message "ERROR" "验证用户 $SUDO_USERNAME 的 SSH 公钥失败"
        return 1
    fi

    log_message "SUCCESS" "管理员用户 $SUDO_USERNAME 配置完成"
    return 0
}

# ==================== SSH 安全加固 ====================

backup_ssh_config() {
    log_message "INFO" "备份当前 SSH 配置到 $CONFIG_BACKUP_DIR..."

    sudo mkdir -p "$CONFIG_BACKUP_DIR"
    sudo chmod 700 "$CONFIG_BACKUP_DIR"

    if [ -f "$SSH_CONFIG" ]; then
        sudo cp -a "$SSH_CONFIG" "$CONFIG_BACKUP_DIR/sshd_config.bak"
    fi

    if [ -d "$SSH_CONFIG_DIR" ]; then
        sudo mkdir -p "$CONFIG_BACKUP_DIR/sshd_config.d"
        sudo cp -a "$SSH_CONFIG_DIR"/. "$CONFIG_BACKUP_DIR/sshd_config.d/"
    fi

    sudo tee "$CONFIG_BACKUP_DIR/restore.sh" >/dev/null << EOF
#!/bin/bash
set -euo pipefail
[ -f "$CONFIG_BACKUP_DIR/sshd_config.bak" ] && sudo cp -a "$CONFIG_BACKUP_DIR/sshd_config.bak" "$SSH_CONFIG"
if [ -d "$CONFIG_BACKUP_DIR/sshd_config.d" ]; then
    sudo mkdir -p "$SSH_CONFIG_DIR"
    sudo find "$SSH_CONFIG_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
    sudo cp -a "$CONFIG_BACKUP_DIR/sshd_config.d"/. "$SSH_CONFIG_DIR/"
fi
sudo systemctl daemon-reload 2>/dev/null || true
if systemctl is-active --quiet ssh.socket 2>/dev/null || systemctl is-enabled --quiet ssh.socket 2>/dev/null; then
    sudo systemctl restart ssh.socket
    sudo systemctl restart ssh 2>/dev/null || true
else
    sudo systemctl restart ssh 2>/dev/null || sudo systemctl restart sshd
fi
echo "SSH 配置已从备份恢复"
EOF
    sudo chmod 700 "$CONFIG_BACKUP_DIR/restore.sh"
}

restore_ssh_config_from_backup() {
    if [ ! -f "$CONFIG_BACKUP_DIR/sshd_config.bak" ]; then
        log_message "ERROR" "未找到 SSH 备份文件: $CONFIG_BACKUP_DIR/sshd_config.bak"
        return 1
    fi

    sudo cp -a "$CONFIG_BACKUP_DIR/sshd_config.bak" "$SSH_CONFIG"
    if [ -d "$CONFIG_BACKUP_DIR/sshd_config.d" ]; then
        sudo mkdir -p "$SSH_CONFIG_DIR"
        sudo find "$SSH_CONFIG_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
        sudo cp -a "$CONFIG_BACKUP_DIR/sshd_config.d"/. "$SSH_CONFIG_DIR/"
    fi
    log_message "INFO" "已从备份恢复 SSH 配置文件"
    return 0
}

# 检查是否存在至少一个非 root 的 sudo 用户，以及是否具备可用 SSH 公钥
find_sudo_user_state() {
    HAS_NONROOT_SUDO_USER="false"
    HAS_KEYED_SUDO_USER="false"

    local candidates=()
    if [ "$CREATE_DEVOPS_USER" = "true" ] && [ -n "$SUDO_USERNAME" ]; then
        candidates+=("$SUDO_USERNAME")
    fi

    local current_user
    current_user=$(id -un)
    if [ "$current_user" != "root" ] && sudo -n true 2>/dev/null; then
        candidates+=("$current_user")
    fi

    local group_members
    group_members=$(getent group sudo 2>/dev/null | awk -F: '{print $4}' | tr ',' ' ')
    local member
    for member in $group_members; do
        [ "$member" != "root" ] && candidates+=("$member")
    done

    local user user_home
    for user in ${candidates[@]+"${candidates[@]}"}; do
        [ -z "$user" ] && continue
        id "$user" &>/dev/null || continue
        HAS_NONROOT_SUDO_USER="true"
        user_home=$(getent passwd "$user" 2>/dev/null | cut -d: -f6)
        if [ -n "$user_home" ] && file_has_usable_ssh_key "$user_home/.ssh/authorized_keys"; then
            HAS_KEYED_SUDO_USER="true"
            break
        fi
    done
}

comment_managed_directives_in_file() {
    local file="$1"
    [ -f "$file" ] || return 0
    sudo sed -i -E \
        's/^[[:space:]]*(Port|PasswordAuthentication|PermitRootLogin|PubkeyAuthentication|PermitEmptyPasswords|ChallengeResponseAuthentication|KbdInteractiveAuthentication|X11Forwarding|ClientAliveInterval|ClientAliveCountMax|UseDNS)[[:space:]=]/#&/I' \
        "$file"
}

validate_and_restart_ssh() {
    local expected_port="$1"
    local sshd_bin
    sshd_bin=$(get_sshd_bin)

    ensure_sshd_run_dir

    if ! sudo "$sshd_bin" -t; then
        log_message "ERROR" "sshd -t 配置语法校验失败"
        return 1
    fi

    sudo systemctl daemon-reload 2>/dev/null || true

    local using_socket="false"
    if systemctl is-active --quiet ssh.socket 2>/dev/null || systemctl is-enabled --quiet ssh.socket 2>/dev/null; then
        using_socket="true"
        log_message "INFO" "检测到 systemd ssh.socket，重新加载并重启 socket..."
        if ! sudo systemctl restart ssh.socket; then
            log_message "ERROR" "重启 ssh.socket 失败"
            return 1
        fi
        sudo systemctl restart ssh 2>/dev/null || true
    else
        if ! (sudo systemctl restart ssh 2>/dev/null || sudo systemctl restart sshd 2>/dev/null); then
            log_message "ERROR" "重启 SSH 服务失败"
            return 1
        fi
    fi

    sleep 1

    # Ubuntu 部分版本 ssh.socket 未跟随自定义端口时，切换为常规 ssh.service 守护进程模式
    if ! sudo ss -tln | grep -qE "[:.]${expected_port}[[:space:]]"; then
        if [ "$using_socket" = "true" ]; then
            log_message "WARNING" "ssh.socket 未监听端口 ${expected_port}，切换为 ssh.service 直接监听..."
            sudo systemctl stop ssh.socket 2>/dev/null || true
            sudo systemctl disable ssh.socket 2>/dev/null || true
            sudo systemctl enable --now ssh 2>/dev/null || sudo systemctl restart ssh 2>/dev/null || true
            sleep 1
        fi
    fi

    if ! sudo ss -tln | grep -qE "[:.]${expected_port}[[:space:]]"; then
        log_message "ERROR" "SSH 未能在端口 $expected_port 上监听"
        return 1
    fi

    log_message "INFO" "SSH 服务已正常监听端口 $expected_port"
    return 0
}

configure_ssh() {
    log_message "INFO" "配置 SSH 安全策略..."

    backup_ssh_config || {
        log_message "ERROR" "SSH 配置备份失败，中止修改以免发生风险"
        return 1
    }

    local current_cfg current_port current_passwd_auth current_permit_root
    current_cfg=$(read_sshd_effective)
    current_port=$(echo "$current_cfg" | awk '/^port / {print $2; exit}')
    current_passwd_auth=$(echo "$current_cfg" | awk '/^passwordauthentication / {print $2; exit}')
    current_permit_root=$(echo "$current_cfg" | awk '/^permitrootlogin / {print $2; exit}')

    local effective_port="${SSH_PORT:-${current_port:-22}}"
    local target_passwd_auth="${current_passwd_auth:-yes}"
    local target_permit_root="${current_permit_root:-yes}"

    local has_root_key="false"
    if file_has_usable_ssh_key "/root/.ssh/authorized_keys"; then
        has_root_key="true"
    fi

    HAS_NONROOT_SUDO_USER="false"
    HAS_KEYED_SUDO_USER="false"
    find_sudo_user_state

    # 1. 计算 Root 登录策略：仅当显式传入 --disable_root_login 时才设为 no，绝不因系统预置普通用户而自动禁 root
    if [ "$DISABLE_ROOT_LOGIN" = "true" ]; then
        if [ "$HAS_NONROOT_SUDO_USER" != "true" ]; then
            log_message "ERROR" "无法禁用 root 登录：未检测到其他具备 sudo 权限的管理员用户"
            return 1
        fi
        target_permit_root="no"
    elif [ "$has_root_key" = "true" ]; then
        if [ "$DISABLE_SSH_PASSWD" = "true" ] && [ "$target_permit_root" != "no" ]; then
            target_permit_root="prohibit-password"
        elif [ "$target_permit_root" = "no" ] && [ -n "$SSH_KEY" ] && [ "$CREATE_DEVOPS_USER" != "true" ]; then
            target_permit_root="prohibit-password"
        fi
    fi

    # 2. 计算密码认证策略：禁用密码前必须确认可登录账户拥有可用公钥
    if [ "$DISABLE_SSH_PASSWD" = "true" ]; then
        if [ "$target_permit_root" = "no" ]; then
            if [ "$HAS_KEYED_SUDO_USER" != "true" ]; then
                log_message "ERROR" "无法同时禁用 root 登录与密码登录：未检测到配置了可用 SSH 公钥的 sudo 用户"
                return 1
            fi
        else
            if [ "$has_root_key" != "true" ] && [ "$HAS_KEYED_SUDO_USER" != "true" ]; then
                log_message "ERROR" "无法禁用密码登录：root 与 sudo 用户均未检测到可用 SSH 公钥"
                return 1
            fi
        fi
        target_passwd_auth="no"
    fi

    # 3. 确保 sshd_config 顶部包含 sshd_config.d，清理各文件冲突项并写入 00-setup-security.conf
    sudo mkdir -p "$SSH_CONFIG_DIR"
    if ! sudo grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$SSH_CONFIG" 2>/dev/null; then
        log_message "INFO" "在 $SSH_CONFIG 顶部补充 Include /etc/ssh/sshd_config.d/*.conf"
        local tmp_sshd="/tmp/sshd_config.$$"
        {
            echo "Include /etc/ssh/sshd_config.d/*.conf"
            sudo cat "$SSH_CONFIG"
        } > "$tmp_sshd"
        sudo cp "$tmp_sshd" "$SSH_CONFIG"
        sudo chmod 644 "$SSH_CONFIG"
        rm -f "$tmp_sshd"
    fi

    [ -f "$SSH_LEGACY_SECURITY_CONF" ] && sudo rm -f "$SSH_LEGACY_SECURITY_CONF"

    comment_managed_directives_in_file "$SSH_CONFIG"
    local dropin
    for dropin in "$SSH_CONFIG_DIR"/*.conf; do
        [ -f "$dropin" ] || continue
        [ "$dropin" = "$SSH_SECURITY_CONF" ] && continue
        comment_managed_directives_in_file "$dropin"
    done

    sudo tee "$SSH_SECURITY_CONF" >/dev/null << EOF
# Managed by setup.sh ($TIMESTAMP)
# Loaded first via Include /etc/ssh/sshd_config.d/*.conf (OpenSSH first-match-wins)

Port $effective_port

PubkeyAuthentication yes
PasswordAuthentication $target_passwd_auth
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no

PermitRootLogin $target_permit_root

X11Forwarding no
UseDNS no
ClientAliveInterval 300
ClientAliveCountMax 2
UsePAM yes
EOF
    sudo chmod 644 "$SSH_SECURITY_CONF"

    if [ -n "$SSH_PORT" ] && command -v ufw >/dev/null 2>&1 && sudo ufw status 2>/dev/null | grep -q "Status: active"; then
        log_message "INFO" "在 UFW 中放行 SSH 端口 $effective_port/tcp"
        sudo ufw allow "$effective_port/tcp" comment 'SSH Port' >/dev/null 2>&1 || true
    fi

    if ! validate_and_restart_ssh "$effective_port"; then
        log_message "ERROR" "SSH 新配置验证或重启失败，正在自动回滚备份..."
        if restore_ssh_config_from_backup; then
            sudo systemctl daemon-reload 2>/dev/null || true
            if systemctl is-active --quiet ssh.socket 2>/dev/null || systemctl is-enabled --quiet ssh.socket 2>/dev/null; then
                sudo systemctl restart ssh.socket 2>/dev/null || true
            fi
            sudo systemctl restart ssh 2>/dev/null || sudo systemctl restart sshd 2>/dev/null || true
            log_message "WARNING" "已回滚到修改前的 SSH 配置"
        fi
        return 1
    fi

    log_message "SUCCESS" "SSH 配置完成（端口: ${effective_port}, 密码登录: ${target_passwd_auth}, Root登录: ${target_permit_root}）"
    return 0
}

# ==================== 系统服务与内核优化 ====================

configure_fail2ban() {
    log_message "INFO" "配置 Fail2ban..."

    local ssh_log_path="/var/log/auth.log"
    if ! grep -rqE '^[[:space:]]*auth,authpriv\.\*[[:space:]]+.*auth\.log' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null; then
        sudo mkdir -p /etc/rsyslog.d
        echo "auth,authpriv.*    /var/log/auth.log" | sudo tee /etc/rsyslog.d/50-setup-auth.conf >/dev/null
    fi

    # rsyslog 在收到首条日志前可能尚未创建 auth.log，预先创建避免 fail2ban 因文件不存在而启动报错
    if [ ! -f "$ssh_log_path" ]; then
        local syslog_owner="root"
        id syslog &>/dev/null && syslog_owner="syslog"
        sudo install -m 0640 -o "$syslog_owner" -g adm /dev/null "$ssh_log_path" 2>/dev/null \
            || { sudo touch "$ssh_log_path" && sudo chmod 0640 "$ssh_log_path"; }
    fi

    sudo systemctl enable --now rsyslog >/dev/null 2>&1 || true
    sudo systemctl restart rsyslog || log_message "WARNING" "rsyslog 重启失败"

    local ssh_port
    ssh_port=$(get_effective_ssh_port)

    sudo mkdir -p /etc/fail2ban/jail.d
    sudo tee /etc/fail2ban/jail.d/custom.conf >/dev/null << EOF
[DEFAULT]
bantime = 1800
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = $ssh_port
filter = sshd
logpath = $ssh_log_path
maxretry = 3
bantime = 3600
EOF

    sudo systemctl unmask fail2ban 2>/dev/null || true
    if ! sudo systemctl enable fail2ban || ! sudo systemctl restart fail2ban; then
        log_message "ERROR" "Fail2ban 启动失败"
        return 1
    fi

    log_message "SUCCESS" "Fail2ban 配置完成（监控端口: ${ssh_port}）"
    return 0
}

detect_region() {
    local country_code=""
    country_code=$(curl -fsSL --max-time 5 "https://ifconfig.co/country-iso" 2>/dev/null | tr -d '[:space:]' || true)
    if ! [[ "$country_code" =~ ^[A-Z]{2}$ ]]; then
        country_code=$(curl -fsSL --max-time 5 "http://ip-api.com/line/?fields=countryCode" 2>/dev/null | tr -d '[:space:]' || true)
    fi

    case "$country_code" in
        CN) echo "cn" ;;
        HK) echo "hk" ;;
        TW) echo "tw" ;;
        JP) echo "jp" ;;
        KR) echo "kr" ;;
        SG) echo "sg" ;;
        US) echo "us" ;;
        GB|DE|FR|NL|IT|ES|PL|SE|NO|FI|DK|CH|AT|BE|IE|PT|CZ|RO|HU|GR) echo "eu" ;;
        *)  echo "asia" ;;
    esac
}

# 仅在原生 Debian 上通过隔离的 deb.debian.org 官方源兜底安装 chrony（应对镜像站 pool 同步延迟 404）
try_install_chrony_via_official_mirror() {
    [ "$OS_DISTRO" != "debian" ] && return 1

    local codename="$OS_CODENAME"
    if [ -z "$codename" ] && command -v lsb_release >/dev/null 2>&1; then
        codename=$(lsb_release -cs 2>/dev/null || true)
    fi

    case "$codename" in
        bullseye|bookworm|trixie) ;;
        *)
            log_message "WARNING" "Debian codename ($codename) 不在官方源兜底列表中，跳过"
            return 1
            ;;
    esac

    local tmp_dir="$APT_FALLBACK_TMP_DIR"
    local tmp_list="$tmp_dir/official.list"
    local tmp_source_parts="$tmp_dir/sourceparts"
    local tmp_lists="$tmp_dir/lists"
    local rc=1

    log_message "INFO" "尝试通过 deb.debian.org 隔离官方源安装 chrony..."
    sudo rm -rf "$tmp_dir" 2>/dev/null || true
    sudo rm -f "$APT_FALLBACK_LEGACY_SOURCE" 2>/dev/null || true

    if ! sudo mkdir -p "$tmp_source_parts" "$tmp_lists/partial"; then
        return 1
    fi

    sudo tee "$tmp_list" >/dev/null << EOF
deb https://deb.debian.org/debian $codename main
deb https://deb.debian.org/debian-security ${codename}-security main
deb https://deb.debian.org/debian ${codename}-updates main
EOF

    local apt_opts=(
        -o "Dir::Etc::SourceList=$tmp_list"
        -o "Dir::Etc::SourceParts=$tmp_source_parts"
        -o "Dir::State::Lists=$tmp_lists"
    )

    if run_apt_get "${apt_opts[@]}" update -y && run_apt_get "${apt_opts[@]}" install -y chrony; then
        log_message "INFO" "通过 deb.debian.org 成功安装 chrony"
        rc=0
    fi

    sudo rm -rf "$tmp_dir" 2>/dev/null || true
    return "$rc"
}

configure_timezone_ntp() {
    log_message "INFO" "配置时区与 NTP 时间同步..."

    sudo timedatectl set-timezone Asia/Shanghai

    local region="$SERVER_REGION"
    if [ "$region" = "auto" ]; then
        region=$(detect_region)
        SERVER_REGION="$region"
        log_message "INFO" "自动检测服务器地区: $region"
    fi

    local ntp_server
    case "$region" in
        cn) ntp_server="ntp.aliyun.com" ;;
        hk) ntp_server="hk.pool.ntp.org" ;;
        tw) ntp_server="tw.pool.ntp.org" ;;
        jp) ntp_server="jp.pool.ntp.org" ;;
        kr) ntp_server="kr.pool.ntp.org" ;;
        sg) ntp_server="sg.pool.ntp.org" ;;
        us) ntp_server="us.pool.ntp.org" ;;
        eu) ntp_server="europe.pool.ntp.org" ;;
        *)  ntp_server="asia.pool.ntp.org" ;;
    esac
    log_message "INFO" "使用 NTP 服务器: $ntp_server"

    local use_chrony="true"
    [ "$NTP_SERVICE" = "timesyncd" ] && use_chrony="false"

    if [ "$use_chrony" = "true" ]; then
        if ! command -v chronyd >/dev/null 2>&1; then
            if ! apt_install_with_retry "chrony" 2 5; then
                log_message "WARNING" "默认源安装 chrony 失败，尝试备用方案..."
                if ! try_install_chrony_via_official_mirror; then
                    log_message "WARNING" "chrony 安装失败，回退到 systemd-timesyncd"
                    use_chrony="false"
                fi
            fi
        fi
    fi

    if [ "$use_chrony" = "true" ]; then
        sudo systemctl stop systemd-timesyncd 2>/dev/null || true
        sudo systemctl disable systemd-timesyncd 2>/dev/null || true

        sudo mkdir -p /var/log/chrony
        sudo tee /etc/chrony/chrony.conf >/dev/null << EOF
pool $ntp_server iburst
keyfile /etc/chrony/chrony.keys
driftfile /var/lib/chrony/chrony.drift
logdir /var/log/chrony
maxupdateskew 100.0
rtcsync
makestep 1 3
EOF
        sudo systemctl unmask chrony 2>/dev/null || true
        if ! sudo systemctl enable chrony || ! sudo systemctl restart chrony; then
            log_message "ERROR" "chrony 服务启用或启动失败"
            return 1
        fi
        log_message "SUCCESS" "时区与 Chrony 配置完成"
        return 0
    fi

    # systemd-timesyncd 分支（显式指定或 chrony 安装失败回退）
    if [ ! -x /lib/systemd/systemd-timesyncd ] && [ ! -x /usr/lib/systemd/systemd-timesyncd ]; then
        if ! apt_install_with_retry "systemd-timesyncd" 2 5; then
            log_message "ERROR" "systemd-timesyncd 安装失败"
            return 1
        fi
    fi

    sudo systemctl stop chrony 2>/dev/null || true
    sudo systemctl disable chrony 2>/dev/null || true

    local fallback_ntp="0.pool.ntp.org 1.pool.ntp.org"
    [ "$region" = "cn" ] && fallback_ntp="ntp.tencent.com cn.pool.ntp.org"

    sudo tee /etc/systemd/timesyncd.conf >/dev/null << EOF
[Time]
NTP=$ntp_server
FallbackNTP=$fallback_ntp
EOF
    sudo systemctl unmask systemd-timesyncd 2>/dev/null || true
    if ! sudo systemctl enable systemd-timesyncd || ! sudo systemctl restart systemd-timesyncd; then
        log_message "ERROR" "systemd-timesyncd 启动失败"
        return 1
    fi

    log_message "SUCCESS" "时区与 systemd-timesyncd 配置完成"
    return 0
}

configure_system_optimization() {
    log_message "INFO" "配置内核网络优化（BBR 与 IPv4 转发）..."

    sudo modprobe tcp_bbr 2>/dev/null || true

    local bbr_available="false"
    if grep -qw "bbr" /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
        bbr_available="true"
    else
        log_message "WARNING" "当前内核或容器环境不支持 tcp_bbr，仅配置 IPv4 转发"
    fi

    sudo mkdir -p /etc/sysctl.d
    {
        echo "# Managed by setup.sh ($TIMESTAMP)"
        if [ "$bbr_available" = "true" ]; then
            echo "net.core.default_qdisc = fq"
            echo "net.ipv4.tcp_congestion_control = bbr"
        fi
        echo "net.ipv4.ip_forward = 1"
    } | sudo tee "$SYSCTL_CUSTOM_CONF" >/dev/null
    sudo chmod 644 "$SYSCTL_CUSTOM_CONF"

    # 避免旧 /etc/sysctl.conf 中显式的 ip_forward=0 造成混淆
    if [ -f /etc/sysctl.conf ] && grep -Eq '^[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=[[:space:]]*0' /etc/sysctl.conf; then
        sudo sed -i -E 's/^[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=.*/net.ipv4.ip_forward = 1/' /etc/sysctl.conf
    fi

    if ! sudo sysctl -p "$SYSCTL_CUSTOM_CONF" >/dev/null; then
        log_message "ERROR" "加载 $SYSCTL_CUSTOM_CONF 失败"
        return 1
    fi

    log_message "SUCCESS" "内核网络优化配置完成"
    return 0
}

# ==================== 配置总结与主流程 ====================

show_summary() {
    local current_cfg ssh_port passwd_auth pubkey_auth root_login
    current_cfg=$(read_sshd_effective)
    ssh_port=$(echo "$current_cfg" | awk '/^port / {print $2; exit}')
    ssh_port="${ssh_port:-$(get_effective_ssh_port)}"
    passwd_auth=$(echo "$current_cfg" | awk '/^passwordauthentication / {print $2; exit}')
    pubkey_auth=$(echo "$current_cfg" | awk '/^pubkeyauthentication / {print $2; exit}')
    root_login=$(echo "$current_cfg" | awk '/^permitrootlogin / {print $2; exit}')

    local tz ntp_state="未运行"
    tz=$(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo "未知")
    if systemctl is-active --quiet chrony 2>/dev/null || systemctl is-active --quiet chronyd 2>/dev/null; then
        ntp_state="chrony (运行中)"
    elif systemctl is-active --quiet systemd-timesyncd 2>/dev/null; then
        ntp_state="systemd-timesyncd (运行中)"
    fi

    echo "--------------------------------------------------"
    echo "系统信息:"
    echo "  OS: ${OS_PRETTY:-$OS_DISTRO $OS_VERSION}"
    echo "  时区: $tz"
    echo "  NTP: $ntp_state"
    echo ""
    echo "SSH 实际生效状态:"
    echo "  端口: $ssh_port"
    echo "  公钥认证: ${pubkey_auth:-未知}"
    echo "  密码认证: ${passwd_auth:-未知}"
    echo "  Root 登录: ${root_login:-未知}"
    echo ""
    echo "安全与内核优化:"
    echo "  Fail2ban: $(systemctl is-active fail2ban 2>/dev/null || echo '未运行')"
    echo "  BBR: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo '未知') (qdisc: $(sysctl -n net.core.default_qdisc 2>/dev/null || echo '未知'))"
    echo "  IPv4 转发: $(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo '未知')"

    if [ "$CREATE_DEVOPS_USER" = "true" ] && id "$SUDO_USERNAME" &>/dev/null; then
        echo ""
        echo "管理员用户: $SUDO_USERNAME"
    fi

    echo "--------------------------------------------------"
    echo "日志文件: $LOG_FILE"
    echo "SSH 备份: $CONFIG_BACKUP_DIR"
    echo "--------------------------------------------------"
    echo "SSH 登录测试命令（请先新开终端验证连接正常，再关闭当前会话）:"
    if [ "$CREATE_DEVOPS_USER" = "true" ] && id "$SUDO_USERNAME" &>/dev/null; then
        echo "  ssh -p $ssh_port $SUDO_USERNAME@<服务器IP>"
    fi
    if [ "${root_login:-yes}" != "no" ] && file_has_usable_ssh_key "/root/.ssh/authorized_keys"; then
        echo "  ssh -p $ssh_port root@<服务器IP>"
    fi
    echo "--------------------------------------------------"
}

main() {
    parse_args "$@"

    LOG_ENABLED="true"
    trap cleanup EXIT
    trap on_interrupt INT TERM

    log_message "INFO" "开始系统初始化 (版本: $SCRIPT_VERSION)，日志: $LOG_FILE"

    log_message "INFO" "=== 阶段 1/4：系统与权限检查 ==="
    check_privileges || die "权限检查未通过"
    check_compatibility || die "系统兼容性检查未通过"
    wait_for_cloud_init
    fix_sudo_and_hosts || die "修复 sudo 或 /etc/hosts 失败"

    local has_failures=0

    log_message "INFO" "=== 阶段 2/4：系统更新与基础软件安装 ==="
    if ! update_system_install_dependencies; then
        has_failures=1
        log_message "ERROR" "系统更新或基础软件安装存在失败项"
    fi

    log_message "INFO" "=== 阶段 3/4：用户与 SSH 安全配置 ==="
    # 密钥或管理员用户配置失败时必须中止 SSH 锁定操作，防止锁死服务器
    configure_ssh_keys || die "SSH 公钥写入或校验失败，已中止 SSH 配置修改"
    create_admin_user || die "管理员用户创建或校验失败，已中止 SSH 配置修改"

    if ! configure_ssh; then
        has_failures=1
        log_message "ERROR" "SSH 配置未能应用，请检查日志与当前连接状态"
    fi

    log_message "INFO" "=== 阶段 4/4：Fail2ban、NTP 与内核网络优化 ==="
    configure_fail2ban || { check_error $? "Fail2ban 配置"; has_failures=1; }
    configure_timezone_ntp || { check_error $? "时区与 NTP 配置"; has_failures=1; }
    configure_system_optimization || { check_error $? "内核网络优化"; has_failures=1; }

    show_summary || log_message "WARNING" "输出配置摘要时出现异常"

    if [ "$has_failures" -ne 0 ]; then
        log_message "WARNING" "初始化完成，但部分步骤存在错误，请查看日志: $LOG_FILE"
        return 1
    fi

    log_message "SUCCESS" "VPS 初始化全部完成"
    return 0
}

if ! main "$@"; then
    exit 1
fi
