#!/bin/bash

# 启用严格模式，显式错误处理（移除-e以避免不可预测行为）
set -uo pipefail

# 脚本版本
readonly SCRIPT_VERSION="2.2.0"

# 已测试的Debian版本
readonly TESTED_DEBIAN_VERSIONS="11 12 13"  # bullseye, bookworm, trixie

# 脚本常量 - 集中配置
readonly DEFAULT_SSH_PORT="22"
readonly MIN_PORT=1024
readonly MAX_PORT=65535
# 获取脚本所在目录（支持管道执行）
if [ -n "${BASH_SOURCE[0]:-}" ] && [[ "${BASH_SOURCE[0]}" != /dev/fd/* ]] && [[ "${BASH_SOURCE[0]}" != /proc/self/fd/* ]]; then
    # 正常文件执行
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
    # 通过管道执行，使用用户家目录或/tmp
    if [ -w "$HOME" ] && [ -d "$HOME" ]; then
        SCRIPT_DIR="$HOME"
    else
        SCRIPT_DIR="/tmp"
    fi
fi
# 添加时间戳到配置备份目录名
readonly TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
readonly CONFIG_BACKUP_DIR="$SCRIPT_DIR/ssh_backups_$TIMESTAMP"
readonly SSH_CONFIG="/etc/ssh/sshd_config"
readonly SSH_CONFIG_DIR="/etc/ssh/sshd_config.d"
# 固定日志文件路径
readonly LOG_FILE="$SCRIPT_DIR/setup-script-$TIMESTAMP.log"

# 脚本参数变量
DISABLE_SSH_PASSWD="false"
SSH_PORT=""
SSH_KEY=""
TMP_FILES=""
OS_TYPE=""
OS_VERSION=""
# 服务器地区参数，默认为asia
SERVER_REGION="asia"
# 创建管理员用户参数
CREATE_DEVOPS_USER="false"
SUDO_USERNAME=""
# NTP服务选择（auto|timesyncd|chrony）
NTP_SERVICE="auto"
# 新增：安全审计参数（合并原来的三个审计相关参数）
ENABLE_SECURITY_AUDIT="false"  # 默认禁用安全审计
# Docker相关
INSTALL_DOCKER="false"
# 新增：控制是否禁用root登录
DISABLE_ROOT_LOGIN="false"

# 设置安全的临时文件处理
cleanup() {
    # 删除所有临时文件
    if [ -n "$TMP_FILES" ]; then
        # 使用引号保护变量，防止空格和特殊字符问题
        rm -f "$TMP_FILES" >/dev/null 2>&1
    fi
    log_message "INFO" "脚本执行完成，清理临时文件"
}

# 注册EXIT信号处理
trap cleanup EXIT INT TERM

# ==================== 基础工具函数 ====================

# ==================== 现代化错误处理函数 ====================

# 致命错误处理函数 - 记录错误并退出
die() {
    local msg="${1:-未知致命错误}"
    local exit_code="${2:-1}"
    
    log_message "ERROR" "致命错误: $msg"
    log_message "ERROR" "脚本终止执行 (退出码: $exit_code)"
    
    # 清理资源
    cleanup 2>/dev/null || true
    exit "$exit_code"
}

# 检查命令执行结果 - 非致命错误处理
check_error() {
    local exit_code=$1
    local operation="${2:-操作}"
    local context="${3:-}"
    
    if [ $exit_code -ne 0 ]; then
        local error_msg="$operation 失败 (错误码: $exit_code)"
        [ -n "$context" ] && error_msg="$error_msg - $context"
        
        log_message "WARNING" "$error_msg"
        return 1
    fi
    return 0
}

# 安全执行命令 - 带错误检查的命令执行
safe_execute() {
    local cmd="$1"
    local description="${2:-执行命令}"
    local fatal="${3:-false}"
    
    log_message "DEBUG" "执行: $cmd"
    
    if ! eval "$cmd"; then
        local exit_code=$?
        if [ "$fatal" = "true" ]; then
            die "$description 失败" "$exit_code"
        else
            check_error "$exit_code" "$description"
            return "$exit_code"
        fi
    fi
    
    log_message "DEBUG" "$description 成功"
    return 0
}

# 统一的日志函数（符合最佳实践）
log_message() {
    local level="${1:-INFO}"
    local message="${2:-}"
    local timestamp
    
    # 参数验证
    [ -z "$message" ] && { echo "[错误] 消息内容不能为空" >&2; return 1; }
    
    # 安全：过滤敏感信息
    if [[ "$message" =~ (ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp[0-9]+)[[:space:]]+[A-Za-z0-9+/]+=*|password.*=|token.*=|key.*= ]]; then
        message="[敏感信息已过滤]"
    fi
    
    # 统一时间戳格式
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # 级别标准化和输出
    case "${level^^}" in
        "ERROR"|"ERR")
            echo "[错误] $message" >&2
            ;;
        "WARNING"|"WARN")
            echo "[警告] $message"
            ;;
        "INFO")
            echo "[信息] $message"
            ;;
        "DEBUG")
            [ "${DEBUG:-}" = "1" ] && echo "[调试] $message"
            ;;
        "SUCCESS"|"OK")
            echo "[成功] $message"
            ;;
        *)
            echo "[日志] $message"
            ;;
    esac
    
    # 文件日志记录（如果定义了 LOG_FILE）
    if [ -n "${LOG_FILE:-}" ]; then
        # 安全创建日志目录
        local log_dir
        log_dir=$(dirname "$LOG_FILE")
        if [ ! -d "$log_dir" ]; then
            mkdir -p "$log_dir" 2>/dev/null || return 0
            chmod 750 "$log_dir" 2>/dev/null || true
        fi
        
        # 写入日志文件
        echo "[$timestamp][$level] $message" >> "$LOG_FILE" 2>/dev/null || true
        chmod 640 "$LOG_FILE" 2>/dev/null || true
        
        # 简单日志轮转（防止过大）
        if [ -f "$LOG_FILE" ] && [ "$(wc -l < "$LOG_FILE" 2>/dev/null || echo 0)" -gt 10000 ]; then
            tail -5000 "$LOG_FILE" > "${LOG_FILE}.tmp" 2>/dev/null && mv "${LOG_FILE}.tmp" "$LOG_FILE" 2>/dev/null
        fi
    fi
    
    # 系统日志记录（错误级别）
    [ "${level^^}" = "ERROR" ] && command -v logger >/dev/null 2>&1 && logger -t "$(basename "$0" .sh)" -p user.err "$message" 2>/dev/null || true
}

# ==================== 系统检查函数 ====================

# 检查系统兼容性
check_compatibility() {
    log_message "INFO" "检查系统兼容性..."
    
    # 检查操作系统类型
    if [ -f /etc/debian_version ]; then
        OS_TYPE="debian"
        local raw_version=$(cat /etc/debian_version)

        # 解析版本号：支持 "13.0", "trixie/sid", "bookworm/sid" 等格式
        if [[ "$raw_version" =~ ^([0-9]+) ]]; then
            OS_VERSION="${BASH_REMATCH[1]}"
        elif [[ "$raw_version" =~ trixie ]]; then
            OS_VERSION="13"
        elif [[ "$raw_version" =~ bookworm ]]; then
            OS_VERSION="12"
        elif [[ "$raw_version" =~ bullseye ]]; then
            OS_VERSION="11"
        elif [[ "$raw_version" =~ buster ]]; then
            OS_VERSION="10"
        else
            OS_VERSION="$raw_version"
        fi

        log_message "INFO" "检测到Debian/Ubuntu系统 (版本: $OS_VERSION, 原始: $raw_version)"

        # 检查是否为已测试版本
        if ! echo "$TESTED_DEBIAN_VERSIONS" | grep -qw "$OS_VERSION"; then
            log_message "WARNING" "Debian $OS_VERSION 尚未经过完整测试，可能存在兼容性问题"
        fi
    elif [ -f /etc/redhat-release ]; then
        OS_TYPE="redhat"
        OS_VERSION=$(cat /etc/redhat-release)
        log_message "INFO" "检测到RHEL/CentOS系统 (版本: $OS_VERSION)"
    elif [ -f /etc/os-release ]; then
        source /etc/os-release
        OS_TYPE="$ID"
        OS_VERSION="$VERSION_ID"
        log_message "INFO" "检测到 $NAME 系统 (版本: $VERSION_ID)"
    else
        log_message "ERROR" "不支持的操作系统类型"
        return 1
    fi
    
    # 检查必要的命令是否存在
    for cmd in ssh systemctl grep sed; do
        if ! command -v $cmd &> /dev/null; then
            log_message "ERROR" "缺少必要的命令: $cmd"
            return 1
        fi
    done
    
    return 0
}

# ==================== 帮助和参数处理 ====================

# 显示用法信息
usage() {
    echo "用法: $0 [选项]"
    echo "选项:"
    echo "  --help                    显示此帮助信息"
    echo "  --disable_ssh_pwd         禁用SSH密码登录，仅允许SSH密钥认证"
    echo "  --port PORT               设置SSH端口号 (例如: --port 2222)"
    echo "  --ssh_key KEY             设置SSH公钥 (直接输入公钥文本)"
    echo "  --region REGION           指定服务器所在地区，用于选择NTP服务器"
    echo "                            (auto|cn|hk|tw|jp|kr|sg|us|eu|asia，默认: asia)"
    echo "  --ntp_service SERVICE     指定NTP服务（auto|timesyncd|chrony，默认: auto）"
    echo "  --version                 显示脚本版本"
    echo "  --create_user USERNAME    创建管理员用户（必须提供SSH密钥）"
    echo "  --enable_audit            启用安全审计（auditd和etckeeper）"
    echo "  --install_docker          安装Docker并自动配置防火墙规则"
    echo "  --disable_root_login      禁用root用户SSH登录（建议在创建管理员用户后使用）"
    echo ""
    echo "地区说明:"
    echo "  auto - 自动检测地区（推荐）"
    echo "  cn   - 中国大陆"
    echo "  hk   - 香港"
    echo "  tw   - 台湾"
    echo "  jp   - 日本"
    echo "  kr   - 韩国"
    echo "  sg   - 新加坡"
    echo "  us   - 美国"
    echo "  eu   - 欧洲"
    echo "  asia - 亚洲通用"
    echo ""
    echo "示例:"
    echo "  $0 --disable_ssh_pwd --port 2222 --ssh_key \"ssh-rsa AAAA...\""
    echo "  $0 --create_user devops --ssh_key \"ssh-rsa AAAA...\" --disable_ssh_pwd"
    echo "  $0 --install_docker --region cn"
    echo "  $0 --create_user admin --ssh_key \"ssh-rsa AAAA...\" --disable_root_login --disable_ssh_pwd"
    echo ""
    echo "支持的系统: Debian 11/12/13, Ubuntu 20.04+, RHEL/CentOS 7+"
    echo "脚本版本: $SCRIPT_VERSION"
}

# 自动检测服务器地区
detect_region() {
    local country_code

    # 尝试多个 API 以提高可靠性
    country_code=$(curl -s --max-time 5 "http://ip-api.com/line/?fields=countryCode" 2>/dev/null)

    # 如果第一个 API 失败，尝试备用
    if [ -z "$country_code" ] || [ ${#country_code} -ne 2 ]; then
        country_code=$(curl -s --max-time 5 "https://ifconfig.co/country-iso" 2>/dev/null)
    fi

    # 映射国家代码到地区
    case "$country_code" in
        CN) echo "cn" ;;
        HK) echo "hk" ;;
        TW) echo "tw" ;;
        JP) echo "jp" ;;
        KR) echo "kr" ;;
        SG) echo "sg" ;;
        US) echo "us" ;;
        GB|DE|FR|NL|IT|ES|PL|SE|NO|FI|DK|CH|AT|BE|IE|PT|CZ|RO|HU|GR)
            echo "eu" ;;
        *) echo "asia" ;;  # 默认 fallback
    esac
}

# 解析参数
parse_args() {
    while [[ "$#" -gt 0 ]]; do
        case $1 in
            --help) usage; exit 0 ;;
            --disable_ssh_pwd) DISABLE_SSH_PASSWD="true" ;;
            --port) 
                if [ -z "$2" ] || [[ "$2" == --* ]]; then
                    log_message "ERROR" "选项 $1 需要一个有效的端口号参数"
                    exit 1
                fi
                if ! [[ "$2" =~ ^[0-9]+$ ]] || [ "$2" -lt "$MIN_PORT" ] || [ "$2" -gt "$MAX_PORT" ]; then
                    log_message "ERROR" "无效的端口号: $2. 端口号应在 $MIN_PORT-$MAX_PORT 范围内"
                    exit 1
                fi
                SSH_PORT="$2"; 
                shift ;;
            --ssh_key) 
                if [ -z "$2" ] || [[ "$2" == --* ]]; then
                    log_message "ERROR" "选项 $1 需要一个有效的SSH公钥参数"
                    exit 1
                fi
                SSH_KEY="$2"; shift ;;
            --region)
                if [ -z "$2" ] || [[ "$2" == --* ]]; then
                    log_message "ERROR" "选项 $1 需要一个有效的地区参数"
                    exit 1
                fi
                case "$2" in
                    auto)
                        SERVER_REGION=$(detect_region)
                        log_message "INFO" "自动检测地区: $SERVER_REGION"
                        ;;
                    cn|hk|tw|jp|kr|sg|us|eu|asia)
                        SERVER_REGION="$2"
                        ;;
                    *)
                        log_message "ERROR" "无效的地区参数: $2"
                        exit 1
                        ;;
                esac
                shift ;;
            --ntp_service)
                if [ -z "$2" ] || [[ "$2" == --* ]]; then
                    log_message "ERROR" "选项 $1 需要一个有效的服务参数"
                    exit 1
                fi
                case "$2" in
                    auto|timesyncd|chrony)
                        NTP_SERVICE="$2"
                        ;;
                    *)
                        log_message "ERROR" "无效的NTP服务参数: $2"
                        exit 1
                        ;;
                esac
                shift ;;
            --version) echo "脚本版本: $SCRIPT_VERSION"; exit 0 ;;
            --create_user)
                if [ -z "$2" ] || [[ "$2" == --* ]]; then
                    log_message "ERROR" "选项 $1 需要一个有效的用户名参数"
                    exit 1
                fi
                CREATE_DEVOPS_USER="true"
                SUDO_USERNAME="$2"
                if ! [[ "$2" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
                    log_message "ERROR" "无效的用户名: $2"
                    exit 1
                fi
                shift ;;
            --enable_audit)
                ENABLE_SECURITY_AUDIT="true" ;;
            --install_docker)
                INSTALL_DOCKER="true" ;;
            --disable_root_login)
                DISABLE_ROOT_LOGIN="true" ;;
            *) echo "未知选项: $1"; usage; exit 1 ;;
        esac
        shift
    done
    
    # 确保备份目录存在并设置安全权限
    if [ ! -d "$CONFIG_BACKUP_DIR" ]; then
        sudo mkdir -p "$CONFIG_BACKUP_DIR"
        # 设置备份目录权限（仅root可访问）
        sudo chmod 700 "$CONFIG_BACKUP_DIR"
    fi
    
    # 验证创建用户时必须提供SSH密钥
    if [ "$CREATE_DEVOPS_USER" = "true" ]; then
        if [ -z "$SSH_KEY" ]; then
            log_message "ERROR" "创建管理员用户时必须提供SSH密钥"
            exit 1
        fi
    fi
    
    log_message "INFO" "脚本开始执行，日志文件: $LOG_FILE"
}

# ==================== APT包管理函数 ====================

# 检查软件包是否可用
check_package_available() {
    local package="$1"
    apt-cache show "$package" >/dev/null 2>&1
}

# 获取兼容的软件包名（处理不同Debian版本的包名差异）
get_compatible_package() {
    local package="$1"
    case "$package" in
        netcat-openbsd)
            # Debian 13 仍使用 netcat-openbsd，但添加备选
            if check_package_available "netcat-openbsd"; then
                echo "netcat-openbsd"
            elif check_package_available "netcat"; then
                echo "netcat"
            else
                log_message "WARNING" "netcat 相关包不可用"
                echo ""
            fi
            ;;
        *)
            echo "$package"
            ;;
    esac
}

# 解析并获取兼容的软件包列表
get_compatible_packages() {
    local packages="$1"
    local result=""
    for pkg in $packages; do
        local compatible_pkg=$(get_compatible_package "$pkg")
        if [ -n "$compatible_pkg" ]; then
            result="$result $compatible_pkg"
        fi
    done
    echo "$result" | xargs  # 去除多余空格
}

# 带重试机制的apt安装函数
apt_install_with_retry() {
    local packages="$1"
    local max_retries=${2:-3}
    local retry_delay=${3:-30}
    local retry_count=0
    
    [ "$OS_TYPE" != "debian" ] && return 0
    
    while [ $retry_count -lt $max_retries ]; do
        # 等待apt锁释放
        if ! wait_for_apt_locks; then
            log_message "ERROR" "等待apt锁失败，重试 $((retry_count + 1))/$max_retries"
            ((retry_count++))
            if [ $retry_count -lt $max_retries ]; then
                sleep $retry_delay
                continue
            else
                return 1
            fi
        fi
        
        # 尝试安装包
        log_message "INFO" "尝试安装包: $packages (第 $((retry_count + 1)) 次)"
        if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y $packages; then
            log_message "INFO" "包安装成功: $packages"
            return 0
        else
            local exit_code=$?
            log_message "WARNING" "包安装失败: $packages (错误码: $exit_code)"
            ((retry_count++))
            
            if [ $retry_count -lt $max_retries ]; then
                log_message "INFO" "等待 $retry_delay 秒后重试..."
                sleep $retry_delay
                
                # 尝试修复损坏的包
                log_message "INFO" "尝试修复包管理器状态..."
                sudo dpkg --configure -a 2>/dev/null || true
                sudo apt-get -f install -y 2>/dev/null || true
            else
                log_message "ERROR" "包安装失败，已重试 $max_retries 次: $packages"
                return $exit_code
            fi
        fi
    done
    
    return 1
}



# 等待apt锁并处理特殊情况（合并版本）
wait_for_apt_locks() {
    [ "$OS_TYPE" != "debian" ] && return 0
    
    local max_wait=900  # 15分钟
    local waited=0
    local check_interval=5
    local first_wait=true
    
    log_message "INFO" "检查包管理器状态..."
    
    # 检查磁盘空间
    local available_space=$(df /var/cache/apt/archives | awk 'NR==2 {print $4}')
    if [ "$available_space" -lt 1000000 ]; then  # 少于1GB
        log_message "WARNING" "磁盘空间不足 (可用: ${available_space}KB)，清理apt缓存..."
        sudo apt-get clean || true
    fi
    
    # 检查包数据库完整性
    if ! sudo dpkg --audit >/dev/null 2>&1; then
        log_message "WARNING" "发现包数据库问题，尝试修复..."
        sudo dpkg --configure -a || true
    fi
    
    # 主锁等待循环
    while true; do
        local locked=false
        local lock_sources=()
        
        # 检查所有锁文件
        if fuser /var/lib/dpkg/lock* >/dev/null 2>&1; then
            locked=true
            lock_sources+=("dpkg-lock")
        fi
        
        if fuser /var/lib/apt/lists/lock* >/dev/null 2>&1; then
            locked=true
            lock_sources+=("apt-lists-lock")
        fi
        
        if fuser /var/cache/apt/archives/lock* >/dev/null 2>&1; then
            locked=true
            lock_sources+=("apt-cache-lock")
        fi
        
        if [ -f /var/lib/dpkg/lock-frontend ] && fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; then
            locked=true
            lock_sources+=("dpkg-frontend-lock")
        fi
        
        # 检查关键进程
        if pgrep -x "apt|apt-get|dpkg|aptitude" >/dev/null 2>&1; then
            locked=true
            lock_sources+=("apt-processes")
        fi
        
        # 特殊处理unattended-upgrades
        if pgrep -f "/usr/bin/unattended-upgrade$" >/dev/null 2>&1 || pgrep -f "unattended-upgrade.*--dry-run" >/dev/null 2>&1; then
            locked=true
            lock_sources+=("unattended-upgrades")
            
            # 首次检测到时显示特殊信息
            if [ "$first_wait" = "true" ]; then
                log_message "INFO" "检测到unattended-upgrades正在运行，等待其完成..."
            fi
        fi
        
        # 检查cloud-init
        if pgrep -f "cloud-init.*apt" >/dev/null 2>&1; then
            locked=true
            lock_sources+=("cloud-init-apt")
        fi
        
        # 检查僵尸dpkg进程
        if pgrep -x "dpkg" >/dev/null 2>&1; then
            sleep 5  # 给进程一些时间自然结束
            if pgrep -x "dpkg" >/dev/null 2>&1; then
                log_message "WARNING" "发现可能的僵尸dpkg进程，尝试修复..."
                sudo dpkg --configure -a 2>/dev/null || true
                locked=true
                lock_sources+=("zombie-dpkg")
            fi
        fi
        
        # 如果没有锁，退出循环
        if [ "$locked" = "false" ]; then
            break
        fi
        
        # 第一次检测到锁时显示信息
        if [ "$first_wait" = "true" ]; then
            log_message "INFO" "检测到包管理器锁定源: ${lock_sources[*]}"
            first_wait=false
        fi
        
        # 超时检查
        if [ $waited -ge $max_wait ]; then
            log_message "ERROR" "等待apt锁超时 ($max_wait秒)，当前锁定源: ${lock_sources[*]}"
            return 1
        fi
        
        # 进度显示
        if [ $((waited % 60)) -eq 0 ] || [ $waited -lt 60 ]; then
            log_message "INFO" "等待apt锁释放... ($waited/$max_wait秒) - 锁定源: ${lock_sources[*]}"
        fi
        
        sleep $check_interval
        ((waited+=$check_interval))
    done
    
    if [ $waited -gt 0 ]; then
        log_message "INFO" "apt锁已释放，等待了 $waited 秒"
        sleep 3  # 确保锁完全释放
    fi
    
    return 0
}

# ==================== 系统初始化函数 ====================

# 等待cloud-init完成
wait_for_cloud_init() {
    if command -v cloud-init &> /dev/null; then
        log_message "INFO" "等待cloud-init完成..."
        cloud-init status --wait || true
    fi
}

# 修复sudo问题
fix_sudo_issue() {
    # 确保sudo已安装
    if ! command -v sudo &> /dev/null; then
        log_message "INFO" "安装sudo..."
        if [ "$OS_TYPE" = "debian" ]; then
            if ! wait_for_apt_locks; then
                log_message "ERROR" "等待apt锁失败，无法安装sudo"
                return 1
            fi
            apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get install -y sudo
        else
            yum install -y sudo || dnf install -y sudo
        fi
    fi
    
    # 修复hostname解析问题
    if sudo -v 2>&1 | grep -q "unable to resolve host"; then
        log_message "INFO" "修复sudo主机名解析问题..."
        # 安全地获取和处理hostname
        local hostname=$(hostname | tr -d '\n' | sed 's/[^a-zA-Z0-9.-]//g')
        if [ -n "$hostname" ] && ! grep -q "$hostname" /etc/hosts; then
            echo "127.0.1.1   $hostname" | sudo tee -a /etc/hosts >/dev/null
        fi
    fi
}

# 更新系统并安装基础软件（完整apt操作流程）
update_system_install_dependencies() {
    log_message "INFO" "更新系统并安装必要软件..."
    
    if [ "$OS_TYPE" = "debian" ]; then
        # 阶段1：等待apt锁并确保环境就绪
        log_message "DEBUG" "系统更新 - 准备阶段"
        if ! wait_for_apt_locks; then
            log_message "ERROR" "无法获取apt锁，系统可能正在进行其他安装操作"
            return 1
        fi
        
        # 阶段2：执行系统更新（允许部分失败但要记录）
        log_message "DEBUG" "系统更新 - 执行系统更新"
        export DEBIAN_FRONTEND=noninteractive
        
        # 更新软件包列表（关键步骤）
        if ! safe_execute "sudo apt-get update -y" "更新软件包列表"; then
            log_message "ERROR" "软件包列表更新失败，可能影响后续安装"
            return 1
        fi
        
        # 系统升级（允许失败但记录）
        safe_execute "sudo apt-get upgrade -y" "系统升级" || \
            check_error $? "系统升级" "可能有包冲突或网络问题"
        
        safe_execute "sudo apt-get full-upgrade -y" "完整系统升级" || \
            check_error $? "完整系统升级" "某些包可能需要手动处理"
        
        # 清理操作（失败不影响主流程）
        safe_execute "sudo apt-get autoclean -y" "清理软件包缓存" || \
            log_message "WARNING" "软件包缓存清理失败"
        
        safe_execute "sudo apt-get autoremove -y" "移除不需要的软件包" || \
            log_message "WARNING" "自动移除软件包失败"
        
        # 阶段3：安装基础软件包（关键功能，失败则退出）
        log_message "DEBUG" "系统更新 - 安装基础软件包"
        log_message "INFO" "安装基础软件包..."
        
        if ! apt_install_with_retry "wget curl vim unzip zip fail2ban rsyslog iptables mtr netcat-openbsd"; then
            log_message "ERROR" "基础软件包安装失败"
            log_message "ERROR" "这些是系统运行的必要软件，无法继续"
            return 1
        fi
        
        # 阶段4：安装可选软件包（失败不影响主流程）
        log_message "DEBUG" "系统更新 - 安装可选软件包"
        log_message "INFO" "安装iperf3..."
        
        # 预设配置避免交互
        if ! echo 'iperf3 iperf3/autostart boolean false' | sudo debconf-set-selections; then
            log_message "WARNING" "iperf3预配置失败"
        fi
        
        if ! apt_install_with_retry "iperf3"; then
            check_error $? "iperf3安装" "网络测试工具，非必需"
            log_message "WARNING" "iperf3安装失败，但不影响主要功能"
        fi
        
    else
        # RedHat系列处理（增强错误处理）
        log_message "DEBUG" "系统更新 - RedHat系列系统"
        
        local pkg_manager="yum"
        command -v dnf &> /dev/null && pkg_manager="dnf"
        
        log_message "INFO" "使用包管理器: $pkg_manager"
        
        # 系统更新
        if ! safe_execute "sudo $pkg_manager update -y" "RedHat系统更新"; then
            log_message "ERROR" "RedHat系统更新失败"
            return 1
        fi
        
        # 软件包安装
        if ! safe_execute "sudo $pkg_manager install -y wget curl vim unzip zip fail2ban rsyslog iptables iperf3 mtr nc" "安装基础软件包"; then
            log_message "ERROR" "RedHat基础软件包安装失败"
            return 1
        fi
    fi
    
    # 验证关键软件包是否安装成功
    log_message "DEBUG" "系统更新 - 验证安装结果"
    local missing_packages=""
    
    # 检查有直接命令的软件包
    for pkg in wget curl vim; do
        if ! command -v "$pkg" >/dev/null 2>&1; then
            missing_packages="$missing_packages $pkg"
        fi
    done
    
    # 特殊检查fail2ban（它的命令是fail2ban-client）
    if ! command -v fail2ban-client >/dev/null 2>&1 && ! systemctl is-enabled fail2ban >/dev/null 2>&1; then
        missing_packages="$missing_packages fail2ban"
    fi
    
    if [ -n "$missing_packages" ]; then
        log_message "WARNING" "以下关键软件包可能安装失败:$missing_packages"
        log_message "WARNING" "建议手动检查和安装这些软件包"
    fi
    
    log_message "SUCCESS" "系统更新和软件安装完成"
    return 0
}

# ==================== 用户管理函数 ====================

# 配置SSH密钥
configure_ssh_keys() {
    [ -z "$SSH_KEY" ] && return 0
    
    # 验证SSH公钥格式
    if ! echo "$SSH_KEY" | grep -qE '^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp[0-9]+) [A-Za-z0-9+/]+=*'; then
        log_message "ERROR" "无效的SSH公钥格式"
        return 1
    fi
    
    local ssh_dir="$HOME/.ssh"
    local auth_keys="$ssh_dir/authorized_keys"
    
    # 创建SSH目录
    [ ! -d "$ssh_dir" ] && { mkdir -p "$ssh_dir" && chmod 700 "$ssh_dir"; }
    [ ! -f "$auth_keys" ] && { touch "$auth_keys" && chmod 600 "$auth_keys"; }
    
    # 添加SSH公钥
    if ! grep -qF "$SSH_KEY" "$auth_keys"; then
        echo "$SSH_KEY" >> "$auth_keys"
        log_message "INFO" "SSH公钥已添加到 $(whoami) 用户 ($auth_keys)"
    else
        log_message "INFO" "SSH公钥已存在于 $(whoami) 用户"
    fi
}

# 创建管理员用户
create_admin_user() {
    [ "$CREATE_DEVOPS_USER" != "true" ] && return 0
    
    log_message "INFO" "创建管理员用户 $SUDO_USERNAME..."
    
    if id "$SUDO_USERNAME" &>/dev/null; then
        log_message "WARNING" "用户 $SUDO_USERNAME 已存在"
    else
        if [ "$OS_TYPE" = "debian" ]; then
            sudo adduser --disabled-password --gecos "Administrator" "$SUDO_USERNAME"
            sudo usermod -aG sudo "$SUDO_USERNAME"
        else
            sudo useradd -m -s /bin/bash -c "Administrator" "$SUDO_USERNAME"
            sudo usermod -aG wheel "$SUDO_USERNAME"
        fi
    fi
    
    # 配置用户SSH密钥
    local user_ssh_dir="/home/$SUDO_USERNAME/.ssh"
    local user_auth_keys="$user_ssh_dir/authorized_keys"
    
    sudo mkdir -p "$user_ssh_dir"
    sudo touch "$user_auth_keys"
    
    # 检查密钥是否已存在
    if ! sudo grep -qF "$SSH_KEY" "$user_auth_keys"; then
        echo "$SSH_KEY" | sudo tee -a "$user_auth_keys" > /dev/null
    fi
    
    sudo chown -R "$SUDO_USERNAME:$SUDO_USERNAME" "$user_ssh_dir"
    sudo chmod 700 "$user_ssh_dir"
    sudo chmod 600 "$user_auth_keys"
    
    # 配置sudo免密码
    echo "$SUDO_USERNAME ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/$SUDO_USERNAME > /dev/null
    sudo chmod 440 /etc/sudoers.d/$SUDO_USERNAME
    
    # 验证用户创建和配置
    log_message "INFO" "验证用户配置..."
    
    # 检查用户是否存在
    if ! id "$SUDO_USERNAME" &>/dev/null; then
        log_message "ERROR" "用户 $SUDO_USERNAME 创建失败"
        return 1
    fi
    
    # 检查SSH目录权限
    local dir_perms=$(sudo stat -c "%a" "$user_ssh_dir" 2>/dev/null)
    if [ "$dir_perms" != "700" ]; then
        log_message "WARNING" "SSH目录权限不正确: $dir_perms，正在修复..."
        sudo chmod 700 "$user_ssh_dir"
    fi
    
    # 检查authorized_keys权限
    local file_perms=$(sudo stat -c "%a" "$user_auth_keys" 2>/dev/null)
    if [ "$file_perms" != "600" ]; then
        log_message "WARNING" "authorized_keys权限不正确: $file_perms，正在修复..."
        sudo chmod 600 "$user_auth_keys"
    fi
    
    # 检查sudo权限
    if ! sudo -u "$SUDO_USERNAME" sudo -n true 2>/dev/null; then
        log_message "ERROR" "用户 $SUDO_USERNAME sudo权限配置失败"
        return 1
    fi
    
    # 检查SSH密钥是否正确添加
    if ! sudo grep -qF "$SSH_KEY" "$user_auth_keys"; then
        log_message "ERROR" "SSH密钥未正确添加到用户 $SUDO_USERNAME"
        return 1
    fi
    
    log_message "INFO" "管理员用户创建完成，所有验证通过"
    log_message "INFO" "可以使用以下命令测试登录: ssh $SUDO_USERNAME@<服务器IP>"
}

# 备份SSH配置
backup_ssh_config() {
    log_message "INFO" "备份SSH配置..."
    
    if [ -f "$SSH_CONFIG" ]; then
        sudo cp "$SSH_CONFIG" "$CONFIG_BACKUP_DIR/sshd_config.$TIMESTAMP.bak"
    fi
    
    if [ -d "$SSH_CONFIG_DIR" ]; then
        sudo cp -r "$SSH_CONFIG_DIR" "$CONFIG_BACKUP_DIR/sshd_config.d.$TIMESTAMP"
    fi
    
    # 创建还原脚本
    sudo tee "$CONFIG_BACKUP_DIR/restore.sh" > /dev/null << EOF
#!/bin/bash
sudo cp "$CONFIG_BACKUP_DIR/sshd_config.$TIMESTAMP.bak" "$SSH_CONFIG"
[ -d "$CONFIG_BACKUP_DIR/sshd_config.d.$TIMESTAMP" ] && sudo cp -r "$CONFIG_BACKUP_DIR/sshd_config.d.$TIMESTAMP"/* "$SSH_CONFIG_DIR/"
sudo systemctl restart ssh || sudo systemctl restart sshd
echo "SSH配置已还原"
EOF
    sudo chmod +x "$CONFIG_BACKUP_DIR/restore.sh"
    
    log_message "INFO" "SSH配置备份完成: $CONFIG_BACKUP_DIR"
}

# ==================== SSH配置函数群 ====================

# 分析SSH环境状态
analyze_ssh_environment() {
    local has_sudo_user="false"
    local current_user=$(whoami)
    local has_root_ssh_key="false"
    local can_disable_root="false"
    
    # 检查当前用户是否有sudo权限
    if [ "$current_user" != "root" ] && sudo -n true 2>/dev/null; then
        has_sudo_user="true"
        log_message "INFO" "当前用户 $current_user 具有sudo权限"
    fi
    
    # 检查是否创建了新的sudo用户
    if [ "$CREATE_DEVOPS_USER" = "true" ] && id "$SUDO_USERNAME" &>/dev/null; then
        has_sudo_user="true"
        log_message "INFO" "已创建sudo用户 $SUDO_USERNAME"
    fi
    
    # 检查是否有其他sudo用户
    if [ "$has_sudo_user" = "false" ]; then
        if [ "$OS_TYPE" = "debian" ]; then
            if getent group sudo | grep -q ":"; then
                has_sudo_user="true"
                log_message "INFO" "系统中存在其他sudo用户"
            fi
        else
            if getent group wheel | grep -q ":"; then
                has_sudo_user="true"
                log_message "INFO" "系统中存在其他wheel用户"
            fi
        fi
    fi
    
    # 检查root SSH密钥
    if [ "$current_user" = "root" ] && [ -f "/root/.ssh/authorized_keys" ] && [ -s "/root/.ssh/authorized_keys" ]; then
        has_root_ssh_key="true"
        log_message "INFO" "root用户已配置SSH密钥"
    fi
    
    # 决定是否可以禁用root登录
    if [ "$has_sudo_user" = "true" ] || ([ "$has_root_ssh_key" = "true" ] && [ "$DISABLE_SSH_PASSWD" = "true" ]); then
        can_disable_root="true"
    fi
    
    # 返回状态信息（使用全局变量）
    SSH_ENV_HAS_SUDO_USER="$has_sudo_user"
    SSH_ENV_HAS_ROOT_KEY="$has_root_ssh_key"
    SSH_ENV_CAN_DISABLE_ROOT="$can_disable_root"
}

# 配置SSH认证设置
configure_ssh_authentication() {
    # 启用公钥认证
    sudo sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' "$SSH_CONFIG"
    grep -q "^PubkeyAuthentication" "$SSH_CONFIG" || echo "PubkeyAuthentication yes" | sudo tee -a "$SSH_CONFIG"
    
    # 处理root登录设置
    if [ "$DISABLE_ROOT_LOGIN" = "true" ]; then
        # 用户明确要求禁用root登录
        if [ "$SSH_ENV_HAS_SUDO_USER" = "true" ] || [ "$SSH_ENV_HAS_ROOT_KEY" = "true" ] || [ "$CREATE_DEVOPS_USER" = "true" ]; then
            log_message "INFO" "根据用户要求禁用root登录"
            sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' "$SSH_CONFIG"
            grep -q "^PermitRootLogin" "$SSH_CONFIG" || echo "PermitRootLogin no" | sudo tee -a "$SSH_CONFIG"
        else
            log_message "ERROR" "无法禁用root登录：未检测到其他管理员账户"
            log_message "ERROR" "请先创建具有sudo权限的用户或配置SSH密钥"
            return 1
        fi
    elif [ "$SSH_ENV_CAN_DISABLE_ROOT" = "true" ]; then
        # 自动逻辑：安全禁用root登录
        log_message "INFO" "检测到其他管理员账户，可以安全禁用root登录"
        sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' "$SSH_CONFIG"
        grep -q "^PermitRootLogin" "$SSH_CONFIG" || echo "PermitRootLogin no" | sudo tee -a "$SSH_CONFIG"
    else
        log_message "WARNING" "未检测到其他管理员账户，保持root登录权限"
        if [ "$DISABLE_SSH_PASSWD" = "true" ] && [ "$SSH_ENV_HAS_ROOT_KEY" = "true" ]; then
            sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' "$SSH_CONFIG"
            grep -q "^PermitRootLogin" "$SSH_CONFIG" || echo "PermitRootLogin prohibit-password" | sudo tee -a "$SSH_CONFIG"
            log_message "INFO" "设置root仅允许密钥登录"
        else
            sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' "$SSH_CONFIG"
            grep -q "^PermitRootLogin" "$SSH_CONFIG" || echo "PermitRootLogin yes" | sudo tee -a "$SSH_CONFIG"
            log_message "WARNING" "保持root密码登录开启，建议创建sudo用户后再禁用"
        fi
    fi
    
    # 禁用密码登录前的安全检查
    if [ "$DISABLE_SSH_PASSWD" = "true" ]; then
        local can_disable_password="false"
        
        # 检查是否有SSH密钥配置
        if [ "$SSH_ENV_HAS_SUDO_USER" = "true" ] || [ "$SSH_ENV_HAS_ROOT_KEY" = "true" ] || [ -n "$SSH_KEY" ]; then
            can_disable_password="true"
        fi
        
        if [ "$can_disable_password" = "true" ]; then
            log_message "INFO" "检测到SSH密钥配置，可以安全禁用密码登录"
            local password_configs=(
                "PasswordAuthentication no"
                "ChallengeResponseAuthentication no"
                "KbdInteractiveAuthentication no"
                "PermitEmptyPasswords no"
            )
            
            for config in "${password_configs[@]}"; do
                local key="${config%% *}"
                sudo sed -i "s/^#*$key.*/$config/" "$SSH_CONFIG"
                grep -q "^$key" "$SSH_CONFIG" || echo "$config" | sudo tee -a "$SSH_CONFIG"
            done
        else
            log_message "ERROR" "未检测到SSH密钥配置，无法禁用密码登录"
            log_message "ERROR" "请先配置SSH密钥或创建具有SSH密钥的管理员用户"
            return 1
        fi
    fi
    
    return 0
}

# 配置SSH安全设置
configure_ssh_security() {
    local security_configs=(
        "X11Forwarding no"
        "ClientAliveInterval 300"
        "ClientAliveCountMax 2"
        "Protocol 2"
        "UseDNS no"
    )
    
    for config in "${security_configs[@]}"; do
        local key="${config%% *}"
        sudo sed -i "s/^#*$key.*/$config/" "$SSH_CONFIG"
        grep -q "^$key" "$SSH_CONFIG" || echo "$config" | sudo tee -a "$SSH_CONFIG"
    done
}

# 配置SSH端口
configure_ssh_port() {
    if [ -n "$SSH_PORT" ]; then
        log_message "INFO" "修改SSH端口为 $SSH_PORT..."
        sudo sed -i "s/^#*Port.*/Port $SSH_PORT/" "$SSH_CONFIG"
        grep -q "^Port" "$SSH_CONFIG" || echo "Port $SSH_PORT" | sudo tee -a "$SSH_CONFIG"
        
        # 配置防火墙
        if command -v ufw &> /dev/null && sudo ufw status | grep -q "active"; then
            sudo ufw allow "$SSH_PORT/tcp" comment 'SSH Port'
        fi
    fi
}

# 处理sshd_config.d目录配置
handle_ssh_config_dir() {
    # 处理sshd_config.d目录 - 与cloud-init和谐共存
        if [ -d "$SSH_CONFIG_DIR" ]; then
        # 创建99-security.conf以确保我们的配置优先级最高
        log_message "INFO" "创建SSH安全配置覆盖文件"
        
        # 从主配置文件中移除我们要管理的配置项，避免冲突
        if [ -n "$SSH_PORT" ] || [ "$DISABLE_SSH_PASSWD" = "true" ]; then
            log_message "INFO" "清理主配置文件中的冲突设置"
            # 注释掉主配置中的这些设置，让sshd_config.d中的配置生效
            sudo sed -i 's/^Port/#Port/' "$SSH_CONFIG"
            sudo sed -i 's/^PasswordAuthentication/#PasswordAuthentication/' "$SSH_CONFIG"
            sudo sed -i 's/^PermitRootLogin/#PermitRootLogin/' "$SSH_CONFIG"
            sudo sed -i 's/^PubkeyAuthentication/#PubkeyAuthentication/' "$SSH_CONFIG"
            sudo sed -i 's/^ChallengeResponseAuthentication/#ChallengeResponseAuthentication/' "$SSH_CONFIG"
            sudo sed -i 's/^KbdInteractiveAuthentication/#KbdInteractiveAuthentication/' "$SSH_CONFIG"
            sudo sed -i 's/^X11Forwarding/#X11Forwarding/' "$SSH_CONFIG"
            sudo sed -i 's/^ClientAliveInterval/#ClientAliveInterval/' "$SSH_CONFIG"
            sudo sed -i 's/^ClientAliveCountMax/#ClientAliveCountMax/' "$SSH_CONFIG"
            sudo sed -i 's/^UseDNS/#UseDNS/' "$SSH_CONFIG"
            sudo sed -i 's/^Protocol/#Protocol/' "$SSH_CONFIG"
        fi
        
        # 读取当前有效的配置值
        local current_port=$(sshd -T 2>/dev/null | grep "^port" | awk '{print $2}' || echo "22")
        local effective_port="${SSH_PORT:-$current_port}"
        
        # 获取当前的PermitRootLogin设置
        local current_permit_root=$(sshd -T 2>/dev/null | grep "^permitrootlogin" | awk '{print $2}' || echo "yes")
        # 如果主配置文件中有明确设置，使用该设置
        if grep -q "^PermitRootLogin" "$SSH_CONFIG" 2>/dev/null; then
            current_permit_root=$(grep "^PermitRootLogin" "$SSH_CONFIG" | awk '{print $2}')
        fi
        
        # 如果用户明确设置了--disable_root_login，确保在99-security.conf中也体现
        if [ "$DISABLE_ROOT_LOGIN" = "true" ]; then
            current_permit_root="no"
        fi
        
        sudo tee "$SSH_CONFIG_DIR/99-security.conf" > /dev/null << EOF
# Security configuration by setup.sh
# This file overrides any previous configurations

# 基本设置
Port $effective_port
Protocol 2

# 认证设置
PubkeyAuthentication yes
PasswordAuthentication $([ "$DISABLE_SSH_PASSWD" = "true" ] && echo "no" || echo "yes")
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no

# Root登录设置
PermitRootLogin $current_permit_root

# 安全设置
X11Forwarding no
UseDNS no
ClientAliveInterval 300
ClientAliveCountMax 2

# PAM设置
UsePAM yes
EOF
        
        # 如果存在cloud-init配置，记录信息
        if [ -f "$SSH_CONFIG_DIR/50-cloud-init.conf" ]; then
            log_message "INFO" "检测到cloud-init SSH配置，我们的99-security.conf将覆盖其设置"
            log_message "INFO" "cloud-init配置内容："
            cat "$SSH_CONFIG_DIR/50-cloud-init.conf" | sed 's/^/  /' >> "$LOG_FILE" 2>/dev/null || true
            
            # 强制确保cloud-init的设置不会生效
            # 方法1：直接修改50-cloud-init.conf，注释掉冲突的设置
            if grep -q "^PasswordAuthentication" "$SSH_CONFIG_DIR/50-cloud-init.conf"; then
                log_message "INFO" "注释掉cloud-init中的PasswordAuthentication设置"
                sudo sed -i 's/^PasswordAuthentication/#PasswordAuthentication/' "$SSH_CONFIG_DIR/50-cloud-init.conf"
            fi
        fi
    fi
}

# 验证并重启SSH服务
validate_and_restart_ssh() {
    # 测试SSH配置
    if ! sudo sshd -t; then
        log_message "ERROR" "SSH配置测试失败，正在还原配置..."
        sudo cp "$CONFIG_BACKUP_DIR/sshd_config.$TIMESTAMP.bak" "$SSH_CONFIG"
        log_message "ERROR" "SSH配置已还原，请检查配置后重试"
        return 1
    fi
    
    # 重启SSH服务
    if sudo systemctl restart ssh 2>/dev/null || sudo systemctl restart sshd 2>/dev/null; then
        log_message "INFO" "SSH服务重启成功"
    else
        log_message "ERROR" "SSH服务重启失败"
        return 1
    fi
    
    # 等待SSH服务启动
    sleep 2
    
    # 验证SSH服务状态
    local ssh_port="${SSH_PORT:-22}"
    if sudo ss -tlnp | grep -q ":$ssh_port"; then
        log_message "INFO" "SSH服务正在监听端口 $ssh_port"
    else
        log_message "ERROR" "SSH服务未能在端口 $ssh_port 上启动"
        return 1
    fi
    
    return 0
}

# 显示SSH配置状态
display_ssh_status() {
    log_message "INFO" "SSH配置完成"
    log_message "INFO" "当前SSH配置状态："
    log_message "INFO" "  端口: $(grep "^Port" "$SSH_CONFIG" 2>/dev/null || echo "22")"
    log_message "INFO" "  密码认证: $(grep "^PasswordAuthentication" "$SSH_CONFIG_DIR/99-security.conf" 2>/dev/null || grep "^PasswordAuthentication" "$SSH_CONFIG" 2>/dev/null || echo "yes")"
    log_message "INFO" "  公钥认证: $(grep "^PubkeyAuthentication" "$SSH_CONFIG_DIR/99-security.conf" 2>/dev/null || grep "^PubkeyAuthentication" "$SSH_CONFIG" 2>/dev/null || echo "yes")"
    log_message "INFO" "  Root登录: $(grep "^PermitRootLogin" "$SSH_CONFIG_DIR/99-security.conf" 2>/dev/null || grep "^PermitRootLogin" "$SSH_CONFIG" 2>/dev/null || echo "yes")"
    
    # 检查authorized_keys文件
    if [ -n "$SSH_KEY" ]; then
        log_message "INFO" "SSH密钥已配置的用户："
        if [ -f "/root/.ssh/authorized_keys" ] && grep -qF "${SSH_KEY%% *}" "/root/.ssh/authorized_keys"; then
            log_message "INFO" "  - root用户"
        fi
        if [ "$CREATE_DEVOPS_USER" = "true" ] && [ -f "/home/$SUDO_USERNAME/.ssh/authorized_keys" ]; then
            if sudo grep -qF "${SSH_KEY%% *}" "/home/$SUDO_USERNAME/.ssh/authorized_keys"; then
                log_message "INFO" "  - $SUDO_USERNAME用户"
            fi
        fi
    fi
}

# 配置SSH（重构后的主函数）
configure_ssh() {
    log_message "INFO" "配置SSH..."
    
    # 1. 准备阶段（关键步骤）
    log_message "DEBUG" "SSH配置 - 准备阶段"
    backup_ssh_config || {
        log_message "WARNING" "SSH配置备份失败，继续配置但存在风险"
    }
    
    analyze_ssh_environment || {
        check_error $? "分析SSH环境"
        log_message "WARNING" "SSH环境分析失败，使用默认配置继续"
    }
    
    # 2. 应用配置阶段（每个步骤独立处理错误）
    log_message "DEBUG" "SSH配置 - 应用配置阶段"
    
    # SSH认证配置是关键步骤，失败则需要特别关注
    if ! configure_ssh_authentication; then
        log_message "ERROR" "SSH认证配置失败，这可能导致无法远程连接"
        log_message "WARNING" "建议检查SSH配置文件和密钥设置"
        return 1
    fi
    
    # 安全配置失败不应该阻断流程，但需要记录
    configure_ssh_security || {
        check_error $? "SSH安全配置"
        log_message "WARNING" "SSH安全配置失败，安全性可能受影响"
    }
    
    # 端口配置失败记录警告
    configure_ssh_port || {
        check_error $? "SSH端口配置"
        log_message "WARNING" "SSH端口配置失败，可能使用默认端口22"
    }
    
    # 配置目录处理
    handle_ssh_config_dir || {
        check_error $? "SSH配置目录处理"
        log_message "WARNING" "SSH配置目录处理失败"
    }
    
    # 3. 验证和重启阶段（最关键步骤）
    log_message "DEBUG" "SSH配置 - 验证和重启阶段"
    
    # SSH服务验证和重启是最关键的步骤
    if ! validate_and_restart_ssh; then
        log_message "ERROR" "SSH服务验证或重启失败"
        log_message "ERROR" "这是严重问题，可能导致远程连接中断"
        log_message "INFO" "尝试恢复SSH配置..."
        
        # 尝试恢复备份配置
        if [ -f "${SSH_CONFIG}.backup" ]; then
            log_message "INFO" "恢复SSH配置备份"
            sudo cp "${SSH_CONFIG}.backup" "$SSH_CONFIG" && \
            sudo systemctl restart sshd && \
            log_message "SUCCESS" "SSH配置已恢复到备份状态" || \
            log_message "ERROR" "SSH配置恢复失败，需要手动检查"
        fi
        
        return 1
    fi
    
    # 显示状态（失败不影响主流程）
    display_ssh_status || {
        check_error $? "显示SSH状态"
        log_message "DEBUG" "显示SSH状态信息失败"
    }
    
    log_message "SUCCESS" "SSH配置完成"
    return 0
}

# ==================== 系统服务配置 ====================

# 配置fail2ban
configure_fail2ban() {
    log_message "INFO" "配置fail2ban..."
    
    # 确定SSH日志路径
    local ssh_log_path="/var/log/auth.log"
    if [ "$OS_TYPE" = "redhat" ]; then
        ssh_log_path="/var/log/secure"
    fi
    
    # 确保日志文件存在
    if [ ! -f "$ssh_log_path" ]; then
        if [ "$OS_TYPE" = "debian" ]; then
        sudo sed -i '/^auth,authpriv.\*/d' /etc/rsyslog.conf
        echo "auth,authpriv.*          /var/log/auth.log" | sudo tee -a /etc/rsyslog.conf
        fi
        sudo systemctl restart rsyslog
    fi

    # 配置fail2ban
    local ssh_port="${SSH_PORT:-22}"
    sudo tee /etc/fail2ban/jail.d/custom.conf > /dev/null << EOF
[DEFAULT]
allowipv6 = auto
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

    sudo systemctl enable fail2ban
    sudo systemctl restart fail2ban
    
    log_message "INFO" "fail2ban配置完成"
}

# 配置时区和NTP
configure_timezone_ntp() {
    log_message "INFO" "配置时区和NTP..."
    
    # 设置时区为东八区
    sudo timedatectl set-timezone Asia/Shanghai
    
    # 使用用户指定的地区
    local region="$SERVER_REGION"
    
    # 选择NTP服务器
    local ntp_server
    case "$region" in
        cn) ntp_server="cn.pool.ntp.org" ;;
        hk) ntp_server="hk.pool.ntp.org" ;;
        tw) ntp_server="tw.pool.ntp.org" ;;
        jp) ntp_server="jp.pool.ntp.org" ;;
        kr) ntp_server="kr.pool.ntp.org" ;;
        sg) ntp_server="sg.pool.ntp.org" ;;
        us) ntp_server="us.pool.ntp.org" ;;
        eu) ntp_server="europe.pool.ntp.org" ;;
        *) ntp_server="asia.pool.ntp.org" ;;
    esac
    
    log_message "INFO" "使用NTP服务器: $ntp_server"
    
    # 配置NTP服务
    if [ "$OS_TYPE" = "debian" ]; then
        if [ "$NTP_SERVICE" = "chrony" ] || ([ "$NTP_SERVICE" = "auto" ] && command -v chronyd &> /dev/null); then
            # 使用chrony
            if ! wait_for_apt_locks; then
                log_message "ERROR" "等待apt锁失败，跳过chrony安装"
                return 1
            fi
            if ! apt_install_with_retry "chrony"; then
                log_message "ERROR" "chrony安装失败"
                return 1
            fi
            sudo systemctl stop systemd-timesyncd 2>/dev/null || true
            sudo systemctl disable systemd-timesyncd 2>/dev/null || true
            
            sudo tee /etc/chrony/chrony.conf > /dev/null << EOF
pool $ntp_server iburst
keyfile /etc/chrony/chrony.keys
driftfile /var/lib/chrony/chrony.drift
logdir /var/log/chrony
maxupdateskew 100.0
rtcsync
makestep 1 3
EOF
            sudo systemctl restart chrony
            sudo systemctl enable chrony
        else
            # 使用systemd-timesyncd
                sudo systemctl stop chrony 2>/dev/null || true
                sudo systemctl disable chrony 2>/dev/null || true
            
            sudo tee /etc/systemd/timesyncd.conf > /dev/null << EOF
[Time]
NTP=$ntp_server
FallbackNTP=0.debian.pool.ntp.org 1.debian.pool.ntp.org
EOF
            sudo systemctl restart systemd-timesyncd
            sudo systemctl enable systemd-timesyncd
        fi
    else
        # RHEL/CentOS使用chrony
        sudo yum install -y chrony || sudo dnf install -y chrony
        sudo tee /etc/chrony.conf > /dev/null << EOF
server $ntp_server iburst
driftfile /var/lib/chrony/drift
makestep 1.0 3
rtcsync
logdir /var/log/chrony
EOF
        sudo systemctl restart chronyd
        sudo systemctl enable chronyd
    fi
    
    log_message "INFO" "时区和NTP配置完成"
}


# 配置系统优化
configure_system_optimization() {
    log_message "INFO" "配置系统优化..."
    
    # 启用BBR
    if dpkg --compare-versions "$(uname -r | cut -d- -f1)" "ge" "4.9"; then
        log_message "INFO" "启用BBR..."
        sudo modprobe tcp_bbr
        
        # 检查并添加sysctl配置
        if ! grep -q "net.core.default_qdisc = fq" /etc/sysctl.conf; then
            echo "net.core.default_qdisc = fq" | sudo tee -a /etc/sysctl.conf
        fi
        if ! grep -q "net.ipv4.tcp_congestion_control = bbr" /etc/sysctl.conf; then
            echo "net.ipv4.tcp_congestion_control = bbr" | sudo tee -a /etc/sysctl.conf
        fi
    fi
    
    # 启用IP转发
    if ! grep -q "net.ipv4.ip_forward = 1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward = 1" | sudo tee -a /etc/sysctl.conf
    fi
    
    # 应用sysctl设置
    sudo sysctl -p
    
    log_message "INFO" "系统优化配置完成"
}

# 配置安全审计（合并后的功能）
configure_security_audit() {
    [ "$ENABLE_SECURITY_AUDIT" != "true" ] && return 0
    
    log_message "INFO" "配置安全审计工具..."
    
    # 安装auditd（带重试机制）
    local install_success=false
    local retry_count=0
    local max_retries=3
    
    while [ $retry_count -lt $max_retries ] && [ "$install_success" = "false" ]; do
        if [ "$OS_TYPE" = "debian" ]; then
            # 等待apt锁释放
            if ! wait_for_apt_locks; then
                log_message "ERROR" "等待apt锁失败，跳过安全审计工具安装"
                return 1
            fi
            
            # 尝试安装auditd
            if apt_install_with_retry "auditd" 2 45; then
                install_success=true
                log_message "INFO" "auditd安装成功"
                break
            else
                ((retry_count++))
                if [ $retry_count -lt $max_retries ]; then
                    log_message "WARNING" "auditd安装失败，将在下次循环重试 ($retry_count/$max_retries)"
                else
                    log_message "ERROR" "auditd安装失败，已重试 $max_retries 次"
                fi
            fi
        else
            if sudo yum install -y audit || sudo dnf install -y audit; then
                install_success=true
            else
                ((retry_count++))
                if [ $retry_count -lt $max_retries ]; then
                    log_message "WARNING" "audit安装失败，等待30秒后重试 ($retry_count/$max_retries)"
                    sleep 30
                fi
            fi
        fi
    done
    
    # 只有在安装成功后才配置auditd
    if [ "$install_success" = "true" ]; then
        # 配置auditd规则
        sudo tee /etc/audit/rules.d/audit.rules > /dev/null << 'EOF'
-D
-b 8192
-w /usr/bin/sudo -p x -k sudo_usage
-w /etc/sudoers -p rw -k sudoers_change
-w /etc/passwd -p rw -k passwd_change
-w /etc/shadow -p rw -k shadow_change
-w /etc/ssh/sshd_config -p rw -k sshd_config_change
-w /var/log -p rwa -k log_directory
EOF
        
        # 重启auditd服务
        if sudo systemctl restart auditd 2>/dev/null; then
            sudo systemctl enable auditd
            log_message "INFO" "auditd服务配置完成"
        else
            # 某些系统可能需要使用service命令重启auditd
            if sudo service auditd restart 2>/dev/null; then
                log_message "INFO" "auditd服务配置完成（使用service命令）"
            else
                log_message "WARNING" "auditd服务重启失败，可能需要手动重启"
            fi
        fi
    else
        log_message "ERROR" "auditd安装失败，跳过auditd配置"
    fi
    
    # 安装etckeeper（带重试机制）
    install_success=false
    retry_count=0
    
    # 在两个apt操作之间添加延迟
    log_message "INFO" "等待5秒后继续安装etckeeper..."
    sleep 5
    
    while [ $retry_count -lt $max_retries ] && [ "$install_success" = "false" ]; do
        if [ "$OS_TYPE" = "debian" ]; then
            # 等待apt锁释放
            if ! wait_for_apt_locks; then
                log_message "ERROR" "等待apt锁失败，跳过etckeeper安装"
                break
            fi
            
            # 尝试安装etckeeper和git
            if apt_install_with_retry "etckeeper git" 2 45; then
                install_success=true
                log_message "INFO" "etckeeper和git安装成功"
                break
            else
                ((retry_count++))
                if [ $retry_count -lt $max_retries ]; then
                    log_message "WARNING" "etckeeper安装失败，将在下次循环重试 ($retry_count/$max_retries)"
                else
                    log_message "ERROR" "etckeeper安装失败，已重试 $max_retries 次"
                fi
            fi
        else
            if sudo yum install -y etckeeper git || sudo dnf install -y etckeeper git; then
                install_success=true
            else
                ((retry_count++))
                if [ $retry_count -lt $max_retries ]; then
                    log_message "WARNING" "etckeeper安装失败，等待30秒后重试 ($retry_count/$max_retries)"
                    sleep 30
                fi
            fi
        fi
    done
    
    # 只有在安装成功后才配置etckeeper
    if [ "$install_success" = "true" ]; then
        # 初始化etckeeper
        if [ ! -d /etc/.git ]; then
            if sudo etckeeper init; then
                sudo etckeeper commit "Initial commit - system setup" || true
                log_message "INFO" "etckeeper初始化完成"
            else
                log_message "WARNING" "etckeeper初始化失败"
            fi
        else
            log_message "INFO" "etckeeper已经初始化"
        fi
    else
        log_message "ERROR" "etckeeper安装失败，跳过etckeeper配置"
    fi
    
    # 总结安装结果
    if command -v auditctl &>/dev/null && command -v etckeeper &>/dev/null; then
        log_message "INFO" "安全审计配置完成（auditd + etckeeper）"
    elif command -v auditctl &>/dev/null; then
        log_message "WARNING" "安全审计部分完成（仅auditd）"
    elif command -v etckeeper &>/dev/null; then
        log_message "WARNING" "安全审计部分完成（仅etckeeper）"
    else
        log_message "ERROR" "安全审计工具安装失败，建议手动安装"
        log_message "INFO" "可以稍后手动执行以下命令安装："
        log_message "INFO" "  sudo apt update && sudo apt install -y auditd etckeeper git"
    fi
}

# ==================== Docker安装 ====================

# 安装Docker
install_docker() {
    [ "$INSTALL_DOCKER" != "true" ] && return 0
    
    log_message "INFO" "安装Docker..."
    
    if command -v docker &> /dev/null; then
        log_message "INFO" "Docker已安装"
        return 0
    fi
    
    # 安全的Docker安装方式
    local docker_script="/tmp/get-docker.sh"
    local docker_script_url="https://get.docker.com"
    
    # 下载脚本
    log_message "INFO" "下载Docker安装脚本..."
    if ! curl -fsSL "$docker_script_url" -o "$docker_script"; then
        log_message "ERROR" "下载Docker安装脚本失败"
        return 1
    fi
    
    # 验证脚本大小（防止下载不完整）
    local script_size=$(stat -c%s "$docker_script" 2>/dev/null || stat -f%z "$docker_script" 2>/dev/null || echo 0)
    if [ "$script_size" -lt 1000 ]; then
        log_message "ERROR" "Docker安装脚本可能不完整"
        rm -f "$docker_script"
            return 1
        fi
        
    # 设置脚本权限
    chmod 700 "$docker_script"
    
    # 执行安装脚本
    if sudo bash "$docker_script"; then
        rm -f "$docker_script"
        sudo systemctl start docker
        sudo systemctl enable docker
        
        # 添加当前用户到docker组
        [ "$(id -u)" != "0" ] && [ -n "${SUDO_USER:-}" ] && sudo usermod -aG docker "$SUDO_USER"
        
        # 配置Docker镜像加速（中国地区）
        local region="$SERVER_REGION"
        
        if [ "$region" = "cn" ]; then
    sudo mkdir -p /etc/docker
            sudo tee /etc/docker/daemon.json > /dev/null << EOF
{
  "registry-mirrors": [
    "https://mirror.ccs.tencentyun.com",
    "https://docker.mirrors.ustc.edu.cn",
    "https://hub-mirror.c.163.com"
  ],
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
EOF
    sudo systemctl daemon-reload
    sudo systemctl restart docker
        fi
        
        log_message "INFO" "Docker安装完成"
    else
        log_message "ERROR" "Docker安装失败"
        rm -f "$docker_script"
                return 1
    fi
}
    
# ==================== 配置总结和主流程 ====================

# 显示配置总结
show_summary() {
    local ssh_port="${SSH_PORT:-22}"
    [ -z "$SSH_PORT" ] && ssh_port=$(sudo ss -tlnp | grep sshd | head -1 | sed 's/.*:\([0-9]\+\) .*/\1/' || echo "22")
    
    log_message "INFO" "========== 配置完成 =========="
    echo "--------------------------------------------------"
    echo "系统信息:"
    echo "  OS: $OS_TYPE $OS_VERSION"
    echo "  时区: $(timedatectl | grep "Time zone" | awk '{print $3}')"
    echo ""
    echo "SSH配置:"
    echo "  端口: $ssh_port"
    echo "  密码登录: $([ "$DISABLE_SSH_PASSWD" = "true" ] && echo "已禁用" || echo "已启用")"
    echo "  公钥认证: 已启用"
    echo "  SSH密钥: $([ -n "$SSH_KEY" ] && echo "已添加" || echo "未添加")"
    echo ""
    echo "安全配置:"
    echo "  fail2ban: $(systemctl is-active fail2ban 2>/dev/null || echo '未运行')"
    echo "  安全审计: $([ "$ENABLE_SECURITY_AUDIT" = "true" ] && echo "已启用 (auditd + etckeeper)" || echo "已禁用")"
    echo ""
    echo "系统优化:"
    echo "  BBR: $(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}' || echo '未启用')"
    echo "  IP转发: $(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo '未启用')"
    echo ""
    
    if command -v docker &> /dev/null; then
        echo "Docker:"
        echo "  版本: $(docker --version | awk '{print $3}' | sed 's/,$//')"
        echo "  状态: $(systemctl is-active docker)"
    fi
    
    [ "$CREATE_DEVOPS_USER" = "true" ] && echo -e "\n管理员用户: $SUDO_USERNAME (已创建)"
    
    echo "--------------------------------------------------"
    echo "日志文件: $LOG_FILE"
    echo "配置备份: $CONFIG_BACKUP_DIR"
    echo "--------------------------------------------------"
    echo "SSH登录命令:"
    if [ "$CREATE_DEVOPS_USER" = "true" ]; then
        echo "  ssh -p $ssh_port $SUDO_USERNAME@服务器IP"
    fi
    if [ -f "/root/.ssh/authorized_keys" ] && [ -s "/root/.ssh/authorized_keys" ]; then
        local root_login=$(grep "^PermitRootLogin" "$SSH_CONFIG_DIR/99-security.conf" 2>/dev/null | awk '{print $2}' || grep "^PermitRootLogin" "$SSH_CONFIG" 2>/dev/null | awk '{print $2}' || echo "yes")
        if [ "$root_login" != "no" ]; then
            echo "  ssh -p $ssh_port root@服务器IP"
        fi
    fi
    echo ""
    
    # 诊断信息
    if [ -f "$SSH_CONFIG_DIR/50-cloud-init.conf.disabled" ]; then
        echo "注意: cloud-init SSH配置已禁用"
    fi
    
    [ "$DISABLE_SSH_PASSWD" = "true" ] && echo "警告: 密码登录已禁用，请确保已保存SSH密钥！"
}

# 主脚本的主函数
main() {
    # 阶段0：参数解析（致命错误会自动退出）
    parse_args "$@" || die "命令行参数解析失败"
    
    log_message "INFO" "开始系统初始化和配置过程"
    
    # 阶段1：系统检查和基础初始化（关键阶段，失败则退出）
    log_message "INFO" "=== 阶段1：系统检查和基础初始化 ==="
    check_compatibility || die "系统兼容性检查失败，无法继续"
    
    wait_for_cloud_init || {
        check_error $? "等待cloud-init完成"
        log_message "WARNING" "cloud-init可能未完全完成，继续执行"
    }
    
    fix_sudo_issue || {
        check_error $? "修复sudo问题"
        log_message "WARNING" "sudo问题修复失败，可能影响后续操作"
    }
    
    # 阶段2：系统更新和软件安装（重要但允许部分失败）
    log_message "INFO" "=== 阶段2：系统更新和软件安装 ==="
    update_system_install_dependencies || {
        check_error $? "系统更新和依赖安装"
        log_message "WARNING" "系统更新出现问题，继续后续配置"
    }
    
    # 阶段3：SSH和用户配置（安全关键，需要特别处理）
    log_message "INFO" "=== 阶段3：SSH和用户配置 ==="
    configure_ssh_keys || {
        check_error $? "SSH密钥配置"
        log_message "WARNING" "SSH密钥配置失败，可能影响安全性"
    }
    
    create_admin_user || {
        check_error $? "创建管理员用户"
        log_message "WARNING" "管理员用户创建失败"
    }
    
    configure_ssh || {
        local ssh_exit=$?
        if [ $ssh_exit -ne 0 ]; then
            log_message "ERROR" "SSH配置失败，这可能导致无法远程连接"
            log_message "WARNING" "请检查SSH配置，确保可以正常连接"
            # SSH配置失败不应该导致脚本退出，但需要特别关注
        fi
    }
    
    # 阶段4：系统服务配置（增强功能，允许失败）
    log_message "INFO" "=== 阶段4：系统服务配置 ==="
    configure_fail2ban || check_error $? "fail2ban配置"
    configure_timezone_ntp || check_error $? "时区和NTP配置"
    configure_system_optimization || check_error $? "系统优化配置"
    
    # 安全审计配置（可选功能）
    if [ "$ENABLE_SECURITY_AUDIT" = "true" ]; then
        configure_security_audit || check_error $? "安全审计配置"
    fi
    
    # 阶段5：Docker安装（可选功能）
    if [ "$INSTALL_DOCKER" = "true" ]; then
        log_message "INFO" "=== 阶段5：Docker安装 ==="
        install_docker || check_error $? "Docker安装"
    fi
    
    # 阶段6：总结和完成
    log_message "INFO" "=== 配置完成总结 ==="
    show_summary || log_message "WARNING" "显示配置总结时出现问题"
    
    log_message "SUCCESS" "系统初始化和配置过程完成"
}

# ==================== 脚本执行入口 ====================

# 脚本执行处理逻辑（现代化错误处理）
execute_script() {
    local exit_code=0
    
    # 捕获所有可能的错误
    if main "$@"; then
        log_message "SUCCESS" "脚本执行完成，所有配置均已成功应用"
        log_message "INFO" "日志文件已保存到: $LOG_FILE"
    else
        exit_code=$?
        log_message "ERROR" "脚本执行过程中遇到错误 (退出码: $exit_code)"
        log_message "INFO" "请查看日志文件获取详细信息: $LOG_FILE"
        
        # 提供故障排除建议
        echo ""
        echo "==================== 故障排除建议 ===================="
        echo "1. 检查系统兼容性: 确保在支持的Linux发行版上运行"
        echo "2. 检查网络连接: 确保可以访问软件包仓库"
        echo "3. 检查权限: 确保有sudo权限"
        echo "4. 检查磁盘空间: 确保有足够的磁盘空间"
        echo "5. 查看详细日志: cat $LOG_FILE"
        echo "======================================================"
    fi
    
    return $exit_code
}

# 主入口：执行脚本并处理退出状态
if ! execute_script "$@"; then
    exit_code=$?
    log_message "ERROR" "脚本执行失败，退出码: $exit_code"
    exit $exit_code
fi
