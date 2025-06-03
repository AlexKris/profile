#!/bin/bash

# 启用严格模式，任何未捕获的错误都会导致脚本退出
set -euo pipefail

# 脚本版本
readonly SCRIPT_VERSION="1.4.0"

# 脚本常量 - 集中配置
readonly DEFAULT_SSH_PORT="22"
readonly MIN_PORT=1024
readonly MAX_PORT=65535
# 获取脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# 添加时间戳到配置备份目录名
readonly TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
readonly CONFIG_BACKUP_DIR="$SCRIPT_DIR/ssh_backups_$TIMESTAMP"
readonly SSH_CONFIG="/etc/ssh/sshd_config"
readonly SSH_CONFIG_DIR="/etc/ssh/sshd_config.d"

# 脚本参数变量
DISABLE_SSH_PASSWD="false"
SSH_PORT=""
SSH_KEY=""
CONFIGURE_NTP="true"
# 添加时间戳到日志文件名
LOG_FILE="$SCRIPT_DIR/setup-script-$TIMESTAMP.log"
TMP_FILES=""
OS_TYPE=""
OS_VERSION=""
# 新增：服务器地区参数，默认为auto自动检测
SERVER_REGION="auto"
# 新增：创建devops用户参数
CREATE_DEVOPS_USER="false"
# 新增：sudo用户名
SUDO_USERNAME=""
# 新增：NTP服务选择（auto|timesyncd|chrony）
NTP_SERVICE="auto"
# 新增：防火墙相关参数
ENABLE_SSH_WHITELIST="false"
SSH_WHITELIST_IPS=""
DISABLE_ICMP="false"
BLOCK_WEB_PORTS="false"
ALLOW_CLOUDFLARE="false"
# 新增：审计方式选择
INSTALL_ETCKEEPER="false"
INSTALL_AUDITD="true"  # 默认安装auditd
# 新增：日志级别控制
LOG_LEVEL="INFO"  # DEBUG, INFO, WARNING, ERROR

# 设置安全的临时文件处理
cleanup() {
    # 删除所有临时文件
    if [ -n "$TMP_FILES" ]; then
        rm -f $TMP_FILES >/dev/null 2>&1
    fi
    log_message "INFO" "脚本执行完成，清理临时文件"
}

# 注册EXIT信号处理
trap cleanup EXIT INT TERM

# 错误处理函数
handle_error() {
    local exit_code=$1
    local error_msg=$2
    local fatal=${3:-false}

    if [ $exit_code -ne 0 ]; then
        log_message "ERROR" "$error_msg (错误码: $exit_code)"
        if [ "$fatal" = "true" ]; then
            log_message "ERROR" "遇到致命错误，脚本终止执行"
            exit $exit_code
        fi
        return 1
    fi
    return 0
}

# 日志记录函数
log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # 日志级别优先级：ERROR(3) > WARNING(2) > INFO(1) > DEBUG(0)
    local level_num=0
    local current_level_num=1  # 默认INFO级别
    
    case "$level" in
        "ERROR") level_num=3 ;;
        "WARNING") level_num=2 ;;
        "INFO") level_num=1 ;;
        "DEBUG") level_num=0 ;;
        *) level_num=1 ;;
    esac
    
    case "$LOG_LEVEL" in
        "ERROR") current_level_num=3 ;;
        "WARNING") current_level_num=2 ;;
        "INFO") current_level_num=1 ;;
        "DEBUG") current_level_num=0 ;;
        *) current_level_num=1 ;;
    esac
    
    # 只显示等于或高于当前日志级别的消息
    if [ $level_num -ge $current_level_num ]; then
        # 打印到控制台
        case "$level" in
            "ERROR")
                echo -e "[错误] $message" >&2
                ;;
            "WARNING")
                echo -e "[警告] $message"
                ;;
            "INFO")
                echo -e "[信息] $message"
                ;;
            "DEBUG")
                echo -e "[调试] $message"
                ;;
            *)
                echo -e "[日志] $message"
                ;;
        esac
    fi
    
    # 分析日志文件路径
    local log_dir=$(dirname "$LOG_FILE")
    
    # 检查日志目录是否存在，不存在则创建
    if [ ! -d "$log_dir" ]; then
        mkdir -p "$log_dir" 2>/dev/null || {
            echo "[警告] 无法创建日志目录: $log_dir，尝试使用临时目录" >&2
            LOG_FILE="/tmp/setup-script-$(date +%s).log"
            echo "[警告] 日志将写入: $LOG_FILE" >&2
        }
    fi
    
    # 写入到日志文件
    if [ ! -f "$LOG_FILE" ]; then
        # 尝试创建日志文件
        touch "$LOG_FILE" 2>/dev/null || {
            echo "[警告] 无法创建日志文件: $LOG_FILE，尝试使用临时文件" >&2
            LOG_FILE="/tmp/setup-script-$(date +%s).log"
            touch "$LOG_FILE" || {
                echo "[错误] 无法创建任何日志文件" >&2
                return 1
            }
        }
        chmod 644 "$LOG_FILE" 2>/dev/null || echo "[警告] 无法设置日志文件权限" >&2
    fi
    
    # 写入日志内容
    echo "[$timestamp][$level] $message" >> "$LOG_FILE" || {
        echo "[警告] 无法写入日志文件: $LOG_FILE" >&2
    }
    
    # 对于错误级别的消息，同时写入系统日志（如果有权限）
    if [ "$level" = "ERROR" ]; then
        logger -t "setup-script" "ERROR: $message" 2>/dev/null || true
    fi
}

# 辅助函数：根据用户是否为root来确定是否添加sudo前缀
run_with_root() {
    if [ "$(id -u)" = "0" ]; then
        "$@"
    else
        sudo "$@"
    fi
}

# 检查系统兼容性
check_compatibility() {
    log_message "INFO" "检查系统兼容性..."
    
    # 检查操作系统类型
    if [ -f /etc/debian_version ]; then
        OS_TYPE="debian"
        OS_VERSION=$(cat /etc/debian_version)
        log_message "INFO" "检测到Debian/Ubuntu系统 (版本: $OS_VERSION)"
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

# 显示用法信息
usage() {
    echo "用法: $0 [选项]"
    echo "选项:"
    echo "  --help                    显示此帮助信息"
    echo "  --disable_ssh_pwd         禁用SSH密码登录，仅允许SSH密钥认证"
    echo "  --port PORT               设置SSH端口号 (例如: --port 2222)"
    echo "  --ssh_key KEY             设置SSH公钥 (直接输入公钥文本，例如: --ssh_key \"ssh-rsa AAAA...\")"
    echo "  --ssh_key_file FILE       从文件读取SSH公钥 (例如: --ssh_key_file ~/.ssh/id_rsa.pub)"
    echo "  --update                  更新此脚本"
    echo "  --log_file FILE           指定日志文件路径 (默认: $LOG_FILE)"
    echo "  --region REGION           指定服务器所在地区，用于选择NTP服务器"
    echo "                            (auto|cn|hk|tw|jp|sg|us|eu|asia，默认: auto)"
    echo "  --disable_ntp             禁用NTP时间同步配置"
    echo "  --ntp_service SERVICE     指定NTP服务（auto|timesyncd|chrony，默认: auto）"
    echo "  --version                 显示脚本版本"
    echo "  --create_user USERNAME    创建管理员用户（必须提供SSH密钥）"
    echo "  --ssh_whitelist IPS       启用SSH白名单，只允许指定IP访问（逗号分隔）"
    echo "  --disable_icmp            禁用ICMP（禁止ping）"
    echo "  --block_web_ports         阻止80和443端口的公网访问"
    echo "  --allow_cloudflare        允许Cloudflare IP访问80和443端口（配合--block_web_ports使用）"
    echo "  --install_etckeeper       安装etckeeper用于配置文件版本控制（保留auditd）"
    echo "  --disable_auditd          不安装auditd安全审计工具"
    echo "  --audit_both              同时安装auditd和etckeeper（推荐用于生产环境）"
    echo "  --debug                   启用调试模式（显示详细日志）"
    echo "  --quiet                   静默模式（只显示警告和错误）"
    echo ""
    echo "地区说明:"
    echo "  auto - 自动检测地区（推荐）"
    echo "  cn   - 中国大陆，使用cn.pool.ntp.org"
    echo "  hk   - 香港，使用hk.pool.ntp.org"
    echo "  tw   - 台湾，使用tw.pool.ntp.org"
    echo "  jp   - 日本，使用jp.pool.ntp.org"
    echo "  sg   - 新加坡，使用sg.pool.ntp.org"
    echo "  us   - 美国，使用us.pool.ntp.org"
    echo "  eu   - 欧洲，使用europe.pool.ntp.org"
    echo "  asia - 亚洲通用，使用asia.pool.ntp.org"
    echo "  注意：所有地区统一使用东八区时区（Asia/Shanghai）"
    echo ""
    echo "示例:"
    echo "  $0 --disable_ssh_pwd --port 2222 --ssh_key_file ~/.ssh/id_rsa.pub"
    echo "  $0 --ssh_key \"ssh-rsa AAAA...\" --region cn"
    echo "  $0 --disable_ntp --region us"
    echo "  $0 --create_user devops --ssh_key_file ~/.ssh/id_rsa.pub --disable_ssh_pwd"
    echo "  $0 --ssh_whitelist \"1.2.3.4,5.6.7.8/24\" --disable_icmp --block_web_ports"
    echo "  $0 --block_web_ports --allow_cloudflare  # 阻止公网访问但允许Cloudflare"
    echo "  $0 --ntp_service chrony --region cn  # 指定使用chrony和中国NTP服务器"
    echo "  $0 --ntp_service timesyncd  # 强制使用systemd-timesyncd"
    echo "  $0 --install_etckeeper  # 安装etckeeper + auditd（默认组合）"
    echo "  $0 --audit_both  # 明确同时安装auditd和etckeeper"
    echo "  $0 --disable_auditd --install_etckeeper  # 只用etckeeper，不用auditd"
    echo ""
    echo "脚本版本: $SCRIPT_VERSION"
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
            --ssh_key_file) 
                if [ -z "$2" ] || [[ "$2" == --* ]]; then
                    log_message "ERROR" "选项 $1 需要一个有效的文件路径参数"
                    exit 1
                fi
                if [ -f "$2" ]; then
                    SSH_KEY=$(cat "$2") || {
                        log_message "ERROR" "无法读取密钥文件 $2"
                        exit 1
                    }
                else
                    log_message "ERROR" "无法找到密钥文件 $2"
                    exit 1
                fi
                shift ;;
            --region)
                if [ -z "$2" ] || [[ "$2" == --* ]]; then
                    log_message "ERROR" "选项 $1 需要一个有效的地区参数"
                    exit 1
                fi
                # 验证地区参数
                case "$2" in
                    auto|cn|hk|tw|jp|sg|us|eu|asia)
                        SERVER_REGION="$2"
                        ;;
                    *)
                        log_message "ERROR" "无效的地区参数: $2. 可用选项: auto, cn, hk, tw, jp, sg, us, eu, asia"
                        exit 1
                        ;;
                esac
                shift ;;
            --disable_ntp) CONFIGURE_NTP="false" ;;
            --ntp_service)
                if [ -z "$2" ] || [[ "$2" == --* ]]; then
                    log_message "ERROR" "选项 $1 需要一个有效的服务参数"
                    exit 1
                fi
                # 验证NTP服务参数
                case "$2" in
                    auto|timesyncd|chrony)
                        NTP_SERVICE="$2"
                        ;;
                    *)
                        log_message "ERROR" "无效的NTP服务参数: $2. 可用选项: auto, timesyncd, chrony"
                        exit 1
                        ;;
                esac
                shift ;;
            --update) update_shell; exit 0 ;;
            --log_file) 
                if [ -z "$2" ] || [[ "$2" == --* ]]; then
                    log_message "ERROR" "选项 $1 需要一个有效的文件路径参数"
                    exit 1
                fi
                # 保留用户指定的日志文件路径但添加时间戳
                local log_dir=$(dirname "$2")
                local log_name=$(basename "$2")
                local log_ext="${log_name##*.}"
                local log_base="${log_name%.*}"
                if [ "$log_ext" = "$log_name" ]; then
                    # 没有扩展名
                    LOG_FILE="${log_dir}/${log_name}-${TIMESTAMP}"
                else
                    # 有扩展名
                    LOG_FILE="${log_dir}/${log_base}-${TIMESTAMP}.${log_ext}"
                fi
                shift ;;
            --version) echo "脚本版本: $SCRIPT_VERSION"; exit 0 ;;
            --create_user)
                if [ -z "$2" ] || [[ "$2" == --* ]]; then
                    log_message "ERROR" "选项 $1 需要一个有效的用户名参数"
                    exit 1
                fi
                CREATE_DEVOPS_USER="true"
                SUDO_USERNAME="$2"
                # 验证用户名格式
                if ! [[ "$2" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
                    log_message "ERROR" "无效的用户名: $2. 用户名必须以小写字母或下划线开头，只能包含小写字母、数字、下划线和连字符"
                    exit 1
                fi
                shift ;;
            --ssh_whitelist)
                if [ -z "$2" ] || [[ "$2" == --* ]]; then
                    log_message "ERROR" "选项 $1 需要一个有效的IP列表参数"
                    exit 1
                fi
                ENABLE_SSH_WHITELIST="true"
                SSH_WHITELIST_IPS="$2"
                shift ;;
            --disable_icmp)
                DISABLE_ICMP="true" ;;
            --block_web_ports)
                BLOCK_WEB_PORTS="true" ;;
            --allow_cloudflare)
                ALLOW_CLOUDFLARE="true" ;;
            --install_etckeeper)
                INSTALL_ETCKEEPER="true" ;;
            --disable_auditd)
                INSTALL_AUDITD="false" ;;
            --audit_both)
                INSTALL_ETCKEEPER="true"
                INSTALL_AUDITD="true" ;;
            --debug)
                LOG_LEVEL="DEBUG" ;;
            --quiet)
                LOG_LEVEL="WARNING" ;;
            *) echo "未知选项: $1"; usage; exit 1 ;;
        esac
        shift
    done
    
    # 确保备份目录存在
    if [ ! -d "$CONFIG_BACKUP_DIR" ]; then
        sudo mkdir -p "$CONFIG_BACKUP_DIR" || log_message "WARNING" "无法创建备份目录 $CONFIG_BACKUP_DIR"
    fi
    
    # 验证创建用户时必须提供SSH密钥和用户名
    if [ "$CREATE_DEVOPS_USER" = "true" ]; then
        if [ -z "$SSH_KEY" ]; then
            log_message "ERROR" "创建管理员用户时必须提供SSH密钥（使用 --ssh_key 或 --ssh_key_file）"
            exit 1
        fi
        if [ -z "$SUDO_USERNAME" ]; then
            log_message "ERROR" "创建管理员用户时必须提供用户名"
            exit 1
        fi
    fi
    
    log_message "INFO" "脚本开始执行，参数: SSH端口=$SSH_PORT, 禁用密码=$DISABLE_SSH_PASSWD, 地区=$SERVER_REGION, NTP配置=$CONFIGURE_NTP, 日志文件=$LOG_FILE"
}

# 更新脚本函数
update_shell(){
    log_message "INFO" "正在获取最新版本的脚本..."
    if command -v git &> /dev/null; then
        log_message "INFO" "使用git克隆获取最新版本..."
        TMP_DIR=$(mktemp -d)
        git clone --depth=1 https://github.com/AlexKris/profile.git "$TMP_DIR"
        cp "$TMP_DIR/tool/setup.sh" ./setup.sh
        rm -rf "$TMP_DIR"
    else
        log_message "INFO" "git未安装，使用wget下载..."
        wget -N "https://raw.githubusercontent.com/AlexKris/profile/main/tool/setup.sh?$(date +%s)" -O setup.sh
    fi
    
    log_message "INFO" "更新完成，正在执行新脚本..."
    bash setup.sh
}

# 修复 sudo 的 'unable to resolve host' 问题
fix_sudo_issue(){
    # 确保 sudo 已安装
    if ! command -v sudo &> /dev/null; then
        log_message "INFO" "sudo 未安装，正在安装..."
        if [ -f /etc/debian_version ]; then
            wait_for_apt || return 1
            apt-get update -y && apt-get install -y sudo
        elif [ -f /etc/redhat-release ]; then
            if command -v dnf &> /dev/null; then
                dnf install -y sudo
            else
                yum install -y sudo
            fi
        else
            log_message "ERROR" "不支持的操作系统，无法安装 sudo"
            return 1
        fi
    fi
    
    # 确保当前用户在 sudo 组中
    CURRENT_USER=$(whoami)
    if ! groups $CURRENT_USER | grep -q "\bsudo\b"; then
        log_message "INFO" "将当前用户 $CURRENT_USER 添加到 sudo 组..."
        if [ -f /etc/debian_version ]; then
            if [ "$CURRENT_USER" != "root" ]; then
                usermod -aG sudo $CURRENT_USER
                log_message "INFO" "用户 $CURRENT_USER 已添加到 sudo 组，可能需要重新登录才能生效"
            fi
        elif [ -f /etc/redhat-release ]; then
            if [ "$CURRENT_USER" != "root" ]; then
                usermod -aG wheel $CURRENT_USER
                log_message "INFO" "用户 $CURRENT_USER 已添加到 wheel 组，可能需要重新登录才能生效"
            fi
        fi
    fi
    
    # 修复 sudo 的 unable to resolve host 问题
    if sudo -v 2>&1 | grep -q "unable to resolve host"; then
        log_message "INFO" "修复 'sudo: unable to resolve host' 问题..."
        HOSTNAME=$(hostname)
        if ! grep -q "$HOSTNAME" /etc/hosts; then
            echo "127.0.1.1   $HOSTNAME" | sudo tee -a /etc/hosts
            log_message "INFO" "已将 $HOSTNAME 添加到 /etc/hosts"
        else
            log_message "INFO" "$HOSTNAME 已存在于 /etc/hosts"
        fi
    else
        log_message "INFO" "sudo 正常运行，无需修复"
    fi
}

# 更新系统包并安装必要的软件
update_system_install_dependencies() {
    log_message "INFO" "正在更新系统包..."
    if [ -f /etc/debian_version ]; then
        log_message "INFO" "检测到 Debian/Ubuntu 系统..."
        wait_for_apt || return 1
        sudo apt-get update && sudo apt-get upgrade -y && sudo apt-get full-upgrade -y && sudo apt-get autoclean -y && sudo apt-get autoremove -y

        log_message "INFO" "正在安装 wget curl vim unzip zip fail2ban rsyslog iptables iperf3 mtr..."
        
        # 预配置可能的交互式包（支持多种可能的配置项名称）
        log_message "INFO" "预配置交互式包以避免安装提示..."
        echo 'iperf3 iperf3/autostart boolean false' | sudo debconf-set-selections
        echo 'iperf3 iperf3/start_daemon boolean false' | sudo debconf-set-selections
        echo 'iperf iperf/autostart boolean false' | sudo debconf-set-selections
        echo 'iperf iperf/start_daemon boolean false' | sudo debconf-set-selections
        
        # 额外设置环境变量确保非交互模式
        export DEBIAN_FRONTEND=noninteractive
        export DEBIAN_PRIORITY=critical
        export DEBCONF_NONINTERACTIVE_SEEN=true
        
        # 先安装基础包
        sudo -E apt-get install -y wget curl vim unzip zip fail2ban rsyslog iptables mtr
        
        # 单独处理iperf3安装（增强非交互模式）
        log_message "INFO" "单独安装iperf3..."
        if ! dpkg -l | grep -q "^ii.*iperf3"; then
            # 再次确保debconf预配置
            echo 'iperf3 iperf3/autostart boolean false' | sudo debconf-set-selections 2>/dev/null || true
            echo 'iperf3 iperf3/start_daemon boolean false' | sudo debconf-set-selections 2>/dev/null || true
                         # 使用最强的非交互模式安装，包含dpkg强制选项
             sudo bash -c 'DEBIAN_FRONTEND=noninteractive DEBIAN_PRIORITY=critical DEBCONF_NONINTERACTIVE_SEEN=true apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" iperf3'
            log_message "INFO" "iperf3 安装完成"
        else
            log_message "INFO" "iperf3 已经安装"
        fi
    elif [ -f /etc/redhat-release ]; then
        log_message "INFO" "检测到 RHEL/CentOS 系统..."
        
        # 检查是否有 dnf（CentOS/RHEL 8+）
        if command -v dnf &> /dev/null; then
            log_message "INFO" "使用 dnf 包管理器进行更新..."
            sudo dnf update -y
            
            log_message "INFO" "正在安装 wget curl vim unzip zip fail2ban rsyslog iptables iperf3 mtr..."
            sudo dnf install -y wget curl vim unzip zip fail2ban rsyslog iptables iperf3 mtr
        else
            log_message "INFO" "使用 yum 包管理器进行更新..."
            sudo yum update -y
            
            log_message "INFO" "正在安装 wget curl vim unzip zip fail2ban rsyslog iptables iperf3 mtr..."
            sudo yum install -y wget curl vim unzip zip fail2ban rsyslog iptables iperf3 mtr
        fi
    else
        log_message "ERROR" "不支持的操作系统，只支持Debian/Ubuntu和CentOS/RHEL。"
        exit 1
    fi
    log_message "INFO" "系统更新完成。"
    log_message "INFO" "安装 wget curl vim unzip zip fail2ban rsyslog iptables iperf3 mtr 完成。"
}

# 配置 SSH 公钥认证
configure_ssh_keys(){
    # 如果没有提供SSH密钥，则跳过此步骤
    if [ -z "$SSH_KEY" ]; then
        log_message "INFO" "未提供SSH公钥，跳过SSH密钥配置"
        return 0
    fi
    
    SSH_DIR="$HOME/.ssh"
    AUTHORIZED_KEYS="$SSH_DIR/authorized_keys"

    # 检查并创建 .ssh 目录
    if [ ! -d "$SSH_DIR" ]; then
        mkdir -p "$SSH_DIR"
        chmod 700 "$SSH_DIR"
        log_message "INFO" "已创建 $SSH_DIR 目录"
    else
        # 确保目录权限正确
        current_perm=$(stat -c %a "$SSH_DIR")
        if [ "$current_perm" != "700" ]; then
            chmod 700 "$SSH_DIR"
            log_message "INFO" "已修复 $SSH_DIR 目录权限 (从 $current_perm 改为 700)"
        else
            log_message "INFO" "$SSH_DIR 目录已存在，权限正确"
        fi
    fi

    # 检查并创建 authorized_keys 文件
    if [ ! -f "$AUTHORIZED_KEYS" ]; then
        touch "$AUTHORIZED_KEYS"
        chmod 600 "$AUTHORIZED_KEYS"
        log_message "INFO" "已创建 $AUTHORIZED_KEYS 文件"
    else
        # 确保文件权限正确
        current_perm=$(stat -c %a "$AUTHORIZED_KEYS")
        if [ "$current_perm" != "600" ]; then
            chmod 600 "$AUTHORIZED_KEYS"
            log_message "INFO" "已修复 $AUTHORIZED_KEYS 文件权限 (从 $current_perm 改为 600)"
        else
            log_message "INFO" "$AUTHORIZED_KEYS 文件已存在，权限正确"
        fi
    fi

    # 验证公钥格式
    if ! echo "$SSH_KEY" | grep -qE "^(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521) "; then
        log_message "WARNING" "提供的 SSH 公钥格式可能不正确。标准格式应该以 'ssh-rsa', 'ssh-ed25519' 等开头。"
        log_message "WARNING" "将仍然尝试添加此密钥"
    fi
    
    # 添加SSH公钥
    if grep -qF "$SSH_KEY" "$AUTHORIZED_KEYS"; then
        log_message "INFO" "提供的公钥已存在于 $AUTHORIZED_KEYS"
    else
        echo "$SSH_KEY" >> "$AUTHORIZED_KEYS"
        log_message "INFO" "已将公钥添加到 $AUTHORIZED_KEYS"
    fi
}

# 检查并启用 SSH 公钥认证
enable_ssh_pubkey_auth(){
    # 检查是否已启用 PubkeyAuthentication
    if grep -E "^\s*PubkeyAuthentication\s+yes" "$SSH_CONFIG" > /dev/null; then
        log_message "INFO" "SSH 已启用公钥认证"
    else
        log_message "INFO" "SSH 未启用公钥认证，正在启用..."

        # 如果存在 'PubkeyAuthentication no'，将其替换为 'PubkeyAuthentication yes'
        if grep -E "^\s*PubkeyAuthentication\s+no" "$SSH_CONFIG" > /dev/null; then
            sudo sed -i 's/^\s*PubkeyAuthentication\s\+no/PubkeyAuthentication yes/' "$SSH_CONFIG"
        elif grep -E "^\s*#\s*PubkeyAuthentication" "$SSH_CONFIG" > /dev/null; then
            # 如果存在被注释的 'PubkeyAuthentication' 行，去掉注释并设置为 'yes'
            sudo sed -i 's/^\s*#\s*PubkeyAuthentication.*/PubkeyAuthentication yes/' "$SSH_CONFIG"
        else
            # 如果配置文件中没有 'PubkeyAuthentication' 这一行，添加到文件末尾
            echo "PubkeyAuthentication yes" | sudo tee -a "$SSH_CONFIG"
        fi

        # 处理模块化配置中的公钥认证设置
        if [ -d "$SSH_CONFIG_DIR" ]; then
            log_message "INFO" "检查模块化配置中的公钥认证设置..."
            
            # 公钥认证配置将统一在ssh-security.conf中设置，由disable_ssh_password_login函数创建
            log_message "INFO" "公钥认证配置将在禁用密码登录时一并处理"
        fi

        # 重启 SSH 服务
        sudo systemctl restart ssh
        log_message "INFO" "SSH 公钥认证已启用，并重启了 SSH 服务"
    fi
}

# 配置 fail2ban 和 rsyslog
configure_fail2ban(){
    log_message "INFO" "配置 fail2ban..."
    
    # 确保需要的包已安装
    if [ -f /etc/debian_version ]; then
        wait_for_apt || return 1
        DEBIAN_FRONTEND=noninteractive sudo apt-get install -y fail2ban rsyslog
    elif [ -f /etc/redhat-release ]; then
        if command -v dnf &> /dev/null; then
            sudo dnf install -y fail2ban rsyslog
        else
            sudo yum install -y fail2ban rsyslog
        fi
    fi
    
    # 检查 /var/log/auth.log 是否存在
    if [ ! -f /var/log/auth.log ]; then
        log_message "INFO" "/var/log/auth.log 不存在，正在配置 rsyslog..."

        # 配置 rsyslog
        sudo sed -i '/^auth,authpriv.\*/d' /etc/rsyslog.conf
        echo "auth,authpriv.*          /var/log/auth.log" | sudo tee -a /etc/rsyslog.conf
        sudo systemctl restart rsyslog
        log_message "INFO" "已配置 rsyslog 并重启服务"
    else
        log_message "INFO" "/var/log/auth.log 已存在"
    fi

    # 创建 fail2ban 的自定义配置
    sudo mkdir -p /etc/fail2ban/jail.d
    sudo tee /etc/fail2ban/jail.d/custom.conf > /dev/null << EOF
[DEFAULT]
# 添加IPv6配置，解决警告
allowipv6 = auto
# 禁止的时间（秒）
bantime = 1800
# 查找失败次数的时间窗口（秒）
findtime = 600
# 最大失败次数
maxretry = 5

[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOF

    # 确保 fail2ban 服务启用并运行
    sudo systemctl enable fail2ban
    sudo systemctl restart fail2ban
    
    # 等待服务完全启动（增加延迟）
    log_message "INFO" "等待 fail2ban 服务完全启动..."
    sleep 5
    
    # 验证 fail2ban 状态
    if sudo systemctl is-active fail2ban &> /dev/null; then
        log_message "INFO" "fail2ban 服务已成功启动并配置"
        if command -v fail2ban-client &> /dev/null; then
            log_message "INFO" "fail2ban 状态:"
            # 使用错误处理，避免因命令失败导致脚本中断
            if ! sudo fail2ban-client status >/dev/null 2>&1; then
                log_message "WARNING" "无法获取 fail2ban 状态，但服务已正常启动"
                log_message "INFO" "这通常是因为服务刚启动，socket文件尚未就绪"
            else
                sudo fail2ban-client status
            fi
        fi
    else
        log_message "WARNING" "fail2ban 服务可能未正确启动，请手动检查"
    fi
}

# 检查并设置时区和NTP同步
configure_timezone(){
    if [ "$CONFIGURE_NTP" = "false" ]; then
        log_message "INFO" "已禁用NTP配置，跳过时区和时间同步设置"
        return 0
    fi
    
    local final_region="$SERVER_REGION"
    
    # 如果设置为auto，则自动检测
    if [ "$SERVER_REGION" = "auto" ]; then
        final_region=$(detect_server_region)
    fi
    
    # 统一使用东八区时区，但根据地区选择不同的NTP服务器
    local TARGET_TIMEZONE="Asia/Shanghai"  # 统一使用东八区
    local NTP_SERVER
    case "$final_region" in
        cn)
            NTP_SERVER="cn.pool.ntp.org"
            ;;
        hk)
            NTP_SERVER="hk.pool.ntp.org"
            ;;
        tw)
            NTP_SERVER="tw.pool.ntp.org"
            ;;
        jp)
            NTP_SERVER="jp.pool.ntp.org"
            ;;
        sg)
            NTP_SERVER="sg.pool.ntp.org"
            ;;
        us)
            NTP_SERVER="us.pool.ntp.org"
            ;;
        eu)
            NTP_SERVER="europe.pool.ntp.org"
            ;;
        asia|*)
            NTP_SERVER="asia.pool.ntp.org"
            ;;
    esac

    CURRENT_TIMEZONE=$(timedatectl | grep "Time zone" | awk '{print $3}')

    if [ "$CURRENT_TIMEZONE" != "$TARGET_TIMEZONE" ]; then
        log_message "INFO" "当前时区为 $CURRENT_TIMEZONE，正在设置为 $TARGET_TIMEZONE（东八区）..."
        sudo timedatectl set-timezone "$TARGET_TIMEZONE"
        log_message "INFO" "时区已设置为 $TARGET_TIMEZONE（东八区）"
    else
        log_message "INFO" "时区已是 $TARGET_TIMEZONE（东八区），无需更改"
    fi

    # 配置时间同步服务
    log_message "INFO" "配置时间同步服务，使用 $final_region 地区的NTP服务器: $NTP_SERVER"
    
    if [ -f /etc/debian_version ]; then
        # Debian/Ubuntu 系统
        log_message "INFO" "检测到 Debian/Ubuntu 系统，使用 systemd-timesyncd 或 chrony 配置时间同步"
        
        # 根据用户选择决定使用哪个NTP服务
        local use_chrony=false
        
        case "$NTP_SERVICE" in
            "chrony")
                use_chrony=true
                log_message "INFO" "用户指定使用 chrony"
                ;;
            "timesyncd")
                use_chrony=false
                log_message "INFO" "用户指定使用 systemd-timesyncd"
                ;;
            "auto"|*)
                # 自动选择：如果已安装chrony则使用，否则使用timesyncd
                if command -v chronyd &> /dev/null || dpkg -l | grep -q "^ii.*chrony"; then
                    use_chrony=true
                    log_message "INFO" "自动选择：检测到 chrony 已安装，将使用 chrony"
                else
                    use_chrony=false
                    log_message "INFO" "自动选择：未检测到 chrony，将使用 systemd-timesyncd"
                fi
                ;;
        esac
        
        if [ "$use_chrony" = "true" ]; then
            log_message "INFO" "使用 chrony 进行时间同步"
            # 如果选择了chrony但是timesyncd正在运行，先停止它
            if systemctl is-active systemd-timesyncd &> /dev/null; then
                log_message "INFO" "停止 systemd-timesyncd 服务"
                sudo systemctl stop systemd-timesyncd
                sudo systemctl disable systemd-timesyncd
            fi
            
            wait_for_apt || return 1
            DEBIAN_FRONTEND=noninteractive sudo apt-get install -y chrony
            # 配置 chrony 使用选定的时间服务器
            sudo tee /etc/chrony/chrony.conf > /dev/null << EOF
pool $NTP_SERVER iburst
keyfile /etc/chrony/chrony.keys
driftfile /var/lib/chrony/chrony.drift
logdir /var/log/chrony
maxupdateskew 100.0
rtcsync
makestep 1 3
EOF
            sudo systemctl restart chrony
            sudo systemctl enable chrony
            log_message "INFO" "chrony 服务已配置并启用"
        else
            # 使用 systemd-timesyncd
            log_message "INFO" "使用 systemd-timesyncd 进行时间同步"
            
            # 如果选择了timesyncd但是chrony正在运行，先停止它
            if systemctl is-active chrony &> /dev/null || systemctl is-active chronyd &> /dev/null; then
                log_message "INFO" "停止 chrony 服务"
                sudo systemctl stop chrony 2>/dev/null || true
                sudo systemctl stop chronyd 2>/dev/null || true
                sudo systemctl disable chrony 2>/dev/null || true
                sudo systemctl disable chronyd 2>/dev/null || true
            fi
            
            wait_for_apt || return 1
            sudo apt-get install -y systemd-timesyncd
            sudo tee /etc/systemd/timesyncd.conf > /dev/null << EOF
[Time]
NTP=$NTP_SERVER
FallbackNTP=0.debian.pool.ntp.org 1.debian.pool.ntp.org 2.debian.pool.ntp.org 3.debian.pool.ntp.org
EOF
            sudo systemctl restart systemd-timesyncd
            sudo systemctl enable systemd-timesyncd
            log_message "INFO" "systemd-timesyncd 服务已配置并启用"
        fi
    elif [ -f /etc/redhat-release ]; then
        # CentOS/RHEL 系统
        log_message "INFO" "检测到 CentOS/RHEL 系统，使用 chronyd 配置时间同步"
        
        # CentOS 7+ 使用 chronyd
        if command -v dnf &> /dev/null; then
            sudo dnf install -y chrony
        else
            sudo yum install -y chrony
        fi
        # 配置 chrony 使用选定的时间服务器
        sudo tee /etc/chrony.conf > /dev/null << EOF
server $NTP_SERVER iburst
driftfile /var/lib/chrony/drift
makestep 1.0 3
rtcsync
logdir /var/log/chrony
EOF
        sudo systemctl start chronyd
        sudo systemctl enable chronyd
        log_message "INFO" "chronyd 服务已配置并启用"
    else
        log_message "ERROR" "不支持的操作系统，无法配置时间同步"
    fi

    # 检查时间同步状态和NTP可用性
    log_message "INFO" "检查NTP服务状态和同步情况..."
    
    # 等待服务启动完成
    sleep 3
    
    # 检查服务是否运行
    local ntp_service_running=false
    local ntp_service_name=""
    
    if systemctl is-active systemd-timesyncd &> /dev/null; then
        ntp_service_running=true
        ntp_service_name="systemd-timesyncd"
    elif systemctl is-active chrony &> /dev/null; then
        ntp_service_running=true
        ntp_service_name="chrony"
    elif systemctl is-active chronyd &> /dev/null; then
        ntp_service_running=true
        ntp_service_name="chronyd"
    fi
    
    if [ "$ntp_service_running" = "true" ]; then
        log_message "INFO" "时间同步服务 $ntp_service_name 已成功启动"
        
        # 检查NTP服务器连通性
        log_message "INFO" "检查NTP服务器连通性: $NTP_SERVER"
        if check_ntp_connectivity "$NTP_SERVER"; then
            log_message "INFO" "NTP服务器 $NTP_SERVER 连接正常"
        else
            log_message "WARNING" "NTP服务器 $NTP_SERVER 连接可能有问题，将尝试使用备用服务器"
        fi
        
        # 检查时间同步状态
        check_ntp_sync_status "$ntp_service_name"
        
    else
        log_message "WARNING" "时间同步服务可能未正确启用，请手动检查"
        log_message "INFO" "您可以手动检查服务状态："
        log_message "INFO" "  systemctl status systemd-timesyncd"
        log_message "INFO" "  systemctl status chrony"
        log_message "INFO" "  systemctl status chronyd"
    fi
}

# 检查NTP服务器连通性
check_ntp_connectivity() {
    local ntp_server="$1"
    local connectivity_ok=false
    
    # 方法1: 使用ntpdate检查（如果可用）
    if command -v ntpdate &> /dev/null; then
        if timeout 10 ntpdate -q "$ntp_server" &> /dev/null; then
            connectivity_ok=true
            log_message "INFO" "通过ntpdate验证NTP服务器连通性成功"
        fi
    fi
    
    # 方法2: 使用chrony客户端检查（如果可用且connectivity_ok为false）
    if [ "$connectivity_ok" = "false" ] && command -v chronyc &> /dev/null; then
        # 等待chrony启动完成
        sleep 2
        local chrony_sources=$(timeout 10 chronyc sources 2>/dev/null || true)
        if echo "$chrony_sources" | grep -q "$ntp_server\|pool"; then
            connectivity_ok=true
            log_message "INFO" "通过chronyc验证NTP服务器连通性成功"
        fi
    fi
    
    # 方法3: 使用UDP端口检查（如果前面方法都失败）
    if [ "$connectivity_ok" = "false" ] && command -v nc &> /dev/null; then
        if timeout 5 nc -u -z "$ntp_server" 123 &> /dev/null; then
            connectivity_ok=true
            log_message "INFO" "NTP端口123可达，连通性检查通过"
        fi
    fi
    
    # 方法4: 使用ping检查基本网络连通性
    if [ "$connectivity_ok" = "false" ] && command -v ping &> /dev/null; then
        if timeout 5 ping -c 2 "$ntp_server" &> /dev/null; then
            log_message "INFO" "NTP服务器网络可达，但NTP协议可能有问题"
        else
            log_message "WARNING" "NTP服务器网络不可达: $ntp_server"
        fi
    fi
    
    [ "$connectivity_ok" = "true" ]
}

# 检查NTP同步状态
check_ntp_sync_status() {
    local service_name="$1"
    
    case "$service_name" in
        "systemd-timesyncd")
            log_message "INFO" "检查systemd-timesyncd同步状态..."
            local timedatectl_output=$(timedatectl status 2>/dev/null || true)
            
            if echo "$timedatectl_output" | grep -q "NTP synchronized: yes"; then
                log_message "INFO" "✓ 时间同步状态: 已同步"
            else
                log_message "WARNING" "⚠ 时间同步状态: 未同步或正在同步中"
                log_message "INFO" "这是正常的，新配置的NTP服务需要几分钟才能完成首次同步"
            fi
            
            # 显示当前NTP服务器信息
            if echo "$timedatectl_output" | grep -q "NTP service"; then
                local ntp_info=$(echo "$timedatectl_output" | grep "NTP service" | cut -d: -f2- | xargs)
                log_message "INFO" "NTP服务状态: $ntp_info"
            fi
            ;;
            
        "chrony"|"chronyd")
            log_message "INFO" "检查chrony同步状态..."
            if command -v chronyc &> /dev/null; then
                # 等待chrony完全启动
                sleep 2
                
                # 检查chrony源状态
                local chrony_sources=$(timeout 10 chronyc sources 2>/dev/null || true)
                if [ -n "$chrony_sources" ]; then
                    log_message "INFO" "Chrony NTP源状态:"
                    echo "$chrony_sources" | while read line; do
                        if [[ "$line" =~ ^\^.*\* ]] || [[ "$line" =~ ^\*.*$ ]]; then
                            log_message "INFO" "  ✓ $line (已同步)"
                        elif [[ "$line" =~ ^\^ ]] || [[ "$line" =~ ^\+ ]]; then
                            log_message "INFO" "  ○ $line (可用)"
                        elif [[ "$line" =~ ^- ]] || [[ "$line" =~ ^\? ]]; then
                            log_message "WARNING" "  ⚠ $line (不可用或未测试)"
                        fi
                    done
                fi
                
                # 检查同步状态
                local chrony_tracking=$(timeout 10 chronyc tracking 2>/dev/null || true)
                if echo "$chrony_tracking" | grep -q "Leap status.*Normal"; then
                    log_message "INFO" "✓ Chrony时间同步状态正常"
                    
                    # 显示时间偏差信息
                    local offset=$(echo "$chrony_tracking" | grep "Last offset" | awk '{print $4" "$5}' | head -1)
                    if [ -n "$offset" ]; then
                        log_message "INFO" "当前时间偏差: $offset"
                    fi
                else
                    log_message "WARNING" "⚠ Chrony可能还在初始化中，请稍后检查同步状态"
                fi
            else
                log_message "WARNING" "chronyc命令不可用，无法详细检查同步状态"
            fi
            ;;
    esac
    
    # 通用时间同步建议
    log_message "INFO" "时间同步配置完成。建议："
    log_message "INFO" "  1. 首次同步可能需要几分钟时间"
    log_message "INFO" "  2. 可使用 'timedatectl status' 查看详细状态"
    log_message "INFO" "  3. 如使用chrony，可用 'chronyc sources -v' 查看NTP源"
}

# 检查并启用 BBR
configure_bbr(){
    # 检查内核版本是否支持 BBR
    KERNEL_VERSION=$(uname -r | awk -F '-' '{print $1}')
    if dpkg --compare-versions "$KERNEL_VERSION" "ge" "4.9"; then
        log_message "INFO" "当前内核版本为 $KERNEL_VERSION，支持 BBR"
    else
        log_message "ERROR" "当前内核版本为 $KERNEL_VERSION，不支持 BBR，请升级内核后再试"
        return
    fi

    # 获取当前的 TCP 拥塞控制算法
    CURRENT_CC=$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')
    # 获取当前的队列调度器
    CURRENT_QDISC=$(sysctl net.core.default_qdisc | awk '{print $3}')

    # 检查BBR和队列调度器的状态
    BBR_ENABLED=0
    FQ_ENABLED=0
    
    if [ "$CURRENT_CC" = "bbr" ]; then
        log_message "INFO" "BBR 已启用"
        BBR_ENABLED=1
    fi
    
    if [ "$CURRENT_QDISC" = "fq" ]; then
        log_message "INFO" "FQ 队列调度器已启用"
        FQ_ENABLED=1
    fi
    
    # 如果需要更新配置
    if [ $BBR_ENABLED -eq 0 ] || [ $FQ_ENABLED -eq 0 ]; then
        if [ $BBR_ENABLED -eq 0 ]; then
            log_message "INFO" "BBR 未启用，正在启用..."
        fi
        
        if [ $FQ_ENABLED -eq 0 ]; then
            log_message "INFO" "FQ 队列调度器未启用，正在启用..."
        fi
        
        sudo modprobe tcp_bbr
        if ! lsmod | grep -q "tcp_bbr"; then
            log_message "ERROR" "无法加载 tcp_bbr 模块"
            return
        fi
        
        # 先删除可能存在的旧配置
        sudo sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
        sudo sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
        
        # 添加新配置
        sudo tee -a /etc/sysctl.conf > /dev/null << EOF
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
        sudo sysctl -p
        
        # 再次获取当前的设置
        CURRENT_CC=$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')
        CURRENT_QDISC=$(sysctl net.core.default_qdisc | awk '{print $3}')
        
        if [ "$CURRENT_CC" = "bbr" ] && [ "$CURRENT_QDISC" = "fq" ]; then
            log_message "INFO" "BBR 和 FQ 队列调度器已成功启用"
        else
            log_message "ERROR" "配置更新失败，请手动检查"
            log_message "INFO" "当前拥塞控制算法: $CURRENT_CC, 当前队列调度器: $CURRENT_QDISC"
        fi
    fi
}

# 检查并启用内核 IP 转发
configure_ip_forward(){
    # 获取当前内核 IP 转发状态
    CURRENT_CC=$(sysctl -n net.ipv4.ip_forward)

    # 检查是否已启用内核 IP 转发
    if [ "$CURRENT_CC" = "1" ]; then
        log_message "INFO" "内核 IP 转发 已启用"
    else
        log_message "INFO" "内核 IP 转发 未启用，正在启用..."
        sudo tee -a /etc/sysctl.conf > /dev/null << EOF
net.ipv4.ip_forward = 1
EOF
        sudo sysctl -p
        # 再次获取当前的内核 IP 转发状态
        CURRENT_CC=$(sysctl -n net.ipv4.ip_forward)
        if [ "$CURRENT_CC" = "1" ]; then
            log_message "INFO" "内核 IP 转发 已成功启用"
        else
            log_message "ERROR" "内核 IP 转发 启用失败，请手动检查"
        fi
    fi
}

# 禁用SSH密码登录
disable_ssh_password_login() {
    # SSH_CONFIG变量由全局定义
    
    if [ "$DISABLE_SSH_PASSWD" = "true" ]; then
        log_message "INFO" "正在禁用 SSH 密码登录..."
        
        # 确保公钥认证已启用
        if ! grep -E "^\s*PubkeyAuthentication\s+yes" "$SSH_CONFIG" > /dev/null; then
            log_message "WARNING" "请确保公钥认证已启用，否则可能无法登录系统"
            log_message "WARNING" "正在确保公钥认证启用..."
            if grep -E "^\s*PubkeyAuthentication\s+no" "$SSH_CONFIG" > /dev/null; then
                sudo sed -i 's/^\s*PubkeyAuthentication\s\+no/PubkeyAuthentication yes/' "$SSH_CONFIG"
            elif grep -E "^\s*#\s*PubkeyAuthentication" "$SSH_CONFIG" > /dev/null; then
                sudo sed -i 's/^\s*#\s*PubkeyAuthentication.*/PubkeyAuthentication yes/' "$SSH_CONFIG"
            else
                echo "PubkeyAuthentication yes" | sudo tee -a "$SSH_CONFIG"
            fi
        fi
        
        # 重启SSH服务以应用公钥认证
        restart_ssh_service

        # 禁用密码认证
        if grep -E "^\s*PasswordAuthentication\s+no" "$SSH_CONFIG" > /dev/null; then
            log_message "INFO" "SSH 密码认证已在主配置文件中禁用"
        else
            if grep -E "^\s*PasswordAuthentication\s+yes" "$SSH_CONFIG" > /dev/null; then
                sudo sed -i 's/^\s*PasswordAuthentication\s\+yes/PasswordAuthentication no/' "$SSH_CONFIG"
            elif grep -E "^\s*#\s*PasswordAuthentication" "$SSH_CONFIG" > /dev/null; then
                sudo sed -i 's/^\s*#\s*PasswordAuthentication.*/PasswordAuthentication no/' "$SSH_CONFIG"
            else
                echo "PasswordAuthentication no" | sudo tee -a "$SSH_CONFIG"
            fi
            log_message "INFO" "SSH 密码认证已在主配置文件中禁用"
        fi
        
        # 禁用挑战应答认证
        if grep -E "^\s*ChallengeResponseAuthentication\s+no" "$SSH_CONFIG" > /dev/null; then
            log_message "INFO" "SSH 挑战应答认证已禁用"
        else
            if grep -E "^\s*ChallengeResponseAuthentication\s+yes" "$SSH_CONFIG" > /dev/null; then
                sudo sed -i 's/^\s*ChallengeResponseAuthentication\s\+yes/ChallengeResponseAuthentication no/' "$SSH_CONFIG"
            elif grep -E "^\s*#\s*ChallengeResponseAuthentication" "$SSH_CONFIG" > /dev/null; then
                sudo sed -i 's/^\s*#\s*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' "$SSH_CONFIG"
            else
                echo "ChallengeResponseAuthentication no" | sudo tee -a "$SSH_CONFIG"
            fi
            log_message "INFO" "SSH 挑战应答认证已禁用"
        fi
        
        # 禁用键盘交互认证
        if grep -E "^\s*KbdInteractiveAuthentication\s+no" "$SSH_CONFIG" > /dev/null; then
            log_message "INFO" "SSH 键盘交互认证已禁用"
        else
            if grep -E "^\s*KbdInteractiveAuthentication\s+yes" "$SSH_CONFIG" > /dev/null; then
                sudo sed -i 's/^\s*KbdInteractiveAuthentication\s\+yes/KbdInteractiveAuthentication no/' "$SSH_CONFIG"
            elif grep -E "^\s*#\s*KbdInteractiveAuthentication" "$SSH_CONFIG" > /dev/null; then
                sudo sed -i 's/^\s*#\s*KbdInteractiveAuthentication.*/KbdInteractiveAuthentication no/' "$SSH_CONFIG"
            else
                echo "KbdInteractiveAuthentication no" | sudo tee -a "$SSH_CONFIG"
            fi
            log_message "INFO" "SSH 键盘交互认证已禁用"
        fi
        
        # 对于旧版本SSH，禁用 KeyboardInteractive 认证
        if grep -E "^\s*KeyboardInteractive\s+no" "$SSH_CONFIG" > /dev/null || ! grep -q "KeyboardInteractive" "$SSH_CONFIG"; then
            log_message "INFO" "SSH KeyboardInteractive 认证检查完成"
        else
            if grep -E "^\s*KeyboardInteractive\s+yes" "$SSH_CONFIG" > /dev/null; then
                sudo sed -i 's/^\s*KeyboardInteractive\s\+yes/KeyboardInteractive no/' "$SSH_CONFIG"
                log_message "INFO" "SSH KeyboardInteractive 认证已禁用"
            fi
        fi
        
        # 禁用空密码
        if grep -E "^\s*PermitEmptyPasswords\s+no" "$SSH_CONFIG" > /dev/null; then
            log_message "INFO" "SSH 空密码已禁用"
        else
            if grep -E "^\s*PermitEmptyPasswords\s+yes" "$SSH_CONFIG" > /dev/null; then
                sudo sed -i 's/^\s*PermitEmptyPasswords\s\+yes/PermitEmptyPasswords no/' "$SSH_CONFIG"
            elif grep -E "^\s*#\s*PermitEmptyPasswords" "$SSH_CONFIG" > /dev/null; then
                sudo sed -i 's/^\s*#\s*PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$SSH_CONFIG"
            else
                echo "PermitEmptyPasswords no" | sudo tee -a "$SSH_CONFIG"
            fi
            log_message "INFO" "SSH 空密码已禁用"
        fi
        
        # 处理模块化配置目录中的文件
        if [ -d "$SSH_CONFIG_DIR" ]; then
            log_message "INFO" "处理模块化配置目录中的文件..."
            
            # 检查是否存在50-cloud-init.conf文件并处理冲突配置
            if [ -f "$SSH_CONFIG_DIR/50-cloud-init.conf" ]; then
                log_message "INFO" "检测到cloud-init配置文件，正在处理冲突配置..."
                # 备份cloud-init配置
                if [ ! -f "$SSH_CONFIG_DIR/50-cloud-init.conf.bak" ]; then
                    sudo cp "$SSH_CONFIG_DIR/50-cloud-init.conf" "$SSH_CONFIG_DIR/50-cloud-init.conf.bak"
                fi
                # 注释掉所有启用密码的配置
                sudo sed -i 's/^\s*PasswordAuthentication\s\+yes/# &/' "$SSH_CONFIG_DIR/50-cloud-init.conf"
                sudo sed -i 's/^\s*ChallengeResponseAuthentication\s\+yes/# &/' "$SSH_CONFIG_DIR/50-cloud-init.conf"
                sudo sed -i 's/^\s*KbdInteractiveAuthentication\s\+yes/# &/' "$SSH_CONFIG_DIR/50-cloud-init.conf"
                log_message "INFO" "已注释cloud-init配置文件中的密码认证设置"
            fi
            
            # 如果存在之前创建的高优先级配置文件，则删除它们
            for file in "$SSH_CONFIG_DIR/99-"* "$SSH_CONFIG_DIR/98-"* "$SSH_CONFIG_DIR/97-"*; do
                if [ -f "$file" ]; then
                    log_message "INFO" "删除旧的优先级配置: $file"
                    sudo rm -f "$file"
                fi
            done
            
            # 使用统一的配置创建函数
            create_or_update_ssh_security_conf
            
            # 确保sshd_config包含Include指令
            if ! grep -q "Include $SSH_CONFIG_DIR/\*.conf" "$SSH_CONFIG"; then
                log_message "INFO" "添加Include指令到主配置文件..."
                echo -e "\n# Include modular configuration files\nInclude $SSH_CONFIG_DIR/*.conf" | sudo tee -a "$SSH_CONFIG" > /dev/null
                log_message "INFO" "Include指令已添加到 $SSH_CONFIG"
            fi
        fi
        
        log_message "INFO" "SSH 密码登录已完全禁用"
        log_message "WARNING" "请确保您已经设置了 SSH 密钥，否则您将无法登录系统!"
    else
        log_message "INFO" "未设置禁用 SSH 密码登录，跳过此步骤"
    fi
}

# 重启SSH服务
restart_ssh_service() {
    log_message "INFO" "重启 SSH 服务以应用更改..."
    
    # 检查系统使用的是哪种SSH服务名称
    if systemctl is-active ssh &>/dev/null; then
        sudo systemctl restart ssh
        log_message "INFO" "SSH 服务(ssh)已重启"
    elif systemctl is-active sshd &>/dev/null; then
        sudo systemctl restart sshd
        log_message "INFO" "SSH 服务(sshd)已重启"
    else
        log_message "WARNING" "无法确定SSH服务名称，请手动重启SSH服务"
    fi
}

# 修改SSH端口
change_ssh_port() {
    # 如果没有指定SSH端口，则不修改端口
    if [ -z "$SSH_PORT" ]; then
        log_message "INFO" "未指定SSH端口，保持当前端口设置"
        return 0
    fi
    
    log_message "INFO" "正在将 SSH 端口修改为 $SSH_PORT..."
    
    # 验证端口号是否有效
    if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [ "$SSH_PORT" -lt 1024 ] || [ "$SSH_PORT" -gt 65535 ]; then
        log_message "ERROR" "无效的端口号: $SSH_PORT. 端口号应在 1024-65535 范围内"
        log_message "INFO" "保持当前端口设置"
        SSH_PORT=""
        return 1
    fi
    
    # 检查当前端口设置
    CURRENT_PORT=$(grep -E "^\s*Port\s+[0-9]+" "$SSH_CONFIG" | awk '{print $2}' | head -1)
    
    if [ "$CURRENT_PORT" = "$SSH_PORT" ]; then
        log_message "INFO" "SSH 端口已经是 $SSH_PORT，无需修改主配置文件"
    else
        # 修改主配置文件中的端口
        if grep -E "^\s*Port\s+[0-9]+" "$SSH_CONFIG" > /dev/null; then
            sudo sed -i "s/^\s*Port\s\+[0-9]\+/Port $SSH_PORT/" "$SSH_CONFIG"
        elif grep -E "^\s*#\s*Port" "$SSH_CONFIG" > /dev/null; then
            # 如果存在被注释的 'Port' 行，去掉注释并设置为新端口
            sudo sed -i "s/^\s*#\s*Port.*/Port $SSH_PORT/" "$SSH_CONFIG"
        else
            # 如果配置文件中没有 'Port' 这一行，添加到文件末尾
            echo "Port $SSH_PORT" | sudo tee -a "$SSH_CONFIG"
        fi
        log_message "INFO" "已更新主配置文件中的SSH端口为 $SSH_PORT"
    fi
    
    # 处理模块化配置中的端口设置（无论主配置是否需要修改，都需要确保模块化配置正确）
    if [ -d "$SSH_CONFIG_DIR" ]; then
        log_message "INFO" "处理模块化配置中的端口设置..."
        
        # 如果存在cloud-init配置，注释掉其中的端口设置以避免冲突
        if [ -f "$SSH_CONFIG_DIR/50-cloud-init.conf" ]; then
            log_message "INFO" "检查cloud-init配置中的端口设置..."
            if grep -qE "^\s*Port\s+[0-9]+" "$SSH_CONFIG_DIR/50-cloud-init.conf"; then
                # 如果cloud-init配置中有端口设置，注释掉它
                sudo sed -i 's/^\s*Port\s\+[0-9]\+/# &/' "$SSH_CONFIG_DIR/50-cloud-init.conf"
                log_message "INFO" "已注释cloud-init配置中的端口设置以避免冲突"
            fi
        fi
        
        # 创建或更新统一的SSH安全配置文件
        create_or_update_ssh_security_conf
    fi
    
    # 配置防火墙规则
    configure_firewall_for_ssh_port
    
    log_message "INFO" "SSH 端口配置完成: $SSH_PORT"
}

# 创建或更新SSH安全配置文件
create_or_update_ssh_security_conf() {
    local security_conf="$SSH_CONFIG_DIR/ssh-security.conf"
    local temp_conf="/tmp/ssh-security-temp.conf"
    
    # 创建临时配置文件
    cat > "$temp_conf" << EOF
# SSH安全配置 - 由setup.sh创建
# 此配置会覆盖cloud-init等其他配置

EOF
    
    # 添加端口配置（如果指定了端口）
    if [ -n "$SSH_PORT" ]; then
        echo "# SSH端口配置" >> "$temp_conf"
        echo "Port $SSH_PORT" >> "$temp_conf"
        echo "" >> "$temp_conf"
    fi
    
    # 添加认证相关配置
    echo "# 认证配置" >> "$temp_conf"
    echo "PubkeyAuthentication yes" >> "$temp_conf"
    
    # 添加安全配置 - 禁用root登录
    cat >> "$temp_conf" << EOF

# 安全配置
PermitRootLogin no
EOF
    
    # 如果需要禁用密码登录，添加相关配置
    if [ "$DISABLE_SSH_PASSWD" = "true" ]; then
        cat >> "$temp_conf" << EOF

# 禁用密码登录
PasswordAuthentication no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
EOF
    fi
    
    # 将临时文件移动到最终位置
    sudo mv "$temp_conf" "$security_conf"
    sudo chmod 644 "$security_conf"
    
    log_message "INFO" "已创建/更新SSH安全配置文件: $security_conf"
}

# 配置防火墙规则允许SSH端口
configure_firewall_for_ssh_port() {
    if [ -z "$SSH_PORT" ]; then
        return 0
    fi
    
    # 如果启用了防火墙，添加规则允许新端口
    if command -v ufw &> /dev/null && sudo ufw status | grep -q "active"; then
        log_message "INFO" "检测到 UFW 防火墙，添加规则允许 SSH 端口 $SSH_PORT"
        sudo ufw allow "$SSH_PORT/tcp" comment 'SSH Port'
    elif command -v firewall-cmd &> /dev/null && sudo firewall-cmd --state | grep -q "running"; then
        log_message "INFO" "检测到 firewalld 防火墙，添加规则允许 SSH 端口 $SSH_PORT"
        sudo firewall-cmd --permanent --add-port="$SSH_PORT/tcp"
        sudo firewall-cmd --reload
    elif command -v iptables &> /dev/null; then
        log_message "INFO" "使用 iptables 添加规则允许 SSH 端口 $SSH_PORT"
        sudo iptables -A INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT
        # 尝试保存 iptables 规则
        if command -v iptables-save &> /dev/null; then
            if [ -f /etc/debian_version ]; then
                sudo iptables-save | sudo tee /etc/iptables/rules.v4 > /dev/null
            elif [ -f /etc/redhat-release ]; then
                sudo iptables-save | sudo tee /etc/sysconfig/iptables > /dev/null
            fi
        fi
    fi
}

# 允许Cloudflare IP访问
allow_cloudflare_ips() {
    log_message "INFO" "获取Cloudflare IP列表..."
    
    # 临时文件存储IP列表
    local cf_ips_v4="/tmp/cloudflare-ips-v4.txt"
    local cf_ips_v6="/tmp/cloudflare-ips-v6.txt"
    
    # 获取Cloudflare IPv4地址
    if curl -s https://www.cloudflare.com/ips-v4 -o "$cf_ips_v4"; then
        local count=0
        while IFS= read -r ip; do
            if [ -n "$ip" ] && [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
                # 检查规则是否已存在，避免重复添加
                if ! sudo iptables -C INPUT -p tcp -s "$ip" --dport 443 -j ACCEPT 2>/dev/null; then
                    sudo iptables -A INPUT -p tcp -s "$ip" --dport 443 -j ACCEPT
                    ((count++))
                fi
                if ! sudo iptables -C INPUT -p tcp -s "$ip" --dport 80 -j ACCEPT 2>/dev/null; then
                    sudo iptables -A INPUT -p tcp -s "$ip" --dport 80 -j ACCEPT
                fi
            fi
        done < "$cf_ips_v4"
        log_message "INFO" "已处理 $count 个Cloudflare IPv4地址（跳过已存在的规则）"
        rm -f "$cf_ips_v4"
    else
        log_message "WARNING" "无法获取Cloudflare IPv4地址列表"
    fi
    
    # 获取Cloudflare IPv6地址
    if command -v ip6tables &> /dev/null; then
        if curl -s https://www.cloudflare.com/ips-v6 -o "$cf_ips_v6"; then
            local count6=0
            while IFS= read -r ip; do
                if [ -n "$ip" ] && [[ "$ip" =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}/[0-9]{1,3}$ ]]; then
                    # 检查IPv6规则是否已存在
                    if ! sudo ip6tables -C INPUT -p tcp -s "$ip" --dport 443 -j ACCEPT 2>/dev/null; then
                        sudo ip6tables -A INPUT -p tcp -s "$ip" --dport 443 -j ACCEPT
                        ((count6++))
                    fi
                    if ! sudo ip6tables -C INPUT -p tcp -s "$ip" --dport 80 -j ACCEPT 2>/dev/null; then
                        sudo ip6tables -A INPUT -p tcp -s "$ip" --dport 80 -j ACCEPT
                    fi
                fi
            done < "$cf_ips_v6"
            log_message "INFO" "已处理 $count6 个Cloudflare IPv6地址（跳过已存在的规则）"
            rm -f "$cf_ips_v6"
        else
            log_message "WARNING" "无法获取Cloudflare IPv6地址列表"
        fi
    fi
}

# 清理重复的防火墙规则
clean_duplicate_firewall_rules() {
    log_message "INFO" "检查并清理重复的防火墙规则..."
    
    # 检查是否有重复的80/443端口规则
    local dup_443=$(sudo iptables -L INPUT -n | grep "tcp dpt:443.*ACCEPT" | wc -l)
    local dup_80=$(sudo iptables -L INPUT -n | grep "tcp dpt:80.*ACCEPT" | wc -l)
    local dup_drop_443=$(sudo iptables -L INPUT -n | grep "tcp dpt:443.*DROP" | wc -l)
    local dup_drop_80=$(sudo iptables -L INPUT -n | grep "tcp dpt:80.*DROP" | wc -l)
    
    if [ "$dup_443" -gt 14 ] || [ "$dup_80" -gt 14 ] || [ "$dup_drop_443" -gt 1 ] || [ "$dup_drop_80" -gt 1 ]; then
        log_message "WARNING" "检测到重复的防火墙规则"
        log_message "INFO" "  - 443端口ACCEPT: $dup_443个, DROP: $dup_drop_443个"
        log_message "INFO" "  - 80端口ACCEPT: $dup_80个, DROP: $dup_drop_80个"
        log_message "INFO" "开始清理重复规则..."
        
        local deleted_rules=0
        
        # 删除所有80/443端口的ACCEPT规则
        while sudo iptables -L INPUT -n --line-numbers | grep "tcp dpt:80.*ACCEPT" | head -1 | awk '{print $1}' | xargs -r sudo iptables -D INPUT 2>/dev/null; do 
            ((deleted_rules++))
        done
        
        while sudo iptables -L INPUT -n --line-numbers | grep "tcp dpt:443.*ACCEPT" | head -1 | awk '{print $1}' | xargs -r sudo iptables -D INPUT 2>/dev/null; do 
            ((deleted_rules++))
        done
        
        # 删除重复的DROP规则
        while sudo iptables -L INPUT -n --line-numbers | grep "tcp dpt:80.*DROP" | head -1 | awk '{print $1}' | xargs -r sudo iptables -D INPUT 2>/dev/null; do 
            ((deleted_rules++))
        done
        
        while sudo iptables -L INPUT -n --line-numbers | grep "tcp dpt:443.*DROP" | head -1 | awk '{print $1}' | xargs -r sudo iptables -D INPUT 2>/dev/null; do 
            ((deleted_rules++))
        done
        
        log_message "INFO" "重复规则清理完成，共删除 $deleted_rules 条规则"
    else
        log_message "DEBUG" "防火墙规则正常（443: ${dup_443}个ACCEPT/${dup_drop_443}个DROP, 80: ${dup_80}个ACCEPT/${dup_drop_80}个DROP）"
    fi
}

# 配置高级防火墙规则
configure_advanced_firewall() {
    log_message "INFO" "配置高级防火墙规则..."
    
    # 检查iptables是否可用
    if ! command -v iptables &> /dev/null; then
        log_message "ERROR" "iptables未安装，无法配置防火墙规则"
        return 1
    fi
    
    # 先清理重复规则
    clean_duplicate_firewall_rules
    
    # 获取SSH端口
    local ssh_port="${SSH_PORT:-22}"
    if [ -z "$SSH_PORT" ]; then
        ssh_port=$(get_current_ssh_port)
    fi
    
    # 1. 配置SSH白名单
    if [ "$ENABLE_SSH_WHITELIST" = "true" ] && [ -n "$SSH_WHITELIST_IPS" ]; then
        log_message "INFO" "配置SSH白名单..."
        
        # 完全清理SSH端口的所有规则（包括带IP的规则）
        log_message "INFO" "清理现有SSH端口 $ssh_port 的所有规则..."
        while sudo iptables -L INPUT -n --line-numbers | grep "tcp dpt:$ssh_port" | head -1 | awk '{print $1}' | xargs -r sudo iptables -D INPUT 2>/dev/null; do 
            log_message "DEBUG" "删除SSH端口规则"
        done
        
        # 为每个白名单IP添加规则
        IFS=',' read -ra IPS <<< "$SSH_WHITELIST_IPS"
        for ip in "${IPS[@]}"; do
            # 去除空格
            ip=$(echo "$ip" | xargs)
            # 验证IP格式
            if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
                # 检查规则是否已存在
                if ! sudo iptables -C INPUT -s "$ip" -p tcp --dport "$ssh_port" -j ACCEPT 2>/dev/null; then
                    sudo iptables -A INPUT -s "$ip" -p tcp --dport "$ssh_port" -j ACCEPT
                    log_message "INFO" "允许IP $ip 访问SSH端口 $ssh_port"
                else
                    log_message "DEBUG" "SSH规则已存在，跳过: $ip"
                fi
            else
                log_message "WARNING" "无效的IP地址格式: $ip"
            fi
        done
        
        # 检查并添加DROP规则（避免重复）
        if ! sudo iptables -C INPUT -p tcp --dport "$ssh_port" -j DROP 2>/dev/null; then
            sudo iptables -A INPUT -p tcp --dport "$ssh_port" -j DROP
            log_message "INFO" "已拒绝白名单外的所有SSH连接"
        else
            log_message "DEBUG" "SSH DROP规则已存在"
        fi
    fi
    
    # 2. 禁用ICMP（禁止ping）
    if [ "$DISABLE_ICMP" = "true" ]; then
        log_message "INFO" "禁用ICMP（禁止ping）..."
        
        # 删除可能存在的允许规则
        while sudo iptables -D INPUT -p icmp -j ACCEPT 2>/dev/null; do 
            log_message "DEBUG" "删除ICMP ACCEPT规则"
        done
        
        # 检查并添加INPUT拒绝规则（避免重复）
        if ! sudo iptables -C INPUT -p icmp -j DROP 2>/dev/null; then
            sudo iptables -A INPUT -p icmp -j DROP
            log_message "INFO" "已添加ICMP INPUT DROP规则"
        else
            log_message "DEBUG" "ICMP INPUT DROP规则已存在"
        fi
        
        # 检查并添加OUTPUT拒绝规则（避免重复）
        if ! sudo iptables -C OUTPUT -p icmp -j DROP 2>/dev/null; then
            sudo iptables -A OUTPUT -p icmp -j DROP
            log_message "INFO" "已添加ICMP OUTPUT DROP规则"
        else
            log_message "DEBUG" "ICMP OUTPUT DROP规则已存在"
        fi
        
        log_message "INFO" "ICMP已禁用"
    fi
    
    # 3. 阻止80和443端口的公网访问
    if [ "$BLOCK_WEB_PORTS" = "true" ]; then
        log_message "INFO" "阻止80和443端口的公网访问..."
        
        # 完全清理所有80/443端口相关的规则（包括带IP的规则）
        log_message "INFO" "清理现有的80/443端口规则..."
        while sudo iptables -D INPUT -p tcp --dport 80 -j DROP 2>/dev/null; do :; done
        while sudo iptables -D INPUT -p tcp --dport 443 -j DROP 2>/dev/null; do :; done
        
        # 删除所有80/443端口的ACCEPT规则（包括带源IP的）
        while sudo iptables -L INPUT -n --line-numbers | grep "tcp dpt:80.*ACCEPT" | head -1 | awk '{print $1}' | xargs -r sudo iptables -D INPUT 2>/dev/null; do :; done
        while sudo iptables -L INPUT -n --line-numbers | grep "tcp dpt:443.*ACCEPT" | head -1 | awk '{print $1}' | xargs -r sudo iptables -D INPUT 2>/dev/null; do :; done
        
        # 允许本地访问
        sudo iptables -A INPUT -p tcp --dport 80 -s 127.0.0.1 -j ACCEPT
        sudo iptables -A INPUT -p tcp --dport 443 -s 127.0.0.1 -j ACCEPT
        
        # 允许内网访问
        sudo iptables -A INPUT -p tcp --dport 80 -s 10.0.0.0/8 -j ACCEPT
        sudo iptables -A INPUT -p tcp --dport 443 -s 10.0.0.0/8 -j ACCEPT
        sudo iptables -A INPUT -p tcp --dport 80 -s 172.16.0.0/12 -j ACCEPT
        sudo iptables -A INPUT -p tcp --dport 443 -s 172.16.0.0/12 -j ACCEPT
        sudo iptables -A INPUT -p tcp --dport 80 -s 192.168.0.0/16 -j ACCEPT
        sudo iptables -A INPUT -p tcp --dport 443 -s 192.168.0.0/16 -j ACCEPT
        
        # 检查是否需要允许Cloudflare IP
        if [ "$ALLOW_CLOUDFLARE" = "true" ]; then
            log_message "INFO" "允许Cloudflare IP访问80和443端口..."
            allow_cloudflare_ips
        fi
        
        # 检查并添加最终的DROP规则（避免重复）
        if ! sudo iptables -C INPUT -p tcp --dport 80 -j DROP 2>/dev/null; then
            sudo iptables -A INPUT -p tcp --dport 80 -j DROP
            log_message "INFO" "已添加80端口DROP规则"
        else
            log_message "DEBUG" "80端口DROP规则已存在"
        fi
        
        if ! sudo iptables -C INPUT -p tcp --dport 443 -j DROP 2>/dev/null; then
            sudo iptables -A INPUT -p tcp --dport 443 -j DROP
            log_message "INFO" "已添加443端口DROP规则"
        else
            log_message "DEBUG" "443端口DROP规则已存在"
        fi
        
        log_message "INFO" "Web端口访问控制配置完成"
    fi
    
    # 保存iptables规则
    save_iptables_rules
    
    log_message "INFO" "高级防火墙规则配置完成"
}

# 保存iptables规则
save_iptables_rules() {
    log_message "INFO" "保存iptables规则..."
    
    if [ -f /etc/debian_version ]; then
        # Debian/Ubuntu系统
            # 安装iptables-persistent包
    if ! dpkg -l | grep -q iptables-persistent; then
        log_message "INFO" "安装iptables-persistent以保存规则..."
        wait_for_apt || return 1
        # 预配置iptables-persistent的答案，自动保存当前规则
        echo 'iptables-persistent iptables-persistent/autosave_v4 boolean true' | sudo debconf-set-selections
        echo 'iptables-persistent iptables-persistent/autosave_v6 boolean true' | sudo debconf-set-selections
        DEBIAN_FRONTEND=noninteractive sudo apt-get install -y iptables-persistent
        fi
        # 保存规则
        sudo mkdir -p /etc/iptables
        sudo iptables-save | sudo tee /etc/iptables/rules.v4 > /dev/null
        sudo ip6tables-save | sudo tee /etc/iptables/rules.v6 > /dev/null
    elif [ -f /etc/redhat-release ]; then
        # RHEL/CentOS系统
        if command -v systemctl &> /dev/null && systemctl is-enabled iptables &> /dev/null; then
            sudo iptables-save | sudo tee /etc/sysconfig/iptables > /dev/null
            sudo systemctl restart iptables
        else
            # 对于没有iptables服务的系统，使用rc.local
            sudo iptables-save | sudo tee /etc/sysconfig/iptables > /dev/null
            log_message "WARNING" "请确保iptables规则在重启后能够加载"
        fi
    fi
    
    log_message "INFO" "iptables规则已保存"
}

# 添加系统安全加固函数
harden_system() {
    log_message "INFO" "正在执行系统安全加固..."
    
    # 1. 限制 root 登录
    # 删除局部变量赋值，使用全局的SSH_CONFIG变量
    # SSH_CONFIG="/etc/ssh/sshd_config"
    if grep -E "^\s*PermitRootLogin\s+(yes|prohibit-password)" "$SSH_CONFIG" > /dev/null; then
        log_message "INFO" "禁用 root 直接登录..."
        sudo sed -i 's/^\s*PermitRootLogin\s\+\(yes\|prohibit-password\)/PermitRootLogin no/' "$SSH_CONFIG"
    elif ! grep -q "PermitRootLogin" "$SSH_CONFIG"; then
        log_message "INFO" "添加 PermitRootLogin no 配置..."
        echo "PermitRootLogin no" | sudo tee -a "$SSH_CONFIG"
    else
        # 检查是否已经是no
        if ! grep -q "PermitRootLogin no" "$SSH_CONFIG"; then
            log_message "INFO" "更新 PermitRootLogin 为 no..."
            sudo sed -i 's/^\s*PermitRootLogin\s\+.*/PermitRootLogin no/' "$SSH_CONFIG"
        fi
    fi
    
    # 2. 修改SSH设置增强安全性
    log_message "INFO" "配置SSH安全设置..."
    
    # 禁用X11转发
    if grep -E "^\s*X11Forwarding\s+yes" "$SSH_CONFIG" > /dev/null; then
        sudo sed -i 's/^\s*X11Forwarding\s\+yes/X11Forwarding no/' "$SSH_CONFIG"
    elif ! grep -q "X11Forwarding" "$SSH_CONFIG"; then
        echo "X11Forwarding no" | sudo tee -a "$SSH_CONFIG"
    fi
    
    # 设置SSH连接超时
    if ! grep -q "ClientAliveInterval" "$SSH_CONFIG"; then
        echo "ClientAliveInterval 300" | sudo tee -a "$SSH_CONFIG"
        log_message "INFO" "已添加SSH连接超时配置"
    else
        log_message "DEBUG" "SSH连接超时配置已存在"
    fi
    
    if ! grep -q "ClientAliveCountMax" "$SSH_CONFIG"; then
        echo "ClientAliveCountMax 2" | sudo tee -a "$SSH_CONFIG"
        log_message "INFO" "已添加SSH连接计数配置"
    else
        log_message "DEBUG" "SSH连接计数配置已存在"
    fi
    
    # 限制SSH版本
    if ! grep -q "Protocol" "$SSH_CONFIG"; then
        echo "Protocol 2" | sudo tee -a "$SSH_CONFIG"
        log_message "INFO" "已添加SSH协议版本限制"
    else
        log_message "DEBUG" "SSH协议版本限制已存在"
    fi
    
    # 禁用主机名查找（提高性能）
    if ! grep -q "UseDNS" "$SSH_CONFIG"; then
        echo "UseDNS no" | sudo tee -a "$SSH_CONFIG"
        log_message "INFO" "已禁用SSH主机名查找"
    else
        log_message "DEBUG" "SSH主机名查找禁用配置已存在"
    fi
    
    # 3. 设置更安全的系统限制
    if [ -f /etc/security/limits.conf ]; then
        log_message "INFO" "配置系统资源限制..."
        
        # 检查是否已经配置过
        if ! grep -q "# 添加系统安全限制" /etc/security/limits.conf; then
            # 备份原始文件
            if [ ! -f /etc/security/limits.conf.bak ]; then
                sudo cp /etc/security/limits.conf /etc/security/limits.conf.bak
                log_message "INFO" "已备份原始limits.conf文件"
            fi
            
            # 添加安全限制
            cat << EOF | sudo tee -a /etc/security/limits.conf > /dev/null
# 添加系统安全限制
* soft core 0
* hard core 0
* soft nproc 1000
* hard nproc 2000
* soft nofile 4096
* hard nofile 10240
EOF
            log_message "INFO" "已添加系统安全限制配置"
        else
            log_message "DEBUG" "系统安全限制配置已存在"
        fi
    fi
    
    # 4. 配置系统日志审计
    log_message "INFO" "配置系统日志审计..."
    
    # 现在支持同时安装auditd和etckeeper，或者只选择其中一个
    local audit_tools_installed=0
    
    # 安装etckeeper用于配置文件版本控制
    if [ "${INSTALL_ETCKEEPER:-false}" = "true" ]; then
        log_message "INFO" "安装etckeeper用于配置文件版本控制..."
        if [ -f /etc/debian_version ]; then
            wait_for_apt || return 1
            DEBIAN_FRONTEND=noninteractive sudo apt-get install -y etckeeper git
        elif [ -f /etc/redhat-release ]; then
            if command -v dnf &> /dev/null; then
                sudo dnf install -y etckeeper git
            else
                sudo yum install -y etckeeper git
            fi
        fi
        
        # 初始化etckeeper
        if [ ! -d /etc/.git ]; then
            log_message "INFO" "初始化etckeeper..."
            sudo etckeeper init
            sudo etckeeper commit "Initial commit - system setup"
            log_message "INFO" "etckeeper已初始化，/etc目录现在受版本控制"
        else
            log_message "INFO" "etckeeper已经初始化"
        fi
        audit_tools_installed=1
    fi
    
    # 安装auditd用于系统安全审计
    if [ "${INSTALL_AUDITD:-true}" = "true" ]; then
        log_message "INFO" "安装auditd用于系统安全审计..."
        if [ -f /etc/debian_version ]; then
            wait_for_apt || return 1
            DEBIAN_FRONTEND=noninteractive sudo apt-get install -y auditd
        elif [ -f /etc/redhat-release ]; then
            if command -v dnf &> /dev/null; then
                sudo dnf install -y audit
            else
                sudo yum install -y audit
            fi
        fi
        
        # 如果auditd已安装，配置基本审计规则
        if command -v auditd &> /dev/null; then
            log_message "INFO" "配置auditd审计规则..."
            # 创建基本的审计规则
            cat << EOF | sudo tee /etc/audit/rules.d/audit.rules > /dev/null
# 删除所有现有规则
-D

# 设置缓冲区大小（根据系统内存调整）
-b 8192

# 审计关键命令
-w /usr/bin/sudo -p x -k sudo_usage
-w /etc/sudoers -p rw -k sudoers_change
-w /etc/passwd -p rw -k passwd_change
-w /etc/shadow -p rw -k shadow_change
-w /etc/ssh/sshd_config -p rw -k sshd_config_change
-w /var/log -p rwa -k log_directory

# 失败的登录尝试
-a always,exit -F arch=b64 -S execve -F euid=0 -F exit=-1 -F key=access
-a always,exit -F arch=b32 -S execve -F euid=0 -F exit=-1 -F key=access

# 用户管理
-w /usr/sbin/useradd -p x -k user_add
-w /usr/sbin/userdel -p x -k user_delete
-w /usr/sbin/usermod -p x -k user_modify
-w /usr/sbin/groupadd -p x -k group_add
-w /usr/sbin/groupdel -p x -k group_delete
-w /usr/sbin/groupmod -p x -k group_modify
EOF

            # 重启auditd服务
            sudo systemctl restart auditd
            sudo systemctl enable auditd
            log_message "INFO" "auditd服务已配置并启用"
        fi
        audit_tools_installed=1
    fi
    
    # 检查是否至少安装了一个审计工具
    if [ $audit_tools_installed -eq 0 ]; then
        log_message "WARNING" "未安装任何审计工具（auditd或etckeeper），这可能降低系统的安全可见性"
        log_message "INFO" "可以使用 --audit_both 参数同时安装两个工具，或使用 --install_etckeeper 安装配置文件版本控制"
    fi
    
    log_message "INFO" "系统安全加固完成"
}

# 检查并处理sshd_config.d目录中的配置
check_sshd_config_d() {
    CONFIG_DIR="/etc/ssh/sshd_config.d"
    
    if [ -d "$CONFIG_DIR" ]; then
        log_message "INFO" "检测到 $CONFIG_DIR 目录，检查模块化配置文件..."
        
        # 检查主配置文件是否包含Include指令
        if ! grep -q "Include $CONFIG_DIR/\*.conf" "$SSH_CONFIG"; then
            log_message "WARNING" "主配置文件未包含Include指令，模块化配置可能不会生效"
        fi
        
        # 检查是否有覆盖我们关心设置的配置文件
        for conf_file in "$CONFIG_DIR"/*.conf; do
            if [ -f "$conf_file" ]; then
                if grep -qE "^\s*(PasswordAuthentication|PubkeyAuthentication|Port|ChallengeResponseAuthentication|KbdInteractiveAuthentication|PermitEmptyPasswords|PermitRootLogin)" "$conf_file"; then
                    log_message "WARNING" "发现模块化配置文件 $conf_file 包含关键SSH设置，可能会覆盖主配置"
                    
                    # 创建配置文件备份
                    sudo cp "$conf_file" "${conf_file}.bak"
                    log_message "INFO" "已创建配置文件备份: ${conf_file}.bak"
                    
                    # 处理密码认证设置
                    if [ "$DISABLE_SSH_PASSWD" = "true" ] && grep -qE "^\s*PasswordAuthentication\s+yes" "$conf_file"; then
                        log_message "INFO" "正在更新 $conf_file 中的密码认证设置..."
                        sudo sed -i 's/^\s*PasswordAuthentication\s\+yes/PasswordAuthentication no/' "$conf_file"
                    fi
                    
                    # 处理公钥认证设置
                    if grep -qE "^\s*PubkeyAuthentication\s+no" "$conf_file"; then
                        log_message "INFO" "正在更新 $conf_file 中的公钥认证设置..."
                        sudo sed -i 's/^\s*PubkeyAuthentication\s\+no/PubkeyAuthentication yes/' "$conf_file"
                    fi
                    
                    # 处理挑战应答认证
                    if [ "$DISABLE_SSH_PASSWD" = "true" ] && grep -qE "^\s*ChallengeResponseAuthentication\s+yes" "$conf_file"; then
                        log_message "INFO" "正在更新 $conf_file 中的挑战应答认证设置..."
                        sudo sed -i 's/^\s*ChallengeResponseAuthentication\s\+yes/ChallengeResponseAuthentication no/' "$conf_file"
                    fi
                    
                    # 处理键盘交互认证
                    if [ "$DISABLE_SSH_PASSWD" = "true" ] && grep -qE "^\s*KbdInteractiveAuthentication\s+yes" "$conf_file"; then
                        log_message "INFO" "正在更新 $conf_file 中的键盘交互认证设置..."
                        sudo sed -i 's/^\s*KbdInteractiveAuthentication\s\+yes/KbdInteractiveAuthentication no/' "$conf_file"
                    fi
                    
                    # 处理空密码
                    if grep -qE "^\s*PermitEmptyPasswords\s+yes" "$conf_file"; then
                        log_message "INFO" "正在更新 $conf_file 中的空密码设置..."
                        sudo sed -i 's/^\s*PermitEmptyPasswords\s\+yes/PermitEmptyPasswords no/' "$conf_file"
                    fi
                    
                    # 处理端口设置 - 注释掉冲突的端口配置，避免与统一配置冲突
                    if grep -qE "^\s*Port\s+[0-9]+" "$conf_file"; then
                        log_message "INFO" "正在注释 $conf_file 中的端口设置以避免配置冲突..."
                        sudo sed -i 's/^\s*Port\s\+[0-9]\+/# &/' "$conf_file"
                    fi
                    
                    # 处理root登录设置 - 确保禁用root登录
                    if grep -qE "^\s*PermitRootLogin\s+(yes|prohibit-password)" "$conf_file"; then
                        log_message "INFO" "正在更新 $conf_file 中的root登录设置..."
                        sudo sed -i 's/^\s*PermitRootLogin\s\+\(yes\|prohibit-password\)/PermitRootLogin no/' "$conf_file"
                    elif grep -qE "^\s*PermitRootLogin\s+" "$conf_file" && ! grep -q "PermitRootLogin no" "$conf_file"; then
                        log_message "INFO" "正在更新 $conf_file 中的root登录设置为no..."
                        sudo sed -i 's/^\s*PermitRootLogin\s\+.*/PermitRootLogin no/' "$conf_file"
                    fi
                fi
            fi
        done
    else
        log_message "INFO" "未检测到 $CONFIG_DIR 目录，跳过模块化配置检查"
    fi
}

# 为非标准SSH端口配置SELinux
configure_selinux_for_ssh() {
    # 只在RHEL/CentOS系统上执行
    if [ ! -f /etc/redhat-release ]; then
        return
    fi
    
    # 确认是否使用自定义端口
    if [ "$SSH_PORT" = "22" ]; then
        return
    fi
    
    # 检查SELinux是否启用
    if command -v getenforce &> /dev/null; then
        SELINUX_STATUS=$(getenforce)
        if [ "$SELINUX_STATUS" = "Disabled" ]; then
            log_message "INFO" "SELinux已禁用，无需配置自定义SSH端口"
            return
        fi
        
        log_message "INFO" "SELinux已启用 ($SELINUX_STATUS)，正在配置以支持自定义SSH端口 $SSH_PORT..."
        
        # 安装SELinux管理工具
        if ! command -v semanage &> /dev/null; then
            log_message "INFO" "安装SELinux管理工具..."
            if command -v dnf &> /dev/null; then
                sudo dnf install -y policycoreutils-python-utils
            else
                sudo yum install -y policycoreutils-python
            fi
        fi
        
        # 配置SELinux允许自定义SSH端口
        if command -v semanage &> /dev/null; then
            log_message "INFO" "添加SELinux策略允许SSH使用端口 $SSH_PORT..."
            sudo semanage port -a -t ssh_port_t -p tcp "$SSH_PORT"
            if [ $? -ne 0 ]; then
                # 如果添加失败，可能是因为端口已添加，尝试修改
                log_message "INFO" "端口可能已存在，尝试修改策略..."
                sudo semanage port -m -t ssh_port_t -p tcp "$SSH_PORT"
                if [ $? -ne 0 ]; then
                    log_message "WARNING" "无法配置SELinux以允许SSH使用端口 $SSH_PORT"
                    log_message "WARNING" "SSH可能无法在此端口上正常工作"
                    
                    # 询问是否要临时禁用SELinux
                    read -p "是否要临时禁用SELinux以允许SSH在端口 $SSH_PORT 上工作？(y/n): " disable_selinux
                    if [[ "$disable_selinux" == "y" || "$disable_selinux" == "Y" ]]; then
                        log_message "INFO" "临时禁用SELinux..."
                        sudo setenforce 0
                        log_message "WARNING" "SELinux已临时禁用，重启后将恢复"
                        log_message "WARNING" "要永久禁用SELinux，请编辑 /etc/selinux/config 文件并设置 SELINUX=disabled"
                    fi
                else
                    log_message "INFO" "SELinux策略已更新，允许SSH使用端口 $SSH_PORT"
                fi
            else
                log_message "INFO" "SELinux策略已添加，允许SSH使用端口 $SSH_PORT"
            fi
        else
            log_message "WARNING" "无法找到semanage命令，无法配置SELinux以允许SSH使用端口 $SSH_PORT"
            log_message "WARNING" "SSH可能无法在此端口上正常工作"
        fi
    else
        log_message "INFO" "未找到getenforce命令，SELinux可能未安装或未启用"
    fi
}

# 备份SSH配置文件
backup_ssh_config() {
    local timestamp=$(date +"%Y%m%d%H%M%S")
    local backup_file="${CONFIG_BACKUP_DIR}/sshd_config.${timestamp}.bak"
    
    # 确保备份目录存在
    if [ ! -d "$CONFIG_BACKUP_DIR" ]; then
        mkdir -p "$CONFIG_BACKUP_DIR" 2>/dev/null || {
            echo "[警告] 无法创建SSH配置备份目录: $CONFIG_BACKUP_DIR" >&2
            # 尝试使用临时目录
            CONFIG_BACKUP_DIR="/tmp/ssh_backups_$(date +%s)"
            mkdir -p "$CONFIG_BACKUP_DIR" || {
                log_message "ERROR" "无法创建SSH配置备份目录: $CONFIG_BACKUP_DIR"
                return 1
            }
            log_message "WARNING" "使用临时目录进行备份: $CONFIG_BACKUP_DIR"
        }
        chmod 700 "$CONFIG_BACKUP_DIR" 2>/dev/null || log_message "WARNING" "无法设置备份目录权限"
    fi
    
    # 检查是否有权限读取SSH配置文件
    if [ -f "$SSH_CONFIG" ]; then
        log_message "INFO" "正在备份SSH配置文件到 $backup_file"
        # 尝试直接拷贝
        if [ -r "$SSH_CONFIG" ]; then
            if cat "$SSH_CONFIG" > "$backup_file" 2>/dev/null; then
                log_message "INFO" "SSH配置备份成功: $backup_file"
            else
                log_message "ERROR" "无法写入备份文件: $backup_file"
                return 1
            fi
        else
            # 如果没有读取权限，尝试使用sudo
            log_message "WARNING" "无法直接读取SSH配置，尝试使用sudo..."
            if command -v sudo &>/dev/null; then
                if sudo cat "$SSH_CONFIG" > "$backup_file" 2>/dev/null; then
                    log_message "INFO" "使用sudo备份SSH配置成功: $backup_file"
                else
                    log_message "ERROR" "SSH配置备份失败"
                    read -p "是否继续执行而不进行备份? (y/n): " continue_without_backup
                    if [[ "$continue_without_backup" != "y" && "$continue_without_backup" != "Y" ]]; then
                        log_message "INFO" "用户选择终止脚本执行"
                        return 1
                    fi
                    log_message "WARNING" "用户选择在没有备份的情况下继续执行，可能无法恢复原始配置"
                    return 0
                fi
            else
                log_message "ERROR" "无法备份SSH配置，sudo未安装，也没有足够的权限"
                read -p "是否继续执行而不进行备份? (y/n): " continue_without_backup
                if [[ "$continue_without_backup" != "y" && "$continue_without_backup" != "Y" ]]; then
                    log_message "INFO" "用户选择终止脚本执行"
                    return 1
                fi
                log_message "WARNING" "用户选择在没有备份的情况下继续执行，可能无法恢复原始配置"
                return 0
            fi
        fi
        
        # 设置备份文件的权限为只读
        chmod 400 "$backup_file" 2>/dev/null || log_message "WARNING" "无法设置备份文件权限"
        
        # 备份sshd_config.d目录下的所有文件
        if [ -d "$SSH_CONFIG_DIR" ]; then
            log_message "INFO" "备份 $SSH_CONFIG_DIR 目录中的配置文件..."
            local config_d_backup="${CONFIG_BACKUP_DIR}/sshd_config.d.${timestamp}"
            mkdir -p "$config_d_backup" 2>/dev/null || log_message "WARNING" "无法创建 sshd_config.d 备份目录"
            
            # 如果有读取权限，直接拷贝
            local backup_success=true
            
            # 使用ls命令获取文件列表，避免通配符的问题
            local conf_files
            conf_files=$(ls "$SSH_CONFIG_DIR"/*.conf 2>/dev/null)
            if [ $? -eq 0 ]; then
                for conf_file in $conf_files; do
                    if [ -f "$conf_file" ]; then
                        local file_name=$(basename "$conf_file")
                        if [ -r "$conf_file" ]; then
                            if ! cat "$conf_file" > "${config_d_backup}/${file_name}" 2>/dev/null; then
                                log_message "WARNING" "无法备份 $file_name (写入失败)"
                                backup_success=false
                            fi
                        else
                            # 如果没有读取权限，尝试使用sudo
                            if command -v sudo &>/dev/null; then
                                if ! sudo cat "$conf_file" > "${config_d_backup}/${file_name}" 2>/dev/null; then
                                    log_message "WARNING" "无法备份 $file_name (即使使用sudo)"
                                    backup_success=false
                                fi
                            else
                                log_message "WARNING" "无法备份 $file_name (没有足够权限)"
                                backup_success=false
                            fi
                        fi
                        chmod 400 "${config_d_backup}/${file_name}" 2>/dev/null || log_message "WARNING" "无法设置 $file_name 的备份权限"
                    fi
                done
            else
                log_message "INFO" "$SSH_CONFIG_DIR 目录中没有找到.conf文件"
            fi
            
            if $backup_success; then
                log_message "INFO" "sshd_config.d 目录备份完成: $config_d_backup"
            else
                log_message "WARNING" "部分 sshd_config.d 文件可能未成功备份"
            fi
        fi
    else
        log_message "WARNING" "SSH配置文件不存在: $SSH_CONFIG"
        read -p "是否继续执行而不进行备份? (y/n): " continue_without_backup
        if [[ "$continue_without_backup" != "y" && "$continue_without_backup" != "Y" ]]; then
            log_message "INFO" "用户选择终止脚本执行"
            return 1
        fi
        log_message "WARNING" "用户选择在没有备份的情况下继续执行，可能无法恢复原始配置"
        return 0
    fi
    
    # 创建还原脚本
    local restore_script="${CONFIG_BACKUP_DIR}/restore_ssh_config.${timestamp}.sh"
    
    # 使用临时变量保存路径，避免在here-document中出现转义问题
    local ssh_conf_path="/etc/ssh/sshd_config"
    local ssh_conf_dir="/etc/ssh/sshd_config.d"
    local backup_path="$backup_file"
    local config_d_path=""
    [ -n "${config_d_backup:-}" ] && config_d_path="$config_d_backup"
    
    # 创建还原脚本
    cat > "$restore_script" << EOF
#!/bin/bash
# SSH配置还原脚本 - 由setup.sh于 $(date) 自动生成

# 检查是否有足够权限
if [ ! -w "$ssh_conf_path" ]; then
    echo "需要管理员权限来还原SSH配置"
    if command -v sudo &>/dev/null; then
        echo "将使用sudo执行还原操作"
        SUDO="sudo"
    else
        echo "sudo未安装，请以root用户运行此脚本"
        exit 1
    fi
else
    SUDO=""
fi

# 还原主配置文件
\$SUDO cp "$backup_path" "$ssh_conf_path" && echo "已还原 $ssh_conf_path"

# 还原sshd_config.d目录
if [ -d "$config_d_path" ]; then
    for conf_file in "$config_d_path"/*.conf; do
        if [ -f "\$conf_file" ]; then
            file_name=\$(basename "\$conf_file")
            \$SUDO cp "\$conf_file" "$ssh_conf_dir/\$file_name" && echo "已还原 $ssh_conf_dir/\$file_name"
        fi
    done
fi

# 重启SSH服务
if systemctl is-active ssh &>/dev/null; then
    \$SUDO systemctl restart ssh && echo "已重启SSH服务"
elif systemctl is-active sshd &>/dev/null; then
    \$SUDO systemctl restart sshd && echo "已重启SSH服务"
else
    echo "警告: 未能重启SSH服务，请手动重启"
fi

echo "SSH配置还原完成!"
EOF
    
    chmod +x "$restore_script" 2>/dev/null || log_message "WARNING" "无法设置还原脚本的执行权限"
    log_message "INFO" "已创建SSH配置还原脚本: $restore_script"
    
    return 0
}

# 自动检测服务器地区
detect_server_region() {
    log_message "INFO" "正在自动检测服务器地区..."
    
    # 尝试通过IP地理位置检测
    local detected_region="asia"  # 默认值
    
    # 方法1：通过curl获取IP地理位置信息
    if command -v curl &> /dev/null; then
        local ip_info
        # 尝试多个IP地理位置服务
        for service in "ipapi.co/country_code" "ifconfig.me/country_code" "api.country.is"; do
            ip_info=$(curl -s --connect-timeout 5 --max-time 10 "http://$service" 2>/dev/null || true)
            if [ -n "$ip_info" ]; then
                case "$ip_info" in
                    *CN*|*China*) detected_region="cn"; break ;;
                    *HK*|*Hong*) detected_region="hk"; break ;;
                    *TW*|*Taiwan*) detected_region="tw"; break ;;
                    *JP*|*Japan*) detected_region="jp"; break ;;
                    *SG*|*Singapore*) detected_region="sg"; break ;;
                    *US*|*United*States*) detected_region="us"; break ;;
                    *GB*|*UK*|*DE*|*FR*|*IT*|*ES*|*NL*) detected_region="eu"; break ;;
                    *) detected_region="asia" ;;
                esac
                log_message "INFO" "通过IP地理位置检测到地区: $ip_info -> $detected_region"
                break
            fi
        done
    fi
    
    # 方法2：通过系统时区推测
    if [ "$detected_region" = "asia" ]; then
        local current_tz=$(timedatectl 2>/dev/null | grep "Time zone" | awk '{print $3}' || echo "")
        case "$current_tz" in
            *Shanghai*|*Beijing*|*Chongqing*) detected_region="cn" ;;
            *Hong_Kong*) detected_region="hk" ;;
            *Taipei*) detected_region="tw" ;;
            *Tokyo*|*Osaka*) detected_region="jp" ;;
            *Singapore*) detected_region="sg" ;;
            *New_York*|*Los_Angeles*|*Chicago*) detected_region="us" ;;
            *London*|*Paris*|*Berlin*|*Rome*) detected_region="eu" ;;
        esac
        if [ "$detected_region" != "asia" ]; then
            log_message "INFO" "通过系统时区推测地区: $current_tz -> $detected_region"
        fi
    fi
    
    # 方法3：通过DNS解析速度测试（简单测试）
    if [ "$detected_region" = "asia" ] && command -v dig &> /dev/null; then
        local cn_speed us_speed eu_speed
        cn_speed=$(timeout 3 dig +time=1 @223.5.5.5 baidu.com 2>/dev/null | grep "Query time" | awk '{print $4}' || echo "999")
        us_speed=$(timeout 3 dig +time=1 @8.8.8.8 google.com 2>/dev/null | grep "Query time" | awk '{print $4}' || echo "999")
        eu_speed=$(timeout 3 dig +time=1 @1.1.1.1 cloudflare.com 2>/dev/null | grep "Query time" | awk '{print $4}' || echo "999")
        
        if [ "$cn_speed" -lt "50" ] && [ "$cn_speed" -lt "$us_speed" ] && [ "$cn_speed" -lt "$eu_speed" ]; then
            detected_region="cn"
            log_message "INFO" "通过DNS解析速度推测为中国大陆地区"
        fi
    fi
    
    log_message "INFO" "自动检测到服务器地区: $detected_region"
    echo "$detected_region"
}

# 主函数
main() {
    parse_args "$@"
    
    # 检查sudo是否已安装
    if ! command -v sudo &> /dev/null; then
        echo "[信息] sudo未安装，正在安装..."
        if [ -f /etc/debian_version ]; then
            wait_for_apt || exit 1
            apt-get update -y && apt-get install -y sudo
            echo "[信息] sudo已安装，正在配置sudo权限..."
            # 为当前用户添加sudo权限（如果不是root）
            if [ "$(id -u)" != "0" ]; then
                usermod -aG sudo $(whoami)
                echo "[信息] 已将用户 $(whoami) 添加到sudo组，重新登录后生效"
            fi
        elif [ -f /etc/redhat-release ]; then
            if command -v dnf &> /dev/null; then
                dnf install -y sudo
            else
                yum install -y sudo
            fi
            echo "[信息] sudo已安装，正在配置sudo权限..."
            # 为当前用户添加sudo权限（如果不是root）
            if [ "$(id -u)" != "0" ]; then
                usermod -aG wheel $(whoami)
                echo "[信息] 已将用户 $(whoami) 添加到wheel组，重新登录后生效"
            fi
        else
            echo "[错误] 不支持的操作系统，无法自动安装sudo"
            exit 1
        fi
    fi
    
    # 检查系统兼容性
    check_compatibility || {
        log_message "ERROR" "系统兼容性检查失败，脚本无法继续执行"
        exit 1
    }
    
    # 等待cloud-init完成
    wait_for_cloud_init
    
    # 以下命令全部使用错误处理
    fix_sudo_issue || log_message "WARNING" "修复sudo问题失败，但继续执行后续步骤"
    
    # 更新系统包和安装依赖
    update_system_install_dependencies || {
        log_message "ERROR" "更新系统和安装依赖失败"
        read -p "是否仍然继续执行? (y/n): " continue_exec
        if [[ "$continue_exec" != "y" && "$continue_exec" != "Y" ]]; then
            log_message "INFO" "用户选择终止脚本执行"
            exit 1
        fi
    }
    
    # 备份SSH配置
    backup_ssh_config || log_message "WARNING" "SSH配置备份失败，但继续执行"
    
    # 配置SSH密钥和认证
    configure_ssh_keys || log_message "WARNING" "配置SSH密钥失败，但继续执行"
    enable_ssh_pubkey_auth || log_message "WARNING" "启用SSH公钥认证失败，但继续执行"
    
    # 创建管理员用户
    create_devops_user || log_message "WARNING" "创建管理员用户失败，但继续执行"
    
    # 禁用SSH密码登录
    if [ "$DISABLE_SSH_PASSWD" = "true" ]; then
        disable_ssh_password_login || {
            log_message "ERROR" "禁用SSH密码登录失败"
            log_message "WARNING" "可能无法通过SSH密钥登录，为安全起见不继续修改端口"
            read -p "是否仍然继续修改SSH端口? (y/n): " continue_port
            if [[ "$continue_port" != "y" && "$continue_port" != "Y" ]]; then
                SSH_PORT=""
                log_message "INFO" "用户选择不修改SSH端口"
            fi
        }
    fi
    
    # 检查并处理sshd_config.d目录中的配置（在修改端口之前处理，避免冲突）
    check_sshd_config_d || log_message "WARNING" "处理SSH模块化配置失败，但继续执行"
    
    # 修改SSH端口（会创建统一的配置文件）
    change_ssh_port || log_message "WARNING" "修改SSH端口失败，但继续执行"
    
    # 配置SELinux以支持自定义SSH端口
    configure_selinux_for_ssh || log_message "WARNING" "配置SELinux失败，但继续执行"
    
    # 重启SSH服务
    restart_ssh_service || {
        log_message "ERROR" "重启SSH服务失败，配置更改可能未生效"
        log_message "WARNING" "请手动重启SSH服务以应用更改: sudo systemctl restart ssh 或 sudo systemctl restart sshd"
    }
    
    # 配置额外服务
    configure_fail2ban || log_message "WARNING" "配置fail2ban失败，但继续执行"
    configure_timezone || log_message "WARNING" "配置时区和NTP失败，但继续执行"
    configure_bbr || log_message "WARNING" "配置BBR失败，但继续执行"
    configure_ip_forward || log_message "WARNING" "配置IP转发失败，但继续执行"
    
    # 系统安全加固
    harden_system || log_message "WARNING" "系统安全加固失败，但继续执行"
    
    # 配置高级防火墙规则
    if [ "$ENABLE_SSH_WHITELIST" = "true" ] || [ "$DISABLE_ICMP" = "true" ] || [ "$BLOCK_WEB_PORTS" = "true" ]; then
        configure_advanced_firewall || log_message "WARNING" "配置高级防火墙规则失败，但继续执行"
    fi
    
    # 验证配置有效性
    verify_configuration || log_message "WARNING" "配置验证失败，请手动检查配置"
    
    log_message "INFO" "========== 系统配置完成 =========="
    log_message "INFO" "SSH 端口: $([ -n "$SSH_PORT" ] && echo "$SSH_PORT" || get_current_ssh_port)"
    if [ "$DISABLE_SSH_PASSWD" = "true" ]; then
        log_message "INFO" "SSH 密码登录: 已禁用"
    else
        log_message "INFO" "SSH 密码登录: 已启用"
    fi
    log_message "INFO" "SSH 密钥: $([ -n "$SSH_KEY" ] && echo "已添加" || echo "未添加")"
    log_message "INFO" "fail2ban 状态: $(systemctl is-active fail2ban 2>/dev/null || echo '未运行')"
    if [ "$CONFIGURE_NTP" = "true" ]; then
        log_message "INFO" "当前时区: $(timedatectl | grep "Time zone" | awk '{print $3}')"
    else
        log_message "INFO" "时区配置: 已跳过"
    fi
    log_message "INFO" "BBR 状态: $(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}' || echo '未启用')"
    log_message "INFO" "IP 转发: $(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo '未启用')"
    
    # 显示审计工具状态
    local audit_status=""
    if [ "${INSTALL_AUDITD:-true}" = "true" ] && [ "${INSTALL_ETCKEEPER:-false}" = "true" ]; then
        audit_status="auditd + etckeeper（双重保护）"
    elif [ "${INSTALL_AUDITD:-true}" = "true" ]; then
        audit_status="auditd（安全审计）"
    elif [ "${INSTALL_ETCKEEPER:-false}" = "true" ]; then
        audit_status="etckeeper（配置版本控制）"
    else
        audit_status="无（未安装审计工具）"
    fi
    log_message "INFO" "审计工具: $audit_status"
    if [ -n "$SSH_KEY" ]; then
        log_message "INFO" "请记住保存您的 SSH 密钥以便远程登录"
    else
        log_message "INFO" "请注意：未添加SSH密钥，确保您有其他方式访问服务器"
    fi
    
    if [ "$CREATE_DEVOPS_USER" = "true" ]; then
        log_message "INFO" "已创建管理员用户 $SUDO_USERNAME，可使用SSH密钥登录"
    fi
    
    # 显示配置总结
    show_configuration_summary
}

# 验证配置有效性
verify_configuration() {
    log_message "INFO" "验证配置有效性..."
    
    # 验证SSH配置语法
    if command -v sshd &> /dev/null; then
        log_message "INFO" "验证SSH配置语法..."
        if ! sudo sshd -t &> /dev/null; then
            log_message "ERROR" "SSH配置语法错误!"
            sudo sshd -t
            return 1
        else
            log_message "INFO" "SSH配置语法验证通过"
        fi
    else
        log_message "WARNING" "找不到sshd命令，无法验证SSH配置语法"
    fi
    
    # 检查SSH端口是否已在监听
    if ! sudo ss -tlnp | grep -q ":$SSH_PORT"; then
        log_message "WARNING" "SSH端口 $SSH_PORT 可能未在监听"
        log_message "INFO" "当前监听的端口:"
        sudo ss -tlnp | grep sshd || true
    else
        log_message "INFO" "SSH端口 $SSH_PORT 已在监听"
    fi
    
    return 0
}

# 显示配置总结
show_configuration_summary() {
    local actual_ssh_port
    
    # 如果脚本中修改了SSH端口，使用修改后的端口；否则获取当前实际端口
    if [ -n "$SSH_PORT" ]; then
        actual_ssh_port="$SSH_PORT"
    else
        actual_ssh_port=$(get_current_ssh_port)
    fi
    
    log_message "INFO" "配置总结:"
    echo "--------------------------------------------------"
    echo "系统类型: $OS_TYPE $OS_VERSION"
    echo "SSH 配置:"
    echo "  - 端口: $actual_ssh_port"
    echo "  - 密码登录: $([ "$DISABLE_SSH_PASSWD" = "true" ] && echo "已禁用" || echo "已启用")"
    echo "  - 公钥认证: 已启用"
    echo "  - SSH密钥: $([ -n "$SSH_KEY" ] && echo "已添加" || echo "未添加")"
    
    # 检查防火墙状态
    FIREWALL_STATUS="未启用"
    if command -v ufw &> /dev/null && sudo ufw status | grep -q "active"; then
        FIREWALL_STATUS="UFW 已启用"
    elif command -v firewall-cmd &> /dev/null && sudo firewall-cmd --state | grep -q "running"; then
        FIREWALL_STATUS="firewalld 已启用"
    elif command -v iptables &> /dev/null && sudo iptables -L | grep -q "Chain"; then
        FIREWALL_STATUS="iptables 规则已配置"
    fi
    echo "  - 防火墙: $FIREWALL_STATUS"
    if [ "$ENABLE_SSH_WHITELIST" = "true" ]; then
        echo "  - SSH白名单: 已启用 (允许: $SSH_WHITELIST_IPS)"
    fi
    if [ "$DISABLE_ICMP" = "true" ]; then
        echo "  - ICMP: 已禁用（禁止ping）"
    fi
    if [ "$BLOCK_WEB_PORTS" = "true" ]; then
        echo "  - Web端口保护: 已启用（80/443端口仅限本地和内网访问）"
    fi
    
    echo "安全加固:"
    echo "  - fail2ban: $(systemctl is-active fail2ban 2>/dev/null || echo '未运行')"
    echo "  - SELinux: $(command -v getenforce &> /dev/null && getenforce || echo '未启用')"
    echo "  - 根用户登录: 已禁用"
    echo "  - auditd: $(systemctl is-active auditd 2>/dev/null || echo '未运行')"
    echo "  - etckeeper: $([ -d /etc/.git ] && echo '已初始化' || echo '未初始化')"
    if [ "$CREATE_DEVOPS_USER" = "true" ]; then
        echo "  - 管理员用户: $SUDO_USERNAME (已创建)"
    fi
    echo "系统优化:"
    echo "  - BBR: $(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}' || echo '未启用')"
    echo "  - IP转发: $(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo '未启用')"
    if [ "$CONFIGURE_NTP" = "true" ]; then
        echo "  - 时区: $(timedatectl | grep "Time zone" | awk '{print $3}')"
        echo "  - NTP同步: 已配置"
    else
        echo "  - 时区: 未修改"
        echo "  - NTP同步: 已跳过"
    fi
    echo "--------------------------------------------------"
    echo "日志文件路径: $LOG_FILE"
    echo "SSH配置备份: $CONFIG_BACKUP_DIR"
    echo "--------------------------------------------------"
    echo "如需远程登录，请使用: ssh -p $actual_ssh_port 用户名@服务器IP"
    
    if [ "$DISABLE_SSH_PASSWD" = "true" ]; then
        echo "注意: 密码登录已禁用，请确保您已保存SSH密钥"
    fi
    if [ -z "$SSH_KEY" ]; then
        echo "注意: 未添加SSH密钥，请确保您有其他方式访问服务器"
    fi
    echo "--------------------------------------------------"
}

# 获取当前实际的SSH端口
get_current_ssh_port() {
    local current_port
    
    # 首先检查是否有监听的SSH端口
    if command -v ss &> /dev/null; then
        current_port=$(sudo ss -tlnp | grep sshd | head -1 | sed 's/.*:\([0-9]\+\) .*/\1/')
    elif command -v netstat &> /dev/null; then
        current_port=$(sudo netstat -tlnp | grep sshd | head -1 | awk '{print $4}' | sed 's/.*:\([0-9]\+\)$/\1/')
    fi
    
    # 如果无法从监听端口获取，则从配置文件读取
    if [ -z "$current_port" ]; then
        current_port=$(grep -E "^\s*Port\s+[0-9]+" "$SSH_CONFIG" | awk '{print $2}' | head -1)
    fi
    
    # 如果仍然为空，则使用默认端口
    if [ -z "$current_port" ]; then
        current_port="22"
    fi
    
    echo "$current_port"
}

# 等待cloud-init完成
wait_for_cloud_init() {
    if command -v cloud-init &> /dev/null; then
        log_message "INFO" "检测到cloud-init，等待其完成初始化..."
        cloud-init status --wait || {
            log_message "WARNING" "cloud-init可能未正常完成，但继续执行"
        }
        log_message "INFO" "cloud-init初始化完成"
    else
        log_message "INFO" "未检测到cloud-init，跳过等待"
    fi
}

# 等待apt锁释放
wait_for_apt() {
    local max_wait=300  # 最多等待5分钟
    local waited=0
    
    while fuser /var/lib/dpkg/lock /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock /var/cache/apt/archives/lock >/dev/null 2>&1; do
        if [ $waited -ge $max_wait ]; then
            log_message "ERROR" "等待apt锁超时（${max_wait}秒），请手动检查"
            return 1
        fi
        log_message "INFO" "等待apt锁释放... ($waited/$max_wait秒)"
        sleep 5
        waited=$((waited + 5))
    done
    
    if [ $waited -gt 0 ]; then
        log_message "INFO" "apt锁已释放，继续执行"
    fi
    return 0
}

# 创建管理员用户
create_devops_user() {
    if [ "$CREATE_DEVOPS_USER" != "true" ]; then
        return 0
    fi
    
    log_message "INFO" "正在创建管理员用户 $SUDO_USERNAME..."
    
    # 检查用户是否已存在
    if id "$SUDO_USERNAME" &>/dev/null; then
        log_message "WARNING" "用户 $SUDO_USERNAME 已存在，跳过创建"
    else
        # 创建用户（不创建密码）
        if [ -f /etc/debian_version ]; then
            # Debian/Ubuntu系统
            sudo adduser --disabled-password --gecos "Administrator" "$SUDO_USERNAME"
            # 添加到sudo组
            sudo usermod -aG sudo "$SUDO_USERNAME"
            log_message "INFO" "用户 $SUDO_USERNAME 已创建并添加到sudo组"
        elif [ -f /etc/redhat-release ]; then
            # RHEL/CentOS系统
            sudo useradd -m -s /bin/bash -c "Administrator" "$SUDO_USERNAME"
            # 添加到wheel组
            sudo usermod -aG wheel "$SUDO_USERNAME"
            log_message "INFO" "用户 $SUDO_USERNAME 已创建并添加到wheel组"
        else
            log_message "ERROR" "不支持的操作系统，无法创建用户"
            return 1
        fi
    fi
    
    # 配置SSH密钥
    local USER_SSH_DIR="/home/$SUDO_USERNAME/.ssh"
    local USER_AUTHORIZED_KEYS="$USER_SSH_DIR/authorized_keys"
    
    # 创建.ssh目录
    sudo mkdir -p "$USER_SSH_DIR"
    sudo chown "$SUDO_USERNAME:$SUDO_USERNAME" "$USER_SSH_DIR"
    sudo chmod 700 "$USER_SSH_DIR"
    
    # 创建authorized_keys文件
    sudo touch "$USER_AUTHORIZED_KEYS"
    sudo chown "$SUDO_USERNAME:$SUDO_USERNAME" "$USER_AUTHORIZED_KEYS"
    sudo chmod 600 "$USER_AUTHORIZED_KEYS"
    
    # 添加SSH公钥
    if sudo grep -qF "$SSH_KEY" "$USER_AUTHORIZED_KEYS"; then
        log_message "INFO" "SSH公钥已存在于用户 $SUDO_USERNAME 的authorized_keys中"
    else
        echo "$SSH_KEY" | sudo tee -a "$USER_AUTHORIZED_KEYS" > /dev/null
        log_message "INFO" "已将SSH公钥添加到用户 $SUDO_USERNAME"
    fi
    
    # 配置sudo免密码（安全且方便）
    echo "$SUDO_USERNAME ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/$SUDO_USERNAME > /dev/null
    sudo chmod 440 /etc/sudoers.d/$SUDO_USERNAME
    log_message "INFO" "已配置用户 $SUDO_USERNAME sudo免密码"
    
    log_message "INFO" "用户 $SUDO_USERNAME 创建完成"
    log_message "INFO" "用户 $SUDO_USERNAME 可以通过'sudo su -'切换到root用户"
}

# 检查并启用 SSH 公钥认证

# 执行主函数
main "$@"
