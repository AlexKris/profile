#!/bin/bash

# 启用严格模式，任何未捕获的错误都会导致脚本退出
set -euo pipefail

# 脚本版本
readonly SCRIPT_VERSION="1.0.0"

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
SSH_PORT="$DEFAULT_SSH_PORT"
SSH_KEY=""
# 添加时间戳到日志文件名
LOG_FILE="$SCRIPT_DIR/setup-script-$TIMESTAMP.log"
TMP_FILES=""
OS_TYPE=""
OS_VERSION=""
# 新增：服务器地区参数
SERVER_REGION="asia"

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
        *)
            echo -e "[日志] $message"
            ;;
    esac
    
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
    echo "  -h, --help                显示此帮助信息"
    echo "  -d, --disable-password    禁用SSH密码登录，仅允许SSH密钥认证"
    echo "  -p, --port PORT           设置SSH端口号 (例如: --port 2222)"
    echo "  -k, --key KEY             设置SSH公钥 (直接输入公钥文本或从文件读取，例如: --key \"ssh-rsa AAAA...\")"
    echo "  -f, --key-file FILE       从文件读取SSH公钥 (例如: --key-file ~/.ssh/id_rsa.pub)"
    echo "  -u, --update              更新此脚本"
    echo "  -l, --log-file FILE       指定日志文件路径 (默认: $LOG_FILE)"
    echo "  -r, --region REGION       指定服务器所在地区，用于选择NTP服务器 (hk|tw|jp|sg|us|eu|asia，默认: asia)"
    echo "  -v, --version             显示脚本版本"
    echo ""
    echo "示例:"
    echo "  $0 -d -p 2222 -f ~/.ssh/id_rsa.pub   # 禁用密码登录，使用端口2222，添加指定的SSH密钥"
    echo "  $0 -k \"ssh-rsa AAAA...\"            # 仅添加指定的SSH公钥"
    echo "  $0 -r us                             # 指定服务器位于美国，使用美国NTP服务器"
    echo ""
    echo "脚本版本: $SCRIPT_VERSION"
}

# 解析参数
parse_args() {
    while [[ "$#" -gt 0 ]]; do
        case $1 in
            -h|--help) usage; exit 0 ;;
            -d|--disable-password) DISABLE_SSH_PASSWD="true" ;;
            -p|--port) 
                if [ -z "$2" ] || [[ "$2" == -* ]]; then
                    log_message "ERROR" "选项 $1 需要一个有效的端口号参数"
                    exit 1
                fi
                if ! [[ "$2" =~ ^[0-9]+$ ]] || [ "$2" -lt "$MIN_PORT" ] || [ "$2" -gt "$MAX_PORT" ]; then
                    log_message "ERROR" "无效的端口号: $2. 端口号应在 $MIN_PORT-$MAX_PORT 范围内"
                    exit 1
                fi
                SSH_PORT="$2"; 
                shift ;;
            -k|--key) 
                if [ -z "$2" ] || [[ "$2" == -* ]]; then
                    log_message "ERROR" "选项 $1 需要一个有效的SSH公钥参数"
                    exit 1
                fi
                SSH_KEY="$2"; shift ;;
            -f|--key-file) 
                if [ -z "$2" ] || [[ "$2" == -* ]]; then
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
            -r|--region)
                if [ -z "$2" ] || [[ "$2" == -* ]]; then
                    log_message "ERROR" "选项 $1 需要一个有效的地区参数"
                    exit 1
                fi
                # 验证地区参数
                case "$2" in
                    hk|tw|jp|sg|us|eu|asia)
                        SERVER_REGION="$2"
                        ;;
                    *)
                        log_message "ERROR" "无效的地区参数: $2. 可用选项: hk, tw, jp, sg, us, eu, asia"
                        exit 1
                        ;;
                esac
                shift ;;
            -u|--update) update_shell; exit 0 ;;
            -l|--log-file) 
                if [ -z "$2" ] || [[ "$2" == -* ]]; then
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
            -v|--version) echo "脚本版本: $SCRIPT_VERSION"; exit 0 ;;
            *) echo "未知选项: $1"; usage; exit 0 ;;
        esac
        shift
    done
    
    # 确保备份目录存在
    if [ ! -d "$CONFIG_BACKUP_DIR" ]; then
        sudo mkdir -p "$CONFIG_BACKUP_DIR" || log_message "WARNING" "无法创建备份目录 $CONFIG_BACKUP_DIR"
    fi
    
    log_message "INFO" "脚本开始执行，参数: SSH端口=$SSH_PORT, 禁用密码=$DISABLE_SSH_PASSWD, 地区=$SERVER_REGION, 日志文件=$LOG_FILE"
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
            apt update -y && apt install -y sudo
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
        sudo apt update && sudo apt upgrade -y && sudo apt full-upgrade -y && sudo apt autoclean -y && sudo apt autoremove -y

        log_message "INFO" "正在安装 wget curl vim unzip zip fail2ban rsyslog iptables iperf3 mtr..."
        sudo apt install -y wget curl vim unzip zip fail2ban rsyslog iptables iperf3 mtr
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

    # 添加 SSH 公钥
    if [ -n "$SSH_KEY" ]; then
        # 验证公钥格式
        if ! echo "$SSH_KEY" | grep -qE "^(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521) "; then
            log_message "WARNING" "提供的 SSH 公钥格式可能不正确。标准格式应该以 'ssh-rsa', 'ssh-ed25519' 等开头。"
            read -p "是否仍然继续添加此密钥？(y/n): " confirm
            if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
                log_message "INFO" "已取消添加 SSH 公钥"
                return
            fi
        fi
        
        # 如果提供了命令行参数的SSH密钥
        if grep -qF "$SSH_KEY" "$AUTHORIZED_KEYS"; then
            log_message "INFO" "命令行提供的公钥已存在于 $AUTHORIZED_KEYS"
        else
            echo "$SSH_KEY" >> "$AUTHORIZED_KEYS"
            log_message "INFO" "已将命令行提供的公钥添加到 $AUTHORIZED_KEYS"
        fi
    else
        # 如果没有通过命令行提供SSH密钥，则交互式输入
        read -p "请输入您的 SSH 公钥（直接回车跳过）： " INPUT_SSH_KEY
        if [ -n "$INPUT_SSH_KEY" ]; then
            # 验证公钥格式
            if ! echo "$INPUT_SSH_KEY" | grep -qE "^(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521) "; then
                log_message "WARNING" "提供的 SSH 公钥格式可能不正确。标准格式应该以 'ssh-rsa', 'ssh-ed25519' 等开头。"
                read -p "是否仍然继续添加此密钥？(y/n): " confirm
                if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
                    log_message "INFO" "已取消添加 SSH 公钥"
                    return
                fi
            fi
            
            if grep -qF "$INPUT_SSH_KEY" "$AUTHORIZED_KEYS"; then
                log_message "INFO" "公钥已存在于 $AUTHORIZED_KEYS"
            else
                echo "$INPUT_SSH_KEY" >> "$AUTHORIZED_KEYS"
                log_message "INFO" "已将公钥添加到 $AUTHORIZED_KEYS"
            fi
        else
            log_message "INFO" "未输入任何公钥，跳过此步骤"
        fi
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
        sudo apt install -y fail2ban rsyslog
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

# 检查并设置时区为香港
configure_timezone(){
    CURRENT_TIMEZONE=$(timedatectl | grep "Time zone" | awk '{print $3}')
    TARGET_TIMEZONE="Asia/Hong_Kong"

    if [ "$CURRENT_TIMEZONE" != "$TARGET_TIMEZONE" ]; then
        log_message "INFO" "当前时区为 $CURRENT_TIMEZONE，正在设置为 $TARGET_TIMEZONE..."
        sudo timedatectl set-timezone "$TARGET_TIMEZONE"
        log_message "INFO" "时区已设置为 $TARGET_TIMEZONE"
    else
        log_message "INFO" "时区已是 $TARGET_TIMEZONE，无需更改"
    fi

    # 根据服务器地区选择NTP服务器
    log_message "INFO" "配置时间同步服务，使用$SERVER_REGION地区的NTP服务器..."
    
    # 根据地区选择NTP服务器
    local NTP_SERVER
    case "$SERVER_REGION" in
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
    
    log_message "INFO" "选择NTP服务器: $NTP_SERVER"
    
    if [ -f /etc/debian_version ]; then
        # Debian/Ubuntu 系统
        log_message "INFO" "检测到 Debian/Ubuntu 系统，使用 systemd-timesyncd 或 chrony 配置时间同步"
        
        # 检查是否有 chrony
        if command -v chronyd &> /dev/null; then
            log_message "INFO" "使用 chrony 进行时间同步"
            sudo apt install -y chrony
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
            sudo apt install -y systemd-timesyncd
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
        sudo yum install -y chrony
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

    # 检查时间同步状态
    if systemctl is-active systemd-timesyncd &> /dev/null || systemctl is-active chrony &> /dev/null || systemctl is-active chronyd &> /dev/null; then
        log_message "INFO" "时间同步服务已成功启用"
    else
        log_message "WARNING" "时间同步服务可能未正确启用，请手动检查"
    fi
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
            log_message "INFO" "检查并修改模块化配置目录中的文件..."
            
            # 检查是否存在50-cloud-init.conf文件
            if [ -f "$SSH_CONFIG_DIR/50-cloud-init.conf" ]; then
                log_message "INFO" "检测到cloud-init配置文件，正在修改..."
                # 备份cloud-init配置
                sudo cp "$SSH_CONFIG_DIR/50-cloud-init.conf" "$SSH_CONFIG_DIR/50-cloud-init.conf.bak"
                # 注释掉所有启用密码的配置
                sudo sed -i 's/^\s*PasswordAuthentication\s\+yes/# &/' "$SSH_CONFIG_DIR/50-cloud-init.conf"
                sudo sed -i 's/^\s*ChallengeResponseAuthentication\s\+yes/# &/' "$SSH_CONFIG_DIR/50-cloud-init.conf"
                sudo sed -i 's/^\s*KbdInteractiveAuthentication\s\+yes/# &/' "$SSH_CONFIG_DIR/50-cloud-init.conf"
                log_message "INFO" "已修改cloud-init配置文件，禁用密码登录"
            fi
            
            # 如果存在之前创建的高优先级配置文件，则删除它们
            for file in "$SSH_CONFIG_DIR/99-"* "$SSH_CONFIG_DIR/98-"* "$SSH_CONFIG_DIR/97-"*; do
                if [ -f "$file" ]; then
                    log_message "INFO" "删除旧的优先级配置: $file"
                    sudo rm -f "$file"
                fi
            done
            
            # 创建统一的SSH安全配置文件（无数字前缀）
            log_message "INFO" "创建SSH安全配置文件..."
            sudo tee "$SSH_CONFIG_DIR/ssh-security.conf" > /dev/null << EOF
# SSH安全加固配置 - 由setup.sh创建
# 此配置会覆盖cloud-init的设置

# 禁用密码登录
PasswordAuthentication no

# 禁用其他不安全的认证方式
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no

# 启用公钥认证
PubkeyAuthentication yes
EOF
            log_message "INFO" "已创建SSH安全配置文件: $SSH_CONFIG_DIR/ssh-security.conf"
            
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
    # 检查是否需要修改SSH端口
    if [ "$SSH_PORT" != "22" ]; then
        log_message "INFO" "正在将 SSH 端口修改为 $SSH_PORT..."
        
        # 验证端口号是否有效
        if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [ "$SSH_PORT" -lt 1024 ] || [ "$SSH_PORT" -gt 65535 ]; then
            log_message "ERROR" "无效的端口号: $SSH_PORT. 端口号应在 1024-65535 范围内"
            log_message "INFO" "使用默认端口 22"
            SSH_PORT="22"
            return
        fi
        
        # 检查当前端口设置
        CURRENT_PORT=$(grep -E "^\s*Port\s+[0-9]+" "$SSH_CONFIG" | awk '{print $2}')
        
        if [ "$CURRENT_PORT" = "$SSH_PORT" ]; then
            log_message "INFO" "SSH 端口已经是 $SSH_PORT，无需修改"
        else
            # 如果存在 'Port' 行，将其替换
            if grep -E "^\s*Port\s+[0-9]+" "$SSH_CONFIG" > /dev/null; then
                sudo sed -i "s/^\s*Port\s\+[0-9]\+/Port $SSH_PORT/" "$SSH_CONFIG"
            elif grep -E "^\s*#\s*Port" "$SSH_CONFIG" > /dev/null; then
                # 如果存在被注释的 'Port' 行，去掉注释并设置为新端口
                sudo sed -i "s/^\s*#\s*Port.*/Port $SSH_PORT/" "$SSH_CONFIG"
            else
                # 如果配置文件中没有 'Port' 这一行，添加到文件末尾
                echo "Port $SSH_PORT" | sudo tee -a "$SSH_CONFIG"
            fi
            
            # 处理模块化配置中的端口设置
            if [ -d "$SSH_CONFIG_DIR" ]; then
                log_message "INFO" "检查模块化配置中的端口设置..."
                
                # 将端口设置添加到统一的安全配置文件中
                if [ -f "$SSH_CONFIG_DIR/ssh-security.conf" ]; then
                    # 如果文件已存在，检查并添加端口配置
                    if ! grep -q "^Port $SSH_PORT" "$SSH_CONFIG_DIR/ssh-security.conf"; then
                        log_message "INFO" "向SSH安全配置文件添加端口设置..."
                        sudo sed -i "1s/^/# SSH端口配置\nPort $SSH_PORT\n\n/" "$SSH_CONFIG_DIR/ssh-security.conf"
                    fi
                else
                    # 如果文件不存在，创建新文件
                    log_message "INFO" "创建SSH安全配置文件，包含端口设置..."
                    sudo tee "$SSH_CONFIG_DIR/ssh-security.conf" > /dev/null << EOF
# SSH安全配置 - 由setup.sh创建

# SSH端口配置
Port $SSH_PORT

# 启用公钥认证
PubkeyAuthentication yes
EOF
                fi
                
                # 如果存在cloud-init配置，也需要处理
                if [ -f "$SSH_CONFIG_DIR/50-cloud-init.conf" ]; then
                    log_message "INFO" "检查cloud-init配置中的端口设置..."
                    if grep -q "^Port" "$SSH_CONFIG_DIR/50-cloud-init.conf"; then
                        # 如果cloud-init配置中有端口设置，注释掉它
                        sudo sed -i 's/^\s*Port\s\+[0-9]\+/# &/' "$SSH_CONFIG_DIR/50-cloud-init.conf"
                        log_message "INFO" "已注释cloud-init配置中的端口设置"
                    fi
                fi
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
            
            log_message "INFO" "SSH 端口已修改为 $SSH_PORT"
        fi
    else
        log_message "INFO" "未设置修改 SSH 端口，保持默认端口 22"
    fi
}

# 添加系统安全加固函数
harden_system() {
    log_message "INFO" "正在执行系统安全加固..."
    
    # 1. 限制 root 登录
    # 删除局部变量赋值，使用全局的SSH_CONFIG变量
    # SSH_CONFIG="/etc/ssh/sshd_config"
    if grep -E "^\s*PermitRootLogin\s+yes" "$SSH_CONFIG" > /dev/null; then
        log_message "INFO" "禁用 root 直接登录..."
        sudo sed -i 's/^\s*PermitRootLogin\s\+yes/PermitRootLogin no/' "$SSH_CONFIG"
    elif ! grep -q "PermitRootLogin" "$SSH_CONFIG"; then
        echo "PermitRootLogin no" | sudo tee -a "$SSH_CONFIG"
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
        echo "ClientAliveCountMax 2" | sudo tee -a "$SSH_CONFIG"
    fi
    
    # 限制SSH版本
    if ! grep -q "Protocol" "$SSH_CONFIG"; then
        echo "Protocol 2" | sudo tee -a "$SSH_CONFIG"
    fi
    
    # 禁用主机名查找（提高性能）
    if ! grep -q "UseDNS" "$SSH_CONFIG"; then
        echo "UseDNS no" | sudo tee -a "$SSH_CONFIG"
    fi
    
    # 3. 设置更安全的系统限制
    if [ -f /etc/security/limits.conf ]; then
        log_message "INFO" "配置系统资源限制..."
        
        # 备份原始文件
        sudo cp /etc/security/limits.conf /etc/security/limits.conf.bak
        
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
    fi
    
    # 4. 配置系统日志审计
    log_message "INFO" "配置系统日志审计..."
    
    # 安装auditd（如果可用）
    if [ -f /etc/debian_version ]; then
        sudo apt install -y auditd
    elif [ -f /etc/redhat-release ]; then
        if command -v dnf &> /dev/null; then
            sudo dnf install -y audit
        else
            sudo yum install -y audit
        fi
    fi
    
    # 如果auditd已安装，配置基本审计规则
    if command -v auditd &> /dev/null; then
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
        log_message "INFO" "审计服务已配置并启用"
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
                if grep -qE "^\s*(PasswordAuthentication|PubkeyAuthentication|Port|ChallengeResponseAuthentication|KbdInteractiveAuthentication|PermitEmptyPasswords)" "$conf_file"; then
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
                    
                    # 处理端口设置
                    if [ "$SSH_PORT" != "22" ] && grep -qE "^\s*Port\s+[0-9]+" "$conf_file"; then
                        log_message "INFO" "正在更新 $conf_file 中的端口设置..."
                        sudo sed -i "s/^\s*Port\s\+[0-9]\+/Port $SSH_PORT/" "$conf_file"
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

# 主函数
main() {
    parse_args "$@"
    
    # 检查sudo是否已安装
    if ! command -v sudo &> /dev/null; then
        echo "[信息] sudo未安装，正在安装..."
        if [ -f /etc/debian_version ]; then
            apt update -y && apt install -y sudo
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
    
    # 禁用SSH密码登录
    if [ "$DISABLE_SSH_PASSWD" = "true" ]; then
        disable_ssh_password_login || {
            log_message "ERROR" "禁用SSH密码登录失败"
            log_message "WARNING" "可能无法通过SSH密钥登录，为安全起见不继续修改端口"
            read -p "是否仍然继续修改SSH端口? (y/n): " continue_port
            if [[ "$continue_port" != "y" && "$continue_port" != "Y" ]]; then
                SSH_PORT="$DEFAULT_SSH_PORT"
                log_message "INFO" "用户选择不修改SSH端口，使用默认端口 $DEFAULT_SSH_PORT"
            fi
        }
    fi
    
    # 修改SSH端口
    if [ "$SSH_PORT" != "$DEFAULT_SSH_PORT" ]; then
        change_ssh_port || log_message "WARNING" "修改SSH端口失败，但继续执行"
    fi
    
    # 检查并处理sshd_config.d目录中的配置
    check_sshd_config_d || log_message "WARNING" "处理SSH模块化配置失败，但继续执行"
    
    # 配置SELinux以支持自定义SSH端口
    configure_selinux_for_ssh || log_message "WARNING" "配置SELinux失败，但继续执行"
    
    # 重启SSH服务
    restart_ssh_service || {
        log_message "ERROR" "重启SSH服务失败，配置更改可能未生效"
        log_message "WARNING" "请手动重启SSH服务以应用更改: sudo systemctl restart ssh 或 sudo systemctl restart sshd"
    }
    
    # 配置额外服务
    configure_fail2ban || log_message "WARNING" "配置fail2ban失败，但继续执行"
    configure_timezone || log_message "WARNING" "配置时区失败，但继续执行"
    configure_bbr || log_message "WARNING" "配置BBR失败，但继续执行"
    configure_ip_forward || log_message "WARNING" "配置IP转发失败，但继续执行"
    
    # 系统安全加固
    harden_system || log_message "WARNING" "系统安全加固失败，但继续执行"
    
    # 验证配置有效性
    verify_configuration || log_message "WARNING" "配置验证失败，请手动检查配置"
    
    log_message "INFO" "========== 系统配置完成 =========="
    log_message "INFO" "SSH 端口: $SSH_PORT"
    if [ "$DISABLE_SSH_PASSWD" = "true" ]; then
        log_message "INFO" "SSH 密码登录: 已禁用"
    else
        log_message "INFO" "SSH 密码登录: 已启用"
    fi
    log_message "INFO" "fail2ban 状态: $(systemctl is-active fail2ban 2>/dev/null || echo '未运行')"
    log_message "INFO" "当前时区: $(timedatectl | grep "Time zone" | awk '{print $3}')"
    log_message "INFO" "BBR 状态: $(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}' || echo '未启用')"
    log_message "INFO" "IP 转发: $(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo '未启用')"
    log_message "INFO" "请记住保存您的 SSH 密钥以便远程登录"
    
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
    log_message "INFO" "配置总结:"
    echo "--------------------------------------------------"
    echo "系统类型: $OS_TYPE $OS_VERSION"
    echo "SSH 配置:"
    echo "  - 端口: $SSH_PORT"
    echo "  - 密码登录: $([ "$DISABLE_SSH_PASSWD" = "true" ] && echo "已禁用" || echo "已启用")"
    echo "  - 公钥认证: 已启用"
    
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
    
    echo "安全加固:"
    echo "  - fail2ban: $(systemctl is-active fail2ban 2>/dev/null || echo '未运行')"
    echo "  - SELinux: $(command -v getenforce &> /dev/null && getenforce || echo '未启用')"
    echo "  - 根用户登录: 已禁用"
    echo "系统优化:"
    echo "  - BBR: $(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}' || echo '未启用')"
    echo "  - IP转发: $(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo '未启用')"
    echo "  - 时区: $(timedatectl | grep "Time zone" | awk '{print $3}')"
    echo "--------------------------------------------------"
    echo "日志文件路径: $LOG_FILE"
    echo "SSH配置备份: $CONFIG_BACKUP_DIR"
    echo "--------------------------------------------------"
    echo "如需远程登录，请使用: ssh -p $SSH_PORT 用户名@服务器IP"
    
    if [ "$DISABLE_SSH_PASSWD" = "true" ]; then
        echo "注意: 密码登录已禁用，请确保您已保存SSH密钥"
    fi
    echo "--------------------------------------------------"
}

# 执行主函数
main "$@"
