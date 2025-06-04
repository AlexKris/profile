#!/bin/bash

# 启用严格模式，任何未捕获的错误都会导致脚本退出
set -euo pipefail

# 脚本版本
readonly SCRIPT_VERSION="2.0.0"

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
# 固定日志文件路径
readonly LOG_FILE="$SCRIPT_DIR/setup-script-$TIMESTAMP.log"
# Cloudflare IP更新脚本路径
readonly CF_UPDATE_SCRIPT="/usr/local/bin/update-cloudflare-ips.sh"
readonly CF_CRON_JOB="/etc/cron.d/cloudflare-ip-update"

# 脚本参数变量
DISABLE_SSH_PASSWD="false"
SSH_PORT=""
SSH_KEY=""
TMP_FILES=""
OS_TYPE=""
OS_VERSION=""
# 服务器地区参数，默认为auto自动检测
SERVER_REGION="auto"
# 创建管理员用户参数
CREATE_DEVOPS_USER="false"
SUDO_USERNAME=""
# NTP服务选择（auto|timesyncd|chrony）
NTP_SERVICE="auto"
# 防火墙相关参数
ENABLE_SSH_WHITELIST="false"
SSH_WHITELIST_IPS=""
DISABLE_ICMP="false"
# 新增：网站防护参数（合并原来的block_web_ports和allow_cloudflare）
PROTECT_WEB_PORTS="false"
# 新增：安全审计参数（合并原来的三个审计相关参数）
ENABLE_SECURITY_AUDIT="true"  # 默认启用安全审计
# Docker相关
INSTALL_DOCKER="false"

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

# 验证IP地址格式
validate_ip() {
    local ip="$1"
    local valid_ip_regex="^([0-9]{1,3}\.){3}[0-9]{1,3}$"
    local valid_cidr_regex="^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$"
    
    if [[ "$ip" =~ $valid_ip_regex ]]; then
        # 检查每个数字段是否在0-255范围内
        IFS='.' read -ra ADDR <<< "$ip"
        for i in "${ADDR[@]}"; do
            if [ "$i" -gt 255 ]; then
                return 1
            fi
        done
        return 0
    elif [[ "$ip" =~ $valid_cidr_regex ]]; then
        # 检查CIDR格式
        local network="${ip%/*}"
        local prefix="${ip#*/}"
        if validate_ip "$network" && [ "$prefix" -ge 0 ] && [ "$prefix" -le 32 ]; then
            return 0
        fi
    fi
    return 1
}

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

# 简化的日志记录函数
log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # 过滤敏感信息
    if [[ "$message" =~ (ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp[0-9]+)[[:space:]]+[A-Za-z0-9+/]+=* ]]; then
        message="[SSH密钥已过滤]"
    fi
    
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
    
    # 确保日志目录存在
    local log_dir=$(dirname "$LOG_FILE")
    if [ ! -d "$log_dir" ]; then
        mkdir -p "$log_dir" 2>/dev/null
        # 设置严格的日志目录权限
        chmod 700 "$log_dir" 2>/dev/null || true
    fi
    
    # 写入到日志文件
    echo "[$timestamp][$level] $message" >> "$LOG_FILE" 2>/dev/null || true
    
    # 设置日志文件权限（仅root可读写）
    chmod 600 "$LOG_FILE" 2>/dev/null || true
    
    # 对于错误级别的消息，同时写入系统日志
    [ "$level" = "ERROR" ] && logger -t "setup-script" "ERROR: $message" 2>/dev/null || true
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
    echo "  --ssh_key KEY             设置SSH公钥 (直接输入公钥文本)"
    echo "  --region REGION           指定服务器所在地区，用于选择NTP服务器"
    echo "                            (auto|cn|hk|tw|jp|sg|us|eu|asia，默认: auto)"
    echo "  --ntp_service SERVICE     指定NTP服务（auto|timesyncd|chrony，默认: auto）"
    echo "  --version                 显示脚本版本"
    echo "  --create_user USERNAME    创建管理员用户（必须提供SSH密钥）"
    echo "  --ssh_whitelist IPS       启用SSH白名单，只允许指定IP访问（逗号分隔）"
    echo "  --disable_icmp            禁用ICMP（禁止ping）"
    echo "  --protect_web             保护Web端口(80/443)，仅允许Cloudflare和内网访问"
    echo "  --disable_audit           禁用安全审计（默认启用auditd和etckeeper）"
    echo "  --install_docker          安装Docker并自动配置防火墙规则"
    echo ""
    echo "地区说明:"
    echo "  auto - 自动检测地区（推荐）"
    echo "  cn   - 中国大陆"
    echo "  hk   - 香港"
    echo "  tw   - 台湾"
    echo "  jp   - 日本"
    echo "  sg   - 新加坡"
    echo "  us   - 美国"
    echo "  eu   - 欧洲"
    echo "  asia - 亚洲通用"
    echo ""
    echo "示例:"
    echo "  $0 --disable_ssh_pwd --port 2222 --ssh_key \"ssh-rsa AAAA...\""
    echo "  $0 --create_user devops --ssh_key \"ssh-rsa AAAA...\" --disable_ssh_pwd"
    echo "  $0 --ssh_whitelist \"1.2.3.4,5.6.7.8/24\" --disable_icmp --protect_web"
    echo "  $0 --install_docker --protect_web --region cn"
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
            --region)
                if [ -z "$2" ] || [[ "$2" == --* ]]; then
                    log_message "ERROR" "选项 $1 需要一个有效的地区参数"
                    exit 1
                fi
                case "$2" in
                    auto|cn|hk|tw|jp|sg|us|eu|asia)
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
            --protect_web)
                PROTECT_WEB_PORTS="true" ;;
            --disable_audit)
                ENABLE_SECURITY_AUDIT="false" ;;
            --install_docker)
                INSTALL_DOCKER="true" ;;
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

# 等待apt锁释放（优化后的版本）
wait_for_apt() {
    [ "$OS_TYPE" != "debian" ] && return 0
    
    local max_wait=300
    local waited=0
    
    while fuser /var/lib/dpkg/lock* /var/lib/apt/lists/lock* /var/cache/apt/archives/lock* >/dev/null 2>&1; do
        [ $waited -ge $max_wait ] && { log_message "ERROR" "等待apt锁超时"; return 1; }
        log_message "INFO" "等待apt锁释放... ($waited/$max_wait秒)"
        sleep 5
        ((waited+=5))
    done
    
    [ $waited -gt 0 ] && log_message "INFO" "apt锁已释放"
    return 0
}

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
            wait_for_apt && apt-get update -y && apt-get install -y sudo
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

# 更新系统并安装基础软件（优化后）
update_system_install_dependencies() {
    log_message "INFO" "更新系统并安装必要软件..."
    
    if [ "$OS_TYPE" = "debian" ]; then
        wait_for_apt || return 1
        export DEBIAN_FRONTEND=noninteractive
        sudo apt-get update
        sudo apt-get upgrade -y
        sudo apt-get install -y wget curl vim unzip zip fail2ban rsyslog iptables mtr netcat-openbsd

        # 单独处理iperf3
        echo 'iperf3 iperf3/autostart boolean false' | sudo debconf-set-selections
        sudo apt-get install -y -o Dpkg::Options::="--force-confdef" iperf3
    else
        local pkg_manager="yum"
        command -v dnf &> /dev/null && pkg_manager="dnf"
        sudo $pkg_manager update -y
        sudo $pkg_manager install -y wget curl vim unzip zip fail2ban rsyslog iptables iperf3 mtr nc
    fi
    
    log_message "INFO" "系统更新和软件安装完成"
}

# 配置SSH密钥
configure_ssh_keys() {
    [ -z "$SSH_KEY" ] && return 0
    
    # 验证SSH公钥格式
    if ! echo "$SSH_KEY" | grep -qE '^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp[0-9]+) [A-Za-z0-9+/]+=* .*$'; then
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
        log_message "INFO" "SSH公钥已添加"
    else
        log_message "INFO" "SSH公钥已存在"
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

# 配置SSH（优化后的版本）
configure_ssh() {
    log_message "INFO" "配置SSH..."
    
    # 备份配置
    backup_ssh_config
    
    # 检查是否有可用的sudo用户
    local has_sudo_user="false"
    local current_user=$(whoami)
    
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
        # 检查系统中是否有其他sudo用户
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
    
    # 如果没有sudo用户且当前是root，检查是否有SSH密钥配置
    local has_root_ssh_key="false"
    if [ "$current_user" = "root" ] && [ -f "/root/.ssh/authorized_keys" ] && [ -s "/root/.ssh/authorized_keys" ]; then
        has_root_ssh_key="true"
        log_message "INFO" "root用户已配置SSH密钥"
    fi
    
    # 决定是否可以禁用root登录
    local can_disable_root="false"
    if [ "$has_sudo_user" = "true" ] || ([ "$has_root_ssh_key" = "true" ] && [ "$DISABLE_SSH_PASSWD" = "true" ]); then
        can_disable_root="true"
    fi
    
    # 启用公钥认证
    sudo sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' "$SSH_CONFIG"
    grep -q "^PubkeyAuthentication" "$SSH_CONFIG" || echo "PubkeyAuthentication yes" | sudo tee -a "$SSH_CONFIG"
    
    # 处理root登录设置
    if [ "$can_disable_root" = "true" ]; then
        log_message "INFO" "检测到其他管理员账户，可以安全禁用root登录"
        sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' "$SSH_CONFIG"
        grep -q "^PermitRootLogin" "$SSH_CONFIG" || echo "PermitRootLogin no" | sudo tee -a "$SSH_CONFIG"
    else
        log_message "WARNING" "未检测到其他管理员账户，保持root登录权限"
        if [ "$DISABLE_SSH_PASSWD" = "true" ] && [ "$has_root_ssh_key" = "true" ]; then
            # 如果禁用了密码登录且root有SSH密钥，允许root使用密钥登录
            sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' "$SSH_CONFIG"
            grep -q "^PermitRootLogin" "$SSH_CONFIG" || echo "PermitRootLogin prohibit-password" | sudo tee -a "$SSH_CONFIG"
            log_message "INFO" "设置root仅允许密钥登录"
        else
            # 保持root登录开启
            sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' "$SSH_CONFIG"
            grep -q "^PermitRootLogin" "$SSH_CONFIG" || echo "PermitRootLogin yes" | sudo tee -a "$SSH_CONFIG"
            log_message "WARNING" "保持root密码登录开启，建议创建sudo用户后再禁用"
        fi
    fi
    
    # 其他安全配置
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
    
    # 禁用密码登录前的安全检查
    if [ "$DISABLE_SSH_PASSWD" = "true" ]; then
        local can_disable_password="false"
        
        # 检查是否有SSH密钥配置
        if [ "$has_sudo_user" = "true" ] || [ "$has_root_ssh_key" = "true" ] || [ -n "$SSH_KEY" ]; then
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
    
    # 修改SSH端口
    if [ -n "$SSH_PORT" ]; then
        log_message "INFO" "修改SSH端口为 $SSH_PORT..."
        sudo sed -i "s/^#*Port.*/Port $SSH_PORT/" "$SSH_CONFIG"
        grep -q "^Port" "$SSH_CONFIG" || echo "Port $SSH_PORT" | sudo tee -a "$SSH_CONFIG"
        
        # 配置防火墙
        if command -v ufw &> /dev/null && sudo ufw status | grep -q "active"; then
            sudo ufw allow "$SSH_PORT/tcp" comment 'SSH Port'
        fi
    fi
    
    # 处理sshd_config.d目录 - 只在主配置中没有设置时才创建
    if [ -d "$SSH_CONFIG_DIR" ]; then
        # 先检查主配置文件中是否已经有这些设置
        local need_config_d="false"
        
        # 如果端口在主配置中没有设置，才在config.d中设置
        if [ -n "$SSH_PORT" ] && ! grep -q "^Port $SSH_PORT" "$SSH_CONFIG"; then
            need_config_d="true"
        fi
        
        # 如果有需要在config.d中设置的内容
        if [ "$need_config_d" = "true" ] || [ ! -f "$SSH_CONFIG_DIR/99-security.conf" ]; then
            # 创建精简的配置文件，只包含必要的覆盖项
            sudo tee "$SSH_CONFIG_DIR/99-security.conf" > /dev/null << EOF
# Security configuration by setup.sh - Only overrides
EOF
            
            # 只添加主配置中没有的设置
            if [ -n "$SSH_PORT" ] && ! grep -q "^Port" "$SSH_CONFIG"; then
                echo "Port $SSH_PORT" | sudo tee -a "$SSH_CONFIG_DIR/99-security.conf"
            fi
        else
            # 如果不需要config.d配置，删除可能存在的旧文件
            [ -f "$SSH_CONFIG_DIR/99-security.conf" ] && sudo rm -f "$SSH_CONFIG_DIR/99-security.conf"
        fi
    fi
    
    # 测试SSH配置
    if ! sudo sshd -t; then
        log_message "ERROR" "SSH配置测试失败，正在还原配置..."
        sudo cp "$CONFIG_BACKUP_DIR/sshd_config.$TIMESTAMP.bak" "$SSH_CONFIG"
        log_message "ERROR" "SSH配置已还原，请检查配置后重试"
        return 1
    fi
    
    # 重启SSH服务
    sudo systemctl restart ssh || sudo systemctl restart sshd
    
    log_message "INFO" "SSH配置完成"
}

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
    
    # 自动检测地区
    local region="$SERVER_REGION"
    [ "$region" = "auto" ] && region=$(detect_server_region)
    
    # 选择NTP服务器
    local ntp_server
    case "$region" in
        cn) ntp_server="cn.pool.ntp.org" ;;
        hk) ntp_server="hk.pool.ntp.org" ;;
        tw) ntp_server="tw.pool.ntp.org" ;;
        jp) ntp_server="jp.pool.ntp.org" ;;
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
            wait_for_apt && sudo apt-get install -y chrony
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

# 自动检测服务器地区
detect_server_region() {
    log_message "INFO" "自动检测服务器地区..."
    
    # 通过IP地理位置检测
    if command -v curl &> /dev/null; then
        local country=$(curl -s --connect-timeout 5 "https://ipapi.co/country_code" 2>/dev/null || echo "")
        case "$country" in
            CN) echo "cn"; return ;;
            HK) echo "hk"; return ;;
            TW) echo "tw"; return ;;
            JP) echo "jp"; return ;;
            SG) echo "sg"; return ;;
            US) echo "us"; return ;;
            GB|DE|FR|IT|ES|NL) echo "eu"; return ;;
        esac
    fi
    
    echo "asia"
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
    
    # 安装auditd
    if [ "$OS_TYPE" = "debian" ]; then
        wait_for_apt && sudo apt-get install -y auditd
    else
        sudo yum install -y audit || sudo dnf install -y audit
    fi
    
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
    
    sudo systemctl restart auditd
    sudo systemctl enable auditd
    
    # 安装etckeeper
    if [ "$OS_TYPE" = "debian" ]; then
        wait_for_apt && sudo apt-get install -y etckeeper git
    else
        sudo yum install -y etckeeper git || sudo dnf install -y etckeeper git
    fi
    
    # 初始化etckeeper
    if [ ! -d /etc/.git ]; then
        sudo etckeeper init
        sudo etckeeper commit "Initial commit - system setup"
    fi
    
    log_message "INFO" "安全审计配置完成"
}

# 创建Cloudflare IP更新脚本
create_cloudflare_update_script() {
    log_message "INFO" "创建Cloudflare IP更新脚本..."
    
    sudo tee "$CF_UPDATE_SCRIPT" > /dev/null << 'EOF'
#!/bin/bash

# Cloudflare IP更新脚本
LOG_FILE="/var/log/cloudflare-ip-update.log"
COMMENT_MARK="cloudflare-auto"  # 用于标记Cloudflare规则

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# 获取当前的Cloudflare IP
get_cloudflare_ips() {
    local ipv4_list=$(curl -s --connect-timeout 10 https://www.cloudflare.com/ips-v4)
    local ipv6_list=$(curl -s --connect-timeout 10 https://www.cloudflare.com/ips-v6)
    
    # 验证获取的内容是否为有效IP
    if [[ ! "$ipv4_list" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3} ]]; then
        log_message "错误: 获取的IPv4列表无效"
        return 1
    fi
    
    echo "$ipv4_list"
    echo "$ipv6_list"
}

# 清理旧的Cloudflare规则（使用注释标记）
clean_old_rules() {
    log_message "清理旧的Cloudflare规则..."
    
    # 清理INPUT链中带有cloudflare-auto标记的规则
    while true; do
        local rule_num=$(iptables -L INPUT -n --line-numbers | grep "$COMMENT_MARK" | head -1 | awk '{print $1}')
        [ -z "$rule_num" ] && break
        iptables -D INPUT "$rule_num" 2>/dev/null || {
            log_message "警告: 无法删除INPUT链规则 #$rule_num"
            break
        }
    done
    
    # 清理DOCKER-USER链中的规则
    if iptables -L DOCKER-USER -n &>/dev/null; then
        while true; do
            local rule_num=$(iptables -L DOCKER-USER -n --line-numbers | grep "$COMMENT_MARK" | head -1 | awk '{print $1}')
            [ -z "$rule_num" ] && break
            iptables -D DOCKER-USER "$rule_num" 2>/dev/null || {
                log_message "警告: 无法删除DOCKER-USER链规则 #$rule_num"
                break
            }
        done
    fi
    
    # 清理IPv6规则
    if command -v ip6tables &>/dev/null; then
        while true; do
            local rule_num=$(ip6tables -L INPUT -n --line-numbers | grep "$COMMENT_MARK" | head -1 | awk '{print $1}')
            [ -z "$rule_num" ] && break
            ip6tables -D INPUT "$rule_num" 2>/dev/null || {
                log_message "警告: 无法删除IPv6规则 #$rule_num"
                break
            }
        done
    fi
    
    log_message "旧规则清理完成"
}

# 检查规则是否已存在
rule_exists() {
    local chain="$1"
    local ip="$2"
    local port="$3"
    
    iptables -C "$chain" -p tcp -s "$ip" --dport "$port" -j ACCEPT -m comment --comment "$COMMENT_MARK" 2>/dev/null || \
    iptables -C "$chain" -p tcp -s "$ip" --dport "$port" -j RETURN -m comment --comment "$COMMENT_MARK" 2>/dev/null
}

# 添加新的Cloudflare规则
add_cloudflare_rules() {
    local ips="$1"
    local count=0
    local errors=0
    
    log_message "添加新的Cloudflare规则..."
    
    # 获取内网和本地规则的位置（在这些规则之后插入）
    local insert_pos_input=$(iptables -L INPUT -n --line-numbers | grep -E "192.168.0.0/16.*tcp dpt:443" | tail -1 | awk '{print $1}')
    [ -z "$insert_pos_input" ] && insert_pos_input=1
    
    while IFS= read -r ip; do
        # 跳过空行和非IP格式的行
        [ -z "$ip" ] && continue
        [[ ! "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]] && \
        [[ ! "$ip" =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}/[0-9]{1,3}$ ]] && continue
        
        if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
            # IPv4规则
            for port in 80 443; do
                # INPUT链
                if ! rule_exists INPUT "$ip" "$port"; then
                    if iptables -I INPUT $((++insert_pos_input)) -p tcp -s "$ip" --dport "$port" -j ACCEPT -m comment --comment "$COMMENT_MARK" 2>/dev/null; then
                        ((count++))
                    else
                        ((errors++))
                        log_message "错误: 无法添加INPUT规则 $ip:$port"
                    fi
                fi
                
                # DOCKER-USER链
                if iptables -L DOCKER-USER -n &>/dev/null; then
                    if ! rule_exists DOCKER-USER "$ip" "$port"; then
                        if iptables -A DOCKER-USER -s "$ip" -p tcp --dport "$port" -j RETURN -m comment --comment "$COMMENT_MARK" 2>/dev/null; then
                            ((count++))
                        else
                            ((errors++))
                            log_message "错误: 无法添加DOCKER-USER规则 $ip:$port"
                        fi
                    fi
                fi
            done
        elif [[ "$ip" =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}/[0-9]{1,3}$ ]]; then
            # IPv6规则
            if command -v ip6tables &>/dev/null; then
                for port in 80 443; do
                    if ! ip6tables -C INPUT -p tcp -s "$ip" --dport "$port" -j ACCEPT -m comment --comment "$COMMENT_MARK" 2>/dev/null; then
                        if ip6tables -A INPUT -p tcp -s "$ip" --dport "$port" -j ACCEPT -m comment --comment "$COMMENT_MARK" 2>/dev/null; then
                            ((count++))
                        else
                            ((errors++))
                            log_message "错误: 无法添加IPv6规则 $ip:$port"
                        fi
                fi
            done
            fi
        fi
    done <<< "$ips"
    
    log_message "已添加 $count 条Cloudflare IP规则，错误 $errors 条"
    
    # 确保DROP规则在最后
    ensure_drop_rules_last
}

# 确保DROP规则在最后
ensure_drop_rules_last() {
    # 移除现有的DROP规则
    while iptables -D INPUT -p tcp --dport 80 -j DROP 2>/dev/null; do :; done
    while iptables -D INPUT -p tcp --dport 443 -j DROP 2>/dev/null; do :; done
    
    # 在末尾重新添加DROP规则
    iptables -A INPUT -p tcp --dport 80 -j DROP
    iptables -A INPUT -p tcp --dport 443 -j DROP
    
    # DOCKER-USER链的DROP规则
    if iptables -L DOCKER-USER -n &>/dev/null; then
        while iptables -D DOCKER-USER -p tcp --dport 80 -j DROP 2>/dev/null; do :; done
        while iptables -D DOCKER-USER -p tcp --dport 443 -j DROP 2>/dev/null; do :; done
        
        # 先添加DROP规则
        iptables -A DOCKER-USER -p tcp --dport 80 -j DROP
        iptables -A DOCKER-USER -p tcp --dport 443 -j DROP
        
        # 确保最后有RETURN规则
        iptables -D DOCKER-USER -j RETURN 2>/dev/null || true
        iptables -A DOCKER-USER -j RETURN
    fi
}

# 验证防火墙规则
verify_rules() {
    local cf_rules=$(iptables -L INPUT -n | grep -c "$COMMENT_MARK" || echo 0)
    local docker_rules=0
    
    if iptables -L DOCKER-USER -n &>/dev/null; then
        docker_rules=$(iptables -L DOCKER-USER -n | grep -c "$COMMENT_MARK" || echo 0)
    fi
    
    log_message "验证: INPUT链中有 $cf_rules 条Cloudflare规则"
    [ $docker_rules -gt 0 ] && log_message "验证: DOCKER-USER链中有 $docker_rules 条Cloudflare规则"
}

# 主函数
main() {
    log_message "========== 开始更新Cloudflare IP规则 =========="
    
    # 检查是否有root权限
    if [ "$EUID" -ne 0 ]; then
        log_message "错误: 此脚本需要root权限运行"
        exit 1
    fi
    
    # 检测IPv6支持
    if command -v ip6tables &>/dev/null && ip6tables -L -n &>/dev/null 2>&1; then
        log_message "信息: 检测到IPv6支持，将配置IPv6规则"
    else
        log_message "信息: 未检测到IPv6支持，仅配置IPv4规则"
    fi
    
    # 获取最新的Cloudflare IP
    local cf_ips=$(get_cloudflare_ips)
    
    if [ -z "$cf_ips" ]; then
        log_message "错误: 无法获取Cloudflare IP列表"
        exit 1
    fi
    
    # 清理旧规则
    clean_old_rules
    
    # 添加新规则
    add_cloudflare_rules "$cf_ips"
    
    # 验证规则
    verify_rules
    
    # 保存iptables规则
    if [ -f /etc/debian_version ]; then
        if command -v iptables-save &>/dev/null; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || log_message "警告: 无法保存IPv4规则"
            ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || log_message "警告: 无法保存IPv6规则"
        fi
    elif [ -f /etc/redhat-release ]; then
        if command -v iptables-save &>/dev/null; then
            iptables-save > /etc/sysconfig/iptables 2>/dev/null || log_message "警告: 无法保存防火墙规则"
        fi
    fi
    
    log_message "========== Cloudflare IP规则更新完成 =========="
}

# 启动日志
mkdir -p $(dirname "$LOG_FILE")
touch "$LOG_FILE"

# 捕获错误
trap 'log_message "错误: 脚本异常退出 (行号: \$LINENO)"' ERR

# 执行主函数
main
EOF
    
    sudo chmod +x "$CF_UPDATE_SCRIPT"
    # 设置脚本权限（仅root可读写执行）
    sudo chmod 700 "$CF_UPDATE_SCRIPT"
    
    # 创建定时任务
    sudo tee "$CF_CRON_JOB" > /dev/null << EOF
# 每天凌晨3点更新Cloudflare IP列表
0 3 * * * root $CF_UPDATE_SCRIPT >/dev/null 2>&1
EOF
    
    # 设置cron文件权限
    sudo chmod 644 "$CF_CRON_JOB"
    
    # 立即执行一次
    sudo "$CF_UPDATE_SCRIPT"
    
    log_message "INFO" "Cloudflare IP更新脚本创建完成"
}

# 配置防火墙（优化后的版本）
configure_firewall() {
    log_message "INFO" "配置防火墙规则..."
    
    # 首先确保SSH端口始终可访问（除非配置了白名单）
    local ssh_port="${SSH_PORT:-22}"
    if [ "$ENABLE_SSH_WHITELIST" != "true" ]; then
        # 确保SSH端口开放
        if ! sudo iptables -C INPUT -p tcp --dport "$ssh_port" -j ACCEPT 2>/dev/null; then
            sudo iptables -I INPUT 1 -p tcp --dport "$ssh_port" -j ACCEPT -m comment --comment "SSH Port"
            log_message "INFO" "添加SSH端口 $ssh_port 防火墙规则"
        fi
    fi
    
    # SSH白名单
    if [ "$ENABLE_SSH_WHITELIST" = "true" ] && [ -n "$SSH_WHITELIST_IPS" ]; then
        log_message "INFO" "配置SSH白名单..."
        
        # 清理现有SSH规则
        while sudo iptables -L INPUT -n --line-numbers | grep "tcp dpt:$ssh_port" | head -1 | awk '{print $1}' | xargs -r sudo iptables -D INPUT 2>/dev/null; do :; done
        
        # 添加白名单规则
        IFS=',' read -ra IPS <<< "$SSH_WHITELIST_IPS"
        for ip in "${IPS[@]}"; do
            ip=$(echo "$ip" | xargs)
            if validate_ip "$ip"; then
                sudo iptables -A INPUT -s "$ip" -p tcp --dport "$ssh_port" -j ACCEPT
            else
                log_message "WARNING" "跳过无效的IP地址: $ip"
            fi
        done
        
        # 拒绝其他SSH连接
        sudo iptables -A INPUT -p tcp --dport "$ssh_port" -j DROP
    fi
    
    # 禁用ICMP
    if [ "$DISABLE_ICMP" = "true" ]; then
        log_message "INFO" "禁用ICMP..."
        sudo iptables -A INPUT -p icmp -j DROP
        sudo iptables -A OUTPUT -p icmp -j DROP
    fi
    
    # Web端口保护
    if [ "$PROTECT_WEB_PORTS" = "true" ]; then
        log_message "INFO" "配置Web端口保护..."
        
        # 清理现有规则
        while sudo iptables -L INPUT -n --line-numbers | grep -E "tcp dpt:(80|443)" | head -1 | awk '{print $1}' | xargs -r sudo iptables -D INPUT 2>/dev/null; do :; done
        
        # 允许本地和内网访问
        for port in 80 443; do
            sudo iptables -A INPUT -p tcp --dport $port -s 127.0.0.1 -j ACCEPT
            sudo iptables -A INPUT -p tcp --dport $port -s 10.0.0.0/8 -j ACCEPT
            sudo iptables -A INPUT -p tcp --dport $port -s 172.16.0.0/12 -j ACCEPT
            sudo iptables -A INPUT -p tcp --dport $port -s 192.168.0.0/16 -j ACCEPT
        done
        
        # 创建Cloudflare IP更新脚本和定时任务
        create_cloudflare_update_script
        
        # 拒绝其他访问
        sudo iptables -A INPUT -p tcp --dport 80 -j DROP
        sudo iptables -A INPUT -p tcp --dport 443 -j DROP
        
        # 如果Docker已安装或将要安装，配置DOCKER-USER链
        if command -v docker &> /dev/null || [ "$INSTALL_DOCKER" = "true" ]; then
            configure_docker_firewall
        fi
    fi
    
    # 保存防火墙规则
    save_firewall_rules
    
    log_message "INFO" "防火墙配置完成"
}

# 配置Docker防火墙
configure_docker_firewall() {
    log_message "INFO" "配置Docker防火墙规则..."
    
    # 确保DOCKER-USER链存在
    sudo iptables -L DOCKER-USER -n &>/dev/null || {
        sudo iptables -N DOCKER-USER
        sudo iptables -I FORWARD -j DOCKER-USER
    }
    
    # 清理旧规则
    while sudo iptables -L DOCKER-USER -n --line-numbers | grep -E "dpt:(80|443)" | head -1 | awk '{print $1}' | xargs -r sudo iptables -D DOCKER-USER 2>/dev/null; do :; done
    
    # 允许本地和内网
    sudo iptables -I DOCKER-USER -i lo -j RETURN
    sudo iptables -A DOCKER-USER -s 127.0.0.1 -j RETURN
    sudo iptables -A DOCKER-USER -s 10.0.0.0/8 -j RETURN
    sudo iptables -A DOCKER-USER -s 172.16.0.0/12 -j RETURN
    sudo iptables -A DOCKER-USER -s 192.168.0.0/16 -j RETURN
    
    # Cloudflare IP会由更新脚本处理
    
    # 拒绝其他访问
    sudo iptables -A DOCKER-USER -p tcp --dport 80 -j DROP
    sudo iptables -A DOCKER-USER -p tcp --dport 443 -j DROP
    
    # 允许其他流量
    sudo iptables -A DOCKER-USER -j RETURN
    
    log_message "INFO" "Docker防火墙配置完成"
}

# 保存防火墙规则
save_firewall_rules() {
    log_message "INFO" "保存防火墙规则..."
    
    if [ "$OS_TYPE" = "debian" ]; then
        # 安装iptables-persistent
        if ! dpkg -l | grep -q iptables-persistent; then
            wait_for_apt
            echo 'iptables-persistent iptables-persistent/autosave_v4 boolean true' | sudo debconf-set-selections
            echo 'iptables-persistent iptables-persistent/autosave_v6 boolean true' | sudo debconf-set-selections
            sudo apt-get install -y iptables-persistent
        fi
        
        sudo mkdir -p /etc/iptables
        sudo iptables-save > /etc/iptables/rules.v4
        # 只有在系统支持IPv6时才尝试保存IPv6规则
        if command -v ip6tables &>/dev/null && ip6tables -L -n &>/dev/null 2>&1; then
            sudo ip6tables-save > /etc/iptables/rules.v6
        fi
    else
        sudo iptables-save > /etc/sysconfig/iptables
    fi
}

# 安装Docker
install_docker() {
    [ "$INSTALL_DOCKER" != "true" ] && return 0
    
    log_message "INFO" "安装Docker..."
    
    if command -v docker &> /dev/null; then
        log_message "INFO" " Docker已安装"
        
        # 如果启用了Web保护，重新运行Cloudflare更新脚本以配置DOCKER-USER链
        if [ "$PROTECT_WEB_PORTS" = "true" ] && [ -f "$CF_UPDATE_SCRIPT" ]; then
            log_message "INFO" "更新Docker防火墙规则..."
            sudo "$CF_UPDATE_SCRIPT"
        fi
        
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
        [ "$region" = "auto" ] && region=$(detect_server_region)
        
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
        
        # 如果启用了Web保护，重新运行Cloudflare更新脚本以配置DOCKER-USER链
        if [ "$PROTECT_WEB_PORTS" = "true" ] && [ -f "$CF_UPDATE_SCRIPT" ]; then
            log_message "INFO" "更新Docker防火墙规则..."
            sudo "$CF_UPDATE_SCRIPT"
        fi
    else
        log_message "ERROR" "Docker安装失败"
        rm -f "$docker_script"
        return 1
    fi
}

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
    [ "$ENABLE_SSH_WHITELIST" = "true" ] && echo "  白名单: $SSH_WHITELIST_IPS"
    echo ""
    echo "安全配置:"
    echo "  fail2ban: $(systemctl is-active fail2ban 2>/dev/null || echo '未运行')"
    echo "  安全审计: $([ "$ENABLE_SECURITY_AUDIT" = "true" ] && echo "已启用 (auditd + etckeeper)" || echo "已禁用")"
    [ "$DISABLE_ICMP" = "true" ] && echo "  ICMP: 已禁用"
    [ "$PROTECT_WEB_PORTS" = "true" ] && echo "  Web端口保护: 已启用 (Cloudflare IP自动更新)"
    echo ""
    echo "系统优化:"
    echo "  BBR: $(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}' || echo '未启用')"
    echo "  IP转发: $(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo '未启用')"
    echo ""
    
    if command -v docker &> /dev/null; then
        echo "Docker:"
        echo "  版本: $(docker --version | awk '{print $3}' | sed 's/,$//')"
        echo "  状态: $(systemctl is-active docker)"
        [ "$PROTECT_WEB_PORTS" = "true" ] && echo "  防火墙: DOCKER-USER链已配置"
    fi
    
    [ "$CREATE_DEVOPS_USER" = "true" ] && echo -e "\n管理员用户: $SUDO_USERNAME (已创建)"
    
    echo "--------------------------------------------------"
    echo "日志文件: $LOG_FILE"
    echo "配置备份: $CONFIG_BACKUP_DIR"
    [ "$PROTECT_WEB_PORTS" = "true" ] && echo "CF更新脚本: $CF_UPDATE_SCRIPT"
    echo "--------------------------------------------------"
    echo "SSH登录命令: ssh -p $ssh_port 用户名@服务器IP"
    
    [ "$DISABLE_SSH_PASSWD" = "true" ] && echo -e "\n注意: 请确保已保存SSH密钥，密码登录已禁用！"
}

# 主脚本的主函数
main() {
    parse_args "$@"
    
    # 系统检查和初始化
    check_compatibility || { log_message "ERROR" "系统兼容性检查失败"; exit 1; }
    wait_for_cloud_init
    fix_sudo_issue
    
    # 系统更新和软件安装
    update_system_install_dependencies
    
    # SSH配置
    configure_ssh_keys
    create_admin_user
    configure_ssh
    
    # 系统服务配置
    configure_fail2ban
    configure_timezone_ntp
    configure_system_optimization
    configure_security_audit
    
    # Docker安装
    install_docker
    
    # 防火墙配置
    configure_firewall
    
    # 显示配置总结
    show_summary
}

# 执行主函数
main "$@"
