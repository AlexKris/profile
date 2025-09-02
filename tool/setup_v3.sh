#!/bin/bash

# Setup Script V3 - 优化版VPS初始化脚本
# 支持预设模板和智能优化
# Version: 3.0.0

set -euo pipefail

# ========== 脚本配置 ==========
readonly SCRIPT_VERSION="3.0.0"
readonly SCRIPT_NAME="$(basename "$0")"
readonly TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
readonly LOG_FILE="/var/log/setup_v3_${TIMESTAMP}.log"
readonly BACKUP_DIR="/root/setup_backups/${TIMESTAMP}"

# 颜色定义
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

# 错误处理
set -euo pipefail
trap 'error_handler $? $LINENO' ERR

# ========== 全局变量 ==========
# SSH配置
SSH_PORT="22"
SSH_KEY=""
DISABLE_SSH_PWD="false"
DISABLE_ROOT_PWD="false"
# 系统配置
SERVER_REGION="auto"
NTP_SERVICE="auto"
# 功能开关
INSTALL_DOCKER="false"
ENABLE_AUDIT="false"
ENABLE_MONITORING="false"
IS_NAT_VPS="false"
IS_GATEWAY="false"
SKIP_MODULES=""
SYSLOG_SERVER=""
# 检测结果
TOTAL_MEMORY=0
CPU_CORES=0
VPS_TYPE=""

# ========== 工具函数 ==========

# 错误处理函数
error_handler() {
    local exit_code=$1
    local line_num=$2
    log_message "ERROR" "脚本在第 $line_num 行失败，退出码: $exit_code"
    log_message "ERROR" "查看日志: $LOG_FILE"
    
    # 尝试恢复
    if [ -d "$BACKUP_DIR" ]; then
        log_message "WARNING" "尝试恢复配置..."
        restore_configs
    fi
    
    exit $exit_code
}

# 日志函数
log_message() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        ERROR)   echo -e "${RED}[ERROR]${NC} $message" ;;
        WARNING) echo -e "${YELLOW}[WARNING]${NC} $message" ;;
        INFO)    echo -e "${BLUE}[INFO]${NC} $message" ;;
        SUCCESS) echo -e "${GREEN}[SUCCESS]${NC} $message" ;;
    esac
    
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

# 备份配置文件
backup_config() {
    local file=$1
    local backup_name=$(basename "$file")
    
    if [ ! -d "$BACKUP_DIR" ]; then
        mkdir -p "$BACKUP_DIR"
        log_message "INFO" "创建备份目录: $BACKUP_DIR"
    fi
    
    if [ -f "$file" ]; then
        cp -p "$file" "$BACKUP_DIR/${backup_name}.backup"
        log_message "INFO" "备份文件: $file -> $BACKUP_DIR/${backup_name}.backup"
        return 0
    fi
    return 1
}

# 恢复配置文件
restore_configs() {
    if [ ! -d "$BACKUP_DIR" ]; then
        log_message "WARNING" "备份目录不存在，无法恢复"
        return 1
    fi
    
    log_message "INFO" "开始恢复配置..."
    
    # 恢复SSH配置
    if [ -f "$BACKUP_DIR/sshd_config.backup" ]; then
        cp -p "$BACKUP_DIR/sshd_config.backup" /etc/ssh/sshd_config
        systemctl reload sshd || true
        log_message "SUCCESS" "SSH配置已恢复"
    fi
    
    # 恢复sysctl配置
    if [ -f "$BACKUP_DIR/99-network-optimization.conf.backup" ]; then
        cp -p "$BACKUP_DIR/99-network-optimization.conf.backup" /etc/sysctl.d/99-network-optimization.conf
        sysctl -p /etc/sysctl.d/99-network-optimization.conf >/dev/null 2>&1 || true
        log_message "SUCCESS" "网络配置已恢复"
    fi
    
    return 0
}

# SSH连接测试（防锁定）
test_ssh_connection() {
    local port=${1:-22}
    local test_timeout=5
    
    log_message "INFO" "测试SSH连接（端口: $port）..."
    
    # 使用nc测试端口
    if command -v nc &>/dev/null; then
        if nc -z -w $test_timeout localhost "$port" 2>/dev/null; then
            log_message "SUCCESS" "SSH端口 $port 可访问"
            return 0
        else
            log_message "ERROR" "SSH端口 $port 无法访问"
            return 1
        fi
    fi
    
    # 备用方案：使用telnet
    if command -v telnet &>/dev/null; then
        if timeout $test_timeout telnet localhost "$port" 2>&1 | grep -q "Connected"; then
            log_message "SUCCESS" "SSH端口 $port 可访问"
            return 0
        fi
    fi
    
    log_message "WARNING" "无法验证SSH连接"
    return 1
}

# 验证SSH配置
validate_ssh_config() {
    local config_file=${1:-/etc/ssh/sshd_config}
    log_message "INFO" "验证SSH配置..."
    
    # 测试配置文件语法
    if sshd -t -f "$config_file" 2>/dev/null; then
        log_message "SUCCESS" "SSH配置语法正确"
        return 0
    else
        log_message "ERROR" "SSH配置语法错误"
        return 1
    fi
}

# 错误处理函数
error_handler() {
    local line_num=$1
    local exit_code=$?
    
    log_message "ERROR" "脚本在第 ${line_num:-unknown} 行发生错误，退出码: $exit_code"
    log_message "INFO" "尝试恢复配置..."
    
    # 尝试恢复配置
    restore_configs
    
    # 确保SSH服务正常
    if systemctl is-active sshd >/dev/null 2>&1; then
        log_message "SUCCESS" "SSH服务正常运行"
    else
        log_message "WARNING" "尝试重启SSH服务..."
        systemctl restart sshd || systemctl restart ssh || true
    fi
    
    log_message "ERROR" "Setup V3 脚本执行失败，已尝试恢复"
    exit $exit_code
}

detect_system_resources() {
    log_message "INFO" "检测系统资源..."
    
    # 检测内存（MB）
    TOTAL_MEMORY=$(free -m | awk '/^Mem:/{print $2}')
    
    # 检测CPU核心数
    CPU_CORES=$(nproc)
    
    # 检测虚拟化类型
    if systemd-detect-virt &>/dev/null; then
        VIRT_TYPE=$(systemd-detect-virt)
    else
        VIRT_TYPE="unknown"
    fi
    
    log_message "INFO" "系统资源: ${TOTAL_MEMORY}MB内存, ${CPU_CORES}核CPU, 虚拟化: $VIRT_TYPE"
}

detect_vps_type() {
    log_message "INFO" "检测VPS类型..."
    
    # 检查是否为NAT（通过端口范围判断）
    local port_count=$(ss -tln | grep -c LISTEN || true)
    if [ "$port_count" -lt 10 ]; then
        VPS_TYPE="nat"
        log_message "INFO" "检测为NAT VPS"
        return
    fi
    
    # 根据内存判断
    if [ "$TOTAL_MEMORY" -le 1024 ]; then
        VPS_TYPE="minimal"
    elif [ "$TOTAL_MEMORY" -le 4096 ]; then
        VPS_TYPE="standard"
    else
        VPS_TYPE="performance"
    fi
    
    log_message "INFO" "VPS类型: $VPS_TYPE"
}

# ========== 核心功能模块 ==========

# 系统更新模块
module_system_update() {
    if [[ "$SKIP_MODULES" == *"update"* ]]; then
        log_message "INFO" "跳过系统更新"
        return
    fi
    
    log_message "INFO" "更新系统包..."
    
    # 等待apt锁（检查所有锁文件）
    local max_wait=300
    local wait_time=0
    while fuser /var/lib/dpkg/lock >/dev/null 2>&1 || \
          fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || \
          fuser /var/lib/apt/lists/lock >/dev/null 2>&1 || \
          fuser /var/cache/apt/archives/lock >/dev/null 2>&1; do
        if [ $wait_time -ge $max_wait ]; then
            log_message "ERROR" "等待apt锁超时"
            return 1
        fi
        log_message "INFO" "等待apt锁释放... ($wait_time/$max_wait秒)"
        sleep 5
        wait_time=$((wait_time + 5))
    done
    
    # 如果仍有问题，尝试修复
    if ! apt-get check >/dev/null 2>&1; then
        log_message "WARNING" "检测到apt问题，尝试修复..."
        dpkg --configure -a
        apt-get install -f -y
    fi
    
    # 更新包列表
    apt-get update -y
    
    # 基础软件包
    local packages="curl wget vim git htop net-tools fail2ban rsync jq"
    
    # 根据内存添加额外包
    if [ "$TOTAL_MEMORY" -ge 2048 ]; then
        packages="$packages iotop iftop nethogs sysstat"
    fi
    
    for pkg in $packages; do
        if ! dpkg -l | grep -q "^ii  $pkg"; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" || true
        fi
    done
    
    log_message "SUCCESS" "系统更新完成"
}

# SSH配置模块
module_ssh_configuration() {
    if [[ "$SKIP_MODULES" == *"ssh"* ]]; then
        log_message "INFO" "跳过SSH配置"
        return
    fi
    
    log_message "INFO" "配置SSH安全..."
    
    # 备份原配置
    backup_config "/etc/ssh/sshd_config"
    backup_config "/etc/ssh/sshd_config.d/99-setup-v3.conf"
    
    # 记录当前SSH端口
    local old_port=$(grep -E "^Port" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
    old_port=${old_port:-22}
    
    # 创建新的配置文件
    local ssh_config_temp="/tmp/99-setup-v3.conf.tmp"
    cat > "$ssh_config_temp" << EOF
# SSH Security Configuration by Setup V3
# Generated: $(date)

# 端口配置
Port ${SSH_PORT}

# 认证配置
PermitRootLogin $([ "$DISABLE_ROOT_PWD" = "true" ] && echo "prohibit-password" || echo "yes")
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

# 密码认证
PasswordAuthentication $([ "$DISABLE_SSH_PWD" = "true" ] && echo "no" || echo "yes")
PermitEmptyPasswords no

# 安全选项
Protocol 2
StrictModes yes
MaxAuthTries 3
MaxSessions 10
ClientAliveInterval 300
ClientAliveCountMax 2

# 性能优化
UseDNS no
Compression yes
TCPKeepAlive yes

# 加密算法（现代安全配置）
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
EOF
    
    # 验证配置文件语法
    if ! validate_ssh_config "$ssh_config_temp"; then
        log_message "ERROR" "SSH配置文件语法错误，跳过SSH配置"
        rm -f "$ssh_config_temp"
        return 1
    fi
    
    # 添加SSH密钥
    if [ -n "$SSH_KEY" ]; then
        mkdir -p /root/.ssh
        echo "$SSH_KEY" >> /root/.ssh/authorized_keys
        chmod 700 /root/.ssh
        chmod 600 /root/.ssh/authorized_keys
        log_message "SUCCESS" "SSH密钥已添加"
    fi
    
    # 移动配置文件到正确位置
    mv "$ssh_config_temp" /etc/ssh/sshd_config.d/99-setup-v3.conf
    
    # 如果端口改变，记录信息
    if [ "$old_port" != "$SSH_PORT" ]; then
        log_message "INFO" "SSH端口将从 $old_port 改为 $SSH_PORT"
    fi
    
    # 测试配置并重启SSH服务
    log_message "INFO" "测试SSH配置..."
    if sshd -t -f /etc/ssh/sshd_config 2>/dev/null; then
        # 重启SSH服务
        systemctl reload-or-restart sshd
        
        # 等待服务启动
        sleep 2
        
        # 测试新端口连接
        if test_ssh_connection "$SSH_PORT"; then
            log_message "SUCCESS" "SSH配置完成，端口: $SSH_PORT"
            
            # 端口切换成功
            if [ "$old_port" != "$SSH_PORT" ] && [ "$old_port" != "" ]; then
                log_message "INFO" "SSH端口切换成功: $old_port -> $SSH_PORT"
            fi
        else
            log_message "ERROR" "SSH端口 $SSH_PORT 无法连接，回滚配置..."
            restore_configs
            systemctl reload-or-restart sshd
            log_message "WARNING" "SSH配置已回滚到之前的状态"
            return 1
        fi
    else
        log_message "ERROR" "SSH配置测试失败，回滚配置..."
        restore_configs
        log_message "WARNING" "SSH配置已回滚"
        return 1
    fi
}

# 网络优化模块
module_network_optimization() {
    if [[ "$SKIP_MODULES" == *"network"* ]]; then
        log_message "INFO" "跳过网络优化"
        return
    fi
    
    log_message "INFO" "应用通用网络优化..."
    
    # 创建sysctl配置（只包含通用安全的优化）
    cat > /etc/sysctl.d/99-network-optimization.conf << EOF
# Universal Network Optimization by Setup V3
# Conservative settings safe for all VPS types

# === BBR拥塞控制（Linux 4.9+）===
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# === 基础TCP优化 ===
# 减少FIN_WAIT2时间（默认60秒）
net.ipv4.tcp_fin_timeout = 30

# TCP keepalive（检测死连接）
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 30

# === 性能特性 ===
# TCP Fast Open（减少握手延迟）
net.ipv4.tcp_fastopen = 3

# 基础TCP特性（通常已默认开启）
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_window_scaling = 1

# === 安全防护 ===
# SYN cookies（防SYN泛洪）
net.ipv4.tcp_syncookies = 1

# 反向路径过滤（防IP欺骗）
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# === 基础系统限制 ===
# 端口范围
net.ipv4.ip_local_port_range = 1024 65535

# 文件描述符（保守值）
fs.file-max = 1048576

EOF
    
    # NAT VPS特殊处理
    if [ "$IS_NAT_VPS" = "true" ]; then
        log_message "INFO" "NAT VPS模式，禁用tw_reuse..."
        
        # NAT环境下不启用tw_reuse（避免连接混淆）
        cat >> /etc/sysctl.d/99-network-optimization.conf << EOF

# === NAT VPS特殊配置 ===
# 不启用TIME_WAIT重用（NAT环境下不安全）
net.ipv4.tcp_tw_reuse = 0
EOF
    else
        # 非NAT环境可以启用tw_reuse
        cat >> /etc/sysctl.d/99-network-optimization.conf << EOF

# === TIME_WAIT优化（非NAT环境）===
# 允许TIME_WAIT套接字重用（提高端口利用率）
net.ipv4.tcp_tw_reuse = 1
EOF
    fi
    
    # 如果是网关模式，添加转发优化
    if [ "$IS_GATEWAY" = "true" ]; then
        log_message "INFO" "应用网关/转发优化..."
        cat >> /etc/sysctl.d/99-network-optimization.conf << EOF

# === 转发优化（网关模式）===
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

# 连接跟踪（保守值）
net.netfilter.nf_conntrack_max = 524288
net.netfilter.nf_conntrack_tcp_timeout_established = 86400
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 120
EOF
    fi
    
    # 加载BBR模块
    modprobe tcp_bbr 2>/dev/null || true
    
    # 应用配置
    sysctl -p /etc/sysctl.d/99-network-optimization.conf >/dev/null 2>&1
    
    # 验证BBR
    if sysctl net.ipv4.tcp_congestion_control | grep -q bbr; then
        log_message "SUCCESS" "BBR已启用"
    else
        log_message "WARNING" "BBR未能启用"
    fi
    
    log_message "SUCCESS" "网络优化完成"
}

# 防火墙配置模块（当前禁用）
module_firewall_configuration() {
    # 暂时跳过防火墙配置
    log_message "INFO" "跳过防火墙配置（当前版本不启用UFW）"
    return 0
}

# Fail2ban配置模块
module_fail2ban_configuration() {
    if [[ "$SKIP_MODULES" == *"fail2ban"* ]]; then
        log_message "INFO" "跳过Fail2ban配置"
        return
    fi
    
    log_message "INFO" "配置Fail2ban..."
    
    # 检查fail2ban是否安装
    if ! command -v fail2ban-client >/dev/null 2>&1; then
        log_message "WARNING" "Fail2ban未安装，尝试安装..."
        apt-get install -y fail2ban || {
            log_message "ERROR" "Fail2ban安装失败"
            return 1
        }
    fi
    
    # 确定SSH日志路径（Debian/Ubuntu用auth.log，RedHat系用secure）
    local ssh_log_path="/var/log/auth.log"
    if [ -f "/var/log/secure" ]; then
        ssh_log_path="/var/log/secure"
    fi
    
    # 确保日志文件存在
    if [ ! -f "$ssh_log_path" ]; then
        log_message "WARNING" "SSH日志文件不存在: $ssh_log_path"
        
        # 确保rsyslog配置正确
        if grep -q "auth,authpriv" /etc/rsyslog.conf 2>/dev/null; then
            systemctl restart rsyslog
            sleep 2
        else
            # 添加auth日志配置
            echo "auth,authpriv.*          $ssh_log_path" >> /etc/rsyslog.conf
            systemctl restart rsyslog
            log_message "INFO" "已配置rsyslog创建auth日志"
        fi
        
        # 创建空日志文件
        touch "$ssh_log_path"
        chmod 640 "$ssh_log_path"
    fi
    
    # 备份现有配置
    backup_config "/etc/fail2ban/jail.local"
    backup_config "/etc/fail2ban/jail.d/custom.conf"
    
    # 创建自定义配置（使用jail.d目录，优先级更高）
    mkdir -p /etc/fail2ban/jail.d
    cat > /etc/fail2ban/jail.d/custom.conf << EOF
# Fail2ban Custom Configuration by Setup V3
# Generated: $(date)

[DEFAULT]
# 默认封禁时间：1小时
bantime = 3600
# 检测时间窗口：10分钟
findtime = 600
# 最大重试次数：5次
maxretry = 5
# 忽略本地IP
ignoreip = 127.0.0.1/8 ::1
# 日志级别
loglevel = INFO
# 日志路径
logtarget = /var/log/fail2ban.log

[sshd]
enabled = true
port = ${SSH_PORT}
filter = sshd
logpath = $ssh_log_path
maxretry = 3
bantime = 7200
findtime = 600
# 使用标准动作（仅封禁，不发邮件）
action = %(action_)s
EOF
    
    # 确保fail2ban目录权限正确
    chmod 644 /etc/fail2ban/jail.d/custom.conf
    
    # 测试配置
    if fail2ban-client -t >/dev/null 2>&1; then
        log_message "SUCCESS" "Fail2ban配置语法正确"
    else
        log_message "ERROR" "Fail2ban配置有误"
        restore_configs
        return 1
    fi
    
    # 启动服务
    systemctl enable fail2ban >/dev/null 2>&1
    systemctl restart fail2ban
    
    # 等待服务启动
    sleep 2
    
    # 验证服务状态
    if systemctl is-active fail2ban >/dev/null 2>&1; then
        # 显示jail状态
        local jail_status=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" || echo "状态未知")
        log_message "SUCCESS" "Fail2ban配置完成 - $jail_status"
    else
        log_message "WARNING" "Fail2ban服务未正常启动"
        return 1
    fi
}

# 时区和NTP配置
module_timezone_configuration() {
    if [[ "$SKIP_MODULES" == *"timezone"* ]]; then
        log_message "INFO" "跳过时区配置"
        return
    fi
    
    log_message "INFO" "配置时区和NTP..."
    
    # 根据地区设置时区
    local timezone="UTC"
    case $SERVER_REGION in
        cn|hk|tw|sg)
            timezone="Asia/Shanghai"
            ;;
        jp)
            timezone="Asia/Tokyo"
            ;;
        kr)
            timezone="Asia/Seoul"
            ;;
        us)
            timezone="America/Los_Angeles"
            ;;
        eu)
            timezone="Europe/London"
            ;;
    esac
    
    timedatectl set-timezone "$timezone"
    log_message "INFO" "时区设置为: $timezone"
    
    # 配置NTP
    if [ "$NTP_SERVICE" = "chrony" ] || [ "$NTP_SERVICE" = "auto" ] && command -v chrony &>/dev/null; then
        systemctl enable chrony
        systemctl restart chrony
        log_message "INFO" "使用chrony同步时间"
    else
        timedatectl set-ntp true
        log_message "INFO" "使用systemd-timesyncd同步时间"
    fi
    
    log_message "SUCCESS" "时区和NTP配置完成"
}

# Docker安装模块（可选）
module_docker_installation() {
    if [ "$INSTALL_DOCKER" != "true" ] || [[ "$SKIP_MODULES" == *"docker"* ]]; then
        log_message "INFO" "跳过Docker安装"
        return
    fi
    
    log_message "INFO" "安装Docker..."
    
    # 使用Docker官方脚本（包含docker compose v2）
    if curl -fsSL https://get.docker.com | bash; then
        log_message "SUCCESS" "Docker安装成功"
        
        # Docker官方脚本已经安装并启动了docker服务
        # 验证Docker Compose V2安装
        if docker compose version &>/dev/null; then
            log_message "SUCCESS" "Docker Compose V2已安装: $(docker compose version)"
        else
            log_message "WARNING" "Docker Compose V2未找到，尝试手动安装"
            apt-get update && apt-get install -y docker-compose-plugin
        fi
        
        # 配置Docker日志限制（防止日志过大）
        mkdir -p /etc/docker
        if [ ! -f /etc/docker/daemon.json ]; then
            cat > /etc/docker/daemon.json << EOF
{
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "10m",
        "max-file": "3"
    }
}
EOF
            systemctl daemon-reload
            systemctl restart docker
            log_message "INFO" "配置Docker日志限制: 单文件10MB，最多3个文件"
        fi
        
        log_message "SUCCESS" "Docker和Docker Compose安装完成"
    else
        log_message "ERROR" "Docker安装失败"
        return 1
    fi
}

# 监控工具安装模块（已禁用）
module_monitoring_setup() {
    log_message "INFO" "跳过监控工具安装（当前版本已禁用）"
    return 0
}

# 安全审计模块（已禁用）
module_security_audit() {
    log_message "INFO" "跳过安全审计配置（当前版本已禁用）"
    return 0
}

# 系统限制优化
module_system_limits() {
    if [[ "$SKIP_MODULES" == *"limits"* ]]; then
        log_message "INFO" "跳过系统限制优化"
        return
    fi
    
    log_message "INFO" "优化系统限制..."
    
    # 根据内存确定限制值
    local nofile_soft="65535"
    local nofile_hard="65535"
    local nproc_soft="32768"
    local nproc_hard="32768"
    
    if [ "$TOTAL_MEMORY" -ge 4096 ]; then
        nofile_soft="131072"
        nofile_hard="131072"
        nproc_soft="65536"
        nproc_hard="65536"
    fi
    
    # 配置limits
    cat >> /etc/security/limits.conf << EOF

# System Limits Optimization by Setup V3
* soft nofile $nofile_soft
* hard nofile $nofile_hard
* soft nproc $nproc_soft
* hard nproc $nproc_hard
* soft memlock unlimited
* hard memlock unlimited
root soft nofile $nofile_hard
root hard nofile $nofile_hard
EOF
    
    # 配置systemd限制
    mkdir -p /etc/systemd/system.conf.d/
    cat > /etc/systemd/system.conf.d/99-limits.conf << EOF
[Manager]
DefaultLimitNOFILE=$nofile_hard
DefaultLimitNPROC=$nproc_hard
EOF
    
    systemctl daemon-reload
    
    log_message "SUCCESS" "系统限制优化完成"
}

# ========== 参数解析 ==========
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --port)
                SSH_PORT="$2"
                shift 2
                ;;
            --ssh_key)
                SSH_KEY="$2"
                shift 2
                ;;
            --disable_ssh_pwd)
                DISABLE_SSH_PWD="true"
                shift
                ;;
            --disable_root_pwd)
                DISABLE_ROOT_PWD="true"
                shift
                ;;
            --region)
                SERVER_REGION="$2"
                shift 2
                ;;
            --ntp_service)
                NTP_SERVICE="$2"
                shift 2
                ;;
            --install_docker)
                INSTALL_DOCKER="true"
                shift
                ;;
            --enable_audit)
                # 已禁用
                shift
                ;;
            --enable_monitoring)
                # 已禁用
                shift
                ;;
            --syslog_server)
                # 已禁用
                shift 2
                ;;
            --nat)
                IS_NAT_VPS="true"
                shift
                ;;
            --gateway)
                IS_GATEWAY="true"
                shift
                ;;
            --skip)
                SKIP_MODULES="$SKIP_MODULES $2"
                shift 2
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                log_message "WARNING" "未知参数: $1"
                shift
                ;;
        esac
    done
}

# ========== 使用帮助 ==========
show_usage() {
    cat << EOF
${GREEN}Setup Script V3 - VPS初始化脚本${NC}
版本: $SCRIPT_VERSION

${YELLOW}用法:${NC}
    curl -sL <url> | bash -s -- [选项]

${YELLOW}VPS类型:${NC}
    --nat               NAT VPS（禁用tw_reuse，保守端口范围）
    --gateway           网关/中转机（启用IP转发和连接跟踪优化）

${YELLOW}基础选项:${NC}
    --port <端口>        SSH端口（默认: 22）
    --ssh_key <密钥>     SSH公钥
    --disable_ssh_pwd    禁用所有SSH密码登录
    --disable_root_pwd   仅禁用root密码登录（允许密钥）
    --region <地区>      服务器地区（cn/hk/jp/kr/us/eu/auto）
    --ntp_service <ntp>  NTP服务（chrony/timesyncd/auto）

${YELLOW}功能选项:${NC}
    --install_docker     安装Docker
    --skip <模块>        跳过指定模块

${YELLOW}可跳过的模块:${NC}
    update              系统更新
    ssh                 SSH配置
    network             网络优化
    fail2ban            Fail2ban
    timezone            时区配置
    docker              Docker安装
    limits              系统限制

${YELLOW}使用示例:${NC}
    # NAT VPS
    ... | bash -s -- --nat --port 12345 --ssh_key "..."
    
    # 普通VPS
    ... | bash -s -- --port 22 --ssh_key "..." --install_docker
    
    # 网关/中转机
    ... | bash -s -- --gateway --region hk --port 27732
    
    # 完整安装
    ... | bash -s -- --install_docker --region cn

EOF
}

# ========== 显示配置摘要 ==========
show_summary() {
    echo ""
    echo -e "${GREEN}========== 配置摘要 ==========${NC}"
    echo -e "${CYAN}系统信息:${NC}"
    echo "  内存: ${TOTAL_MEMORY}MB"
    echo "  CPU: ${CPU_CORES}核"
    echo "  VPS类型: ${VPS_TYPE:-standard}"
    echo ""
    echo -e "${CYAN}网络配置:${NC}"
    echo "  BBR: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)"
    echo "  缓冲区: ${NETWORK_BUFFER_SIZE:-medium}"
    echo ""
    echo -e "${CYAN}SSH配置:${NC}"
    echo "  端口: $SSH_PORT"
    echo "  密码登录: $([ "$DISABLE_SSH_PWD" = "true" ] && echo "禁用" || echo "启用")"
    echo ""
    echo -e "${CYAN}服务状态:${NC}"
    systemctl is-active sshd >/dev/null 2>&1 && echo "  SSH: 运行中" || echo "  SSH: 未运行"
    systemctl is-active fail2ban >/dev/null 2>&1 && echo "  Fail2ban: 运行中" || echo "  Fail2ban: 未运行"
    [ "$INSTALL_DOCKER" = "true" ] && (systemctl is-active docker >/dev/null 2>&1 && echo "  Docker: 运行中" || echo "  Docker: 未运行")
    echo ""
    echo -e "${GREEN}初始化完成！${NC}"
    echo -e "${YELLOW}SSH连接命令:${NC}"
    echo "  ssh -p $SSH_PORT root@$(curl -s ifconfig.me 2>/dev/null || echo "<服务器IP>")"
    echo ""
    echo -e "${BLUE}日志文件: $LOG_FILE${NC}"
}

# ========== 主函数 ==========
main() {
    # 检查root权限
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}错误: 需要root权限运行此脚本${NC}"
        exit 1
    fi
    
    # 设置错误处理trap
    trap error_handler ERR
    
    # 解析参数
    parse_arguments "$@"
    
    # 显示开始信息
    log_message "INFO" "========== Setup V3 开始 =========="
    log_message "INFO" "版本: $SCRIPT_VERSION"
    log_message "INFO" "备份目录: $BACKUP_DIR"
    
    # 创建备份目录
    mkdir -p "$BACKUP_DIR"
    
    # 检测系统资源
    detect_system_resources
    
    # 检测VPS类型
    detect_vps_type
    
    # 执行核心模块（添加错误检查）
    module_system_update || log_message "WARNING" "系统更新模块失败，继续..."
    module_ssh_configuration || log_message "WARNING" "SSH配置模块失败，继续..."
    module_network_optimization || log_message "WARNING" "网络优化模块失败，继续..."
    module_firewall_configuration || log_message "WARNING" "防火墙配置模块失败，继续..."
    module_fail2ban_configuration || log_message "WARNING" "Fail2ban配置模块失败，继续..."
    module_timezone_configuration || log_message "WARNING" "时区配置模块失败，继续..."
    module_system_limits || log_message "WARNING" "系统限制模块失败，继续..."
    
    # 可选模块
    module_docker_installation || log_message "WARNING" "Docker安装模块失败，继续..."
    
    # 清理trap
    trap - ERR
    
    # 显示摘要
    show_summary
    
    log_message "SUCCESS" "========== Setup V3 完成 =========="
}

# 执行主函数
main "$@"