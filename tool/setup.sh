#!/bin/bash

# 脚本参数变量
DISABLE_SSH_PASSWD="false"
SSH_PORT="22"
SSH_KEY=""

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
}

# 解析参数
parse_args() {
    while [[ "$#" -gt 0 ]]; do
        case $1 in
            -h|--help) usage; exit 0 ;;
            -d|--disable-password) DISABLE_SSH_PASSWD="true" ;;
            -p|--port) SSH_PORT="$2"; shift ;;
            -k|--key) SSH_KEY="$2"; shift ;;
            -f|--key-file) 
                if [ -f "$2" ]; then
                    SSH_KEY=$(cat "$2")
                else
                    echo "错误: 无法找到密钥文件 $2"
                    exit 1
                fi
                shift ;;
            -u|--update) update_shell; exit 0 ;;
            *) echo "未知选项: $1"; usage; exit 1 ;;
        esac
        shift
    done
}

# 更新脚本函数
update_shell(){
    echo -e "[信息] 正在获取最新版本的脚本..."
    if command -v git &> /dev/null; then
        echo -e "[信息] 使用git克隆获取最新版本..."
        TMP_DIR=$(mktemp -d)
        git clone --depth=1 https://github.com/AlexKris/profile.git "$TMP_DIR"
        cp "$TMP_DIR/tool/setup.sh" ./setup.sh
        rm -rf "$TMP_DIR"
    else
        echo -e "[信息] git未安装，使用wget下载..."
        wget -N "https://raw.githubusercontent.com/AlexKris/profile/main/tool/setup.sh?$(date +%s)" -O setup.sh
    fi
    
    echo -e "[信息] 更新完成，正在执行新脚本..."
    bash setup.sh
}

# 修复 sudo 的 'unable to resolve host' 问题
fix_sudo_issue(){
    # 确保 sudo 已安装
    if ! command -v sudo &> /dev/null; then
        echo -e "[信息] sudo 未安装，正在安装..."
        if [ -f /etc/debian_version ]; then
            apt update -y && apt install -y sudo
        elif [ -f /etc/redhat-release ]; then
            if command -v dnf &> /dev/null; then
                dnf install -y sudo
            else
                yum install -y sudo
            fi
        else
            echo -e "[错误] 不支持的操作系统，无法安装 sudo"
            return 1
        fi
    fi
    
    # 确保当前用户在 sudo 组中
    CURRENT_USER=$(whoami)
    if ! groups $CURRENT_USER | grep -q "\bsudo\b"; then
        echo -e "[信息] 将当前用户 $CURRENT_USER 添加到 sudo 组..."
        if [ -f /etc/debian_version ]; then
            if [ "$CURRENT_USER" != "root" ]; then
                usermod -aG sudo $CURRENT_USER
                echo -e "[信息] 用户 $CURRENT_USER 已添加到 sudo 组，可能需要重新登录才能生效"
            fi
        elif [ -f /etc/redhat-release ]; then
            if [ "$CURRENT_USER" != "root" ]; then
                usermod -aG wheel $CURRENT_USER
                echo -e "[信息] 用户 $CURRENT_USER 已添加到 wheel 组，可能需要重新登录才能生效"
            fi
        fi
    fi
    
    # 修复 sudo 的 unable to resolve host 问题
    if sudo -v 2>&1 | grep -q "unable to resolve host"; then
        echo -e "[信息] 修复 'sudo: unable to resolve host' 问题..."
        HOSTNAME=$(hostname)
        if ! grep -q "$HOSTNAME" /etc/hosts; then
            echo "127.0.1.1   $HOSTNAME" | sudo tee -a /etc/hosts
            echo -e "[信息] 已将 $HOSTNAME 添加到 /etc/hosts"
        else
            echo -e "[提示] $HOSTNAME 已存在于 /etc/hosts"
        fi
    else
        echo -e "[信息] sudo 正常运行，无需修复"
    fi
}

# 更新系统包并安装必要的软件
update_system_install_dependencies() {
    echo -e "[信息] 正在更新系统包..."
    if [ -f /etc/debian_version ]; then
        echo -e "[信息] 检测到 Debian/Ubuntu 系统..."
        sudo apt update && sudo apt upgrade -y && sudo apt full-upgrade -y && sudo apt autoclean -y && sudo apt autoremove -y

        echo -e "[信息] 正在安装 wget curl vim unzip zip fail2ban rsyslog iptables iperf3 mtr..."
        sudo apt install -y wget curl vim unzip zip fail2ban rsyslog iptables iperf3 mtr
    elif [ -f /etc/redhat-release ]; then
        echo -e "[信息] 检测到 RHEL/CentOS 系统..."
        
        # 检查是否有 dnf（CentOS/RHEL 8+）
        if command -v dnf &> /dev/null; then
            echo -e "[信息] 使用 dnf 包管理器进行更新..."
            sudo dnf update -y
            
            echo -e "[信息] 正在安装 wget curl vim unzip zip fail2ban rsyslog iptables iperf3 mtr..."
            sudo dnf install -y wget curl vim unzip zip fail2ban rsyslog iptables iperf3 mtr
        else
            echo -e "[信息] 使用 yum 包管理器进行更新..."
            sudo yum update -y
            
            echo -e "[信息] 正在安装 wget curl vim unzip zip fail2ban rsyslog iptables iperf3 mtr..."
            sudo yum install -y wget curl vim unzip zip fail2ban rsyslog iptables iperf3 mtr
        fi
    else
        echo -e "[错误] 不支持的操作系统，只支持Debian/Ubuntu和CentOS/RHEL。"
        exit 1
    fi
    echo -e "[信息] 系统更新完成。"
    echo -e "[信息] 安装 wget curl vim unzip zip fail2ban rsyslog iptables iperf3 mtr 完成。"
}

# 配置 SSH 公钥认证
configure_ssh_keys(){
    SSH_DIR="$HOME/.ssh"
    AUTHORIZED_KEYS="$SSH_DIR/authorized_keys"

    # 检查并创建 .ssh 目录
    if [ ! -d "$SSH_DIR" ]; then
        mkdir -p "$SSH_DIR"
        chmod 700 "$SSH_DIR"
        echo -e "[信息] 已创建 $SSH_DIR 目录"
    else
        # 确保目录权限正确
        current_perm=$(stat -c %a "$SSH_DIR")
        if [ "$current_perm" != "700" ]; then
            chmod 700 "$SSH_DIR"
            echo -e "[信息] 已修复 $SSH_DIR 目录权限 (从 $current_perm 改为 700)"
        else
            echo -e "[提示] $SSH_DIR 目录已存在，权限正确"
        fi
    fi

    # 检查并创建 authorized_keys 文件
    if [ ! -f "$AUTHORIZED_KEYS" ]; then
        touch "$AUTHORIZED_KEYS"
        chmod 600 "$AUTHORIZED_KEYS"
        echo -e "[信息] 已创建 $AUTHORIZED_KEYS 文件"
    else
        # 确保文件权限正确
        current_perm=$(stat -c %a "$AUTHORIZED_KEYS")
        if [ "$current_perm" != "600" ]; then
            chmod 600 "$AUTHORIZED_KEYS"
            echo -e "[信息] 已修复 $AUTHORIZED_KEYS 文件权限 (从 $current_perm 改为 600)"
        else
            echo -e "[提示] $AUTHORIZED_KEYS 文件已存在，权限正确"
        fi
    fi

    # 添加 SSH 公钥
    if [ -n "$SSH_KEY" ]; then
        # 验证公钥格式
        if ! echo "$SSH_KEY" | grep -qE "^(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521) "; then
            echo -e "[警告] 提供的 SSH 公钥格式可能不正确。标准格式应该以 'ssh-rsa', 'ssh-ed25519' 等开头。"
            read -p "是否仍然继续添加此密钥？(y/n): " confirm
            if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
                echo -e "[信息] 已取消添加 SSH 公钥"
                return
            fi
        fi
        
        # 如果提供了命令行参数的SSH密钥
        if grep -qF "$SSH_KEY" "$AUTHORIZED_KEYS"; then
            echo -e "[提示] 命令行提供的公钥已存在于 $AUTHORIZED_KEYS"
        else
            echo "$SSH_KEY" >> "$AUTHORIZED_KEYS"
            echo -e "[信息] 已将命令行提供的公钥添加到 $AUTHORIZED_KEYS"
        fi
    else
        # 如果没有通过命令行提供SSH密钥，则交互式输入
        read -p "请输入您的 SSH 公钥（直接回车跳过）： " INPUT_SSH_KEY
        if [ -n "$INPUT_SSH_KEY" ]; then
            # 验证公钥格式
            if ! echo "$INPUT_SSH_KEY" | grep -qE "^(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521) "; then
                echo -e "[警告] 提供的 SSH 公钥格式可能不正确。标准格式应该以 'ssh-rsa', 'ssh-ed25519' 等开头。"
                read -p "是否仍然继续添加此密钥？(y/n): " confirm
                if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
                    echo -e "[信息] 已取消添加 SSH 公钥"
                    return
                fi
            fi
            
            if grep -qF "$INPUT_SSH_KEY" "$AUTHORIZED_KEYS"; then
                echo -e "[提示] 公钥已存在于 $AUTHORIZED_KEYS"
            else
                echo "$INPUT_SSH_KEY" >> "$AUTHORIZED_KEYS"
                echo -e "[信息] 已将公钥添加到 $AUTHORIZED_KEYS"
            fi
        else
            echo -e "[提示] 未输入任何公钥，跳过此步骤"
        fi
    fi
}

# 检查并启用 SSH 公钥认证
enable_ssh_pubkey_auth(){
    SSH_CONFIG="/etc/ssh/sshd_config"

    # 检查是否已启用 PubkeyAuthentication
    if grep -E "^\s*PubkeyAuthentication\s+yes" "$SSH_CONFIG" > /dev/null; then
        echo -e "[信息] SSH 已启用公钥认证"
    else
        echo -e "[信息] SSH 未启用公钥认证，正在启用..."

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

        # 重启 SSH 服务
        sudo systemctl restart ssh
        echo -e "[信息] SSH 公钥认证已启用，并重启了 SSH 服务"
    fi
}

# 配置 fail2ban 和 rsyslog
configure_fail2ban(){
    echo -e "[信息] 配置 fail2ban..."
    
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
        echo -e "[信息] /var/log/auth.log 不存在，正在配置 rsyslog..."

        # 配置 rsyslog
        sudo sed -i '/^auth,authpriv.\*/d' /etc/rsyslog.conf
        echo "auth,authpriv.*          /var/log/auth.log" | sudo tee -a /etc/rsyslog.conf
        sudo systemctl restart rsyslog
        echo -e "[信息] 已配置 rsyslog 并重启服务"
    else
        echo -e "[提示] /var/log/auth.log 已存在"
    fi

    # 创建 fail2ban 的自定义配置
    sudo mkdir -p /etc/fail2ban/jail.d
    sudo tee /etc/fail2ban/jail.d/custom.conf > /dev/null << EOF
[DEFAULT]
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
    
    # 验证 fail2ban 状态
    if sudo systemctl is-active fail2ban &> /dev/null; then
        echo -e "[信息] fail2ban 服务已成功启动并配置"
        if command -v fail2ban-client &> /dev/null; then
            echo -e "[信息] fail2ban 状态:"
            sudo fail2ban-client status
        fi
    else
        echo -e "[警告] fail2ban 服务可能未正确启动，请手动检查"
    fi
}

# 检查并设置时区为香港
configure_timezone(){
    CURRENT_TIMEZONE=$(timedatectl | grep "Time zone" | awk '{print $3}')
    TARGET_TIMEZONE="Asia/Hong_Kong"

    if [ "$CURRENT_TIMEZONE" != "$TARGET_TIMEZONE" ]; then
        echo -e "[信息] 当前时区为 $CURRENT_TIMEZONE，正在设置为 $TARGET_TIMEZONE..."
        sudo timedatectl set-timezone "$TARGET_TIMEZONE"
        echo -e "[信息] 时区已设置为 $TARGET_TIMEZONE"
    else
        echo -e "[信息] 时区已是 $TARGET_TIMEZONE，无需更改"
    fi

    # 配置时间同步
    echo -e "[信息] 配置时间同步服务..."
    if [ -f /etc/debian_version ]; then
        # Debian/Ubuntu 系统
        echo -e "[信息] 检测到 Debian/Ubuntu 系统，使用 systemd-timesyncd 或 chrony 配置时间同步"
        
        # 检查是否有 chrony
        if command -v chronyd &> /dev/null; then
            echo -e "[信息] 使用 chrony 进行时间同步"
            sudo apt install -y chrony
            # 配置 chrony 使用亚洲时间服务器
            sudo tee /etc/chrony/chrony.conf > /dev/null << EOF
pool asia.pool.ntp.org iburst
keyfile /etc/chrony/chrony.keys
driftfile /var/lib/chrony/chrony.drift
logdir /var/log/chrony
maxupdateskew 100.0
rtcsync
makestep 1 3
EOF
            sudo systemctl restart chrony
            sudo systemctl enable chrony
            echo -e "[信息] chrony 服务已配置并启用"
        else
            # 使用 systemd-timesyncd
            echo -e "[信息] 使用 systemd-timesyncd 进行时间同步"
            sudo apt install -y systemd-timesyncd
            sudo tee /etc/systemd/timesyncd.conf > /dev/null << EOF
[Time]
NTP=asia.pool.ntp.org
FallbackNTP=0.debian.pool.ntp.org 1.debian.pool.ntp.org 2.debian.pool.ntp.org 3.debian.pool.ntp.org
EOF
            sudo systemctl restart systemd-timesyncd
            sudo systemctl enable systemd-timesyncd
            echo -e "[信息] systemd-timesyncd 服务已配置并启用"
        fi
    elif [ -f /etc/redhat-release ]; then
        # CentOS/RHEL 系统
        echo -e "[信息] 检测到 CentOS/RHEL 系统，使用 chronyd 配置时间同步"
        
        # CentOS 7+ 使用 chronyd
        sudo yum install -y chrony
        # 配置 chrony 使用亚洲时间服务器
        sudo tee /etc/chrony.conf > /dev/null << EOF
server asia.pool.ntp.org iburst
driftfile /var/lib/chrony/drift
makestep 1.0 3
rtcsync
logdir /var/log/chrony
EOF
        sudo systemctl start chronyd
        sudo systemctl enable chronyd
        echo -e "[信息] chronyd 服务已配置并启用"
    else
        echo -e "[错误] 不支持的操作系统，无法配置时间同步"
    fi

    # 检查时间同步状态
    if systemctl is-active systemd-timesyncd &> /dev/null || systemctl is-active chrony &> /dev/null || systemctl is-active chronyd &> /dev/null; then
        echo -e "[信息] 时间同步服务已成功启用"
    else
        echo -e "[警告] 时间同步服务可能未正确启用，请手动检查"
    fi
}

# 检查并启用 BBR
configure_bbr(){
    # 检查内核版本是否支持 BBR
    KERNEL_VERSION=$(uname -r | awk -F '-' '{print $1}')
    if dpkg --compare-versions "$KERNEL_VERSION" "ge" "4.9"; then
        echo -e "[信息] 当前内核版本为 $KERNEL_VERSION，支持 BBR"
    else
        echo -e "[错误] 当前内核版本为 $KERNEL_VERSION，不支持 BBR，请升级内核后再试"
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
        echo -e "[信息] BBR 已启用"
        BBR_ENABLED=1
    fi
    
    if [ "$CURRENT_QDISC" = "fq" ]; then
        echo -e "[信息] FQ 队列调度器已启用"
        FQ_ENABLED=1
    fi
    
    # 如果需要更新配置
    if [ $BBR_ENABLED -eq 0 ] || [ $FQ_ENABLED -eq 0 ]; then
        if [ $BBR_ENABLED -eq 0 ]; then
            echo -e "[信息] BBR 未启用，正在启用..."
        fi
        
        if [ $FQ_ENABLED -eq 0 ]; then
            echo -e "[信息] FQ 队列调度器未启用，正在启用..."
        fi
        
        sudo modprobe tcp_bbr
        if ! lsmod | grep -q "tcp_bbr"; then
            echo -e "[错误] 无法加载 tcp_bbr 模块"
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
            echo -e "[信息] BBR 和 FQ 队列调度器已成功启用"
        else
            echo -e "[错误] 配置更新失败，请手动检查"
            echo -e "当前拥塞控制算法: $CURRENT_CC, 当前队列调度器: $CURRENT_QDISC"
        fi
    fi
}

# 检查并启用内核 IP 转发
configure_ip_forward(){
    # 获取当前内核 IP 转发状态
    CURRENT_CC=$(sysctl -n net.ipv4.ip_forward)

    # 检查是否已启用内核 IP 转发
    if [ "$CURRENT_CC" = "1" ]; then
        echo -e "[信息] 内核 IP 转发 已启用"
    else
        echo -e "[信息] 内核 IP 转发 未启用，正在启用..."
        sudo tee -a /etc/sysctl.conf > /dev/null << EOF
net.ipv4.ip_forward = 1
EOF
        sudo sysctl -p
        # 再次获取当前的内核 IP 转发状态
        CURRENT_CC=$(sysctl -n net.ipv4.ip_forward)
        if [ "$CURRENT_CC" = "1" ]; then
            echo -e "[信息] 内核 IP 转发 已成功启用"
        else
            echo -e "[错误] 内核 IP 转发 启用失败，请手动检查"
        fi
    fi
}

# 禁用SSH密码登录
disable_ssh_password_login() {
    SSH_CONFIG="/etc/ssh/sshd_config"
    
    if [ "$DISABLE_SSH_PASSWD" = "true" ]; then
        echo -e "[信息] 正在禁用 SSH 密码登录..."
        
        # 确保公钥认证已启用
        if ! grep -E "^\s*PubkeyAuthentication\s+yes" "$SSH_CONFIG" > /dev/null; then
            echo -e "[警告] 请确保公钥认证已启用，否则可能无法登录系统"
            echo -e "[警告] 正在确保公钥认证启用..."
            if grep -E "^\s*PubkeyAuthentication\s+no" "$SSH_CONFIG" > /dev/null; then
                sudo sed -i 's/^\s*PubkeyAuthentication\s\+no/PubkeyAuthentication yes/' "$SSH_CONFIG"
            elif grep -E "^\s*#\s*PubkeyAuthentication" "$SSH_CONFIG" > /dev/null; then
                sudo sed -i 's/^\s*#\s*PubkeyAuthentication.*/PubkeyAuthentication yes/' "$SSH_CONFIG"
            else
                echo "PubkeyAuthentication yes" | sudo tee -a "$SSH_CONFIG"
            fi
        fi
        
        # 禁用密码认证
        if grep -E "^\s*PasswordAuthentication\s+no" "$SSH_CONFIG" > /dev/null; then
            echo -e "[信息] SSH 密码认证已禁用"
        else
            if grep -E "^\s*PasswordAuthentication\s+yes" "$SSH_CONFIG" > /dev/null; then
                sudo sed -i 's/^\s*PasswordAuthentication\s\+yes/PasswordAuthentication no/' "$SSH_CONFIG"
            elif grep -E "^\s*#\s*PasswordAuthentication" "$SSH_CONFIG" > /dev/null; then
                sudo sed -i 's/^\s*#\s*PasswordAuthentication.*/PasswordAuthentication no/' "$SSH_CONFIG"
            else
                echo "PasswordAuthentication no" | sudo tee -a "$SSH_CONFIG"
            fi
            echo -e "[信息] SSH 密码认证已禁用"
        fi
        
        # 禁用挑战应答认证
        if grep -E "^\s*ChallengeResponseAuthentication\s+no" "$SSH_CONFIG" > /dev/null; then
            echo -e "[信息] SSH 挑战应答认证已禁用"
        else
            if grep -E "^\s*ChallengeResponseAuthentication\s+yes" "$SSH_CONFIG" > /dev/null; then
                sudo sed -i 's/^\s*ChallengeResponseAuthentication\s\+yes/ChallengeResponseAuthentication no/' "$SSH_CONFIG"
            elif grep -E "^\s*#\s*ChallengeResponseAuthentication" "$SSH_CONFIG" > /dev/null; then
                sudo sed -i 's/^\s*#\s*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' "$SSH_CONFIG"
            else
                echo "ChallengeResponseAuthentication no" | sudo tee -a "$SSH_CONFIG"
            fi
            echo -e "[信息] SSH 挑战应答认证已禁用"
        fi
        
        # 禁用键盘交互认证
        if grep -E "^\s*KbdInteractiveAuthentication\s+no" "$SSH_CONFIG" > /dev/null; then
            echo -e "[信息] SSH 键盘交互认证已禁用"
        else
            if grep -E "^\s*KbdInteractiveAuthentication\s+yes" "$SSH_CONFIG" > /dev/null; then
                sudo sed -i 's/^\s*KbdInteractiveAuthentication\s\+yes/KbdInteractiveAuthentication no/' "$SSH_CONFIG"
            elif grep -E "^\s*#\s*KbdInteractiveAuthentication" "$SSH_CONFIG" > /dev/null; then
                sudo sed -i 's/^\s*#\s*KbdInteractiveAuthentication.*/KbdInteractiveAuthentication no/' "$SSH_CONFIG"
            else
                echo "KbdInteractiveAuthentication no" | sudo tee -a "$SSH_CONFIG"
            fi
            echo -e "[信息] SSH 键盘交互认证已禁用"
        fi
        
        # 对于旧版本SSH，禁用 KeyboardInteractive 认证
        if grep -E "^\s*KeyboardInteractive\s+no" "$SSH_CONFIG" > /dev/null || ! grep -q "KeyboardInteractive" "$SSH_CONFIG"; then
            echo -e "[信息] SSH KeyboardInteractive 认证检查完成"
        else
            if grep -E "^\s*KeyboardInteractive\s+yes" "$SSH_CONFIG" > /dev/null; then
                sudo sed -i 's/^\s*KeyboardInteractive\s\+yes/KeyboardInteractive no/' "$SSH_CONFIG"
                echo -e "[信息] SSH KeyboardInteractive 认证已禁用"
            fi
        fi
        
        # 禁用空密码
        if grep -E "^\s*PermitEmptyPasswords\s+no" "$SSH_CONFIG" > /dev/null; then
            echo -e "[信息] SSH 空密码已禁用"
        else
            if grep -E "^\s*PermitEmptyPasswords\s+yes" "$SSH_CONFIG" > /dev/null; then
                sudo sed -i 's/^\s*PermitEmptyPasswords\s\+yes/PermitEmptyPasswords no/' "$SSH_CONFIG"
            elif grep -E "^\s*#\s*PermitEmptyPasswords" "$SSH_CONFIG" > /dev/null; then
                sudo sed -i 's/^\s*#\s*PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$SSH_CONFIG"
            else
                echo "PermitEmptyPasswords no" | sudo tee -a "$SSH_CONFIG"
            fi
            echo -e "[信息] SSH 空密码已禁用"
        fi
        
        echo -e "[信息] SSH 密码登录已完全禁用"
        echo -e "[警告] 请确保您已经设置了 SSH 密钥，否则您将无法登录系统!"
    else
        echo -e "[信息] 未设置禁用 SSH 密码登录，跳过此步骤"
    fi
}

# 修改SSH端口
change_ssh_port() {
    SSH_CONFIG="/etc/ssh/sshd_config"
    
    # 检查是否需要修改SSH端口
    if [ "$SSH_PORT" != "22" ]; then
        echo -e "[信息] 正在将 SSH 端口修改为 $SSH_PORT..."
        
        # 验证端口号是否有效
        if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [ "$SSH_PORT" -lt 1024 ] || [ "$SSH_PORT" -gt 65535 ]; then
            echo -e "[错误] 无效的端口号: $SSH_PORT. 端口号应在 1024-65535 范围内"
            echo -e "[信息] 使用默认端口 22"
            SSH_PORT="22"
            return
        fi
        
        # 检查当前端口设置
        CURRENT_PORT=$(grep -E "^\s*Port\s+[0-9]+" "$SSH_CONFIG" | awk '{print $2}')
        
        if [ "$CURRENT_PORT" = "$SSH_PORT" ]; then
            echo -e "[信息] SSH 端口已经是 $SSH_PORT，无需修改"
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
            
            # 如果启用了防火墙，添加规则允许新端口
            if command -v ufw &> /dev/null && sudo ufw status | grep -q "active"; then
                echo -e "[信息] 检测到 UFW 防火墙，添加规则允许 SSH 端口 $SSH_PORT"
                sudo ufw allow "$SSH_PORT/tcp" comment 'SSH Port'
            elif command -v firewall-cmd &> /dev/null && sudo firewall-cmd --state | grep -q "running"; then
                echo -e "[信息] 检测到 firewalld 防火墙，添加规则允许 SSH 端口 $SSH_PORT"
                sudo firewall-cmd --permanent --add-port="$SSH_PORT/tcp"
                sudo firewall-cmd --reload
            elif command -v iptables &> /dev/null; then
                echo -e "[信息] 使用 iptables 添加规则允许 SSH 端口 $SSH_PORT"
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
            
            echo -e "[信息] SSH 端口已修改为 $SSH_PORT"
        fi
    else
        echo -e "[信息] 未设置修改 SSH 端口，保持默认端口 22"
    fi
}

# 重启SSH服务
restart_ssh_service() {
    echo -e "[信息] 重启 SSH 服务以应用更改..."
    
    # 检查系统使用的是哪种SSH服务名称
    if systemctl is-active ssh &>/dev/null; then
        sudo systemctl restart ssh
        echo -e "[信息] SSH 服务(ssh)已重启"
    elif systemctl is-active sshd &>/dev/null; then
        sudo systemctl restart sshd
        echo -e "[信息] SSH 服务(sshd)已重启"
    else
        echo -e "[警告] 无法确定SSH服务名称，请手动重启SSH服务"
    fi
}

# 主函数
main() {
    parse_args "$@"
    fix_sudo_issue
    update_system_install_dependencies
    configure_ssh_keys
    enable_ssh_pubkey_auth
    disable_ssh_password_login
    change_ssh_port
    restart_ssh_service
    configure_fail2ban
    configure_timezone
    configure_bbr
    configure_ip_forward
    harden_system
    
    echo -e "\n[信息] ========== 系统配置完成 =========="
    echo -e "[信息] SSH 端口: $SSH_PORT"
    if [ "$DISABLE_SSH_PASSWD" = "true" ]; then
        echo -e "[信息] SSH 密码登录: 已禁用"
    else
        echo -e "[信息] SSH 密码登录: 已启用"
    fi
    echo -e "[信息] fail2ban 状态: $(systemctl is-active fail2ban 2>/dev/null || echo '未运行')"
    echo -e "[信息] 当前时区: $(timedatectl | grep "Time zone" | awk '{print $3}')"
    echo -e "[信息] BBR 状态: $(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')"
    echo -e "[信息] IP 转发: $(sysctl -n net.ipv4.ip_forward)"
    echo -e "[信息] 请记住保存您的 SSH 密钥以便远程登录\n"
}

# 执行主函数
main "$@"

# 添加系统安全加固函数
harden_system() {
    echo -e "[信息] 正在执行系统安全加固..."
    
    # 1. 限制 root 登录
    SSH_CONFIG="/etc/ssh/sshd_config"
    if grep -E "^\s*PermitRootLogin\s+yes" "$SSH_CONFIG" > /dev/null; then
        echo -e "[信息] 禁用 root 直接登录..."
        sudo sed -i 's/^\s*PermitRootLogin\s\+yes/PermitRootLogin no/' "$SSH_CONFIG"
    elif ! grep -q "PermitRootLogin" "$SSH_CONFIG"; then
        echo "PermitRootLogin no" | sudo tee -a "$SSH_CONFIG"
    fi
    
    # 2. 修改SSH设置增强安全性
    echo -e "[信息] 配置SSH安全设置..."
    
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
        echo -e "[信息] 配置系统资源限制..."
        
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
    echo -e "[信息] 配置系统日志审计..."
    
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
        echo -e "[信息] 审计服务已配置并启用"
    fi
    
    echo -e "[信息] 系统安全加固完成"
}
