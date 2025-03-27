#!/bin/bash

# 更新脚本函数
update_shell(){
    wget -N "https://raw.githubusercontent.com/AlexKris/profile/main/tool/setup.sh" -O setup.sh && bash setup.sh
}

# 修复 sudo 的 'unable to resolve host' 问题
fix_sudo_issue(){
    apt update -y && apt install -y sudo
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
        echo -e "[提示] $SSH_DIR 目录已存在"
    fi

    # 检查并创建 authorized_keys 文件
    if [ ! -f "$AUTHORIZED_KEYS" ]; then
        touch "$AUTHORIZED_KEYS"
        chmod 600 "$AUTHORIZED_KEYS"
        echo -e "[信息] 已创建 $AUTHORIZED_KEYS 文件"
    else
        echo -e "[提示] $AUTHORIZED_KEYS 文件已存在"
    fi

    # 添加 SSH 公钥
    read -p "请输入您的 SSH 公钥（直接回车跳过）： " SSH_KEY
    if [ -n "$SSH_KEY" ]; then
        if grep -qxF "$SSH_KEY" "$AUTHORIZED_KEYS"; then
            echo -e "[提示] 公钥已存在于 $AUTHORIZED_KEYS"
        else
            echo "$SSH_KEY" >> "$AUTHORIZED_KEYS"
            echo -e "[信息] 已将公钥添加到 $AUTHORIZED_KEYS"
        fi
    else
        echo -e "[提示] 未输入任何公钥，跳过此步骤"
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
    # 检查 /var/log/auth.log 是否存在
    if [ ! -f /var/log/auth.log ]; then
        echo -e "[信息] /var/log/auth.log 不存在，正在配置 rsyslog..."
        sudo apt install -y rsyslog

        # 配置 rsyslog
        sudo sed -i '/^auth,authpriv.\*/d' /etc/rsyslog.conf
        echo "auth,authpriv.*          /var/log/auth.log" | sudo tee -a /etc/rsyslog.conf
        sudo systemctl restart rsyslog
        echo -e "[信息] 已配置 rsyslog 并重启服务"
    else
        echo -e "[提示] /var/log/auth.log 已存在"
    fi

    # 重启 fail2ban 服务
    sudo systemctl restart fail2ban
    echo -e "[信息] 已重启 fail2ban 服务"
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

fix_sudo_issue
update_system_install_dependencies
configure_ssh_keys
enable_ssh_pubkey_auth
configure_fail2ban
configure_timezone
configure_bbr
configure_ip_forward
