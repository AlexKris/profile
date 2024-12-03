#!/bin/bash

# 定义颜色和提示信息
Green_font_prefix="\033[32m"
Red_font_prefix="\033[31m"
Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[信息]${Font_color_suffix}"
Error="${Red_font_prefix}[错误]${Font_color_suffix}"
Tip="${Green_font_prefix}[提示]${Font_color_suffix}"

# 更新系统包并安装必要的软件
echo -e "${Info} 正在更新系统包..."
sudo apt update && sudo apt upgrade -y && sudo apt full-upgrade -y && sudo apt autoclean -y && sudo apt autoremove -y

# 更新脚本函数
update_shell(){
    wget -N "https://raw.githubusercontent.com/AlexKris/profile/main/tool/setup.sh" -O setup.sh && bash setup.sh
}

# 修复 sudo 的 'unable to resolve host' 问题
fix_sudo_issue(){
    if sudo -v 2>&1 | grep -q "unable to resolve host"; then
        echo -e "${Info} 修复 'sudo: unable to resolve host' 问题..."
        HOSTNAME=$(hostname)
        if ! grep -q "$HOSTNAME" /etc/hosts; then
            echo "127.0.1.1   $HOSTNAME" | sudo tee -a /etc/hosts
            echo -e "${Info} 已将 $HOSTNAME 添加到 /etc/hosts"
        else
            echo -e "${Tip} $HOSTNAME 已存在于 /etc/hosts"
        fi
    else
        echo -e "${Info} sudo 正常运行，无需修复"
    fi
}

# 安装必要的工具
install_tools(){
    echo -e "${Info} 安装必要的工具..."
    sudo apt install -y sudo wget unzip zip curl vim iperf3 fail2ban rsyslog
}

# 配置 SSH 公钥认证
configure_ssh_keys(){
    SSH_DIR="$HOME/.ssh"
    AUTHORIZED_KEYS="$SSH_DIR/authorized_keys"

    # 检查并创建 .ssh 目录
    if [ ! -d "$SSH_DIR" ]; then
        mkdir -p "$SSH_DIR"
        chmod 700 "$SSH_DIR"
        echo -e "${Info} 已创建 $SSH_DIR 目录"
    else
        echo -e "${Tip} $SSH_DIR 目录已存在"
    fi

    # 检查并创建 authorized_keys 文件
    if [ ! -f "$AUTHORIZED_KEYS" ]; then
        touch "$AUTHORIZED_KEYS"
        chmod 600 "$AUTHORIZED_KEYS"
        echo -e "${Info} 已创建 $AUTHORIZED_KEYS 文件"
    else
        echo -e "${Tip} $AUTHORIZED_KEYS 文件已存在"
    fi

    # 添加 SSH 公钥
    read -p "请输入您的 SSH 公钥（直接回车跳过）： " SSH_KEY
    if [ -n "$SSH_KEY" ]; then
        if grep -qxF "$SSH_KEY" "$AUTHORIZED_KEYS"; then
            echo -e "${Tip} 公钥已存在于 $AUTHORIZED_KEYS"
        else
            echo "$SSH_KEY" >> "$AUTHORIZED_KEYS"
            echo -e "${Info} 已将公钥添加到 $AUTHORIZED_KEYS"
        fi
    else
        echo -e "${Tip} 未输入任何公钥，跳过此步骤"
    fi
}

# 检查并启用 SSH 公钥认证
enable_ssh_pubkey_auth(){
    SSH_CONFIG="/etc/ssh/sshd_config"

    if grep -E "^\s*PubkeyAuthentication\s+yes" "$SSH_CONFIG" > /dev/null; then
        echo -e "${Info} SSH 已启用公钥认证"
    else
        echo -e "${Info} SSH 未启用公钥认证，正在启用..."
        sudo sed -i 's/^#\s*PubkeyAuthentication.*/PubkeyAuthentication yes/' "$SSH_CONFIG"
        if ! grep -E "^\s*PubkeyAuthentication\s+yes" "$SSH_CONFIG" > /dev/null; then
            echo "PubkeyAuthentication yes" | sudo tee -a "$SSH_CONFIG"
        fi
        sudo systemctl restart ssh
        echo -e "${Info} SSH 公钥认证已启用，并重启了 SSH 服务"
    fi
}

# 配置 fail2ban 和 rsyslog
configure_fail2ban(){
    # 检查 /var/log/auth.log 是否存在
    if [ ! -f /var/log/auth.log ]; then
        echo -e "${Info} /var/log/auth.log 不存在，正在配置 rsyslog..."
        sudo apt install -y rsyslog

        # 配置 rsyslog
        sudo sed -i '/^auth,authpriv.\*/d' /etc/rsyslog.conf
        echo "auth,authpriv.*          /var/log/auth.log" | sudo tee -a /etc/rsyslog.conf
        sudo systemctl restart rsyslog
        echo -e "${Info} 已配置 rsyslog 并重启服务"
    else
        echo -e "${Tip} /var/log/auth.log 已存在"
    fi

    # 重启 fail2ban 服务
    sudo systemctl restart fail2ban
    echo -e "${Info} 已重启 fail2ban 服务"
}

# 检查并设置时区为香港
configure_timezone(){
    CURRENT_TIMEZONE=$(timedatectl | grep "Time zone" | awk '{print $3}')
    TARGET_TIMEZONE="Asia/Hong_Kong"

    if [ "$CURRENT_TIMEZONE" != "$TARGET_TIMEZONE" ]; then
        echo -e "${Info} 当前时区为 $CURRENT_TIMEZONE，正在设置为 $TARGET_TIMEZONE..."
        sudo timedatectl set-timezone "$TARGET_TIMEZONE"
        echo -e "${Info} 时区已设置为 $TARGET_TIMEZONE"
    else
        echo -e "${Info} 时区已是 $TARGET_TIMEZONE，无需更改"
    fi
}

# 检查并启用 BBR
configure_bbr(){
    # 检查内核版本是否支持 BBR
    KERNEL_VERSION=$(uname -r | awk -F '-' '{print $1}')
    if dpkg --compare-versions "$KERNEL_VERSION" "ge" "4.9"; then
        echo -e "${Info} 当前内核版本为 $KERNEL_VERSION，支持 BBR"
    else
        echo -e "${Error} 当前内核版本为 $KERNEL_VERSION，不支持 BBR，请升级内核后再试"
        return
    fi

    # 获取当前的 TCP 拥塞控制算法
    CURRENT_CC=$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')

    # 检查是否已启用 BBR
    if [ "$CURRENT_CC" = "bbr" ]; then
        echo -e "${Info} BBR 已启用"
    else
        echo -e "${Info} BBR 未启用，正在启用..."
        sudo modprobe tcp_bbr
        if ! lsmod | grep -q "tcp_bbr"; then
            echo -e "${Error} 无法加载 tcp_bbr 模块"
            return
        fi
        sudo tee -a /etc/sysctl.conf > /dev/null << EOF
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
        sudo sysctl -p
        # 再次获取当前的 TCP 拥塞控制算法
        CURRENT_CC=$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')
        if [ "$CURRENT_CC" = "bbr" ]; then
            echo -e "${Info} BBR 已成功启用"
        else
            echo -e "${Error} BBR 启用失败，请手动检查"
        fi
    fi
}

# 主逻辑
echo -e "\
${Green_font_prefix}1.${Font_color_suffix} 更新脚本
${Green_font_prefix}2.${Font_color_suffix} 修复 sudo 问题
${Green_font_prefix}3.${Font_color_suffix} 安装必要的工具
${Green_font_prefix}4.${Font_color_suffix} 配置 SSH 公钥认证
${Green_font_prefix}5.${Font_color_suffix} 检查并启用 SSH 公钥认证
${Green_font_prefix}6.${Font_color_suffix} 配置 fail2ban 和 rsyslog
${Green_font_prefix}7.${Font_color_suffix} 检查并设置时区为香港
${Green_font_prefix}8.${Font_color_suffix} 检查并启用 BBR
${Green_font_prefix}9.${Font_color_suffix} 执行所有操作
${Green_font_prefix}0.${Font_color_suffix} 退出脚本
"
read -p "请选择一个操作: " action

case $action in
    1)
        update_shell
        ;;
    2)
        fix_sudo_issue
        ;;
    3)
        install_tools
        ;;
    4)
        configure_ssh_keys
        ;;
    5)
        enable_ssh_pubkey_auth
        ;;
    6)
        configure_fail2ban
        ;;
    7)
        configure_timezone
        ;;
    8)
        configure_bbr
        ;;
    9)
        fix_sudo_issue
        install_tools
        configure_ssh_keys
        enable_ssh_pubkey_auth
        configure_fail2ban
        configure_timezone
        configure_bbr
        ;;
    0)
        echo -e "${Info} 退出脚本..."
        exit 0
        ;;
    *)
        echo -e "${Error} 输入无效，退出..."
        exit 1
        ;;
esac