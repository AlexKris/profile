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
            echo "127.0.1.1   $HOSTNAME" >> /etc/hosts
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
    read -p "请输入您的 SSH 公钥：" SSH_KEY
    if grep -q "$SSH_KEY" "$AUTHORIZED_KEYS"; then
        echo -e "${Tip} 公钥已存在于 $AUTHORIZED_KEYS"
    else
        echo "$SSH_KEY" >> "$AUTHORIZED_KEYS"
        echo -e "${Info} 已将公钥添加到 $AUTHORIZED_KEYS"
    fi
}

# 检查并启用 SSH 公钥认证
enable_ssh_pubkey_auth(){
    SSH_CONFIG="/etc/ssh/sshd_config"

    if grep -E "^\s*PubkeyAuthentication\s+yes" "$SSH_CONFIG" > /dev/null; then
        echo -e "${Info} SSH 已启用公钥认证"
    else
        echo -e "${Info} SSH 未启用公钥认证，正在启用..."
        sed -i 's/^#\s*PubkeyAuthentication.*/PubkeyAuthentication yes/' "$SSH_CONFIG"
        if ! grep -E "^\s*PubkeyAuthentication\s+yes" "$SSH_CONFIG" > /dev/null; then
            echo "PubkeyAuthentication yes" >> "$SSH_CONFIG"
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
        sed -i '/^auth,authpriv.\*/d' /etc/rsyslog.conf
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

# 主逻辑
echo -e "${Green_font_prefix}1.${Font_color_suffix} 更新脚本"
echo -e "${Green_font_prefix}2.${Font_color_suffix} 修复 sudo 问题"
echo -e "${Green_font_prefix}3.${Font_color_suffix} 安装必要的工具"
echo -e "${Green_font_prefix}4.${Font_color_suffix} 配置 SSH 公钥认证"
echo -e "${Green_font_prefix}5.${Font_color_suffix} 检查并启用 SSH 公钥认证"
echo -e "${Green_font_prefix}6.${Font_color_suffix} 配置 fail2ban 和 rsyslog"
echo -e "${Green_font_prefix}7.${Font_color_suffix} 执行所有操作"
echo -e "${Green_font_prefix}0.${Font_color_suffix} 退出脚本"
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
        fix_sudo_issue
        install_tools
        configure_ssh_keys
        enable_ssh_pubkey_auth
        configure_fail2ban
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