#!/bin/bash

# 定义颜色和提示信息
Green_font_prefix="\033[32m"
Red_font_prefix="\033[31m"
Yellow_font_prefix="\033[33m"
Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[信息]${Font_color_suffix}"
Error="${Red_font_prefix}[错误]${Font_color_suffix}"
Tip="${Yellow_font_prefix}[提示]${Font_color_suffix}"

# 更新脚本函数
update_shell(){
    wget -N "https://raw.githubusercontent.com/AlexKris/profile/main/tool/snell.sh" -O snell.sh && bash snell.sh
}

# 更新系统包
update_system(){
    echo -e "${Info} 正在更新系统包..."
    sudo apt update && sudo apt upgrade -y
    if [ $? -ne 0 ]; then
        echo -e "${Error} 系统更新失败，请检查网络连接。"
        exit 1
    fi
}

# 安装 Snell 服务
install_snell(){
    echo -e "${Info} 正在下载并安装 Snell 服务..."
    SNELL_VERSION="v4.1.1"
    SNELL_ARCH="amd64"  # 根据您的系统架构修改

    SNELL_URL="https://dl.nssurge.com/snell/snell-server-${SNELL_VERSION}-linux-${SNELL_ARCH}.zip"

    cd /tmp
    wget -O snell-server.zip "${SNELL_URL}"
    if [ $? -ne 0 ]; then
        echo -e "${Error} 下载 Snell 失败，请检查网络连接。"
        exit 1
    fi

    unzip snell-server.zip
    if [ $? -ne 0 ]; then
        echo -e "${Error} 解压 Snell 失败。"
        exit 1
    fi

    sudo mv snell-server /usr/local/bin/
    sudo chmod +x /usr/local/bin/snell-server
    echo -e "${Info} Snell 服务已安装。"
}

# 配置 systemd 服务
configure_systemd_service(){
    echo -e "${Info} 正在配置 Snell 的 systemd 服务..."
    sudo bash -c 'cat > /etc/systemd/system/snell.service <<EOF
[Unit]
Description=Snell Proxy Service
After=network.target

[Service]
Type=simple
DynamicUser=yes
LimitNOFILE=32768
ExecStart=/usr/local/bin/snell-server -c /etc/snell/snell-server.conf
AmbientCapabilities=CAP_NET_BIND_SERVICE
StandardOutput=journal
StandardError=journal
SyslogIdentifier=snell-server

[Install]
WantedBy=multi-user.target
EOF
'
    sudo systemctl daemon-reload
    echo -e "${Info} Snell 的 systemd 服务已配置。"
}

# 配置 Snell 服务
configure_snell(){
    echo -e "${Info} 正在配置 Snell 服务..."

    sudo mkdir -p /etc/snell

    read -p "请输入 Snell 监听端口 [默认: 46820]: " SNELL_PORT
    SNELL_PORT=${SNELL_PORT:-46820}

    read -p "请输入 Snell 密钥 (PSK) [默认随机生成]: " SNELL_PSK
    if [ -z "$SNELL_PSK" ]; then
        SNELL_PSK=$(head -c 16 /dev/urandom | md5sum | cut -d ' ' -f1)
        echo -e "${Tip} 已生成随机 PSK：$SNELL_PSK"
    fi

    sudo bash -c "cat > /etc/snell/snell-server.conf <<EOF
[snell-server]
listen = 0.0.0.0:${SNELL_PORT}
psk = ${SNELL_PSK}
ipv6 = false
EOF
"
    echo -e "${Info} Snell 配置文件已生成。"
}

# 启动 Snell 服务
start_snell(){
    echo -e "${Info} 正在启动 Snell 服务..."
    sudo systemctl start snell
    sleep 2
    sudo systemctl status snell --no-pager
}

# 停止 Snell 服务
stop_snell(){
    echo -e "${Info} 停止 Snell 服务..."
    sudo systemctl stop snell
}

# 重启 Snell 服务
restart_snell(){
    echo -e "${Info} 重启 Snell 服务..."
    sudo systemctl restart snell
    sleep 2
    sudo systemctl status snell --no-pager
}

# 查看 Snell 服务状态
status_snell(){
    echo -e "${Info} 获取 Snell 服务状态..."
    sudo systemctl status snell --no-pager
}

# 设置 Snell 服务开机自启
enable_snell(){
    echo -e "${Info} 设置 Snell 服务开机自启动..."
    sudo systemctl enable snell
}

# 卸载 Snell 服务
uninstall_snell(){
    echo -e "${Info} 卸载 Snell 服务..."
    sudo systemctl stop snell
    sudo systemctl disable snell
    sudo rm -f /usr/local/bin/snell-server
    sudo rm -f /etc/systemd/system/snell.service
    sudo rm -rf /etc/snell
    sudo systemctl daemon-reload
    echo -e "${Info} Snell 服务已卸载。"
}

# 主菜单
echo -e "\
${Green_font_prefix}1.${Font_color_suffix} 更新脚本
${Green_font_prefix}2.${Font_color_suffix} 安装 Snell 服务
${Green_font_prefix}3.${Font_color_suffix} 配置 Snell 服务
${Green_font_prefix}4.${Font_color_suffix} 启动 Snell 服务
${Green_font_prefix}5.${Font_color_suffix} 停止 Snell 服务
${Green_font_prefix}6.${Font_color_suffix} 重启 Snell 服务
${Green_font_prefix}7.${Font_color_suffix} 查看 Snell 服务状态
${Green_font_prefix}8.${Font_color_suffix} 卸载 Snell 服务
${Green_font_prefix}0.${Font_color_suffix} 退出脚本
"

read -p "请选择一个操作: " action

case $action in
    1)
        update_shell
        ;;
    2)
        update_system
        install_snell
        configure_systemd_service
        configure_snell
        enable_snell
        start_snell
        ;;
    3)
        configure_snell
        restart_snell
        ;;
    4)
        start_snell
        ;;
    5)
        stop_snell
        ;;
    6)
        restart_snell
        ;;
    7)
        status_snell
        ;;
    8)
        uninstall_snell
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