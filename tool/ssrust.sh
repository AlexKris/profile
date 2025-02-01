#!/bin/bash

# ==================================================
#  本脚本用于部署 Shadowsocks-rust，包含两种方式：
#   1) Docker 部署
#   2) 直接部署(非Docker)
#
#  功能特点：
#   - 可选择 aes-128-gcm 或 2022-blake3-aes-128-gcm (ss2022)
#   - 在直接部署时，用户可输入所需的 Shadowsocks-rust 版本号
#   - 根据当前系统架构（x86_64、aarch64）自动选择对应的安装包
#   - 初始化时会更新系统，注意可能耗时
#
#  适用于 Debian/Ubuntu 等常见 Linux 发行版
#  若需要支持其他包管理器或更多架构，请自行修改
# ==================================================

SSRUST_BASE_DIR="/root/ssrust"
SSRUST_CONFIG_DIR="${SSRUST_BASE_DIR}/conf"
SSRUST_DOCKER_DIR="${SSRUST_BASE_DIR}/docker"
DOCKER_IMAGE="ghcr.io/shadowsocks/ssserver-rust:latest"
DOCKER_COMPOSE_VERSION="3.0"

# 直接部署相关
SSRUST_DIRECT_DIR="/usr/local/bin"  # 放置 ssserver 的目录
SSRUST_DIRECT_CONFIG="/etc/shadowsocks-rust/config.json"
SSRUST_SYSTEMD_FILE="/etc/systemd/system/shadowsocks-rust.service"

# Docker Compose 命令名（某些系统可能使用 docker-compose-plugin ）
DOCKER_COMPOSE_CMD="docker-compose"

echo "=============================="
echo " Shadowsocks-rust 部署脚本 "
echo "=============================="

# -- 1. 更新系统包（可视情况去掉或移动位置） --
update_system() {
    echo "正在更新系统包，这可能需要较长时间..."
    sudo apt update && sudo apt upgrade -y && sudo apt full-upgrade -y
    sudo apt autoclean -y && sudo apt autoremove -y
}

# -- 2. 更新脚本本身 --
update_shell(){
    wget -N "https://raw.githubusercontent.com/AlexKris/profile/main/tool/ssrust.sh" -O ssrust.sh && bash ssrust.sh
}

# -- 3. 安装 Docker --
install_docker() {
    echo "正在检查 Docker 是否已安装..."
    if ! command -v docker &> /dev/null; then
        echo "Docker 未安装，开始安装 Docker..."
        sudo apt install docker.io -y
        if [ $? -ne 0 ]; then
            echo "Docker 安装失败，退出..."
            exit 1
        fi
    else
        echo "Docker 已经安装."
    fi
}

# -- 4. 安装 Docker Compose --
install_docker_compose() {
    echo "正在检查 Docker Compose 是否已安装..."
    if ! command -v "${DOCKER_COMPOSE_CMD}" &> /dev/null; then
        echo "Docker Compose 未安装，开始安装 Docker Compose..."
        sudo apt install docker-compose -y
        if [ $? -ne 0 ]; then
            echo "Docker Compose 安装失败，退出..."
            exit 1
        fi
    else
        echo "Docker Compose 已经安装."
    fi
}

# -- 5. 启用服务端 TCP Fast Open --
enable_tcp_fastopen() {
    echo "正在启用服务端 TCP Fast Open..."
    sed -i '/net.ipv4.tcp_fastopen/d' /etc/sysctl.conf
    cat >> /etc/sysctl.conf << EOF
net.ipv4.tcp_fastopen=3
EOF
    sysctl -p && sysctl --system
    echo "服务端 TCP Fast Open 已启用."
}

# -- 选择加密方式函数（将提示输出到stderr，仅返回最终加密方式） --
choose_encryption_method() {
    # 输出提示到 stderr
    echo "请选择加密方式:" >&2
    echo "1) aes-128-gcm (默认)" >&2
    echo "2) 2022-blake3-aes-128-gcm (ss2022)" >&2
    echo -n "输入数字选择 [1/2], 默认为 1: " >&2
    
    # 不使用 read -p ，而是先输出提示到 stderr，再单独 read
    read method_choice
    
    local method
    case "$method_choice" in
        2)
            method="2022-blake3-aes-128-gcm"
            ;;
        1|"")
            method="aes-128-gcm"
            ;;
        *)
            echo "输入无效，默认使用 aes-128-gcm" >&2
            method="aes-128-gcm"
            ;;
    esac

    # 最终只 echo 一行到 stdout
    echo "$method"
}

# =============== Docker 方式部署 shadowsocks-rust ===============
configure_and_start_ssrust() {
    echo "开始配置 (Docker) shadowsocks-rust..."
    mkdir -p "$SSRUST_CONFIG_DIR"
    mkdir -p "$SSRUST_DOCKER_DIR"

    read -p "请输入 Shadowsocks 监听端口: " port
    read -sp "请输入 Shadowsocks 密码: " password
    echo  # 换行

    echo "请选择网络模式：1) bridge（默认） 2) host"
    read -p "输入选择（默认为 1）: " network_mode_choice

    network_mode="bridge"
    if [ "$network_mode_choice" == "2" ]; then
        network_mode="host"
    fi

    # 选择加密方式
    enc_method=$(choose_encryption_method)
    echo "当前加密方式: $enc_method"

    # 生成 Docker 版 Shadowsocks 配置
    cat > "$SSRUST_CONFIG_DIR/config.json" <<EOF
{
    "servers": [
        {
            "server": "0.0.0.0",
            "server_port": $port,
            "method": "$enc_method",
            "password": "$password",
            "timeout": 300,
            "mode": "tcp_and_udp",
            "fast_open": true
        }
    ]
}
EOF

    # 生成 docker-compose.yml
    if [ "$network_mode" == "host" ]; then
        cat > "$SSRUST_DOCKER_DIR/docker-compose.yml" <<EOF
version: "$DOCKER_COMPOSE_VERSION"
services:
  shadowsocks:
    image: $DOCKER_IMAGE
    container_name: ss-rust
    restart: always
    network_mode: host
    volumes:
      - $SSRUST_CONFIG_DIR:/etc/shadowsocks-rust
EOF
    else
        cat > "$SSRUST_DOCKER_DIR/docker-compose.yml" <<EOF
version: "$DOCKER_COMPOSE_VERSION"
services:
  shadowsocks:
    image: $DOCKER_IMAGE
    container_name: ss-rust
    restart: always
    network_mode: bridge
    volumes:
      - $SSRUST_CONFIG_DIR:/etc/shadowsocks-rust
    ports:
      - "$port:$port"
      - "$port:$port/udp"
EOF
    fi

    # 启动
    echo "正在启动 shadowsocks-rust (Docker)..."
    cd "$SSRUST_DOCKER_DIR"
    docker-compose down
    docker-compose up -d

    if [ $? -eq 0 ]; then
        echo "shadowsocks-rust (Docker) 配置并启动完成."
        echo "已写入配置文件: $SSRUST_CONFIG_DIR/config.json"
    else
        echo "服务启动失败，请检查日志."
    fi
}

# 停止 Docker 方式 shadowsocks-rust
stop_ssrust() {
    echo "正在停止 (Docker) shadowsocks-rust..."
    cd "$SSRUST_DOCKER_DIR"
    docker-compose down
    echo "shadowsocks-rust 已停止."
}

# 卸载 Docker & Docker Compose
uninstall_docker_and_compose() {
    echo "正在卸载 Docker 和 Docker Compose..."
    sudo apt purge docker-compose -y && sudo apt autoremove --purge docker-compose -y
    sudo apt purge docker.io -y && sudo apt autoremove --purge docker.io -y
    echo "Docker 和 Docker Compose 已卸载完成."
}

# 清理 shadowsocks-rust 配置 (Docker 版本)
cleanup_ssrust() {
    echo "正在清理 shadowsocks-rust 配置 (Docker)..."
    rm -rf "$SSRUST_BASE_DIR"
    echo "shadowsocks-rust 配置已清理完成."
}

# =============== 直接部署(非 Docker)安装 Shadowsocks-rust ===============
install_ssrust_direct() {
    echo "正在检查系统中是否已有 ssserver..."
    if command -v ssserver &> /dev/null; then
        echo "系统已检测到 ssserver，可能已安装 shadowsocks-rust."
        read -p "是否继续覆盖安装？[y/n], 默认为 n: " cover
        cover=${cover:-n}
        if [ "$cover" != "y" ]; then
            echo "取消安装."
            return
        fi
    fi

    # 让用户输入需要安装的版本号，如 v1.15.3、v1.15.2 等
    read -p "请输入 Shadowsocks-rust 的版本号 (例如 v1.15.3): " SSRUST_VERSION

    # 检测当前系统架构
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)
            SSRUST_TARBALL="shadowsocks-${SSRUST_VERSION}.x86_64-unknown-linux-gnu.tar.xz"
            ;;
        aarch64 | arm64)
            SSRUST_TARBALL="shadowsocks-${SSRUST_VERSION}.aarch64-unknown-linux-gnu.tar.xz"
            ;;
        *)
            echo "未识别的架构: $ARCH, 将默认使用 x86_64-unknown-linux-gnu 包名." >&2
            SSRUST_TARBALL="shadowsocks-${SSRUST_VERSION}.x86_64-unknown-linux-gnu.tar.xz"
            ;;
    esac

    DOWNLOAD_URL="https://github.com/shadowsocks/shadowsocks-rust/releases/download/${SSRUST_VERSION}/${SSRUST_TARBALL}"

    echo "将下载 Shadowsocks-rust 包: $DOWNLOAD_URL" >&2
    echo "如果版本或架构不对，请 Ctrl+C 取消，然后手动修改脚本或换输入。" >&2

    # 开始下载
    cd /tmp
    wget -N "$DOWNLOAD_URL" -O "$SSRUST_TARBALL"
    if [ $? -ne 0 ]; then
        echo "下载失败，请检查网络或版本号是否存在."
        exit 1
    fi

    # 解压
    tar -xvf "$SSRUST_TARBALL"

    # 将可执行文件放置到 /usr/local/bin
    if [ -f "ssserver" ]; then
        mv ssserver "$SSRUST_DIRECT_DIR"
        chmod +x "$SSRUST_DIRECT_DIR/ssserver"
        echo "Shadowsocks-rust (ssserver) 已安装到 $SSRUST_DIRECT_DIR."
    else
        echo "解压后未找到 ssserver 文件，可能下载包不匹配或版本不存在."
        exit 1
    fi

    # 清理临时文件
    rm -f "$SSRUST_TARBALL"
}

# 配置并启动 Shadowsocks-rust (直接部署)
configure_and_start_ssrust_direct() {
    echo "配置并启动 Shadowsocks-rust (直接部署)..."
    if ! command -v ssserver &> /dev/null; then
        echo "未检测到 ssserver，请先执行 '直接部署安装' 步骤 (选项 9)."
        return
    fi

    # 创建配置目录
    mkdir -p "$(dirname "$SSRUST_DIRECT_CONFIG")"

    read -p "请输入 Shadowsocks 监听端口: " port
    read -sp "请输入 Shadowsocks 密码: " password
    echo  # 换行

    # 选择加密方式
    enc_method=$(choose_encryption_method)
    echo "当前加密方式: $enc_method"

    # 写入配置文件
    cat > "$SSRUST_DIRECT_CONFIG" <<EOF
{
    "servers": [
        {
            "server": "0.0.0.0",
            "server_port": $port,
            "method": "$enc_method",
            "password": "$password",
            "timeout": 300,
            "mode": "tcp_and_udp",
            "fast_open": true
        }
    ]
}
EOF

    # 创建 systemd 服务文件
    cat > "$SSRUST_SYSTEMD_FILE" <<EOF
[Unit]
Description=Shadowsocks-rust Service (ssserver)
After=network.target

[Service]
Type=simple
ExecStart=${SSRUST_DIRECT_DIR}/ssserver -c ${SSRUST_DIRECT_CONFIG}
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

    # 刷新 systemd 并启动
    systemctl daemon-reload
    systemctl enable shadowsocks-rust
    systemctl start shadowsocks-rust

    if systemctl status shadowsocks-rust --no-pager; then
        echo "Shadowsocks-rust 已启动 (直接部署)."
        echo "已写入配置文件: $SSRUST_DIRECT_CONFIG"
    else
        echo "服务启动失败，请检查日志: journalctl -u shadowsocks-rust"
    fi
}

# 停止 Shadowsocks-rust (直接部署)
stop_ssrust_direct() {
    echo "停止 Shadowsocks-rust (直接部署)"
    systemctl stop shadowsocks-rust
}

# 卸载 Shadowsocks-rust (直接部署)
uninstall_ssrust_direct() {
    echo "卸载 Shadowsocks-rust (直接部署)..."
    systemctl stop shadowsocks-rust
    systemctl disable shadowsocks-rust
    rm -f "$SSRUST_SYSTEMD_FILE"
    systemctl daemon-reload

    rm -f "$SSRUST_DIRECT_DIR/ssserver"
    rm -f "$SSRUST_DIRECT_CONFIG"

    echo "Shadowsocks-rust (直接部署) 已卸载."
}

# =============== 主菜单逻辑 ===============
main_menu() {
    echo "-----------------------------------------"
    echo "1. 更新脚本"
    echo "2. 安装 Docker & Docker Compose, 启用 TCP Fast Open, 并使用 Docker 部署 Shadowsocks-rust"
    echo "3. 安装 Docker & Docker Compose"
    echo "4. 启用服务端 TCP Fast Open"
    echo "5. 配置并启动 Shadowsocks-rust (Docker)"
    echo "6. 停止 Shadowsocks-rust (Docker)"
    echo "7. 卸载 Docker & Docker Compose"
    echo "8. 清理 Shadowsocks-rust 配置 (Docker)"
    echo "9. 直接部署安装 shadowsocks-rust (非 Docker)"
    echo "10. 配置并启动 Shadowsocks-rust (直接部署)"
    echo "11. 停止 Shadowsocks-rust (直接部署)"
    echo "12. 卸载 Shadowsocks-rust (直接部署)"
    echo "0. 退出"
    echo "-----------------------------------------"
    read -p "请选择一个操作: " action

    case $action in
        1)
            update_shell
            ;;
        2)
            install_docker
            install_docker_compose
            enable_tcp_fastopen
            configure_and_start_ssrust
            ;;
        3)
            install_docker
            install_docker_compose
            ;;
        4)
            enable_tcp_fastopen
            ;;
        5)
            configure_and_start_ssrust
            ;;
        6)
            stop_ssrust
            ;;
        7)
            uninstall_docker_and_compose
            ;;
        8)
            cleanup_ssrust
            ;;
        9)
            install_ssrust_direct
            ;;
        10)
            configure_and_start_ssrust_direct
            ;;
        11)
            stop_ssrust_direct
            ;;
        12)
            uninstall_ssrust_direct
            ;;
        0)
            echo "退出脚本."
            exit 0
            ;;
        *)
            echo "输入无效，请重新选择."
            ;;
    esac
}

# 可选：先更新系统包（如不需要可注释以下行）
update_system

# 进入主菜单循环
while true; do
    main_menu
done