#!/bin/bash
#
# set_router.sh
#
# 功能：
# - 自动识别 npag (rel_nodeclient) 的端口
# - 自动修复 UDP/TCP mangle 规则
# - 自动修复策略路由 fwmark
# - systemd 自动安装、自动启用、自动启动
# - npag 重启自动修复端口
# - 每 20 秒检查一次 npag PID（低负载）
# - 可重复执行脚本（幂等）
#
# 用法：
#   set_router.sh           # 安装服务并立即修复
#   set_router.sh run       # 后台监控模式（systemd 调用）
#   set_router.sh fix       # 仅执行一次修复（不安装服务）
#   set_router.sh status    # 显示当前状态
#   set_router.sh clean     # 清理 iptables 和路由规则
#   set_router.sh uninstall # 完全卸载
#   set_router.sh -h        # 帮助信息
#

set -o pipefail

# ============ 配置区域 ============
SERVICE_NAME="set_router.service"
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME"
SCRIPT_PATH="/usr/local/sbin/set_router.sh"
NPAG_PROC="rel_nodeclient"
FWMARK=200
TABLE_ID=20000
CHECK_INTERVAL=20
CHAIN_NAME="FIX_NPAG"

# 可通过环境变量覆盖
PRIMARY_IF="${PRIMARY_IF:-eth0}"
FALLBACK_IF="${FALLBACK_IF:-eth2}"

# ============ 日志函数 ============
log() {
    echo "[set_router] $1"
}

# ============ 帮助信息 ============
show_help() {
    cat <<'EOF'
用法: set_router.sh [命令]

命令:
  (无参数)    安装 systemd 服务并立即修复
  run         后台监控模式（由 systemd 调用）
  fix         仅执行一次修复（不安装服务）
  status      显示当前状态
  clean       清理 iptables 和路由规则
  uninstall   完全卸载（停止服务、删除文件、清理规则）
  -h, --help  显示此帮助信息

环境变量:
  PRIMARY_IF   主网卡接口（默认: eth0）
  FALLBACK_IF  备用接口，当路由匹配此接口时回退到主接口（默认: eth2）

示例:
  PRIMARY_IF=ens192 ./set_router.sh       # 使用自定义主接口
  ./set_router.sh status                   # 查看当前状态
  ./set_router.sh uninstall                # 完全卸载
EOF
}

# ============ 清理规则 ============
clean_rules() {
    log "cleaning iptables and routing rules..."

    # 删除链跳转（可能存在多条，循环删除）
    while iptables -t mangle -D OUTPUT -j "$CHAIN_NAME" 2>/dev/null; do :; done
    while iptables -t mangle -D PREROUTING -j "$CHAIN_NAME" 2>/dev/null; do :; done

    # 删除链
    iptables -t mangle -F "$CHAIN_NAME" 2>/dev/null
    iptables -t mangle -X "$CHAIN_NAME" 2>/dev/null

    # 删除路由规则
    ip rule del fwmark "$FWMARK" table "$TABLE_ID" 2>/dev/null
    ip route flush table "$TABLE_ID" 2>/dev/null

    # 删除 PID 记录
    rm -f /run/npag_last.pid

    log "cleanup completed"
}

# ============ 卸载服务 ============
uninstall() {
    log "uninstalling service..."

    systemctl stop "$SERVICE_NAME" 2>/dev/null
    systemctl disable "$SERVICE_NAME" 2>/dev/null
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload

    clean_rules

    log "uninstall completed"
}

# ============ 显示状态 ============
show_status() {
    echo "=== npag 进程状态 ==="
    if pgrep -f "$NPAG_PROC" >/dev/null; then
        local pid
        pid=$(pgrep -f "$NPAG_PROC")
        echo "PID: $pid"
        echo "端口:"
        ss -tulpen 2>/dev/null | awk -v pid="$pid" '$0 ~ "pid="pid"," {print "  " $1 " " $5}'
    else
        echo "npag 未运行"
    fi

    echo ""
    echo "=== systemd 服务状态 ==="
    if [ -f "$SERVICE_FILE" ]; then
        systemctl status "$SERVICE_NAME" --no-pager 2>/dev/null | head -5
    else
        echo "服务未安装"
    fi

    echo ""
    echo "=== iptables mangle 规则 ==="
    if iptables -t mangle -L "$CHAIN_NAME" -n 2>/dev/null; then
        :
    else
        echo "链 $CHAIN_NAME 不存在"
    fi

    echo ""
    echo "=== 策略路由 ==="
    echo "规则:"
    ip rule list | grep -E "fwmark.*$FWMARK" || echo "  无 fwmark $FWMARK 规则"
    echo "路由表 $TABLE_ID:"
    ip route show table "$TABLE_ID" 2>/dev/null || echo "  路由表为空"

    echo ""
    echo "=== 上次修复的 PID ==="
    if [ -f /run/npag_last.pid ]; then
        cat /run/npag_last.pid
    else
        echo "无记录"
    fi
}

# ============ 安装 systemd 服务 ============
install_systemd() {
    # 自动复制脚本到目标路径
    local current_script
    current_script="$(readlink -f "$0")"
    if [ "$current_script" != "$SCRIPT_PATH" ]; then
        log "copying script to $SCRIPT_PATH..."
        cp "$current_script" "$SCRIPT_PATH"
        chmod +x "$SCRIPT_PATH"
    fi

    if [ ! -f "$SERVICE_FILE" ]; then
        log "creating systemd service..."

        cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Auto fix npag asymmetric routing
After=network.target

[Service]
Type=simple
ExecStart=$SCRIPT_PATH run
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

        chmod 644 "$SERVICE_FILE"
        systemctl daemon-reload
        systemctl enable "$SERVICE_NAME"

        log "systemd service installed"
    else
        log "systemd service already exists"
        systemctl daemon-reload
    fi

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log "systemd is running, restarting it..."
        systemctl restart "$SERVICE_NAME"
    else
        log "starting systemd service..."
        systemctl start "$SERVICE_NAME"
    fi
}

# ============ 检测 npag 端口 ============
detect_npag_ports() {
    local pid
    pid=$(pgrep -f "$NPAG_PROC" | head -1)
    if [ -z "$pid" ]; then
        return 1
    fi

    # 使用精确的 pid= 匹配，避免误匹配
    local ss_output
    ss_output=$(ss -tulpen 2>/dev/null)

    # 提取 UDP 端口（处理 IPv4 和 IPv6 格式）
    # 格式: 0.0.0.0:port 或 [::]:port 或 *:port
    NPAG_UDP_PORT=$(echo "$ss_output" | awk -v pid="$pid" '
        $0 ~ "pid="pid"," && /udp/ {
            addr = $5
            # 移除 IPv6 方括号
            gsub(/\[|\]/, "", addr)
            # 提取最后一个冒号后的端口
            n = split(addr, parts, ":")
            if (n > 0) print parts[n]
        }
    ' | head -1)

    # 提取 TCP 端口（可能有多个）
    NPAG_TCP_PORTS=$(echo "$ss_output" | awk -v pid="$pid" '
        $0 ~ "pid="pid"," && /tcp/ {
            addr = $5
            gsub(/\[|\]/, "", addr)
            n = split(addr, parts, ":")
            if (n > 0) print parts[n]
        }
    ' | sort -u | tr '\n' ' ')

    # 提取监听 IP
    local listen_ip
    listen_ip=$(echo "$ss_output" | awk -v pid="$pid" '
        $0 ~ "pid="pid"," && /udp/ {
            addr = $5
            gsub(/\[|\]/, "", addr)
            n = split(addr, parts, ":")
            # 重建 IP（除最后一部分外的所有部分）
            ip = ""
            for (i = 1; i < n; i++) {
                if (i > 1) ip = ip ":"
                ip = ip parts[i]
            }
            print ip
        }
    ' | head -1)

    # 如果监听在通配符地址，使用主接口 IP
    if [ "$listen_ip" = "*" ] || [ "$listen_ip" = "0.0.0.0" ] || [ -z "$listen_ip" ] || [ "$listen_ip" = "::" ]; then
        listen_ip=$(ip -o -4 addr show dev "$PRIMARY_IF" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
    fi

    NPAG_PID="$pid"
    NPAG_LISTEN_IP="$listen_ip"

    # 验证至少有一个端口被检测到
    if [ -z "$NPAG_UDP_PORT" ] && [ -z "$NPAG_TCP_PORTS" ]; then
        log "warning: no ports detected for pid $pid"
        return 1
    fi

    return 0
}

# ============ 确定出口接口和网关 ============
determine_exit() {
    local route
    route=$(ip route get 8.8.8.8 from "$NPAG_LISTEN_IP" 2>/dev/null)
    EXIT_IF=$(echo "$route" | grep -oP 'dev \K[^ ]+')
    EXIT_SRC=$(echo "$route" | grep -oP 'src \K[^ ]+')

    # 如果路由走备用接口，回退到主接口
    if [ "$EXIT_IF" = "$FALLBACK_IF" ]; then
        EXIT_IF="$PRIMARY_IF"
        EXIT_SRC=$(ip -o -4 addr show dev "$PRIMARY_IF" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
    fi

    # 获取默认网关
    GATEWAY=$(ip route | grep "^default" | head -n 1 | awk '{print $3}')

    if [ -z "$EXIT_IF" ] || [ -z "$GATEWAY" ]; then
        log "error: failed to determine exit interface or gateway"
        return 1
    fi

    return 0
}

# ============ 应用路由规则 ============
apply_routing_rules() {
    # 先清理旧规则
    ip rule del fwmark "$FWMARK" table "$TABLE_ID" 2>/dev/null
    ip route flush table "$TABLE_ID" 2>/dev/null

    # 添加新规则
    ip route add default via "$GATEWAY" dev "$EXIT_IF" src "$EXIT_SRC" table "$TABLE_ID"
    ip rule add fwmark "$FWMARK" table "$TABLE_ID"
}

# ============ 应用 mangle 规则 ============
apply_mangle_rules() {
    # 删除旧的跳转规则（循环删除确保清理干净）
    while iptables -t mangle -D OUTPUT -j "$CHAIN_NAME" 2>/dev/null; do :; done
    while iptables -t mangle -D PREROUTING -j "$CHAIN_NAME" 2>/dev/null; do :; done

    # 删除并重建链
    iptables -t mangle -F "$CHAIN_NAME" 2>/dev/null
    iptables -t mangle -X "$CHAIN_NAME" 2>/dev/null
    iptables -t mangle -N "$CHAIN_NAME"

    # 恢复连接标记（用于后续包）
    iptables -t mangle -A "$CHAIN_NAME" -j CONNMARK --restore-mark

    # 如果已有标记则跳过
    iptables -t mangle -A "$CHAIN_NAME" -m mark ! --mark 0 -j RETURN

    # UDP 端口规则
    if [ -n "$NPAG_UDP_PORT" ]; then
        iptables -t mangle -A "$CHAIN_NAME" -p udp --sport "$NPAG_UDP_PORT" -j MARK --set-mark "$FWMARK"
        iptables -t mangle -A "$CHAIN_NAME" -p udp --dport "$NPAG_UDP_PORT" -j MARK --set-mark "$FWMARK"
    fi

    # TCP 端口规则
    for p in $NPAG_TCP_PORTS; do
        [ -z "$p" ] && continue
        iptables -t mangle -A "$CHAIN_NAME" -p tcp --sport "$p" -j MARK --set-mark "$FWMARK"
        iptables -t mangle -A "$CHAIN_NAME" -p tcp --dport "$p" -j MARK --set-mark "$FWMARK"
    done

    # 保存标记到连接（用于后续包自动继承）
    iptables -t mangle -A "$CHAIN_NAME" -m mark ! --mark 0 -j CONNMARK --save-mark

    # 添加到 OUTPUT 和 PREROUTING 链
    iptables -t mangle -A OUTPUT -j "$CHAIN_NAME"
    iptables -t mangle -A PREROUTING -j "$CHAIN_NAME"
}

# ============ 执行修复 ============
fix_now() {
    if ! detect_npag_ports; then
        log "npag not running or no ports detected"
        return 1
    fi

    if ! determine_exit; then
        return 1
    fi

    apply_routing_rules
    apply_mangle_rules

    echo "$NPAG_PID" > /run/npag_last.pid

    log "fix completed: pid=$NPAG_PID udp=$NPAG_UDP_PORT tcp=[$NPAG_TCP_PORTS] exit=$EXIT_IF gw=$GATEWAY"
}

# ============ 主循环 ============
main_loop() {
    log "background monitoring started (interval=${CHECK_INTERVAL}s)"

    while true; do
        local current_pid
        current_pid=$(pgrep -f "$NPAG_PROC" | head -1)

        if [ -z "$current_pid" ]; then
            sleep "$CHECK_INTERVAL"
            continue
        fi

        local last_pid=""
        if [ -f /run/npag_last.pid ]; then
            last_pid=$(cat /run/npag_last.pid)
        fi

        if [ "$current_pid" != "$last_pid" ]; then
            log "npag pid changed from $last_pid to $current_pid, fixing..."
            fix_now
        fi

        sleep "$CHECK_INTERVAL"
    done
}

# ============ 主入口 ============
case "$1" in
    run)
        main_loop
        ;;
    fix)
        fix_now
        ;;
    status)
        show_status
        ;;
    clean)
        clean_rules
        ;;
    uninstall)
        uninstall
        ;;
    -h|--help)
        show_help
        ;;
    *)
        install_systemd
        fix_now
        ;;
esac

exit 0
