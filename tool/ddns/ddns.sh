#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

# CloudFlare DDNS Management Script
# Cron-first version with enhanced reliability and logging

SCRIPT_VERSION="2.5"
SCRIPT_NAME="cf-ddns"

# Function to show usage
show_usage() {
    echo "CloudFlare DDNS 管理脚本 v${SCRIPT_VERSION}"
    echo ""
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  install   安装 DDNS 服务（自动安装cron，创建执行脚本和定时任务）"
    echo "  run       手动执行一次 DDNS 更新"
    echo "  remove    移除 DDNS 服务（删除定时任务和执行脚本）"
    echo "  status    查看 DDNS 服务状态"
    echo ""
    echo "Install Options:"
    echo "  -k TOKEN     CloudFlare API Token (required)"
    echo "  -z ZONE      Zone name, e.g., example.com (required)"
    echo "  -h HOSTNAME  Hostname to update, e.g., server.example.com (required)"
    echo "  -t TYPE      Record type: A (IPv4) or AAAA (IPv6), default: A"
    echo "  -l TTL       TTL value (120-86400), default: 120"
    echo "  -i INTERVAL  Crontab interval in minutes, default: 5"
    echo "  -d DIR       Installation directory, default: ~/.local/bin"
    echo "  -b BOT_TOKEN Telegram Bot Token (optional)"
    echo "  -c CHAT_ID   Telegram Chat ID (optional)"
    echo ""
    echo "Run Options:"
    echo "  -f FORCE     Force update (true/false), default: false"
    echo ""
    echo "Examples:"
    echo "  # 安装 DDNS 服务"
    echo "  $0 install -k your_api_token -z example.com -h server.example.com"
    echo "  # 安装 DDNS 服务并启用 Telegram 通知"
    echo "  $0 install -k your_api_token -z example.com -h server.example.com -b bot_token -c chat_id"
    echo "  # 手动执行更新"
    echo "  $0 run"
    echo "  # 强制更新"
    echo "  $0 run -f true"
    echo "  # 移除服务"
    echo "  $0 remove"
    exit 1
}

# Function to auto-install cron service
install_cron_service() {
    echo "正在检测系统类型并安装cron..."
    
    # 检测包管理器并安装cron
    if command -v apt-get >/dev/null 2>&1; then
        # Debian/Ubuntu系统
        echo "检测到Debian/Ubuntu系统，使用apt安装cron"
        if sudo apt-get update >/dev/null 2>&1 && sudo apt-get install -y cron >/dev/null 2>&1; then
            sudo systemctl enable cron >/dev/null 2>&1
            sudo systemctl start cron >/dev/null 2>&1
            return 0
        fi
    elif command -v yum >/dev/null 2>&1; then
        # RHEL/CentOS 7及以下
        echo "检测到RHEL/CentOS系统，使用yum安装cronie"
        if sudo yum install -y cronie >/dev/null 2>&1; then
            sudo systemctl enable crond >/dev/null 2>&1
            sudo systemctl start crond >/dev/null 2>&1
            return 0
        fi
    elif command -v dnf >/dev/null 2>&1; then
        # Fedora/RHEL 8+
        echo "检测到Fedora/RHEL 8+系统，使用dnf安装cronie"
        if sudo dnf install -y cronie >/dev/null 2>&1; then
            sudo systemctl enable crond >/dev/null 2>&1
            sudo systemctl start crond >/dev/null 2>&1
            return 0
        fi
    elif command -v pacman >/dev/null 2>&1; then
        # Arch Linux
        echo "检测到Arch Linux系统，使用pacman安装cronie"
        if sudo pacman -S --noconfirm cronie >/dev/null 2>&1; then
            sudo systemctl enable cronie >/dev/null 2>&1
            sudo systemctl start cronie >/dev/null 2>&1
            return 0
        fi
    elif command -v apk >/dev/null 2>&1; then
        # Alpine Linux (常见于Docker容器)
        echo "检测到Alpine Linux系统，使用apk安装dcron"
        if sudo apk add --no-cache dcron >/dev/null 2>&1; then
            sudo rc-update add dcron default >/dev/null 2>&1
            sudo rc-service dcron start >/dev/null 2>&1
            return 0
        fi
    elif command -v zypper >/dev/null 2>&1; then
        # openSUSE
        echo "检测到openSUSE系统，使用zypper安装cron"
        if sudo zypper install -y cron >/dev/null 2>&1; then
            sudo systemctl enable cron >/dev/null 2>&1
            sudo systemctl start cron >/dev/null 2>&1
            return 0
        fi
    else
        echo "无法识别的包管理器，请手动安装cron服务"
        return 1
    fi
    
    echo "cron安装失败，可能需要管理员权限或网络连接"
    return 1
}

# Function to start cron service
start_cron_service() {
    # 尝试启动cron服务（适配不同系统）
    if systemctl start crond >/dev/null 2>&1 || \
       systemctl start cron >/dev/null 2>&1 || \
       service cron start >/dev/null 2>&1 || \
       rc-service dcron start >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

# Function to check and setup scheduler (Cron-first approach)
setup_scheduler() {
    local exec_script="$1"
    local interval="$2"
    local service_name="$3"
    
    echo "正在设置定时任务..."
    
    # 优先使用cron (推荐，兼容性最好)
    echo "使用cron定时任务（推荐方案）..."
    if setup_cron_with_checks "$exec_script" "$interval"; then
        echo "✓ cron 定时任务设置成功"
        return 0
    fi
    
    # 备选方案: systemd user timer
    echo "cron设置失败，尝试systemd timer..."
    if command -v systemctl >/dev/null 2>&1 && systemctl --user list-timers >/dev/null 2>&1; then
        if create_systemd_timer "$exec_script" "$interval" "$service_name"; then
            echo "✓ systemd timer 设置成功"
            return 0
        else
            echo "✗ systemd timer 设置失败"
        fi
    fi
    
    # 手动方案提示
    echo "⚠️  无法自动设置定时任务，请手动配置："
    show_manual_setup_guide "$exec_script" "$interval" "$service_name"
    return 1
}

# Function to create systemd timer
create_systemd_timer() {
    local exec_script="$1"
    local interval="$2"
    local service_name="$3"
    
    local user_systemd_dir="$HOME/.config/systemd/user"
    
    # 创建systemd用户目录
    if ! mkdir -p "$user_systemd_dir" 2>/dev/null; then
        echo "错误: 无法创建systemd用户目录"
        return 1
    fi
    
    # 创建service文件
    cat > "$user_systemd_dir/${service_name}.service" << EOF
[Unit]
Description=${service_name} execution service
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$exec_script
StandardOutput=journal
StandardError=journal
User=$USER
Environment=HOME=$HOME
EOF

    # 创建timer文件
    cat > "$user_systemd_dir/${service_name}.timer" << EOF
[Unit]
Description=${service_name} timer
Requires=${service_name}.service

[Timer]
OnCalendar=*:0/${interval}
Persistent=true

[Install]
WantedBy=timers.target
EOF

    # 重载systemd配置并启用timer
    if systemctl --user daemon-reload 2>/dev/null && \
       systemctl --user enable "$service_name.timer" 2>/dev/null && \
       systemctl --user start "$service_name.timer" 2>/dev/null; then
        echo "systemd timer 已创建并启动: $service_name.timer"
        echo "查看状态: systemctl --user status $service_name.timer"
        echo "查看日志: journalctl --user -u $service_name.service"
        return 0
    else
        echo "错误: systemd timer 启动失败"
        return 1
    fi
}

# Function to setup cron with comprehensive checks
setup_cron_with_checks() {
    local exec_script="$1"
    local interval="$2"
    local log_file="/var/log/ddns.log"
    local cron_cmd="*/$interval * * * * $exec_script >> $log_file 2>&1"
    
    # 1. 检查cron命令是否可用，如果没有则尝试安装
    if ! command -v crontab >/dev/null 2>&1; then
        echo "检测到系统未安装cron服务，尝试自动安装..."
        if ! install_cron_service; then
            echo "错误: cron服务安装失败，请手动安装后重试"
            return 1
        fi
        echo "✓ cron服务安装成功"
    fi
    
    # 2. 检查cron服务状态，如果未运行则尝试启动
    local cron_running=false
    if systemctl is-active crond >/dev/null 2>&1 || \
       systemctl is-active cron >/dev/null 2>&1 || \
       service cron status >/dev/null 2>&1 || \
       pgrep -x "crond\|cron" >/dev/null 2>&1; then
        cron_running=true
    fi
    
    if [ "$cron_running" = "false" ]; then
        echo "检测到cron服务未运行，尝试启动..."
        if start_cron_service; then
            echo "✓ cron服务启动成功"
        else
            echo "警告: 无法自动启动cron服务"
            echo "请手动启动: sudo systemctl start crond 或 sudo systemctl start cron"
        fi
    fi
    
    # 3. 测试crontab权限
    if ! crontab -l >/dev/null 2>&1; then
        echo "警告: 当前用户可能没有crontab权限"
        echo "请检查 /etc/cron.allow 和 /etc/cron.deny 文件"
    fi
    
    # 4. 移除现有的相同脚本定时任务
    if crontab -l 2>/dev/null | grep -F "$exec_script" >/dev/null; then
        crontab -l 2>/dev/null | grep -v -F "$exec_script" | crontab - 2>/dev/null
    fi
    
    # 5. 创建日志文件目录
    local log_dir=$(dirname "$log_file")
    if [ ! -d "$log_dir" ]; then
        if ! mkdir -p "$log_dir" 2>/dev/null; then
            echo "警告: 无法创建日志目录 $log_dir，使用 ~/.ddns/ddns.log"
            log_file="$HOME/.ddns/ddns.log"
            cron_cmd="*/$interval * * * * $exec_script >> $log_file 2>&1"
            mkdir -p "$(dirname "$log_file")"
        fi
    fi
    
    # 6. 添加新的定时任务
    if (crontab -l 2>/dev/null; echo "$cron_cmd") | crontab - 2>/dev/null; then
        echo "cron 定时任务: 每 $interval 分钟执行一次"
        echo "日志文件: $log_file"
        echo "查看任务: crontab -l"
        echo "查看日志: tail -f $log_file"
        return 0
    else
        echo "错误: 无法设置cron定时任务"
        return 1
    fi
}

# Function to show manual setup guide
show_manual_setup_guide() {
    local exec_script="$1"
    local interval="$2"
    local service_name="$3"
    
    echo ""
    echo "==================== 手动配置指南 ===================="
    echo ""
    echo "方案1: 手动添加cron任务（推荐）"
    echo "  运行: crontab -e"
    echo "  添加: */$interval * * * * $exec_script >> /var/log/ddns.log 2>&1"
    echo ""
    echo "方案2: 创建systemd用户timer"
    echo "  1. mkdir -p ~/.config/systemd/user"
    echo "  2. 创建 ~/.config/systemd/user/${service_name}.service"
    echo "  3. 创建 ~/.config/systemd/user/${service_name}.timer"
    echo "  4. systemctl --user enable ${service_name}.timer"
    echo "  5. systemctl --user start ${service_name}.timer"
    echo ""
    echo "方案3: 使用系统任务计划程序或其他调度工具"
    echo ""
    echo "=================================================="
}

# Function to remove systemd timer
remove_systemd_timer() {
    local service_name="$1"
    
    if systemctl --user is-enabled "$service_name.timer" >/dev/null 2>&1; then
        systemctl --user stop "$service_name.timer" 2>/dev/null
        systemctl --user disable "$service_name.timer" 2>/dev/null
        echo "已停止并禁用 systemd timer: $service_name.timer"
    fi
    
    local user_systemd_dir="$HOME/.config/systemd/user"
    if [ -f "$user_systemd_dir/${service_name}.service" ]; then
        rm -f "$user_systemd_dir/${service_name}.service"
        echo "已删除 systemd service 文件"
    fi
    
    if [ -f "$user_systemd_dir/${service_name}.timer" ]; then
        rm -f "$user_systemd_dir/${service_name}.timer"
        echo "已删除 systemd timer 文件"
    fi
    
    systemctl --user daemon-reload 2>/dev/null
}

# Function to create execution script
create_execution_script() {
    local install_dir="$1"
    local token="$2"
    local zone="$3"
    local hostname="$4"
    local record_type="$5"
    local ttl="$6"
    local bot_token="${7:-}"
    local chat_id="${8:-}"
    
    local exec_script="$install_dir/${SCRIPT_NAME}-exec.sh"
    
    cat > "$exec_script" << 'EOF'
#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

# CloudFlare DDNS Execution Script (Auto-generated)
# This script only performs DNS updates, no management functions

# Function to rotate logs if they get too large
rotate_logs_if_needed() {
    local log_file="$1"
    local max_lines="${2:-1000}"
    local keep_lines="${3:-500}"
    
    # Check if log file exists and has content
    if [ -f "$log_file" ]; then
        local current_lines
        current_lines=$(wc -l < "$log_file" 2>/dev/null || echo 0)
        
        # If log file exceeds max_lines, rotate it
        if [ "$current_lines" -gt "$max_lines" ]; then
            # Create a backup and keep only the most recent lines
            if tail -n "$keep_lines" "$log_file" > "${log_file}.tmp" 2>/dev/null; then
                mv "${log_file}.tmp" "$log_file" 2>/dev/null
                echo "$(date '+%Y-%m-%d %H:%M:%S'): 日志已轮转，从 $current_lines 行减少到 $keep_lines 行" >> "$log_file"
            fi
        fi
    fi
}

# Configuration (DO NOT MODIFY)
CFTOKEN="__TOKEN__"
CFZONE_NAME="__ZONE__"
CFRECORD_NAME="__HOSTNAME__"
CFRECORD_TYPE="__RECORD_TYPE__"
CFTTL=__TTL__
FORCE=false

# Telegram Configuration
TG_BOT_TOKEN="__BOT_TOKEN__"
TG_CHAT_ID="__CHAT_ID__"

# Parse force flag if provided
while getopts f: opts 2>/dev/null; do
    case ${opts} in
        f) FORCE=${OPTARG} ;;
    esac
done

# Function to send Telegram message
send_telegram_message() {
    local message="$1"
    local success="${2:-true}"
    
    # Skip if Telegram not configured
    [ -z "$TG_BOT_TOKEN" ] || [ -z "$TG_CHAT_ID" ] && return 0
    
    # Choose emoji based on success status
    local emoji="✅"
    [ "$success" = "false" ] && emoji="❌"
    
    local full_message="${emoji} DDNS 通知

🌐 域名: $CFRECORD_NAME
📍 IP地址: ${WAN_IP:-未知}
⏰ 时间: $(date '+%Y-%m-%d %H:%M:%S')

📝 消息: $message"
    
    # Send message via Telegram API
    curl -s -X POST "https://api.telegram.org/bot$TG_BOT_TOKEN/sendMessage" \
        -d "chat_id=$TG_CHAT_ID" \
        -d "text=$full_message" \
        -d "parse_mode=HTML" \
        >/dev/null 2>&1 || true
}

# IPv6 services list for better reliability
IPV6_SERVICES=(
    "https://api64.ipify.org"
    "https://ipv6.icanhazip.com"
    "https://ident.me"
    "https://ifconfig.me"
)

IPV4_SERVICES=(
    "https://api.ipify.org"
    "https://ipv4.icanhazip.com" 
    "https://ident.me"
    "https://ifconfig.me"
)

# Function to get IP address with fallback services
get_wan_ip() {
    local services=()
    local curl_protocol_flag=""

    if [ "$CFRECORD_TYPE" = "AAAA" ]; then
        services=("${IPV6_SERVICES[@]}")
        curl_protocol_flag="-6"
    else
        services=("${IPV4_SERVICES[@]}")
        curl_protocol_flag="-4"
    fi

    for service in "${services[@]}"; do
        local ip
        if ip=$(curl $curl_protocol_flag -s --connect-timeout 5 --max-time 10 "$service" 2>/dev/null); then
            if [ -n "$ip" ]; then
                # 验证是否为有效的 IP 地址格式
                if [ "$CFRECORD_TYPE" = "AAAA" ]; then
                    # IPv6: 必须包含冒号
                    if [[ "$ip" =~ : ]]; then
                        echo "$ip"
                        return 0
                    fi
                else
                    # IPv4: 匹配 x.x.x.x 格式 (简单验证)
                    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                        echo "$ip"
                        return 0
                    fi
                fi
                # 如果格式不对，记录到 stderr 并继续尝试下一个服务
                echo "$(date): 警告: $service 返回了无效的IP格式: $ip" >&2
            fi
        fi
    done
    return 1
}

# Create directory for cache files
DDNS_DIR="$HOME/.ddns"
mkdir -p "$DDNS_DIR"

# Rotate logs if needed (check common log locations)
# Priority: /var/log/ddns.log -> ~/.ddns/ddns.log -> skip if neither exists
for potential_log in "/var/log/ddns.log" "$HOME/.ddns/ddns.log"; do
    if [ -f "$potential_log" ] || [ -d "$(dirname "$potential_log")" ]; then
        rotate_logs_if_needed "$potential_log" 1000 500
        break
    fi
done

# Get current IP
WAN_IP=$(get_wan_ip || {
    echo "$(date): 错误: 无法获取公网 IP 地址" >&2
    send_telegram_message "无法获取公网 IP 地址" "false"
    exit 1
})

if [ -z "$WAN_IP" ]; then
    echo "$(date): 错误: 获取到的 IP 地址为空" >&2
    send_telegram_message "获取到的 IP 地址为空" "false"
    exit 1
fi

# Check cached IP
WAN_IP_FILE="$DDNS_DIR/.cf-wan_ip_$CFRECORD_NAME.txt"
if [ -f "$WAN_IP_FILE" ]; then
    OLD_WAN_IP=$(cat "$WAN_IP_FILE")
else
    OLD_WAN_IP=""
fi

# Skip update if IP unchanged and not forcing
if [ "$WAN_IP" = "$OLD_WAN_IP" ] && [ "$FORCE" = "false" ]; then
    echo "$(date): IP 地址未变化 ($WAN_IP)，跳过更新"
    exit 0
fi

# Handle FQDN
if [ "$CFRECORD_NAME" != "$CFZONE_NAME" ] && [[ "$CFRECORD_NAME" != *"$CFZONE_NAME" ]]; then
    CFRECORD_NAME="$CFRECORD_NAME.$CFZONE_NAME"
fi

# Get cached IDs
ID_FILE="$DDNS_DIR/.cf-id_$CFRECORD_NAME.txt"
if [ -f "$ID_FILE" ] && [ "$(wc -l < "$ID_FILE")" -eq 4 ] \
    && [ "$(sed -n '3p' "$ID_FILE")" = "$CFZONE_NAME" ] \
    && [ "$(sed -n '4p' "$ID_FILE")" = "$CFRECORD_NAME" ]; then
    CFZONE_ID=$(sed -n '1p' "$ID_FILE")
    CFRECORD_ID=$(sed -n '2p' "$ID_FILE")
else
    # Get Zone ID
    CFZONE_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$CFZONE_NAME" \
        -H "Authorization: Bearer $CFTOKEN" \
        -H "Content-Type: application/json" | \
        grep -Po '(?<="id":")[^"]*' | head -1)
    
    if [ -z "$CFZONE_ID" ]; then
        echo "$(date): 错误: 无法获取区域 ID" >&2
        send_telegram_message "无法获取 CloudFlare 区域 ID" "false"
        exit 1
    fi
    
    # Get Record ID
    CFRECORD_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$CFZONE_ID/dns_records?name=$CFRECORD_NAME" \
        -H "Authorization: Bearer $CFTOKEN" \
        -H "Content-Type: application/json" | \
        grep -Po '(?<="id":")[^"]*' | head -1)
    
    if [ -z "$CFRECORD_ID" ]; then
        echo "$(date): 错误: 无法获取记录 ID" >&2
        send_telegram_message "无法获取 DNS 记录 ID" "false"
        exit 1
    fi
    
    # Cache IDs
    {
        echo "$CFZONE_ID"
        echo "$CFRECORD_ID"
        echo "$CFZONE_NAME"
        echo "$CFRECORD_NAME"
    } > "$ID_FILE"
fi

# Update DNS record
RESPONSE=$(curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$CFZONE_ID/dns_records/$CFRECORD_ID" \
    -H "Authorization: Bearer $CFTOKEN" \
    -H "Content-Type: application/json" \
    --data "{\"type\":\"$CFRECORD_TYPE\",\"name\":\"$CFRECORD_NAME\",\"content\":\"$WAN_IP\",\"ttl\":$CFTTL}")

if echo "$RESPONSE" | grep -q '"success":true'; then
    echo "$(date): DNS 更新成功: $CFRECORD_NAME -> $WAN_IP"
    echo "$WAN_IP" > "$WAN_IP_FILE"
    
    # Send success notification
    if [ -n "$OLD_WAN_IP" ] && [ "$OLD_WAN_IP" != "$WAN_IP" ]; then
        send_telegram_message "DNS 记录更新成功！IP 地址从 $OLD_WAN_IP 变更为 $WAN_IP" "true"
    elif [ "$FORCE" = "true" ]; then
        send_telegram_message "强制更新 DNS 记录成功！" "true"
    fi
else
    echo "$(date): DNS 更新失败: $RESPONSE" >&2
    send_telegram_message "DNS 更新失败: $(echo "$RESPONSE" | grep -o '"message":"[^"]*"' | cut -d'"' -f4)" "false"
    exit 1
fi
EOF

    # Replace placeholders
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS sed syntax
        sed -i '' \
            -e "s|__TOKEN__|$token|g" \
            -e "s|__ZONE__|$zone|g" \
            -e "s|__HOSTNAME__|$hostname|g" \
            -e "s|__RECORD_TYPE__|$record_type|g" \
            -e "s|__TTL__|$ttl|g" \
            -e "s|__BOT_TOKEN__|$bot_token|g" \
            -e "s|__CHAT_ID__|$chat_id|g" \
            "$exec_script"
    else
        # Linux sed syntax
        sed -i \
            -e "s|__TOKEN__|$token|g" \
            -e "s|__ZONE__|$zone|g" \
            -e "s|__HOSTNAME__|$hostname|g" \
            -e "s|__RECORD_TYPE__|$record_type|g" \
            -e "s|__TTL__|$ttl|g" \
            -e "s|__BOT_TOKEN__|$bot_token|g" \
            -e "s|__CHAT_ID__|$chat_id|g" \
            "$exec_script"
    fi
    chmod 700 "$exec_script"
    echo "$exec_script"
}

# Function to install DDNS service
install_ddns() {
    local token="" zone="" hostname="" record_type="A" ttl=120 interval=5 install_dir="$HOME/.local/bin"
    local bot_token="" chat_id=""
    
    # Parse arguments
    while getopts k:z:h:t:l:i:d:b:c: opts; do
        case ${opts} in
            k) token=${OPTARG} ;;
            z) zone=${OPTARG} ;;
            h) hostname=${OPTARG} ;;
            t) record_type=${OPTARG} ;;
            l) ttl=${OPTARG} ;;
            i) interval=${OPTARG} ;;
            d) install_dir=${OPTARG} ;;
            b) bot_token=${OPTARG} ;;
            c) chat_id=${OPTARG} ;;
        esac
    done
    
    # Validate required parameters
    local missing_params=()
    [ -z "$token" ] && missing_params+=("API Token (-k)")
    [ -z "$zone" ] && missing_params+=("Zone Name (-z)")
    [ -z "$hostname" ] && missing_params+=("Hostname (-h)")
    
    if [ ${#missing_params[@]} -gt 0 ]; then
        echo "错误: 缺少必需参数:"
        printf '  %s\n' "${missing_params[@]}"
        exit 1
    fi
    
    # Validate Telegram parameters (both or neither)
    if [ -n "$bot_token" ] && [ -z "$chat_id" ]; then
        echo "错误: 设置了 Bot Token 但缺少 Chat ID (-c)"
        exit 1
    elif [ -z "$bot_token" ] && [ -n "$chat_id" ]; then
        echo "错误: 设置了 Chat ID 但缺少 Bot Token (-b)"
        exit 1
    fi
    
    # Create installation directory
    mkdir -p "$install_dir"
    
    # Create execution script
    echo "正在创建执行脚本..."
    local exec_script
    exec_script=$(create_execution_script "$install_dir" "$token" "$zone" "$hostname" "$record_type" "$ttl" "$bot_token" "$chat_id")
    
    # Setup scheduled task using enhanced scheduler
    echo "正在设置定时任务..."
    if ! setup_scheduler "$exec_script" "$interval" "$SCRIPT_NAME"; then
        echo "定时任务设置遇到问题，但脚本安装已完成"
        echo "可以手动运行测试: $0 run"
    fi
    
    echo "安装完成！"
    echo "执行脚本: $exec_script"
    echo "定时任务: 每 $interval 分钟执行一次"
    echo "域名记录: $hostname -> $record_type"
    
    if [ -n "$bot_token" ] && [ -n "$chat_id" ]; then
        echo "Telegram 通知: 已启用"
    else
        echo "Telegram 通知: 未启用"
    fi
    
    # Test execution
    echo ""
    echo "正在执行首次更新测试..."
    if "$exec_script"; then
        echo "测试成功！"
    else
        echo "测试失败，请检查配置"
        exit 1
    fi
}

# Function to run DDNS update manually
run_ddns() {
    local force="false"
    local exec_script="$HOME/.local/bin/${SCRIPT_NAME}-exec.sh"
    
    # Parse arguments
    while getopts f: opts; do
        case ${opts} in
            f) force=${OPTARG} ;;
        esac
    done
    
    if [ ! -f "$exec_script" ]; then
        echo "错误: 执行脚本不存在，请先运行 install 命令"
        exit 1
    fi
    
    if [ ! -x "$exec_script" ]; then
        echo "错误: 执行脚本没有执行权限"
        exit 1
    fi
    
    echo "正在执行 DDNS 更新..."
    if [ "$force" = "true" ]; then
        "$exec_script" -f true
    else
        "$exec_script"
    fi
}

# Function to remove DDNS service
remove_ddns() {
    local install_dir="$HOME/.local/bin"
    local exec_script="$install_dir/${SCRIPT_NAME}-exec.sh"
    
    echo "正在移除 DDNS 服务..."
    
    # Remove systemd timer if exists
    remove_systemd_timer "$SCRIPT_NAME"
    
    # Remove crontab entry
    if crontab -l 2>/dev/null | grep -F "$exec_script" >/dev/null; then
        crontab -l 2>/dev/null | grep -v -F "$exec_script" | crontab -
        echo "已移除 cron 定时任务"
    fi
    
    # Remove execution script
    if [ -f "$exec_script" ]; then
        rm -f "$exec_script"
        echo "已删除执行脚本: $exec_script"
    fi
    
    echo "DDNS 服务移除完成"
}

# Function to show service status
show_status() {
    local install_dir="$HOME/.local/bin"
    local exec_script="$install_dir/${SCRIPT_NAME}-exec.sh"
    
    echo "CloudFlare DDNS 服务状态:"
    echo "=========================="
    
    # Check execution script
    if [ -f "$exec_script" ]; then
        echo "✓ 执行脚本: $exec_script"
        
        # Extract configuration from script
        if grep -q "CFRECORD_NAME=" "$exec_script"; then
            local hostname
            hostname=$(grep "^CFRECORD_NAME=" "$exec_script" | head -1 | cut -d'"' -f2)
            echo "  域名: $hostname"
        fi
        
        if grep -q "CFRECORD_TYPE=" "$exec_script"; then
            local record_type
            record_type=$(grep "^CFRECORD_TYPE=" "$exec_script" | head -1 | cut -d'"' -f2)
            echo "  记录类型: $record_type"
        fi
        
        if grep -q "CFTTL=" "$exec_script"; then
            local ttl
            ttl=$(grep "^CFTTL=" "$exec_script" | head -1 | cut -d'=' -f2)
            echo "  TTL: $ttl"
        fi
    else
        echo "✗ 执行脚本不存在"
    fi
    
    # Check scheduled tasks
    local has_scheduler=false
    
    # Check crontab first (preferred method)
    if crontab -l 2>/dev/null | grep -F "$exec_script" >/dev/null; then
        echo "✓ cron 定时任务已设置（推荐方案）"
        local cron_line
        cron_line=$(crontab -l 2>/dev/null | grep -F "$exec_script")
        echo "  定时规则: $cron_line"
        
        # Parse interval from cron line
        local interval=$(echo "$cron_line" | awk '{print $1}' | sed 's/\*//' | sed 's|/||')
        [ -n "$interval" ] && echo "  执行间隔: 每 $interval 分钟"
        
        # Check log file
        local log_file=$(echo "$cron_line" | grep -o '>>[^2]*' | sed 's/>>//' | xargs)
        if [ -n "$log_file" ] && [ -f "$log_file" ]; then
            echo "  日志文件: $log_file ($(wc -l < "$log_file") 行)"
            echo "  最后执行: $(stat -c %y "$log_file" 2>/dev/null | cut -d. -f1)"
        fi
        has_scheduler=true
    fi
    
    # Check systemd timer (backup method)
    if systemctl --user is-enabled "${SCRIPT_NAME}.timer" >/dev/null 2>&1; then
        echo "✓ systemd timer 已设置（备选方案）"
        local timer_status
        timer_status=$(systemctl --user is-active "${SCRIPT_NAME}.timer" 2>/dev/null || echo "inactive")
        echo "  状态: $timer_status"
        if [ "$timer_status" = "active" ]; then
            # 获取详细的timer信息
            local timer_info
            timer_info=$(systemctl --user list-timers "${SCRIPT_NAME}.timer" --no-pager --no-legend 2>/dev/null)
            if [ -n "$timer_info" ]; then
                local next_run=$(echo "$timer_info" | awk '{print $1, $2}')
                local left_time=$(echo "$timer_info" | awk '{print $3}')
                
                if [ -n "$next_run" ] && [ "$next_run" != "- -" ]; then
                    echo "  下次运行: $next_run"
                fi
                if [ -n "$left_time" ] && [ "$left_time" != "-" ]; then
                    echo "  剩余时间: $left_time"
                fi
            fi
        fi
        has_scheduler=true
    fi
    
    if [ "$has_scheduler" = "false" ]; then
        echo "✗ 未发现定时任务配置"
    fi
    
    # Check Telegram configuration
    if [ -f "$exec_script" ]; then
        if grep -q "^TG_BOT_TOKEN=" "$exec_script" && ! grep -q 'TG_BOT_TOKEN=""' "$exec_script"; then
            echo "✓ Telegram 通知: 已配置"
        else
            echo "✗ Telegram 通知: 未配置"
        fi
    fi
    
    # Check current IP status
    if [ -f "$exec_script" ]; then
        echo ""
        echo "📍 IP 状态信息:"
        
        # Get current IP from multiple sources
        local current_ip=""
        local ip_services=("https://api.ipify.org" "https://ipv4.icanhazip.com" "https://ident.me")
        for service in "${ip_services[@]}"; do
            if current_ip=$(curl -4 -s --connect-timeout 5 --max-time 10 "$service" 2>/dev/null); then
                if [ -n "$current_ip" ]; then
                    echo "  当前公网IP: $current_ip"
                    break
                fi
            fi
        done
        
        if [ -z "$current_ip" ]; then
            echo "  当前公网IP: 无法获取"
        fi
        
        # Check cached IP and show comparison
        local hostname
        if hostname=$(grep "^CFRECORD_NAME=" "$exec_script" | head -1 | cut -d'"' -f2 2>/dev/null); then
            local ddns_dir="$HOME/.ddns"
            local ip_cache_file="$ddns_dir/.cf-wan_ip_$hostname.txt"
            
            if [ -f "$ip_cache_file" ]; then
                local cached_ip
                cached_ip=$(cat "$ip_cache_file" 2>/dev/null)
                if [ -n "$cached_ip" ]; then
                    echo "  DNS记录IP: $cached_ip"
                    
                    # Compare IPs
                    if [ -n "$current_ip" ]; then
                        if [ "$current_ip" = "$cached_ip" ]; then
                            echo "  IP状态: ✓ 同步（无需更新）"
                        else
                            echo "  IP状态: ⚠️  不同步（需要更新）"
                        fi
                    fi
                    
                    # Show last update time
                    local last_update
                    last_update=$(stat -c %y "$ip_cache_file" 2>/dev/null | cut -d. -f1)
                    [ -n "$last_update" ] && echo "  最后更新: $last_update"
                fi
            else
                echo "  DNS记录IP: 未缓存"
                echo "  IP状态: ⚠️  首次运行或缓存丢失"
            fi
        fi
    fi
    
    # Check cache files
    local ddns_dir="$HOME/.ddns"
    if [ -d "$ddns_dir" ]; then
        echo ""
        echo "✓ 缓存目录: $ddns_dir"
        local ip_files
        ip_files=$(find "$ddns_dir" -name ".cf-wan_ip_*.txt" 2>/dev/null | wc -l)
        echo "  IP 缓存文件: $ip_files 个"
        
        # Show cache file details
        if [ "$ip_files" -gt 0 ]; then
            echo "  缓存详情:"
            find "$ddns_dir" -name ".cf-wan_ip_*.txt" 2>/dev/null | while read -r cache_file; do
                if [ -f "$cache_file" ]; then
                    local domain_name
                    domain_name=$(basename "$cache_file" | sed 's/^\.cf-wan_ip_//' | sed 's/\.txt$//')
                    local cached_ip
                    cached_ip=$(cat "$cache_file" 2>/dev/null)
                    local cache_time
                    cache_time=$(stat -c %y "$cache_file" 2>/dev/null | cut -d. -f1)
                    echo "    - $domain_name: $cached_ip ($cache_time)"
                fi
            done
        fi
    else
        echo "✗ 缓存目录不存在"
    fi
}

# Main script logic
case "${1:-}" in
    install)
        shift
        install_ddns "$@"
        ;;
    run)
        shift
        run_ddns "$@"
        ;;
    remove)
        remove_ddns
        ;;
    status)
        show_status
        ;;
    *)
        show_usage
        ;;
esac