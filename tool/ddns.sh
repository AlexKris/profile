#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

# CloudFlare DDNS Management Script
# Enhanced version with separate execution script generation and Telegram notifications

SCRIPT_VERSION="2.1"
SCRIPT_NAME="cf-ddns"

# Function to show usage
show_usage() {
    echo "CloudFlare DDNS 管理脚本 v${SCRIPT_VERSION}"
    echo ""
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  install   安装 DDNS 服务（创建执行脚本和定时任务）"
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
                echo "$ip"
                return 0
            fi
        fi
    done
    return 1
}

# Create directory for cache files
DDNS_DIR="$HOME/.ddns"
mkdir -p "$DDNS_DIR"

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
    chmod +x "$exec_script"
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
    
    # Create crontab entry
    echo "正在设置定时任务..."
    local cron_cmd="*/$interval * * * * $exec_script >/dev/null 2>&1"
    
    # Remove existing entries for this script
    if crontab -l 2>/dev/null | grep -F "$exec_script" >/dev/null; then
        crontab -l 2>/dev/null | grep -v -F "$exec_script" | crontab -
    fi
    
    # Add new entry
    (crontab -l 2>/dev/null; echo "$cron_cmd") | crontab - 2>/dev/null || {
        echo "警告: 无法设置定时任务，可能需要手动添加:"
        echo "$cron_cmd"
    }
    
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
    
    # Remove crontab entry
    if crontab -l 2>/dev/null | grep -F "$exec_script" >/dev/null; then
        crontab -l 2>/dev/null | grep -v -F "$exec_script" | crontab -
        echo "已移除定时任务"
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
    
    # Check crontab
    if crontab -l 2>/dev/null | grep -F "$exec_script" >/dev/null; then
        echo "✓ 定时任务已设置"
        local cron_line
        cron_line=$(crontab -l 2>/dev/null | grep -F "$exec_script")
        echo "  定时规则: $cron_line"
    else
        echo "✗ 定时任务未设置"
    fi
    
    # Check Telegram configuration
    if [ -f "$exec_script" ]; then
        if grep -q "^TG_BOT_TOKEN=" "$exec_script" && ! grep -q 'TG_BOT_TOKEN=""' "$exec_script"; then
            echo "✓ Telegram 通知: 已配置"
        else
            echo "✗ Telegram 通知: 未配置"
        fi
    fi
    
    # Check cache files
    local ddns_dir="$HOME/.ddns"
    if [ -d "$ddns_dir" ]; then
        echo "✓ 缓存目录: $ddns_dir"
        local ip_files
        ip_files=$(find "$ddns_dir" -name ".cf-wan_ip_*.txt" 2>/dev/null | wc -l)
        echo "  IP 缓存文件: $ip_files 个"
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