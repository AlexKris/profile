#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

# Netflix 检测管理脚本
# 类似于ddns.sh的结构，用于自动创建Netflix检测脚本和定时任务

SCRIPT_VERSION="1.0"
SCRIPT_NAME="nf-check"

# 显示使用说明
show_usage() {
    echo "Netflix 检测管理脚本 v${SCRIPT_VERSION}"
    echo ""
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  install   安装 Netflix 检测服务（创建检测脚本和定时任务）"
    echo "  run       手动执行一次 Netflix 检测"
    echo "  remove    移除 Netflix 检测服务（删除定时任务和脚本）"
    echo "  status    查看 Netflix 检测服务状态"
    echo ""
    echo "Install Options:"
    echo "  -u URL       更换IP的API接口URL (与-s互斥)"
    echo "  -s SCRIPT    更换IP的脚本路径 (与-u互斥)"
    echo "  -v VM        VM标识名称 (required)"
    echo "  -i INTERVAL  定时检测间隔(分钟), 默认: 30"
    echo "  -w COOLDOWN  更换IP冷却时间(分钟), 默认: 0 (不启用)"
    echo "  -d DIR       安装目录, 默认: ~/.local/bin"
    echo "  -b BOT_TOKEN Telegram Bot Token (可选)"
    echo "  -c CHAT_ID   Telegram Chat ID (可选)"
    echo "  -4           使用IPv4检测 (默认)"
    echo "  -6           使用IPv6检测"
    echo ""
    echo "Examples:"
    echo "  # 使用API接口安装 Netflix 检测服务"
    echo "  $0 install -u \"https://api.example.com/change-ip\" -v \"Server01\""
    echo "  # 使用脚本文件安装 Netflix 检测服务"
    echo "  $0 install -s \"/path/to/change-ip.sh\" -v \"Server01\""
    echo "  # 安装并启用 Telegram 通知"
    echo "  $0 install -u \"https://api.example.com/change-ip\" -v \"Server01\" -b bot_token -c chat_id"
    echo "  # 如需防止频繁调用，可设置冷却时间"
    echo "  $0 install -u \"https://api.example.com/change-ip\" -v \"Server01\" -w 15"
    echo "  # 手动执行检测"
    echo "  $0 run"
    echo "  # 移除服务"
    echo "  $0 remove"
    exit 1
}

# 创建Netflix检测执行脚本
create_execution_script() {
    local install_dir="$1"
    local change_method="$2"  # "url" 或 "script"
    local change_target="$3"  # URL或脚本路径
    local vm_name="$4"
    local ipv="$5"
    local cooldown_minutes="$6"  # 冷却时间(分钟)
    local bot_token="${7:-}"
    local chat_id="${8:-}"
    
    local exec_script="$install_dir/${SCRIPT_NAME}-exec.sh"
    
    cat > "$exec_script" << 'EOF'
#!/bin/bash
# Netflix 检测执行脚本 (自动生成)
# 检测Netflix是否可以观看非自制剧，如果不能则更换IP

# 配置参数 (请勿修改)
IPv="__IPV__"
UA_Browser="Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/116.0"
url="https://www.netflix.com/title/70143836"
change_method="__CHANGE_METHOD__"  # "url" 或 "script"
change_target="__CHANGE_TARGET__"  # URL或脚本路径
VM="__VM_NAME__"
COOLDOWN_MINUTES="__COOLDOWN_MINUTES__"  # 冷却时间(分钟)

# Telegram 配置
TG_BOT_TOKEN="__BOT_TOKEN__"
TG_CHAT_ID="__CHAT_ID__"

# 创建工作目录
WORK_DIR="$HOME/.nf_check"
mkdir -p "$WORK_DIR"
log="$WORK_DIR/ip.txt"

# 发送Telegram消息函数
send_telegram_message() {
    local message="$1"
    local success="${2:-true}"
    
    # 如果没有配置Telegram则跳过
    [ -z "$TG_BOT_TOKEN" ] || [ -z "$TG_CHAT_ID" ] && return 0
    
    # 根据成功状态选择表情符号
    local emoji="✅"
    [ "$success" = "false" ] && emoji="❌"
    
    local full_message="${emoji} Netflix 检测通知

🖥️  服务器: $VM
📍 当前IP: ${current_ip:-未知}
⏰ 时间: $(date '+%Y-%m-%d %H:%M:%S')

📝 消息: $message"
    
    # 通过Telegram API发送消息
    curl -s -X POST "https://api.telegram.org/bot$TG_BOT_TOKEN/sendMessage" \
        -d "chat_id=$TG_CHAT_ID" \
        -d "text=$full_message" \
        -d "parse_mode=HTML" \
        >/dev/null 2>&1 || true
}

# Netflix检测函数
check_nf() { 
    curl -${IPv}fsL -A "${UA_Browser}" -w %{http_code} -o /dev/null -m 10 "${url}" 2>&1
}

# 获取当前IP地址
get_current_ip() {
    if [ "$IPv" = "6" ]; then
        curl -6 -s --connect-timeout 5 --max-time 10 ipv6.ip.sb 2>/dev/null || \
        curl -6 -s --connect-timeout 5 --max-time 10 api64.ipify.org 2>/dev/null
    else
        curl -4 -s --connect-timeout 5 --max-time 10 ipv4.ip.sb 2>/dev/null || \
        curl -4 -s --connect-timeout 5 --max-time 10 api.ipify.org 2>/dev/null
    fi
}

# 主要检测逻辑
main() {
    local current_time=$(date +"%Y-%m-%d %H:%M:%S")
    local current_ip
    current_ip=$(get_current_ip)
    
    if [ -z "$current_ip" ]; then
        echo "${current_time} ${VM} 错误: 无法获取当前IP地址" | tee -a "$log"
        send_telegram_message "无法获取当前IP地址" "false"
        exit 1
    fi
    
    local code
    code=$(check_nf)
    
    if [ "$code" = "404" ]; then
        # Netflix非自制剧不可用，需要更换IP
        echo "${current_time} ${VM} 当前IP不解锁Netflix非自制剧 当前IP: ${current_ip}" | tee -a "$log"
        
        # 检查冷却时间（仅在启用时检查）
        if [ "$COOLDOWN_MINUTES" -gt 0 ]; then
            local last_change_file="$WORK_DIR/.last_ip_change"
            local current_timestamp=$(date +%s)
            local cooldown_seconds=$((COOLDOWN_MINUTES * 60))
            
            if [ -f "$last_change_file" ]; then
                local last_change_timestamp=$(cat "$last_change_file" 2>/dev/null || echo 0)
                local time_diff=$((current_timestamp - last_change_timestamp))
                
                if [ "$time_diff" -lt "$cooldown_seconds" ]; then
                    local remaining_minutes=$(( (cooldown_seconds - time_diff) / 60 ))
                    local remaining_seconds=$(( (cooldown_seconds - time_diff) % 60 ))
                    echo "${current_time} ${VM} 更换IP冷却中，还需等待 ${remaining_minutes}分${remaining_seconds}秒" | tee -a "$log"
                    send_telegram_message "检测到Netflix非自制剧不可用，但在冷却期内（还需${remaining_minutes}分${remaining_seconds}秒）" "false"
                    exit 0
                fi
            fi
        fi
        
        echo "${current_time} ${VM} 开始尝试更换IP..." | tee -a "$log"
        
        # 根据配置的方法更换IP
        local change_result
        if [ "$change_method" = "script" ]; then
            # 使用脚本方式更换IP
            if [ -f "$change_target" ] && [ -x "$change_target" ]; then
                echo "${current_time} ${VM} 开始执行更换IP脚本: $change_target" | tee -a "$log"
                if change_result=$("$change_target" 2>&1); then
                    echo "${current_time} ${VM} 更换IP脚本执行完成: $change_result" | tee -a "$log"
                else
                    echo "${current_time} ${VM} 执行更换IP脚本失败: $change_result" | tee -a "$log"
                    send_telegram_message "执行更换IP脚本失败: $change_result" "false"
                    exit 1
                fi
                
                # 脚本执行完成后，等待网络和IP恢复
                echo "${current_time} ${VM} 更换IP脚本执行完成，等待网络恢复..." | tee -a "$log"
                
                # 等待网络恢复，最多等待3分钟
                local wait_count=0
                local max_wait=36  # 36 * 5秒 = 3分钟
                while [ $wait_count -lt $max_wait ]; do
                    sleep 5
                    wait_count=$((wait_count + 1))
                    
                    # 尝试获取新IP
                    local test_ip
                    test_ip=$(get_current_ip 2>/dev/null)
                    if [ -n "$test_ip" ]; then
                        echo "${current_time} ${VM} 网络已恢复，当前IP: $test_ip" | tee -a "$log"
                        break
                    fi
                    
                    echo "${current_time} ${VM} 等待网络恢复中... ($((wait_count * 5))秒)" | tee -a "$log"
                done
                
                # 检查是否成功恢复网络
                if [ $wait_count -ge $max_wait ]; then
                    echo "${current_time} ${VM} 等待网络恢复超时，但继续尝试检测..." | tee -a "$log"
                    send_telegram_message "更换IP脚本执行完成，但网络恢复超时" "false"
                fi
            else
                echo "${current_time} ${VM} 更换IP脚本不存在或无执行权限: $change_target" | tee -a "$log"
                send_telegram_message "更换IP脚本不存在或无执行权限: $change_target" "false"
                exit 1
            fi
        else
            # 使用API方式更换IP
            echo "${current_time} ${VM} 开始调用更换IP接口: $change_target" | tee -a "$log"
            
            # API调用重试机制
            local api_retry_count=0
            local max_api_retries=3
            local api_success=false
            
            while [ $api_retry_count -lt $max_api_retries ] && [ "$api_success" = "false" ]; do
                api_retry_count=$((api_retry_count + 1))
                echo "${current_time} ${VM} 调用更换IP接口 (第${api_retry_count}次尝试)" | tee -a "$log"
                
                # 使用curl调用API，设置超时时间
                if change_result=$(curl -s --connect-timeout 10 --max-time 30 "${change_target}" 2>&1); then
                    # 检查HTTP状态码
                    local http_code
                    http_code=$(curl -s --connect-timeout 10 --max-time 30 -w "%{http_code}" -o /dev/null "${change_target}" 2>/dev/null)
                    
                    if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then
                        echo "${current_time} ${VM} API调用成功 (HTTP $http_code): $change_result" | tee -a "$log"
                        api_success=true
                    else
                        echo "${current_time} ${VM} API返回错误状态码 (HTTP $http_code): $change_result" | tee -a "$log"
                    fi
                else
                    echo "${current_time} ${VM} API调用失败: $change_result" | tee -a "$log"
                fi
                
                # 如果不是最后一次尝试且失败了，等待后重试
                if [ "$api_success" = "false" ] && [ $api_retry_count -lt $max_api_retries ]; then
                    echo "${current_time} ${VM} API调用失败，15秒后重试..." | tee -a "$log"
                    sleep 15
                fi
            done
            
            # 检查API调用是否最终成功
            if [ "$api_success" = "false" ]; then
                echo "${current_time} ${VM} API调用最终失败，已重试${max_api_retries}次" | tee -a "$log"
                send_telegram_message "更换IP接口调用失败，已重试${max_api_retries}次" "false"
                exit 1
            fi
            
            # API调用成功后，等待IP更换生效
            echo "${current_time} ${VM} API调用成功，等待IP更换生效..." | tee -a "$log"
            sleep 15  # API方式等待更长时间确保IP更换生效
        fi
        
        # 记录更换IP的时间戳（仅在启用冷却时记录）
        if [ "$COOLDOWN_MINUTES" -gt 0 ]; then
            echo "$current_timestamp" > "$last_change_file"
            echo "${current_time} ${VM} 已记录IP更换时间戳" | tee -a "$log"
        fi
            
            # 获取新IP，增加重试机制
            local new_ip=""
            local retry_count=0
            local max_retries=6  # 最多重试6次，每次间隔10秒
            
            while [ $retry_count -lt $max_retries ] && [ -z "$new_ip" ]; do
                retry_count=$((retry_count + 1))
                echo "${current_time} ${VM} 尝试获取新IP地址 (第${retry_count}次)" | tee -a "$log"
                
                new_ip=$(get_current_ip 2>/dev/null)
                if [ -n "$new_ip" ]; then
                    break
                fi
                
                if [ $retry_count -lt $max_retries ]; then
                    echo "${current_time} ${VM} 获取IP失败，10秒后重试..." | tee -a "$log"
                    sleep 10
                fi
            done
            
            if [ -n "$new_ip" ]; then
                if [ "$new_ip" != "$current_ip" ]; then
                    echo "${current_time} ${VM} IP更换成功 原IP: ${current_ip} 新IP: ${new_ip}" | tee -a "$log"
                    send_telegram_message "检测到Netflix非自制剧不可用，已成功更换IP
原IP: ${current_ip}
新IP: ${new_ip}" "true"
                    
                    # 再次检测新IP是否解锁，等待更长时间确保IP完全生效
                    echo "${current_time} ${VM} 等待新IP完全生效..." | tee -a "$log"
                    sleep 10
                    
                    local new_code
                    new_code=$(check_nf 2>/dev/null)
                    if [ "$new_code" != "404" ]; then
                        echo "${current_time} ${VM} 新IP解锁Netflix非自制剧成功 新IP: ${new_ip} 状态码: ${new_code}" | tee -a "$log"
                        send_telegram_message "新IP解锁Netflix非自制剧成功！✨" "true"
                    else
                        echo "${current_time} ${VM} 新IP仍不解锁Netflix非自制剧 新IP: ${new_ip}" | tee -a "$log"
                        send_telegram_message "新IP仍不解锁Netflix非自制剧，可能需要手动处理" "false"
                    fi
                else
                    echo "${current_time} ${VM} IP未发生变化 当前IP: ${current_ip}" | tee -a "$log"
                    send_telegram_message "IP更换命令执行完成，但IP未发生变化" "false"
                fi
            else
                echo "${current_time} ${VM} 无法获取新IP地址，网络可能仍有问题" | tee -a "$log"
                send_telegram_message "IP更换完成但无法获取新IP地址，网络可能仍有问题" "false"
            fi
    else
        # Netflix非自制剧可用
        echo "${current_time} ${VM} 当前IP解锁Netflix非自制剧 当前IP: ${current_ip} 状态码: ${code}" | tee -a "$log"
        # 只有在检测到状态变化时才发送成功通知（避免频繁通知）
        local last_status_file="$WORK_DIR/.last_status"
        local last_status=""
        [ -f "$last_status_file" ] && last_status=$(cat "$last_status_file")
        
        if [ "$last_status" != "success" ]; then
            send_telegram_message "Netflix非自制剧解锁正常 ✨" "true"
            echo "success" > "$last_status_file"
        fi
    fi
}

# 运行主函数
main
EOF

    # 替换占位符（转义特殊字符以避免sed问题）
    local escaped_change_target
    escaped_change_target=$(printf '%s\n' "$change_target" | sed 's|[[\.*^$()+?{|&/]|\\&|g')
    local escaped_vm_name
    escaped_vm_name=$(printf '%s\n' "$vm_name" | sed 's|[[\.*^$()+?{|&/]|\\&|g')
    local escaped_bot_token
    escaped_bot_token=$(printf '%s\n' "$bot_token" | sed 's|[[\.*^$()+?{|&/]|\\&|g')
    local escaped_chat_id
    escaped_chat_id=$(printf '%s\n' "$chat_id" | sed 's|[[\.*^$()+?{|&/]|\\&|g')
    
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS sed语法
        sed -i '' \
            -e "s|__IPV__|$ipv|g" \
            -e "s|__CHANGE_METHOD__|$change_method|g" \
            -e "s|__CHANGE_TARGET__|$escaped_change_target|g" \
            -e "s|__VM_NAME__|$escaped_vm_name|g" \
            -e "s|__COOLDOWN_MINUTES__|$cooldown_minutes|g" \
            -e "s|__BOT_TOKEN__|$escaped_bot_token|g" \
            -e "s|__CHAT_ID__|$escaped_chat_id|g" \
            "$exec_script"
    else
        # Linux sed语法
        sed -i \
            -e "s|__IPV__|$ipv|g" \
            -e "s|__CHANGE_METHOD__|$change_method|g" \
            -e "s|__CHANGE_TARGET__|$escaped_change_target|g" \
            -e "s|__VM_NAME__|$escaped_vm_name|g" \
            -e "s|__COOLDOWN_MINUTES__|$cooldown_minutes|g" \
            -e "s|__BOT_TOKEN__|$escaped_bot_token|g" \
            -e "s|__CHAT_ID__|$escaped_chat_id|g" \
            "$exec_script"
    fi
    
    chmod +x "$exec_script"
    echo "$exec_script"
}

# 安装Netflix检测服务
install_nf_check() {
    local change_ip_url="" change_script="" vm_name="" interval=30 cooldown_minutes=0 install_dir="$HOME/.local/bin"
    local bot_token="" chat_id="" ipv="4"
    
    # 解析参数
    while getopts u:s:v:i:w:d:b:c:46 opts; do
        case ${opts} in
            u) change_ip_url=${OPTARG} ;;
            s) change_script=${OPTARG} ;;
            v) vm_name=${OPTARG} ;;
            i) interval=${OPTARG} ;;
            w) cooldown_minutes=${OPTARG} ;;
            d) install_dir=${OPTARG} ;;
            b) bot_token=${OPTARG} ;;
            c) chat_id=${OPTARG} ;;
            4) ipv="4" ;;
            6) ipv="6" ;;
        esac
    done
    
    # 验证必需参数
    local missing_params=()
    local change_method="" change_target=""
    
    # 检查更换IP方式参数
    if [ -n "$change_ip_url" ] && [ -n "$change_script" ]; then
        echo "错误: 不能同时指定API接口URL (-u) 和脚本路径 (-s)"
        exit 1
    elif [ -n "$change_ip_url" ]; then
        change_method="url"
        change_target="$change_ip_url"
    elif [ -n "$change_script" ]; then
        change_method="script"
        change_target="$change_script"
        # 验证脚本文件是否存在
        if [ ! -f "$change_script" ]; then
            echo "错误: 指定的更换IP脚本不存在: $change_script"
            exit 1
        fi
        # 检查脚本是否有执行权限
        if [ ! -x "$change_script" ]; then
            echo "警告: 脚本没有执行权限，正在添加执行权限..."
            chmod +x "$change_script" || {
                echo "错误: 无法为脚本添加执行权限: $change_script"
                exit 1
            }
        fi
    else
        missing_params+=("更换IP方式: 必须指定API接口URL (-u) 或脚本路径 (-s)")
    fi
    
    [ -z "$vm_name" ] && missing_params+=("VM名称 (-v)")
    
    if [ ${#missing_params[@]} -gt 0 ]; then
        echo "错误: 缺少必需参数:"
        printf '  %s\n' "${missing_params[@]}"
        exit 1
    fi
    
    # 验证冷却时间参数
    if ! [[ "$cooldown_minutes" =~ ^[0-9]+$ ]] || [ "$cooldown_minutes" -lt 0 ] || [ "$cooldown_minutes" -gt 1440 ]; then
        echo "错误: 冷却时间必须是0-1440之间的整数（分钟），0表示不启用冷却"
        exit 1
    fi
    
    # 验证Telegram参数（要么都有要么都没有）
    if [ -n "$bot_token" ] && [ -z "$chat_id" ]; then
        echo "错误: 设置了 Bot Token 但缺少 Chat ID (-c)"
        exit 1
    elif [ -z "$bot_token" ] && [ -n "$chat_id" ]; then
        echo "错误: 设置了 Chat ID 但缺少 Bot Token (-b)"
        exit 1
    fi
    
    # 创建安装目录
    mkdir -p "$install_dir"
    
    # 创建执行脚本
    echo "正在创建Netflix检测脚本..."
    local exec_script
    exec_script=$(create_execution_script "$install_dir" "$change_method" "$change_target" "$vm_name" "$ipv" "$cooldown_minutes" "$bot_token" "$chat_id")
    
    # 创建定时任务
    echo "正在设置定时任务..."
    local cron_cmd="*/$interval * * * * $exec_script >/dev/null 2>&1"
    
    # 移除现有的相同脚本定时任务
    if crontab -l 2>/dev/null | grep -F "$exec_script" >/dev/null; then
        crontab -l 2>/dev/null | grep -v -F "$exec_script" | crontab -
    fi
    
    # 添加新的定时任务
    (crontab -l 2>/dev/null; echo "$cron_cmd") | crontab - 2>/dev/null || {
        echo "警告: 无法设置定时任务，可能需要手动添加:"
        echo "$cron_cmd"
    }
    
    echo "安装完成！"
    echo "执行脚本: $exec_script"
    echo "定时任务: 每 $interval 分钟执行一次"
    if [ "$cooldown_minutes" -gt 0 ]; then
        echo "冷却时间: $cooldown_minutes 分钟"
    else
        echo "冷却时间: 未启用"
    fi
    echo "服务器标识: $vm_name"
    echo "IP版本: IPv$ipv"
    if [ "$change_method" = "script" ]; then
        echo "更换IP方式: 执行脚本"
        echo "更换IP脚本: $change_target"
    else
        echo "更换IP方式: API接口"
        echo "更换IP接口: $change_target"
    fi
    
    if [ -n "$bot_token" ] && [ -n "$chat_id" ]; then
        echo "Telegram 通知: 已启用"
    else
        echo "Telegram 通知: 未启用"
    fi
    
    # 执行首次测试
    echo ""
    echo "正在执行首次Netflix检测测试..."
    if "$exec_script"; then
        echo "测试完成！"
    else
        echo "测试执行完成，请查看日志了解详情"
    fi
}

# 手动运行Netflix检测
run_nf_check() {
    local exec_script="$HOME/.local/bin/${SCRIPT_NAME}-exec.sh"
    
    if [ ! -f "$exec_script" ]; then
        echo "错误: 执行脚本不存在，请先运行 install 命令"
        exit 1
    fi
    
    if [ ! -x "$exec_script" ]; then
        echo "错误: 执行脚本没有执行权限"
        exit 1
    fi
    
    echo "正在执行Netflix检测..."
    "$exec_script"
}

# 移除Netflix检测服务
remove_nf_check() {
    local install_dir="$HOME/.local/bin"
    local exec_script="$install_dir/${SCRIPT_NAME}-exec.sh"
    
    echo "正在移除Netflix检测服务..."
    
    # 移除定时任务
    if crontab -l 2>/dev/null | grep -F "$exec_script" >/dev/null; then
        crontab -l 2>/dev/null | grep -v -F "$exec_script" | crontab -
        echo "已移除定时任务"
    fi
    
    # 删除执行脚本
    if [ -f "$exec_script" ]; then
        rm -f "$exec_script"
        echo "已删除执行脚本: $exec_script"
    fi
    
    echo "Netflix检测服务移除完成"
}

# 显示服务状态
show_status() {
    local install_dir="$HOME/.local/bin"
    local exec_script="$install_dir/${SCRIPT_NAME}-exec.sh"
    
    echo "Netflix 检测服务状态:"
    echo "======================"
    
    # 检查执行脚本
    if [ -f "$exec_script" ]; then
        echo "✓ 执行脚本: $exec_script"
        
        # 从脚本中提取配置信息
        if grep -q "VM=" "$exec_script"; then
            local vm_name
            vm_name=$(grep "^VM=" "$exec_script" | head -1 | cut -d'"' -f2)
            echo "  服务器标识: $vm_name"
        fi
        
        if grep -q "IPv=" "$exec_script"; then
            local ipv
            ipv=$(grep "^IPv=" "$exec_script" | head -1 | cut -d'"' -f2)
            echo "  IP版本: IPv$ipv"
        fi
        
        if grep -q "change_method=" "$exec_script"; then
            local change_method
            change_method=$(grep "^change_method=" "$exec_script" | head -1 | cut -d'"' -f2)
            local change_target
            change_target=$(grep "^change_target=" "$exec_script" | head -1 | cut -d'"' -f2)
            local cooldown_minutes
            cooldown_minutes=$(grep "^COOLDOWN_MINUTES=" "$exec_script" | head -1 | cut -d'"' -f2)
            if [ "$cooldown_minutes" -gt 0 ]; then
                echo "  冷却时间: $cooldown_minutes 分钟"
            else
                echo "  冷却时间: 未启用"
            fi
            if [ "$change_method" = "script" ]; then
                echo "  更换IP方式: 执行脚本"
                echo "  更换IP脚本: $change_target"
            else
                echo "  更换IP方式: API接口"
                echo "  更换IP接口: $change_target"
            fi
        fi
    else
        echo "✗ 执行脚本不存在"
    fi
    
    # 检查定时任务
    if crontab -l 2>/dev/null | grep -F "$exec_script" >/dev/null; then
        echo "✓ 定时任务已设置"
        local cron_line
        cron_line=$(crontab -l 2>/dev/null | grep -F "$exec_script")
        echo "  定时规则: $cron_line"
    else
        echo "✗ 定时任务未设置"
    fi
    
    # 检查Telegram配置
    if [ -f "$exec_script" ]; then
        if grep -q "^TG_BOT_TOKEN=" "$exec_script" && ! grep -q 'TG_BOT_TOKEN=""' "$exec_script"; then
            echo "✓ Telegram 通知: 已配置"
        else
            echo "✗ Telegram 通知: 未配置"
        fi
    fi
    
    # 检查工作目录和日志
    local work_dir="$HOME/.nf_check"
    if [ -d "$work_dir" ]; then
        echo "✓ 工作目录: $work_dir"
        
        # 检查冷却状态（仅在启用时显示）
        if [ -f "$exec_script" ] && grep -q "^COOLDOWN_MINUTES=" "$exec_script"; then
            local cooldown_minutes
            cooldown_minutes=$(grep "^COOLDOWN_MINUTES=" "$exec_script" | head -1 | cut -d'"' -f2)
            
            if [ "$cooldown_minutes" -gt 0 ]; then
                local last_change_file="$work_dir/.last_ip_change"
                
                if [ -f "$last_change_file" ]; then
                    local last_change_timestamp=$(cat "$last_change_file" 2>/dev/null || echo 0)
                    local current_timestamp=$(date +%s)
                    local time_diff=$((current_timestamp - last_change_timestamp))
                    local cooldown_seconds=$((cooldown_minutes * 60))
                    
                    if [ "$time_diff" -lt "$cooldown_seconds" ]; then
                        local remaining_minutes=$(( (cooldown_seconds - time_diff) / 60 ))
                        local remaining_seconds=$(( (cooldown_seconds - time_diff) % 60 ))
                        echo "🕐 冷却状态: 冷却中（还需${remaining_minutes}分${remaining_seconds}秒）"
                    else
                        echo "✅ 冷却状态: 可执行更换IP"
                    fi
                    echo "  上次更换: $(date -d "@$last_change_timestamp" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "时间解析失败")"
                else
                    echo "✅ 冷却状态: 可执行更换IP（未曾执行过）"
                fi
            fi
        fi
        
        if [ -f "$work_dir/ip.txt" ]; then
            echo "  日志文件: $work_dir/ip.txt"
            local log_lines
            log_lines=$(wc -l < "$work_dir/ip.txt" 2>/dev/null || echo 0)
            echo "  日志记录: $log_lines 条"
            
            # 显示最近的几条日志
            if [ "$log_lines" -gt 0 ]; then
                echo "  最近记录:"
                tail -3 "$work_dir/ip.txt" | sed 's/^/    /'
            fi
        fi
    else
        echo "✗ 工作目录不存在"
    fi
}

# 主脚本逻辑
case "${1:-}" in
    install)
        shift
        install_nf_check "$@"
        ;;
    run)
        run_nf_check
        ;;
    remove)
        remove_nf_check
        ;;
    status)
        show_status
        ;;
    *)
        show_usage
        ;;
esac
