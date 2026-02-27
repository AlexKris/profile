#!/bin/bash

# Cloudflare IP 防火墙管理脚本
# 专门处理 Cloudflare IP 白名单和 Web 端口保护
# Version: 2.0.0

set -euo pipefail

# 脚本配置
readonly SCRIPT_VERSION="2.0.0"
readonly LOG_FILE="/var/log/cloudflare_firewall.log"
readonly COMMENT_MARK="cloudflare-auto"     # Cloudflare 规则标记
readonly INTERNAL_MARK="internal-network"   # 内网规则标记
readonly CF_UPDATE_SCRIPT="/usr/local/bin/update_cloudflare_ips.sh"
readonly CF_CRON_JOB="/etc/cron.d/cloudflare_ip_update"
readonly CF_IPV4_URL="https://www.cloudflare.com/ips-v4"
readonly CF_IPV6_URL="https://www.cloudflare.com/ips-v6"

# 内网地址段
readonly INTERNAL_NETWORKS=("127.0.0.1" "10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16")

# 统一的日志函数（符合最佳实践）
log_message() {
    local level="${1:-INFO}"
    local message="${2:-}"
    local timestamp
    
    # 参数验证
    [ -z "$message" ] && { echo "[错误] 消息内容不能为空" >&2; return 1; }
    
    # 安全：过滤敏感信息
    if [[ "$message" =~ (ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp[0-9]+)[[:space:]]+[A-Za-z0-9+/]+=*|password.*=|token.*=|key.*= ]]; then
        message="[敏感信息已过滤]"
    fi
    
    # 统一时间戳格式
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # 级别标准化和输出
    case "${level^^}" in
        "ERROR"|"ERR")
            echo "[错误] $message" >&2
            ;;
        "WARNING"|"WARN")
            echo "[警告] $message"
            ;;
        "INFO")
            echo "[信息] $message"
            ;;
        "DEBUG")
            [ "${DEBUG:-}" = "1" ] && echo "[调试] $message"
            ;;
        "SUCCESS"|"OK")
            echo "[成功] $message"
            ;;
        *)
            echo "[日志] $message"
            ;;
    esac
    
    # 文件日志记录（如果定义了 LOG_FILE）
    if [ -n "${LOG_FILE:-}" ]; then
        # 安全创建日志目录
        local log_dir
        log_dir=$(dirname "$LOG_FILE")
        if [ ! -d "$log_dir" ]; then
            mkdir -p "$log_dir" 2>/dev/null || return 0
            chmod 750 "$log_dir" 2>/dev/null || true
        fi
        
        # 写入日志文件
        echo "[$timestamp][$level] $message" >> "$LOG_FILE" 2>/dev/null || true
        chmod 640 "$LOG_FILE" 2>/dev/null || true
        
        # 简单日志轮转（防止过大）
        if [ -f "$LOG_FILE" ] && [ "$(wc -l < "$LOG_FILE" 2>/dev/null || echo 0)" -gt 10000 ]; then
            tail -5000 "$LOG_FILE" > "${LOG_FILE}.tmp" 2>/dev/null && mv "${LOG_FILE}.tmp" "$LOG_FILE" 2>/dev/null
        fi
    fi
    
    # 系统日志记录（错误级别）
    [ "${level^^}" = "ERROR" ] && command -v logger >/dev/null 2>&1 && logger -t "$(basename "$0" .sh)" -p user.err "$message" 2>/dev/null || true
}

# 检查 root 权限
check_root() {
    if [ "$(id -u)" != "0" ]; then
        log_message "ERROR" "此脚本需要 root 权限运行"
        exit 1
    fi
}

# 检查 Docker 状态
check_docker_status() {
    local docker_available=false
    
    # 检查 Docker 命令是否存在
    if command -v docker &>/dev/null; then
        # 检查 Docker 服务是否运行
        if systemctl is-active docker &>/dev/null 2>&1; then
            docker_available=true
            log_message "INFO" "检测到 Docker 正在运行"
            
            # 检查 DOCKER-USER 链是否存在
            if iptables -L DOCKER-USER -n &>/dev/null 2>&1; then
                log_message "INFO" "检测到 DOCKER-USER 链，将配置 Docker 防火墙规则"
                return 0
            else
                log_message "WARNING" "Docker 运行但 DOCKER-USER 链不存在"
            fi
        else
            log_message "INFO" "Docker 已安装但未运行"
        fi
    else
        log_message "INFO" "未检测到 Docker"
    fi
    
    return 1
}

# 获取 Cloudflare IP 列表
get_cloudflare_ips() {
    log_message "INFO" "获取最新的 Cloudflare IP 列表..."
    
    local ipv4_list=""
    local ipv6_list=""
    
    # 获取 IPv4 列表
    ipv4_list=$(curl -s --connect-timeout 10 --max-time 30 "$CF_IPV4_URL")
    if [ $? -ne 0 ] || [ -z "$ipv4_list" ]; then
        log_message "ERROR" "无法获取 Cloudflare IPv4 地址列表"
        return 1
    fi
    
    # 验证 IPv4 列表格式
    if [[ ! "$ipv4_list" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3} ]]; then
        log_message "ERROR" "获取的 IPv4 列表格式无效"
        return 1
    fi
    
    # 获取 IPv6 列表
    if command -v ip6tables &>/dev/null && ip6tables -L -n &>/dev/null 2>&1; then
        ipv6_list=$(curl -s --connect-timeout 10 --max-time 30 "$CF_IPV6_URL")
        if [ $? -eq 0 ] && [ -n "$ipv6_list" ]; then
            log_message "INFO" "成功获取 IPv6 地址列表"
        else
            log_message "WARNING" "无法获取 IPv6 地址列表"
        fi
    else
        log_message "INFO" "系统不支持 IPv6 或 ip6tables 未安装"
    fi
    
    # 合并输出
    echo "$ipv4_list"
    if [ -n "$ipv6_list" ]; then
        echo "$ipv6_list"
    fi
}

# 确保内网规则存在
ensure_internal_rules() {
    log_message "INFO" "确保内网访问规则存在..."
    
    # INPUT 链内网规则
    for network in "${INTERNAL_NETWORKS[@]}"; do
        for port in 80 443; do
            if ! iptables -C INPUT -p tcp -s "$network" --dport "$port" -j ACCEPT -m comment --comment "$INTERNAL_MARK" 2>/dev/null; then
                iptables -I INPUT 1 -p tcp -s "$network" --dport "$port" -j ACCEPT -m comment --comment "$INTERNAL_MARK"
                log_message "INFO" "添加内网规则: $network -> $port"
            fi
        done
    done
    
    # DOCKER-USER 链规则
    if check_docker_status; then
        # 先添加 lo 接口规则
        if ! iptables -C DOCKER-USER -i lo -j RETURN -m comment --comment "$INTERNAL_MARK" 2>/dev/null; then
            iptables -I DOCKER-USER 1 -i lo -j RETURN -m comment --comment "$INTERNAL_MARK"
            log_message "INFO" "添加 DOCKER-USER lo 接口规则"
        fi
        
        # 添加内网规则
        for network in "${INTERNAL_NETWORKS[@]}"; do
            for port in 80 443; do
                if ! iptables -C DOCKER-USER -s "$network" -p tcp --dport "$port" -j RETURN -m comment --comment "$INTERNAL_MARK" 2>/dev/null; then
                    iptables -A DOCKER-USER -s "$network" -p tcp --dport "$port" -j RETURN -m comment --comment "$INTERNAL_MARK"
                    log_message "INFO" "添加 DOCKER-USER 内网规则: $network -> $port"
                fi
            done
        done
    fi
}

# 清理旧的 Cloudflare 规则
clean_cloudflare_rules() {
    log_message "INFO" "清理旧的 Cloudflare 规则..."
    
    # 清理 INPUT 链
    while true; do
        local rule_num=$(iptables -L INPUT -n --line-numbers | grep "$COMMENT_MARK" | head -1 | awk '{print $1}')
        [ -z "$rule_num" ] && break
        iptables -D INPUT "$rule_num" 2>/dev/null || break
    done
    
    # 清理 DOCKER-USER 链
    if iptables -L DOCKER-USER -n &>/dev/null 2>&1; then
        while true; do
            local rule_num=$(iptables -L DOCKER-USER -n --line-numbers | grep "$COMMENT_MARK" | head -1 | awk '{print $1}')
            [ -z "$rule_num" ] && break
            iptables -D DOCKER-USER "$rule_num" 2>/dev/null || break
        done
    fi
    
    # 清理 IPv6 规则
    if command -v ip6tables &>/dev/null && ip6tables -L -n &>/dev/null 2>&1; then
        while true; do
            local rule_num=$(ip6tables -L INPUT -n --line-numbers | grep "$COMMENT_MARK" | head -1 | awk '{print $1}')
            [ -z "$rule_num" ] && break
            ip6tables -D INPUT "$rule_num" 2>/dev/null || break
        done
    fi
    
    log_message "INFO" "旧规则清理完成"
}

# 添加 Cloudflare 规则
add_cloudflare_rules() {
    local ips="$1"
    local count=0
    local errors=0
    
    log_message "INFO" "添加新的 Cloudflare 规则..."

    # 提前检查 Docker 状态，避免循环内重复调用
    local has_docker=false
    if check_docker_status; then
        has_docker=true
    fi

    # 获取插入位置
    local insert_pos_input=$(iptables -L INPUT -n --line-numbers | grep "$INTERNAL_MARK" | tail -1 | awk '{print $1}')
    [ -z "$insert_pos_input" ] && insert_pos_input=8

    local insert_pos_docker=1
    if [ "$has_docker" = "true" ]; then
        insert_pos_docker=$(iptables -L DOCKER-USER -n --line-numbers | grep "$INTERNAL_MARK" | tail -1 | awk '{print $1}')
        [ -z "$insert_pos_docker" ] && insert_pos_docker=9
    fi
    
    while IFS= read -r ip; do
        # 跳过空行
        [ -z "$ip" ] && continue
        
        # 验证 IP 格式
        if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
            # IPv4 规则
            for port in 80 443; do
                # INPUT 链
                if iptables -I INPUT $((++insert_pos_input)) -p tcp -s "$ip" --dport "$port" -j ACCEPT -m comment --comment "$COMMENT_MARK" 2>/dev/null; then
                    ((count++))
                else
                    ((errors++))
                    log_message "WARNING" "无法添加 INPUT 规则: $ip:$port"
                fi
                
                # DOCKER-USER 链
                if [ "$has_docker" = "true" ]; then
                    if iptables -I DOCKER-USER $((++insert_pos_docker)) -s "$ip" -p tcp --dport "$port" -j RETURN -m comment --comment "$COMMENT_MARK" 2>/dev/null; then
                        ((count++))
                    else
                        ((errors++))
                        log_message "WARNING" "无法添加 DOCKER-USER 规则: $ip:$port"
                    fi
                fi
            done
        elif [[ "$ip" =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}/[0-9]{1,3}$ ]]; then
            # IPv6 规则
            if command -v ip6tables &>/dev/null && ip6tables -L -n &>/dev/null 2>&1; then
                for port in 80 443; do
                    if ip6tables -I INPUT $((++insert_pos_input)) -p tcp -s "$ip" --dport "$port" -j ACCEPT -m comment --comment "$COMMENT_MARK" 2>/dev/null; then
                        ((count++))
                    else
                        ((errors++))
                        log_message "WARNING" "无法添加 IPv6 规则: $ip:$port"
                    fi
                done
            fi
        fi
    done <<< "$ips"
    
    log_message "INFO" "添加了 $count 条规则，失败 $errors 条"
    ensure_drop_rules_last
}

# 确保 DROP 规则在最后
ensure_drop_rules_last() {
    log_message "INFO" "确保阻断规则在最后..."
    
    # 移除现有的 DROP 规则
    while iptables -D INPUT -p tcp --dport 80 -j DROP 2>/dev/null; do :; done
    while iptables -D INPUT -p tcp --dport 443 -j DROP 2>/dev/null; do :; done
    
    # 重新添加到末尾
    iptables -A INPUT -p tcp --dport 80 -j DROP
    iptables -A INPUT -p tcp --dport 443 -j DROP
    
    # DOCKER-USER 链
    if check_docker_status; then
        while iptables -D DOCKER-USER -p tcp --dport 80 -j DROP 2>/dev/null; do :; done
        while iptables -D DOCKER-USER -p tcp --dport 443 -j DROP 2>/dev/null; do :; done
        
        iptables -A DOCKER-USER -p tcp --dport 80 -j DROP
        iptables -A DOCKER-USER -p tcp --dport 443 -j DROP
        
        # 确保最后有 RETURN 规则
        iptables -D DOCKER-USER -j RETURN 2>/dev/null || true
        iptables -A DOCKER-USER -j RETURN
    fi
}

# 创建自动更新脚本
create_update_script() {
    log_message "INFO" "创建 Cloudflare IP 自动更新脚本..."
    
    # 获取当前脚本的绝对路径，写入更新脚本中
    local self_script
    self_script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"

    cat > "$CF_UPDATE_SCRIPT" << UPDATEEOF
#!/bin/bash

# Cloudflare IP 自动更新脚本
# 由 cloudflare.sh 生成

LOG_FILE="/var/log/cloudflare_ip_update.log"

log_message() {
    echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$1" >> "\$LOG_FILE"
}

log_message "开始更新 Cloudflare IP 规则"

CLOUDFLARE_SCRIPT="$self_script"

if [ -f "\$CLOUDFLARE_SCRIPT" ]; then
    bash "\$CLOUDFLARE_SCRIPT" --update-internal 2>&1 | tee -a "\$LOG_FILE"
else
    log_message "错误: 找不到 cloudflare.sh 脚本: \$CLOUDFLARE_SCRIPT"
    exit 1
fi

log_message "Cloudflare IP 规则更新完成"
UPDATEEOF

    chmod +x "$CF_UPDATE_SCRIPT"
    log_message "INFO" "更新脚本已创建: $CF_UPDATE_SCRIPT"
}

# 创建定时任务
create_cron_job() {
    log_message "INFO" "创建定时更新任务..."
    
    tee "$CF_CRON_JOB" > /dev/null << EOF
# Cloudflare IP 自动更新任务
# 每6小时更新一次
0 */6 * * * root $CF_UPDATE_SCRIPT >/dev/null 2>&1
EOF

    chmod 644 "$CF_CRON_JOB"
    log_message "INFO" "定时任务已创建: $CF_CRON_JOB"
}

# 保存防火墙规则
save_rules() {
    log_message "INFO" "保存防火墙规则..."
    
    if [ -f /etc/debian_version ]; then
        # Debian/Ubuntu
        mkdir -p /etc/iptables 2>/dev/null
        if iptables-save > /etc/iptables/rules.v4 2>/dev/null; then
            log_message "INFO" "IPv4 规则已保存"
        else
            log_message "WARNING" "无法保存 IPv4 规则"
        fi
        
        if command -v ip6tables &>/dev/null && ip6tables -L -n &>/dev/null 2>&1; then
            if ip6tables-save > /etc/iptables/rules.v6 2>/dev/null; then
                log_message "INFO" "IPv6 规则已保存"
            else
                log_message "WARNING" "无法保存 IPv6 规则"
            fi
        fi
    elif [ -f /etc/redhat-release ]; then
        # RHEL/CentOS
        if iptables-save > /etc/sysconfig/iptables 2>/dev/null; then
            log_message "INFO" "规则已保存"
        else
            log_message "WARNING" "无法保存规则"
        fi
    fi
}

# 显示当前状态
show_status() {
    echo ""
    echo "========== Cloudflare 防火墙状态 =========="
    
    # 统计规则数量
    local internal_count=$(iptables -L INPUT -n | grep -c "$INTERNAL_MARK" 2>/dev/null || echo 0)
    local cloudflare_count=$(iptables -L INPUT -n | grep -c "$COMMENT_MARK" 2>/dev/null || echo 0)
    
    echo "INPUT 链规则:"
    echo "  内网规则: $internal_count 条"
    echo "  Cloudflare 规则: $cloudflare_count 条"
    
    # Docker 规则统计
    if iptables -L DOCKER-USER -n &>/dev/null 2>&1; then
        local docker_internal=$(iptables -L DOCKER-USER -n | grep -c "$INTERNAL_MARK" 2>/dev/null || echo 0)
        local docker_cloudflare=$(iptables -L DOCKER-USER -n | grep -c "$COMMENT_MARK" 2>/dev/null || echo 0)
        echo "DOCKER-USER 链规则:"
        echo "  内网规则: $docker_internal 条"
        echo "  Cloudflare 规则: $docker_cloudflare 条"
    fi
    
    # 检查脚本和定时任务
    echo ""
    echo "自动更新状态:"
    if [ -f "$CF_UPDATE_SCRIPT" ]; then
        echo "  更新脚本: 已安装"
    else
        echo "  更新脚本: 未安装"
    fi
    
    if [ -f "$CF_CRON_JOB" ]; then
        echo "  定时任务: 已配置"
        echo "  更新间隔: 每6小时"
    else
        echo "  定时任务: 未配置"
    fi
    
    echo "=========================================="
    echo ""
}

# 启用 Cloudflare 保护
enable_protection() {
    log_message "INFO" "启用 Cloudflare 保护..."
    
    # 确保内网规则存在
    ensure_internal_rules
    
    # 获取 Cloudflare IP
    local cf_ips
    cf_ips=$(get_cloudflare_ips)
    if [ $? -ne 0 ] || [ -z "$cf_ips" ]; then
        log_message "ERROR" "无法获取 Cloudflare IP 列表"
        return 1
    fi
    
    # 清理旧规则
    clean_cloudflare_rules
    
    # 添加新规则
    add_cloudflare_rules "$cf_ips"
    
    # 创建自动更新
    create_update_script
    create_cron_job
    
    # 保存规则
    save_rules
    
    log_message "INFO" "Cloudflare 保护已启用"
}

# 禁用 Cloudflare 保护
disable_protection() {
    log_message "INFO" "禁用 Cloudflare 保护..."
    
    # 清理规则
    clean_cloudflare_rules
    
    # 删除更新脚本和定时任务
    rm -f "$CF_UPDATE_SCRIPT" "$CF_CRON_JOB"
    
    # 保存规则
    save_rules
    
    log_message "INFO" "Cloudflare 保护已禁用"
}

# 仅更新 IP（内部调用）
update_ips_internal() {
    log_message "INFO" "更新 Cloudflare IP 列表..."
    
    # 确保内网规则存在
    ensure_internal_rules
    
    # 获取最新 IP
    local cf_ips
    cf_ips=$(get_cloudflare_ips)
    if [ $? -ne 0 ] || [ -z "$cf_ips" ]; then
        log_message "ERROR" "无法获取 Cloudflare IP 列表"
        return 1
    fi
    
    # 清理并添加新规则
    clean_cloudflare_rules
    add_cloudflare_rules "$cf_ips"
    save_rules
    
    log_message "INFO" "IP 列表更新完成"
}

# 显示帮助信息
show_help() {
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  --enable          启用 Cloudflare 保护"
    echo "  --disable         禁用 Cloudflare 保护"
    echo "  --update          手动更新 IP 列表"
    echo "  --status          显示当前状态"
    echo "  --help            显示此帮助信息"
    echo ""
    echo "示例:"
    echo "  $0 --enable       # 启用保护并设置自动更新"
    echo "  $0 --disable      # 禁用保护并清理规则"
    echo "  $0 --update       # 手动更新 IP 列表"
    echo "  $0 --status       # 查看当前状态"
    echo ""
    echo "版本: $SCRIPT_VERSION"
}

# 主函数
main() {
    local action="$1"
    
    check_root
    
    case "$action" in
        --enable)
            enable_protection
            ;;
        --disable)
            disable_protection
            ;;
        --update)
            update_ips_internal
            ;;
        --update-internal)
            # 内部调用，用于定时任务
            update_ips_internal
            ;;
        --status)
            show_status
            ;;
        --help|*)
            show_help
            ;;
    esac
}

# 脚本入口
if [ $# -eq 0 ]; then
    show_help
    exit 1
fi

main "$1"