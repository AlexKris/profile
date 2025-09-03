#!/bin/bash

# Cloudflare IP Manager - 独立的Cloudflare IP白名单管理脚本
# 从setup.sh提取的Cloudflare功能
# Version: 1.0.0

set -euo pipefail

# 配置
readonly SCRIPT_VERSION="1.0.0"
readonly LOG_FILE="/var/log/cloudflare-ip-manager.log"
readonly COMMENT_MARK="cloudflare-auto"  # 用于标记Cloudflare规则
readonly INTERNAL_MARK="internal-network"  # 用于标记内网规则
readonly CF_UPDATE_SCRIPT="/usr/local/bin/update-cloudflare-ips.sh"
readonly CF_CRON_JOB="/etc/cron.d/cloudflare-ip-update"

# 颜色定义
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# 日志函数
log_message() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        ERROR)   echo -e "${RED}[ERROR]${NC} $message" ;;
        WARNING) echo -e "${YELLOW}[WARNING]${NC} $message" ;;
        INFO)    echo -e "${BLUE}[INFO]${NC} $message" ;;
        SUCCESS) echo -e "${GREEN}[SUCCESS]${NC} $message" ;;
    esac
    
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

# 获取当前的Cloudflare IP
get_cloudflare_ips() {
    local ipv4_list=$(curl -s --connect-timeout 10 https://www.cloudflare.com/ips-v4)
    local ipv6_list=$(curl -s --connect-timeout 10 https://www.cloudflare.com/ips-v6)
    
    # 验证获取的内容是否为有效IP
    if [[ ! "$ipv4_list" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3} ]]; then
        log_message "ERROR" "获取的IPv4列表无效"
        return 1
    fi
    
    echo "$ipv4_list"
    echo "$ipv6_list"
}

# 确保内网规则存在
ensure_internal_rules() {
    log_message "INFO" "检查并确保内网规则存在..."
    
    local internal_networks=("127.0.0.1" "10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16")
    
    for network in "${internal_networks[@]}"; do
        for port in 80 443; do
            # INPUT链
            if ! iptables -C INPUT -p tcp -s "$network" --dport "$port" -j ACCEPT -m comment --comment "$INTERNAL_MARK" 2>/dev/null; then
                iptables -I INPUT 1 -p tcp -s "$network" --dport "$port" -j ACCEPT -m comment --comment "$INTERNAL_MARK"
                log_message "INFO" "添加INPUT内网规则: $network:$port"
            fi
        done
    done
    
    # DOCKER-USER链
    if iptables -L DOCKER-USER -n &>/dev/null; then
        # 先处理lo接口规则
        if ! iptables -C DOCKER-USER -i lo -j RETURN -m comment --comment "$INTERNAL_MARK" 2>/dev/null; then
            iptables -I DOCKER-USER 1 -i lo -j RETURN -m comment --comment "$INTERNAL_MARK"
            log_message "INFO" "添加DOCKER-USER lo接口规则"
        fi
        
        # 添加内网规则
        for network in "${internal_networks[@]}"; do
            for port in 80 443; do
                if ! iptables -C DOCKER-USER -s "$network" -p tcp --dport "$port" -j RETURN -m comment --comment "$INTERNAL_MARK" 2>/dev/null; then
                    iptables -A DOCKER-USER -s "$network" -p tcp --dport "$port" -j RETURN -m comment --comment "$INTERNAL_MARK"
                    log_message "INFO" "添加DOCKER-USER内网规则: $network:$port"
                fi
            done
        done
    fi
}

# 清理旧的Cloudflare规则
clean_old_rules() {
    log_message "INFO" "清理旧的Cloudflare规则..."
    
    # 清理INPUT链中带有cloudflare-auto标记的规则
    while true; do
        local rule_num=$(iptables -L INPUT -n --line-numbers | grep "$COMMENT_MARK" | head -1 | awk '{print $1}')
        [ -z "$rule_num" ] && break
        iptables -D INPUT "$rule_num" 2>/dev/null || break
    done
    
    # 清理DOCKER-USER链中的规则
    if iptables -L DOCKER-USER -n &>/dev/null; then
        while true; do
            local rule_num=$(iptables -L DOCKER-USER -n --line-numbers | grep "$COMMENT_MARK" | head -1 | awk '{print $1}')
            [ -z "$rule_num" ] && break
            iptables -D DOCKER-USER "$rule_num" 2>/dev/null || break
        done
    fi
    
    # 清理IPv6规则
    if command -v ip6tables &>/dev/null; then
        while true; do
            local rule_num=$(ip6tables -L INPUT -n --line-numbers | grep "$COMMENT_MARK" | head -1 | awk '{print $1}')
            [ -z "$rule_num" ] && break
            ip6tables -D INPUT "$rule_num" 2>/dev/null || break
        done
    fi
    
    log_message "SUCCESS" "旧规则清理完成"
}

# 检查规则是否已存在
rule_exists() {
    local chain="$1"
    local ip="$2"
    local port="$3"
    
    iptables -C "$chain" -p tcp -s "$ip" --dport "$port" -j ACCEPT -m comment --comment "$COMMENT_MARK" 2>/dev/null || \
    iptables -C "$chain" -p tcp -s "$ip" --dport "$port" -j RETURN -m comment --comment "$COMMENT_MARK" 2>/dev/null
}

# 添加新的Cloudflare规则
add_cloudflare_rules() {
    local ips="$1"
    local count=0
    local errors=0
    
    log_message "INFO" "添加新的Cloudflare规则..."
    
    # 获取插入位置
    local insert_pos_input=$(iptables -L INPUT -n --line-numbers | grep -E "$INTERNAL_MARK|192.168.0.0/16.*tcp dpt:443" | tail -1 | awk '{print $1}')
    [ -z "$insert_pos_input" ] && insert_pos_input=8
    
    local insert_pos_docker=1
    if iptables -L DOCKER-USER -n &>/dev/null; then
        insert_pos_docker=$(iptables -L DOCKER-USER -n --line-numbers | grep "$INTERNAL_MARK" | tail -1 | awk '{print $1}')
        [ -z "$insert_pos_docker" ] && insert_pos_docker=9
    fi
    
    while IFS= read -r ip; do
        # 跳过空行和非IP格式的行
        [ -z "$ip" ] && continue
        [[ ! "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]] && \
        [[ ! "$ip" =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}/[0-9]{1,3}$ ]] && continue
        
        if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
            # IPv4规则
            for port in 80 443; do
                # INPUT链
                if ! rule_exists INPUT "$ip" "$port"; then
                    if iptables -I INPUT $((++insert_pos_input)) -p tcp -s "$ip" --dport "$port" -j ACCEPT -m comment --comment "$COMMENT_MARK" 2>/dev/null; then
                        ((count++))
                    else
                        ((errors++))
                        log_message "ERROR" "无法添加INPUT规则 $ip:$port"
                    fi
                fi
                
                # DOCKER-USER链
                if iptables -L DOCKER-USER -n &>/dev/null; then
                    if ! rule_exists DOCKER-USER "$ip" "$port"; then
                        if iptables -I DOCKER-USER $((++insert_pos_docker)) -s "$ip" -p tcp --dport "$port" -j RETURN -m comment --comment "$COMMENT_MARK" 2>/dev/null; then
                            ((count++))
                        else
                            ((errors++))
                            log_message "ERROR" "无法添加DOCKER-USER规则 $ip:$port"
                        fi
                    fi
                fi
            done
        elif [[ "$ip" =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}/[0-9]{1,3}$ ]]; then
            # IPv6规则
            if command -v ip6tables &>/dev/null; then
                for port in 80 443; do
                    if ! ip6tables -C INPUT -p tcp -s "$ip" --dport "$port" -j ACCEPT -m comment --comment "$COMMENT_MARK" 2>/dev/null; then
                        if ip6tables -I INPUT $((++insert_pos_input)) -p tcp -s "$ip" --dport "$port" -j ACCEPT -m comment --comment "$COMMENT_MARK" 2>/dev/null; then
                            ((count++))
                        else
                            ((errors++))
                            log_message "ERROR" "无法添加IPv6规则 $ip:$port"
                        fi
                    fi
                done
            fi
        fi
    done <<< "$ips"
    
    log_message "SUCCESS" "添加了 $count 条规则，$errors 个错误"
}

# 确保DROP规则在最后
ensure_drop_rules_last() {
    log_message "INFO" "确保DROP规则在最后..."
    
    # 查找并移动DROP规则到末尾
    while true; do
        local rule_num=$(iptables -L INPUT -n --line-numbers | grep -E "DROP.*tcp dpt:(80|443)" | grep -v "$COMMENT_MARK\|$INTERNAL_MARK" | head -1 | awk '{print $1}')
        [ -z "$rule_num" ] && break
        
        local rule_content=$(iptables -L INPUT -n --line-numbers | grep "^$rule_num ")
        iptables -D INPUT "$rule_num" 2>/dev/null || break
        
        # 重新添加到末尾
        if [[ "$rule_content" =~ tcp\ dpt:80 ]]; then
            iptables -A INPUT -p tcp --dport 80 -j DROP
        elif [[ "$rule_content" =~ tcp\ dpt:443 ]]; then
            iptables -A INPUT -p tcp --dport 443 -j DROP
        fi
    done
    
    # DOCKER-USER链
    if iptables -L DOCKER-USER -n &>/dev/null; then
        while true; do
            local rule_num=$(iptables -L DOCKER-USER -n --line-numbers | grep -E "DROP.*tcp dpt:(80|443)" | grep -v "$COMMENT_MARK\|$INTERNAL_MARK" | head -1 | awk '{print $1}')
            [ -z "$rule_num" ] && break
            
            iptables -D DOCKER-USER "$rule_num" 2>/dev/null || break
            iptables -A DOCKER-USER -p tcp --dport 80 -j DROP
            iptables -A DOCKER-USER -p tcp --dport 443 -j DROP
        done
    fi
}

# 验证规则
verify_rules() {
    log_message "INFO" "验证防火墙规则..."
    
    local internal_count=$(iptables -L INPUT -n | grep -c "$INTERNAL_MARK" || echo 0)
    local cloudflare_count=$(iptables -L INPUT -n | grep -c "$COMMENT_MARK" || echo 0)
    
    log_message "INFO" "INPUT链: 内网规则 $internal_count 条，Cloudflare规则 $cloudflare_count 条"
    
    if iptables -L DOCKER-USER -n &>/dev/null; then
        local docker_internal=$(iptables -L DOCKER-USER -n | grep -c "$INTERNAL_MARK" || echo 0)
        local docker_cloudflare=$(iptables -L DOCKER-USER -n | grep -c "$COMMENT_MARK" || echo 0)
        log_message "INFO" "DOCKER-USER链: 内网规则 $docker_internal 条，Cloudflare规则 $docker_cloudflare 条"
    fi
    
    # 保存规则
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save
        log_message "SUCCESS" "规则已持久化保存"
    elif command -v iptables-save &>/dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || iptables-save > /etc/sysconfig/iptables 2>/dev/null
        log_message "SUCCESS" "规则已保存"
    fi
}

# 设置定时任务
setup_cron() {
    log_message "INFO" "设置定时更新任务..."
    
    # 创建更新脚本
    cp "$0" "$CF_UPDATE_SCRIPT"
    chmod +x "$CF_UPDATE_SCRIPT"
    
    # 创建cron任务
    cat > "$CF_CRON_JOB" << EOF
# Cloudflare IP自动更新
# 每6小时更新一次
0 */6 * * * root $CF_UPDATE_SCRIPT --update >> $LOG_FILE 2>&1
EOF
    
    log_message "SUCCESS" "定时任务已设置（每6小时更新）"
}

# 删除Cloudflare规则
remove_rules() {
    log_message "INFO" "删除所有Cloudflare规则..."
    clean_old_rules
    log_message "SUCCESS" "Cloudflare规则已删除"
}

# 显示当前规则
show_rules() {
    echo -e "\n${BLUE}========== 当前Cloudflare规则 ==========${NC}"
    
    echo -e "\n${YELLOW}INPUT链:${NC}"
    iptables -L INPUT -n --line-numbers | grep -E "$COMMENT_MARK|$INTERNAL_MARK" || echo "  无规则"
    
    if iptables -L DOCKER-USER -n &>/dev/null; then
        echo -e "\n${YELLOW}DOCKER-USER链:${NC}"
        iptables -L DOCKER-USER -n --line-numbers | grep -E "$COMMENT_MARK|$INTERNAL_MARK" || echo "  无规则"
    fi
    
    if command -v ip6tables &>/dev/null && ip6tables -L INPUT -n &>/dev/null 2>&1; then
        echo -e "\n${YELLOW}IPv6 INPUT链:${NC}"
        ip6tables -L INPUT -n --line-numbers | grep "$COMMENT_MARK" || echo "  无规则"
    fi
}

# 更新Cloudflare IP
update_cloudflare() {
    log_message "INFO" "========== 开始更新Cloudflare IP =========="
    
    # 确保内网规则存在
    ensure_internal_rules
    
    # 获取最新的Cloudflare IP
    local cf_ips=$(get_cloudflare_ips)
    
    if [ -z "$cf_ips" ]; then
        log_message "ERROR" "无法获取Cloudflare IP列表"
        return 1
    fi
    
    # 清理旧规则
    clean_old_rules
    
    # 添加新规则
    add_cloudflare_rules "$cf_ips"
    
    # 确保DROP规则在最后
    ensure_drop_rules_last
    
    # 验证规则
    verify_rules
    
    log_message "SUCCESS" "========== Cloudflare IP更新完成 =========="
}

# 显示帮助
show_help() {
    cat << EOF
${GREEN}Cloudflare IP Manager${NC}
版本: $SCRIPT_VERSION

${YELLOW}用法:${NC}
    $0 [命令]

${YELLOW}命令:${NC}
    update      更新Cloudflare IP规则
    show        显示当前规则
    remove      删除所有Cloudflare规则
    cron        设置定时更新任务
    help        显示帮助

${YELLOW}示例:${NC}
    # 更新Cloudflare IP
    $0 update
    
    # 查看当前规则
    $0 show
    
    # 设置每6小时自动更新
    $0 cron

${YELLOW}说明:${NC}
    此脚本管理iptables规则，只允许Cloudflare IP访问80/443端口
    内网访问始终允许
    支持Docker环境（DOCKER-USER链）

EOF
}

# 主函数
main() {
    # 检查root权限
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}错误: 需要root权限运行${NC}"
        exit 1
    fi
    
    case "${1:-help}" in
        update|--update)
            update_cloudflare
            ;;
        show|--show)
            show_rules
            ;;
        remove|--remove)
            remove_rules
            ;;
        cron|--cron)
            setup_cron
            ;;
        help|--help)
            show_help
            ;;
        *)
            echo -e "${RED}未知命令: $1${NC}"
            show_help
            exit 1
            ;;
    esac
}

# 执行主函数
main "$@"