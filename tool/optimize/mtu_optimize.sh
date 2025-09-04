#!/bin/bash

# MTU检测和优化脚本 v2.0
# 用于VPS环境的智能MTU检测和优化
# 支持各种网络环境的自动识别和配置
# 
# 作者: AlexKris  
# 版本: 2.0
# 更新: $(date '+%Y-%m-%d')

# 启用严格模式，显式错误处理（移除-e以避免不可预测行为）
set -uo pipefail

# 脚本版本
readonly SCRIPT_VERSION="2.0"

# 获取脚本所在目录（支持管道执行）
if [ -n "${BASH_SOURCE[0]:-}" ] && [[ "${BASH_SOURCE[0]}" != /dev/fd/* ]] && [[ "${BASH_SOURCE[0]}" != /proc/self/fd/* ]]; then
    # 正常文件执行
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
    # 通过管道执行，使用用户家目录或/tmp
    if [ -w "$HOME" ] && [ -d "$HOME" ]; then
        SCRIPT_DIR="$HOME"
    else
        SCRIPT_DIR="/tmp"
    fi
fi

# 时间戳
readonly TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# 临时文件清理变量
TMP_FILES=""

# 全局变量
BACKUP_DIR="/etc/mtu-optimize.backup"
readonly LOG_FILE="$SCRIPT_DIR/mtu_optimize-$TIMESTAMP.log"

# 默认配置
DEFAULT_TARGET="8.8.8.8"
DEFAULT_INTERFACE=""
MIN_MTU=576
MAX_MTU=9000
COMMON_MTUS=(1500 1492 1480 1472 1468 1464 1460 1454 1400 1436 1420)

# 配置变量
INTERFACE=""
TARGET=""
PROFILE=""
AUTO_MODE=false
DRY_RUN=false
APPLY_CONFIG=false
RESTORE=false
PERSIST=false

# 设置安全的临时文件处理
cleanup() {
    # 删除所有临时文件
    if [ -n "$TMP_FILES" ]; then
        rm -f $TMP_FILES >/dev/null 2>&1
    fi
    log_message "INFO" "MTU脚本执行完成，清理临时文件"
}

# 注册EXIT信号处理
trap cleanup EXIT INT TERM

# ==================== 现代化错误处理函数 ====================

# 致命错误处理函数 - 记录错误并退出
die() {
    local msg="${1:-未知致命错误}"
    local exit_code="${2:-1}"
    
    log_message "ERROR" "致命错误: $msg"
    log_message "ERROR" "脚本终止执行 (退出码: $exit_code)"
    
    # 清理资源
    cleanup 2>/dev/null || true
    exit "$exit_code"
}

# 检查命令执行结果 - 非致命错误处理
check_error() {
    local exit_code=$1
    local operation="${2:-操作}"
    local context="${3:-}"
    
    if [ $exit_code -ne 0 ]; then
        local error_msg="$operation 失败 (错误码: $exit_code)"
        [ -n "$context" ] && error_msg="$error_msg - $context"
        
        log_message "WARNING" "$error_msg"
        return 1
    fi
    return 0
}

# 安全执行命令 - 带错误检查的命令执行
safe_execute() {
    local cmd="$1"
    local description="${2:-执行命令}"
    local fatal="${3:-false}"
    
    log_message "DEBUG" "执行: $cmd"
    
    # 执行命令并捕获退出码
    eval "$cmd"
    local exit_code=$?
    
    # 只有非零退出码才算真正失败
    if [ "$exit_code" -ne 0 ]; then
        local error_msg="$description 失败 (错误码: $exit_code)"
        
        if [ "$fatal" = "true" ]; then
            die "$error_msg" "$exit_code"
        else
            log_message "WARNING" "$error_msg"
            return "$exit_code"
        fi
    fi
    
    log_message "DEBUG" "$description 成功"
    return 0
}

# 日志记录函数（与network_optimize.sh保持一致）
log_message() {
    local level="${1:-INFO}"
    local message="${2:-}"
    local timestamp
    
    # 参数验证
    [ -z "$message" ] && { echo "[错误] 消息内容不能为空" >&2; return 1; }
    
    # 统一时间戳格式
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # 级别标准化和输出（兼容老版本bash）
    local upper_level=$(echo "$level" | tr '[:lower:]' '[:upper:]')
    case "$upper_level" in
        "ERROR"|"ERR")
            echo "[错误] $message" | tee -a "$LOG_FILE" >&2
            ;;
        "WARNING"|"WARN")
            echo "[警告] $message" | tee -a "$LOG_FILE"
            ;;
        "INFO")
            echo "[信息] $message" | tee -a "$LOG_FILE"
            ;;
        "SUCCESS"|"OK")
            echo "[成功] $message" | tee -a "$LOG_FILE"
            ;;
        "DEBUG")
            [ "${DEBUG:-}" = "1" ] && echo "[调试] $message" | tee -a "$LOG_FILE"
            ;;
        *)
            echo "[信息] $message" | tee -a "$LOG_FILE"
            ;;
    esac
    
    # 写入日志文件（带时间戳）
    echo "[$timestamp][$level] $message" >> "$LOG_FILE" 2>/dev/null || true
}

# 检查是否为root用户
check_root() {
    if [[ $EUID -ne 0 ]]; then
        die "此脚本需要root权限运行"
    fi
}

# 创建备份目录
ensure_backup_dir() {
    if [[ ! -d "$BACKUP_DIR" ]]; then
        if mkdir -p "$BACKUP_DIR" 2>/dev/null; then
            log_message "INFO" "创建备份目录: $BACKUP_DIR"
        else
            # 如果无法创建系统目录，使用用户目录
            BACKUP_DIR="$SCRIPT_DIR/mtu-backup"
            mkdir -p "$BACKUP_DIR"
            log_message "WARNING" "无法创建系统备份目录，使用: $BACKUP_DIR"
        fi
    fi
}

# 获取默认网络接口
get_default_interface() {
    # 尝试从默认路由获取
    local iface=$(ip route | grep default | awk '{print $5}' | head -1)
    if [ -z "$iface" ]; then
        # 如果没有默认路由，获取第一个非lo接口
        iface=$(ip link show | grep -E "^[0-9]+:" | grep -v "lo:" | head -1 | cut -d: -f2 | tr -d ' ')
    fi
    echo "$iface"
}

# 显示当前MTU设置
show_current_mtu() {
    echo "========== 当前MTU设置 =========="
    ip link show | grep -E "^[0-9]+:" | while read -r line; do
        local iface=$(echo "$line" | cut -d: -f2 | tr -d ' ')
        if [[ "$iface" != "lo" ]]; then
            local mtu=$(ip link show "$iface" | grep -oP 'mtu \K[0-9]+' | head -1)
            local state=$(ip link show "$iface" | grep -oP 'state \K[A-Z]+' | head -1)
            printf "  %-15s MTU: %-6s 状态: %s\n" "$iface" "$mtu" "$state"
        fi
    done
    
    echo ""
    echo "========== 路由表MTU信息 =========="
    ip route show | grep -E "mtu|metric" | head -10 || echo "  无特殊MTU路由"
}

# 检测VPS环境类型
detect_vps_environment() {
    local env_info=""
    
    # 检测虚拟化类型
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        local virt_type=$(systemd-detect-virt 2>/dev/null)
        case "$virt_type" in
            "kvm") env_info="KVM虚拟化" ;;
            "xen") env_info="Xen虚拟化" ;;
            "vmware") env_info="VMware虚拟化" ;;
            "microsoft") env_info="Hyper-V虚拟化" ;;
            "oracle") env_info="VirtualBox" ;;
            "openvz") env_info="OpenVZ容器" ;;
            "lxc") env_info="LXC容器" ;;
            "docker") env_info="Docker容器" ;;
            "none") env_info="物理机" ;;
            *) env_info="未知虚拟化: $virt_type" ;;
        esac
    else
        # 备用检测方法
        if [ -f /.dockerenv ]; then
            env_info="Docker容器"
        elif grep -q docker /proc/1/cgroup 2>/dev/null; then
            env_info="Docker容器"
        elif [ -d /proc/vz ]; then
            env_info="OpenVZ容器"
        elif grep -q "QEMU\|KVM" /proc/cpuinfo 2>/dev/null; then
            env_info="KVM虚拟化"
        elif command -v dmidecode >/dev/null 2>&1 && dmidecode -s system-product-name 2>/dev/null | grep -qi vmware; then
            env_info="VMware虚拟化"
        else
            env_info="未知环境"
        fi
    fi
    
    echo "$env_info"
}

# 检测云服务商
detect_cloud_provider() {
    local provider="未知"
    
    # 检查DMI信息
    if command -v dmidecode >/dev/null 2>&1; then
        local dmi_info=$(dmidecode -s system-product-name 2>/dev/null)
        case "$dmi_info" in
            *"Amazon EC2"*) provider="AWS" ;;
            *"Google"*) provider="Google Cloud" ;;
            *"Microsoft"*) provider="Azure" ;;
            *"Alibaba"*) provider="阿里云" ;;
            *"QCLOUD"*) provider="腾讯云" ;;
            *"DigitalOcean"*) provider="DigitalOcean" ;;
            *"Vultr"*) provider="Vultr" ;;
            *"Linode"*) provider="Linode" ;;
        esac
    fi
    
    # 检查网络接口名称模式
    if [ "$provider" = "未知" ]; then
        local interfaces=$(ip link show | grep -oP '^\d+: \K[^:]+' | grep -v lo)
        for iface in $interfaces; do
            case "$iface" in
                ens*) provider="可能是云服务器" ;;
                eth*) ;;
            esac
        done
    fi
    
    echo "$provider"
}

# 获取推荐的MTU值
get_recommended_mtu() {
    local provider=$1
    local virt_type=$2
    local current_mtu=$3
    
    case "$provider" in
        "AWS")
            if [ "$current_mtu" -eq 9000 ]; then
                echo "1500"  # AWS外网需要1500
            else
                echo "1500"
            fi
            ;;
        "Google Cloud")
            echo "1460"  # GCP推荐值
            ;;
        "阿里云"|"腾讯云")
            echo "1500"
            ;;
        "DigitalOcean"|"Vultr"|"Linode")
            echo "1500"
            ;;
        *)
            # 通用推荐
            if [ "$current_mtu" -gt 1500 ]; then
                echo "1500"
            else
                echo "$current_mtu"  # 保持现状
            fi
            ;;
    esac
}

# 检测网络环境特征
detect_network_environment() {
    local env_features=""
    
    # 检查PPPoE特征
    if ip link show | grep -q ppp || [ -f /etc/ppp/pppoe.conf ]; then
        env_features="$env_features PPPoE"
    fi
    
    # 检查VPN接口
    if ip link show | grep -qE "(tun|tap|wg|ipsec)"; then
        env_features="$env_features VPN隧道"
    fi
    
    # 检查NAT配置
    if iptables -t nat -L >/dev/null 2>&1; then
        if iptables -t nat -L | grep -q MASQUERADE; then
            env_features="$env_features NAT网关"
        fi
    fi
    
    echo "$env_features"
}

# 使用ping测试MTU
test_mtu_with_ping() {
    local target=$1
    local mtu=$2
    local interface=$3
    local packet_size=$((mtu - 28))  # 减去IP头(20字节)和ICMP头(8字节)
    
    # 验证参数
    if [ $packet_size -le 0 ]; then
        log_message "WARNING" "无效的数据包大小: $packet_size (MTU: $mtu)"
        return 1
    fi
    
    log_message "DEBUG" "测试MTU $mtu (数据包大小: $packet_size)"
    
    if [ -n "$interface" ]; then
        # Linux平台使用-I指定接口
        ping -c 1 -W 1 -M do -s "$packet_size" -I "$interface" "$target" >/dev/null 2>&1
    else
        ping -c 1 -W 1 -M do -s "$packet_size" "$target" >/dev/null 2>&1
    fi
    return $?
}

# 二分查找最优MTU
find_optimal_mtu() {
    local target=$1
    local interface=$2
    local low=$MIN_MTU
    local high=$MAX_MTU
    local optimal_mtu=$MIN_MTU
    
    echo ""
    log_message "INFO" "开始MTU探测 (目标: $target)"
    echo "使用二分查找法..."
    
    # 首先测试几个常见值
    echo ""
    echo "测试常见MTU值:"
    for mtu in "${COMMON_MTUS[@]}"; do
        printf "  测试 MTU %4d ... " "$mtu"
        if test_mtu_with_ping "$target" "$mtu" "$interface"; then
            echo "成功"
            if [ "$mtu" -gt "$optimal_mtu" ]; then
                optimal_mtu=$mtu
                low=$mtu
            fi
        else
            echo "失败"
            if [ "$mtu" -lt "$high" ]; then
                high=$mtu
            fi
        fi
    done
    
    echo ""
    echo "精确查找最优值 (范围: $low - $high):"
    while [ $((high - low)) -gt 1 ]; do
        local mid=$(((low + high) / 2))
        printf "  测试 MTU %4d ... " "$mid"
        
        if test_mtu_with_ping "$target" "$mid" "$interface"; then
            echo "成功"
            low=$mid
            optimal_mtu=$mid
        else
            echo "失败"
            high=$mid
        fi
    done
    
    echo ""
    log_message "SUCCESS" "最优MTU值: $optimal_mtu"
    echo "$optimal_mtu"
}

# 路径MTU发现
path_mtu_discovery() {
    local target=$1
    echo ""
    echo "========== 路径MTU发现 =========="
    
    # 使用tracepath进行路径MTU发现
    if command -v tracepath >/dev/null 2>&1; then
        echo "使用tracepath探测到$target的路径MTU:"
        tracepath -n "$target" | tail -5
    else
        log_message "WARNING" "tracepath未安装，使用ping探测"
        local mtu=$(find_optimal_mtu "$target" "")
        echo "探测到的路径MTU: $mtu"
    fi
}

# 测试不同MTU的性能
benchmark_mtu() {
    local interface=$1
    local target=$2
    local current_mtu=$(ip link show "$interface" | grep -oP 'mtu \K[0-9]+' | head -1)
    
    echo ""
    echo "========== MTU性能测试 =========="
    echo "接口: $interface, 目标: $target"
    echo "当前MTU: $current_mtu"
    echo ""
    
    local test_mtus=(1400 1450 1480 1492 1500)
    if [ "$current_mtu" -gt 1500 ]; then
        test_mtus+=(2000 4000 9000)
    fi
    
    echo "MTU  | 延迟(ms) | 丢包率 | 吞吐量评分"
    echo "-----|----------|--------|------------"
    
    for mtu in "${test_mtus[@]}"; do
        if [ "$mtu" -le "$MAX_MTU" ]; then
            # 临时设置MTU
            safe_execute "ip link set dev '$interface' mtu '$mtu'" "设置测试MTU" "false" || continue
            sleep 1
            
            # 测试延迟和丢包率
            local ping_result=$(ping -c 10 -W 1 -i 0.2 "$target" 2>/dev/null | tail -2)
            local loss=$(echo "$ping_result" | grep -oP '\d+(?=% packet loss)' | head -1)
            local latency=$(echo "$ping_result" | grep -oP 'avg = [\d.]+/\K[\d.]+' | head -1)
            
            # 计算吞吐量评分 (MTU越大，开销越小)
            local overhead=$((28 * 100 / mtu))
            local throughput_score=$((100 - overhead))
            
            printf "%4d | %8s | %6s%% | %10d%%\n" \
                "$mtu" \
                "${latency:-N/A}" \
                "${loss:-100}" \
                "$throughput_score"
        fi
    done
    
    # 恢复原始MTU
    safe_execute "ip link set dev '$interface' mtu '$current_mtu'" "恢复MTU设置" "false"
    echo ""
    log_message "INFO" "MTU已恢复到: $current_mtu"
}

# 备份当前MTU配置
backup_mtu_config() {
    local interface=$1
    local current_mtu=$(ip link show "$interface" | grep -oP 'mtu \K[0-9]+' | head -1)
    local backup_file="$BACKUP_DIR/mtu_backup_${interface}_$(date +%Y%m%d_%H%M%S).conf"
    
    echo "interface=$interface" > "$backup_file"
    echo "mtu=$current_mtu" >> "$backup_file"
    echo "timestamp=$(date)" >> "$backup_file"
    
    log_message "INFO" "MTU配置已备份到: $backup_file"
    echo "$backup_file"
}

# 恢复MTU配置
restore_mtu_config() {
    local backup_file=$1
    
    if [ ! -f "$backup_file" ]; then
        log_message "ERROR" "备份文件不存在: $backup_file"
        return 1
    fi
    
    # 读取备份信息
    local interface=$(grep "^interface=" "$backup_file" | cut -d= -f2)
    local mtu=$(grep "^mtu=" "$backup_file" | cut -d= -f2)
    
    if [ -z "$interface" ] || [ -z "$mtu" ]; then
        log_message "ERROR" "备份文件格式错误"
        return 1
    fi
    
    log_message "INFO" "恢复MTU配置: $interface -> $mtu"
    safe_execute "ip link set dev '$interface' mtu '$mtu'" "恢复MTU" "false"
}

# 列出可用的备份
list_mtu_backups() {
    echo "可用的MTU备份文件:"
    ls -la "$BACKUP_DIR"/mtu_backup_*.conf 2>/dev/null | head -10 || {
        echo "没有找到备份文件"
        return 1
    }
}

# 安全应用MTU设置（带自动回滚）
safe_apply_mtu() {
    local interface=$1
    local mtu=$2
    local timeout=${3:-30}  # 默认30秒超时
    
    echo ""
    log_message "INFO" "安全应用MTU设置 (超时: ${timeout}秒)"
    echo "接口: $interface"
    echo "新MTU: $mtu"
    
    # 检查是否需要root权限
    check_root
    
    # 备份当前配置
    local backup_file
    backup_file=$(backup_mtu_config "$interface")
    
    # 应用新的MTU设置
    if safe_execute "ip link set dev '$interface' mtu '$mtu'" "设置MTU" "false"; then
        log_message "SUCCESS" "MTU设置成功"
        
        # 验证设置
        local current_mtu=$(ip link show "$interface" | grep -oP 'mtu \K[0-9]+' | head -1)
        if [ "$current_mtu" = "$mtu" ]; then
            echo "验证成功: MTU已设置为 $current_mtu"
            
            # 测试网络连通性
            echo "测试网络连通性，如无响应将在 ${timeout} 秒后自动回滚..."
            echo "按 Ctrl+C 可立即回滚"
            
            # 设置自动回滚
            (
                sleep "$timeout"
                echo ""
                log_message "WARNING" "超时自动回滚MTU设置"
                restore_mtu_config "$backup_file"
                exit 0
            ) &
            local rollback_pid=$!
            
            # 等待用户确认
            echo "网络连通正常? (y/n): "
            read -r -t "$timeout" confirm
            
            # 杀死自动回滚进程
            kill "$rollback_pid" 2>/dev/null
            wait "$rollback_pid" 2>/dev/null
            
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                log_message "SUCCESS" "MTU设置确认成功"
                rm -f "$backup_file"  # 删除备份文件
                return 0
            else
                log_message "WARNING" "用户取消，回滚MTU设置"
                restore_mtu_config "$backup_file"
                return 1
            fi
        else
            log_message "WARNING" "MTU设置验证失败，期望: $mtu，实际: $current_mtu"
            restore_mtu_config "$backup_file"
            return 1
        fi
    else
        log_message "ERROR" "MTU设置失败"
        return 1
    fi
}

# 应用MTU设置（简化版本，向后兼容）
apply_mtu() {
    local interface=$1
    local mtu=$2
    
    # 如果是交互模式，使用安全模式
    if [ -t 0 ] && [ -t 1 ]; then
        safe_apply_mtu "$interface" "$mtu" 30
    else
        # 非交互模式，直接应用
        echo ""
        log_message "INFO" "应用MTU设置（非交互模式）"
        echo "接口: $interface"
        echo "新MTU: $mtu"
        
        check_root
        
        if safe_execute "ip link set dev '$interface' mtu '$mtu'" "设置MTU" "false"; then
            log_message "SUCCESS" "MTU设置成功"
            
            local current_mtu=$(ip link show "$interface" | grep -oP 'mtu \K[0-9]+' | head -1)
            if [ "$current_mtu" = "$mtu" ]; then
                echo "验证成功: MTU已设置为 $current_mtu"
            else
                log_message "WARNING" "MTU设置验证失败，期望: $mtu，实际: $current_mtu"
            fi
            
            return 0
        else
            log_message "ERROR" "MTU设置失败"
            return 1
        fi
    fi
}

# MTU问题诊断
diagnose_mtu_issues() {
    echo ""
    echo "========== MTU问题诊断 =========="
    
    echo ""
    echo "1. 检查MSS钳制:"
    iptables -t mangle -L FORWARD -n -v 2>/dev/null | grep -i "tcp.*mss" || echo "  未发现MSS钳制规则"
    
    echo ""
    echo "2. 检查PMTU黑洞:"
    local icmp_setting=$(sysctl net.ipv4.tcp_mtu_probing 2>/dev/null | cut -d= -f2 | tr -d ' ')
    case "$icmp_setting" in
        0) echo "  PMTU探测: 关闭 (可能存在黑洞问题)" ;;
        1) echo "  PMTU探测: 默认关闭" ;;
        2) echo "  PMTU探测: 始终开启 (推荐)" ;;
        *) echo "  PMTU探测: 未知状态" ;;
    esac
    
    echo ""
    echo "3. 检查ICMP过滤:"
    local icmp_ignore=$(sysctl net.ipv4.icmp_ignore_all 2>/dev/null | cut -d= -f2 | tr -d ' ')
    if [ "$icmp_ignore" = "1" ]; then
        echo "  警告: ICMP被忽略，可能影响PMTU发现"
    else
        echo "  ICMP正常处理"
    fi
    
    echo ""
    echo "4. 常见MTU问题症状:"
    echo "  - 小文件传输正常，大文件传输失败: MTU过大"
    echo "  - SSH能连接但传输卡住: MTU问题"
    echo "  - 网页部分加载: MTU或MSS问题"
    echo "  - VPN连接后速度慢: MTU需要调整"
    
    echo ""
    echo "5. 建议的MTU值:"
    echo "  - 以太网标准: 1500"
    echo "  - PPPoE: 1492"
    echo "  - VPN (IPSec): 1400-1420"
    echo "  - VPN (OpenVPN): 1400-1450"
    echo "  - IPv6隧道: 1280"
    echo "  - Jumbo帧: 9000"
    
    # 检测当前环境问题
    echo ""
    echo "6. 当前环境检测:"
    detect_mtu_problems
}

# 检测MTU相关问题
detect_mtu_problems() {
    local problems=0
    
    echo ""
    echo "========== 系统环境检测 =========="
    
    # 虚拟化环境
    local virt_env=$(detect_vps_environment)
    echo "虚拟化环境: $virt_env"
    
    # 云服务商
    local cloud_provider=$(detect_cloud_provider)
    echo "云服务商: $cloud_provider"
    
    # 网络特征
    local net_features=$(detect_network_environment)
    if [ -n "$net_features" ]; then
        echo "网络特征:$net_features"
    fi
    
    echo ""
    echo "========== MTU问题检测 =========="
    
    # 检查接口MTU设置
    while IFS= read -r line; do
        local iface=$(echo "$line" | cut -d: -f2 | tr -d ' ')
        if [[ "$iface" != "lo" ]]; then
            local mtu=$(ip link show "$iface" | grep -oP 'mtu \K[0-9]+' | head -1)
            if [ "$mtu" -gt 1500 ]; then
                echo "  ⚠️  接口 $iface MTU=${mtu} (>1500，可能导致外网访问问题)"
                problems=$((problems + 1))
                
                # 提供具体建议
                local recommended=$(get_recommended_mtu "$cloud_provider" "$virt_env" "$mtu")
                echo "      建议调整为: $recommended"
            elif [ "$mtu" -lt 1500 ] && [ "$mtu" -gt 1000 ]; then
                echo "  ℹ️  接口 $iface MTU=${mtu} (较小值，可能针对特殊环境优化)"
            fi
        fi
    done < <(ip link show | grep -E "^[0-9]+:")
    
    # 检查容器环境特殊情况
    if echo "$virt_env" | grep -q "容器"; then
        echo "  ℹ️  检测到容器环境，MTU设置可能受宿主机限制"
    fi
    
    if [ $problems -eq 0 ]; then
        echo "  ✓ 未发现明显的MTU配置问题"
    fi
    
    echo ""
}

# 生成MTU优化报告
generate_report() {
    local output_file="mtu_report_$(date +%Y%m%d_%H%M%S).txt"
    
    {
        echo "===== MTU优化报告 ====="
        echo "生成时间: $(date)"
        echo ""
        show_current_mtu
        echo ""
        diagnose_mtu_issues
    } > "$output_file"
    
    echo ""
    log_message "SUCCESS" "报告已保存到: $output_file"
}

# 一键自动优化
auto_optimize_mtu() {
    log_message "INFO" "开始一键MTU自动优化"
    
    local interface
    interface=$(get_default_interface)
    if [ -z "$interface" ]; then
        log_message "ERROR" "无法获取默认网络接口"
        return 1
    fi
    
    log_message "INFO" "使用接口: $interface"
    
    # 检测当前MTU
    local current_mtu
    current_mtu=$(ip link show "$interface" | grep -oP 'mtu \K[0-9]+' | head -1)
    log_message "INFO" "当前MTU: $current_mtu"
    
    # 如果MTU > 1500，很可能需要优化
    if [ "$current_mtu" -gt 1500 ]; then
        log_message "WARNING" "检测到MTU > 1500，可能影响外网访问，建议优化"
        
        # 自动检测最优MTU
        local optimal_mtu
        optimal_mtu=$(find_optimal_mtu "$DEFAULT_TARGET" "$interface")
        
        if [ -n "$optimal_mtu" ] && [ "$optimal_mtu" != "$current_mtu" ]; then
            echo ""
            echo "建议将MTU从 $current_mtu 调整为 $optimal_mtu"
            echo "是否应用此设置? (y/n): "
            read -r confirm
            
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                if apply_mtu "$interface" "$optimal_mtu"; then
                    log_message "SUCCESS" "MTU优化完成"
                    suggest_persistence "$interface" "$optimal_mtu"
                fi
            fi
        fi
    else
        log_message "INFO" "当前MTU配置合理，无需调整"
    fi
}

# 检测网络管理器类型
detect_network_manager() {
    if systemctl is-active NetworkManager >/dev/null 2>&1; then
        echo "NetworkManager"
    elif systemctl is-active systemd-networkd >/dev/null 2>&1; then
        echo "systemd-networkd"
    elif [ -f /etc/network/interfaces ]; then
        echo "ifupdown"
    else
        echo "unknown"
    fi
}

# 自动持久化MTU配置
persist_mtu_config() {
    local interface=$1
    local mtu=$2
    local manager=$(detect_network_manager)
    
    echo ""
    log_message "INFO" "检测到网络管理器: $manager"
    
    case "$manager" in
        "NetworkManager")
            # 获取活动连接名称
            local connection=$(nmcli -t -f NAME con show --active | head -1)
            if [ -n "$connection" ]; then
                if safe_execute "nmcli con mod '$connection' 802-3-ethernet.mtu $mtu" "配置NetworkManager MTU" "false"; then
                    safe_execute "nmcli con up '$connection'" "重新加载连接" "false"
                    log_message "SUCCESS" "NetworkManager MTU配置已生效"
                    return 0
                fi
            else
                log_message "ERROR" "无法找到活动的NetworkManager连接"
                return 1
            fi
            ;;
        "systemd-networkd")
            # 查找网络配置文件
            local network_file="/etc/systemd/network/50-$interface.network"
            if [ ! -f "$network_file" ]; then
                # 创建基本的网络配置文件
                cat > "$network_file" << EOF
[Match]
Name=$interface

[Network]
DHCP=yes
MTUBytes=$mtu
EOF
                log_message "INFO" "创建systemd-networkd配置文件: $network_file"
            else
                # 更新现有文件
                if grep -q "MTUBytes=" "$network_file"; then
                    sed -i "s/MTUBytes=.*/MTUBytes=$mtu/" "$network_file"
                else
                    echo "MTUBytes=$mtu" >> "$network_file"
                fi
                log_message "INFO" "更新systemd-networkd配置文件"
            fi
            
            # 重启网络服务
            if safe_execute "systemctl restart systemd-networkd" "重启systemd-networkd" "false"; then
                log_message "SUCCESS" "systemd-networkd MTU配置已生效"
                return 0
            fi
            ;;
        "ifupdown")
            # 备份原配置
            cp /etc/network/interfaces /etc/network/interfaces.bak.$(date +%Y%m%d_%H%M%S)
            
            # 添加MTU配置
            if grep -q "iface $interface" /etc/network/interfaces; then
                # 接口已存在，添加mtu行
                sed -i "/iface $interface/a\\    mtu $mtu" /etc/network/interfaces
            else
                # 添加新接口配置
                cat >> /etc/network/interfaces << EOF

# Auto-generated MTU configuration for $interface
auto $interface
iface $interface inet dhcp
    mtu $mtu
EOF
            fi
            log_message "SUCCESS" "已添加到 /etc/network/interfaces"
            log_message "INFO" "重启后生效，或执行: ifdown $interface && ifup $interface"
            return 0
            ;;
        *)
            log_message "WARNING" "无法识别网络管理器，需要手动配置"
            suggest_persistence "$interface" "$mtu"
            return 1
            ;;
    esac
}

# 持久化配置建议
suggest_persistence() {
    local interface=$1
    local mtu=$2
    
    echo ""
    echo "========== 持久化配置建议 =========="
    echo "为了让MTU设置在重启后保持，请选择适合您系统的方法:"
    echo ""
    echo "1. NetworkManager (推荐):"
    echo "   nmcli con mod \$(nmcli -t -f NAME con show --active | head -1) 802-3-ethernet.mtu $mtu"
    echo ""
    echo "2. 传统网络配置 (/etc/network/interfaces):"
    echo "   在接口配置中添加: mtu $mtu"
    echo ""
    echo "3. systemd-networkd:"
    echo "   在对应的 .network 文件中添加: MTUBytes=$mtu"
    echo ""
    echo "4. 使用 --persist 参数让脚本自动配置:"
    echo "   $0 --set $interface $mtu --persist"
}

# 显示使用帮助
show_help() {
    cat << EOF
MTU检测和优化工具 v$SCRIPT_VERSION

用法: $0 [选项]

主要参数:
  --auto               一键自动优化MTU
  --show               显示当前MTU设置
  --detect [target]    检测最优MTU值
  --diagnose           诊断MTU问题
  --set <if> <mtu>     手动设置接口MTU

安全选项:
  --restore            从备份恢复MTU设置
  --list-backups       列出可用的备份文件
  --persist            自动配置持久化（配合--set使用）

可选参数:
  --interface=<name>   指定网络接口
  --target=<ip>        指定测试目标 (默认: $DEFAULT_TARGET)
  --dry-run           预览模式，不实际应用更改
  --help              显示此帮助信息

使用示例:
  # 一键自动优化
  $0 --auto
  
  # 检测最优MTU
  $0 --detect
  
  # 手动设置MTU（带持久化）
  $0 --set eth0 1500 --persist
  
  # 显示当前配置
  $0 --show
  
  # 诊断问题
  $0 --diagnose
  
  # 从备份恢复
  $0 --restore
  
  # 列出备份文件
  $0 --list-backups
  
无参数运行进入交互菜单

EOF
}

# 主菜单
main_menu() {
    while true; do
        echo ""
        echo "========== MTU检测和优化工具 v$SCRIPT_VERSION =========="
        echo "1. 显示当前MTU设置"
        echo "2. 自动检测最优MTU"
        echo "3. 路径MTU发现"
        echo "4. MTU性能基准测试"
        echo "5. 手动设置MTU"
        echo "6. MTU问题诊断"
        echo "7. 生成优化报告"
        echo "8. 一键自动优化"
        echo "9. 备份和恢复管理"
        echo "0. 退出"
        echo "请选择操作 [0-9]: "
        read -r choice
        
        case $choice in
            1)
                show_current_mtu
                ;;
            2)
                echo "请输入目标地址 (默认: $DEFAULT_TARGET): "
                read -r target
                target=${target:-$DEFAULT_TARGET}
                
                DEFAULT_INTERFACE=$(get_default_interface)
                echo "请输入网络接口 (默认: $DEFAULT_INTERFACE): "
                read -r interface
                interface=${interface:-$DEFAULT_INTERFACE}
                
                local optimal_mtu
                optimal_mtu=$(find_optimal_mtu "$target" "$interface")
                echo "建议的最优MTU值: $optimal_mtu"
                ;;
            3)
                echo "请输入目标地址: "
                read -r target
                if [ -n "$target" ]; then
                    path_mtu_discovery "$target"
                fi
                ;;
            4)
                DEFAULT_INTERFACE=$(get_default_interface)
                echo "请输入网络接口 (默认: $DEFAULT_INTERFACE): "
                read -r interface
                interface=${interface:-$DEFAULT_INTERFACE}
                
                echo "请输入测试目标 (默认: $DEFAULT_TARGET): "
                read -r target
                target=${target:-$DEFAULT_TARGET}
                
                if [[ $EUID -ne 0 ]]; then
                    log_message "ERROR" "性能测试需要root权限"
                else
                    benchmark_mtu "$interface" "$target"
                fi
                ;;
            5)
                DEFAULT_INTERFACE=$(get_default_interface)
                echo "请输入网络接口 (默认: $DEFAULT_INTERFACE): "
                read -r interface
                interface=${interface:-$DEFAULT_INTERFACE}
                
                echo "请输入MTU值: "
                read -r mtu
                if [ -n "$mtu" ] && [[ "$mtu" =~ ^[0-9]+$ ]]; then
                    apply_mtu "$interface" "$mtu"
                else
                    log_message "ERROR" "无效的MTU值"
                fi
                ;;
            6)
                diagnose_mtu_issues
                ;;
            7)
                generate_report
                ;;
            8)
                echo "执行一键自动优化..."
                auto_optimize_mtu
                ;;
            9)
                # 备份和恢复子菜单
                echo ""
                echo "========== 备份和恢复管理 =========="
                echo "1. 列出可用备份"
                echo "2. 从备份恢复"
                echo "3. 返回主菜单"
                echo "请选择操作 [1-3]: "
                read -r backup_choice
                
                case $backup_choice in
                    1)
                        list_mtu_backups
                        ;;
                    2)
                        list_mtu_backups
                        if [ $? -eq 0 ]; then
                            echo ""
                            echo "请输入备份文件的完整路径: "
                            read -r backup_file
                            if [ -n "$backup_file" ]; then
                                restore_mtu_config "$backup_file"
                            fi
                        fi
                        ;;
                    3)
                        continue
                        ;;
                    *)
                        echo "无效选择"
                        ;;
                esac
                ;;
            0)
                echo "退出"
                exit 0
                ;;
            *)
                echo "无效选择"
                ;;
        esac
        
        echo ""
        echo "按Enter键继续..."
        read -r
    done
}

# 参数解析
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --auto)
                AUTO_MODE=true
                shift
                ;;
            --interface=*)
                INTERFACE="${1#*=}"
                shift
                ;;
            --target=*)
                TARGET="${1#*=}"
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --persist)
                PERSIST=true
                shift
                ;;
            --restore)
                echo "可用的备份文件:"
                list_mtu_backups
                if [ $? -eq 0 ]; then
                    echo ""
                    echo "请输入要恢复的备份文件路径:"
                    read -r backup_file
                    if [ -n "$backup_file" ]; then
                        restore_mtu_config "$backup_file"
                    fi
                fi
                exit 0
                ;;
            --list-backups)
                list_mtu_backups
                exit 0
                ;;
            --show)
                show_current_mtu
                exit 0
                ;;
            --detect)
                TARGET=${2:-$DEFAULT_TARGET}
                INTERFACE=${3:-$(get_default_interface)}
                local optimal_mtu
                optimal_mtu=$(find_optimal_mtu "$TARGET" "$INTERFACE")
                echo "最优MTU值: $optimal_mtu"
                exit 0
                ;;
            --diagnose)
                diagnose_mtu_issues
                exit 0
                ;;
            --set)
                if [ $# -lt 3 ]; then
                    die "用法: $0 --set <interface> <mtu> [--persist]"
                fi
                
                # 应用MTU设置
                if apply_mtu "$2" "$3"; then
                    # 如果指定了持久化选项
                    if [ "$PERSIST" = "true" ]; then
                        echo ""
                        echo "正在配置持久化..."
                        persist_mtu_config "$2" "$3"
                    else
                        suggest_persistence "$2" "$3"
                    fi
                fi
                exit 0
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                die "未知参数: $1。使用 --help 查看帮助"
                ;;
        esac
    done
}

# 主函数
main() {
    # 初始化
    ensure_backup_dir
    
    # 解析参数
    parse_arguments "$@"
    
    # 如果没有参数，显示交互菜单
    if [[ $# -eq 0 ]]; then
        main_menu
        return 0
    fi
    
    # 执行自动优化
    if [[ "$AUTO_MODE" == "true" ]]; then
        auto_optimize_mtu
    fi
}

# 启动脚本
main "$@"