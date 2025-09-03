# 通用日志函数 - 符合最佳实践
# 特性：简洁、安全、实用、性能优化

log_message() {
    local level="${1:-INFO}"
    local message="${2:-}"
    local timestamp
    local log_prefix
    
    # 参数验证
    if [ -z "$message" ]; then
        echo "[错误] log_message: 消息内容不能为空" >&2
        return 1
    fi
    
    # 安全：过滤敏感信息
    if [[ "$message" =~ (ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp[0-9]+)[[:space:]]+[A-Za-z0-9+/]+=*|password.*=|token.*=|key.*= ]]; then
        message="[敏感信息已过滤]"
    fi
    
    # 统一时间戳格式（ISO 8601）
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # 级别标准化和输出
    case "${level^^}" in  # 转换为大写，提高容错性
        "ERROR"|"ERR")
            log_prefix="[错误]"
            echo "$log_prefix $message" >&2  # 错误输出到 stderr
            ;;
        "WARNING"|"WARN"|"W")
            log_prefix="[警告]"
            echo "$log_prefix $message"
            ;;
        "INFO"|"I")
            log_prefix="[信息]"
            echo "$log_prefix $message"
            ;;
        "DEBUG"|"D")
            # DEBUG 级别只在设置了 DEBUG 环境变量时才输出到控制台
            log_prefix="[调试]"
            [ "${DEBUG:-}" = "1" ] && echo "$log_prefix $message"
            ;;
        "SUCCESS"|"OK")
            log_prefix="[成功]"
            echo "$log_prefix $message"
            ;;
        *)
            log_prefix="[日志]"
            echo "$log_prefix $message"
            ;;
    esac
    
    # 文件日志记录（如果定义了 LOG_FILE）
    if [ -n "${LOG_FILE:-}" ]; then
        # 确保日志目录存在（安全创建）
        local log_dir
        log_dir=$(dirname "$LOG_FILE")
        if [ ! -d "$log_dir" ]; then
            if ! mkdir -p "$log_dir" 2>/dev/null; then
                echo "[警告] 无法创建日志目录: $log_dir" >&2
                return 0  # 不影响主程序执行
            fi
            # 设置安全的目录权限
            chmod 750 "$log_dir" 2>/dev/null || true
        fi
        
        # 写入日志文件（原子操作，避免并发问题）
        {
            echo "[$timestamp][$level] $message"
        } >> "$LOG_FILE" 2>/dev/null || {
            echo "[警告] 无法写入日志文件: $LOG_FILE" >&2
        }
        
        # 设置安全的文件权限
        chmod 640 "$LOG_FILE" 2>/dev/null || true
        
        # 简单的日志轮转（防止日志文件过大）
        if [ -f "$LOG_FILE" ] && [ "$(wc -l < "$LOG_FILE" 2>/dev/null || echo 0)" -gt 10000 ]; then
            # 保留最后 5000 行
            tail -5000 "$LOG_FILE" > "${LOG_FILE}.tmp" 2>/dev/null && mv "${LOG_FILE}.tmp" "$LOG_FILE" 2>/dev/null
        fi
    fi
    
    # 系统日志记录（重要消息）
    if [ "${level^^}" = "ERROR" ] && command -v logger >/dev/null 2>&1; then
        logger -t "$(basename "$0" .sh)" -p user.err "$message" 2>/dev/null || true
    fi
}

