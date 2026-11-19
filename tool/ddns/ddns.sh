#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

# CloudFlare DDNS Management Script

SCRIPT_VERSION="3.0"
SCRIPT_NAME="cf-ddns"
DDNS_STATE_DIR="$HOME/.ddns"
DDNS_INSTANCES_DIR="$DDNS_STATE_DIR/instances"
LEGACY_EXEC_SCRIPT="$HOME/.local/bin/${SCRIPT_NAME}-exec.sh"

show_usage() {
    cat <<EOF
CloudFlare DDNS 管理脚本 v${SCRIPT_VERSION}

Usage: $0 <COMMAND> [OPTIONS]

Commands:
  install   安装或更新 DDNS 服务（创建执行脚本并配置定时任务）
  run       手动执行 DDNS 更新
  remove    移除 DDNS 服务（删除定时任务、执行脚本及缓存）
  status    查看 DDNS 服务及 IP 同步状态

Install Options:
  -k TOKEN     CloudFlare API Token (必需)
  -z ZONE      主域名 Zone, 如 example.com (必需)
  -h HOSTNAME  记录主机名, 如 server.example.com、server 或 @ (必需)
  -t TYPE      记录类型: A (IPv4) 或 AAAA (IPv6), 默认: A
  -l TTL       TTL 秒数: 1 (自动) 或 60-86400, 默认: 120
  -i INTERVAL  执行间隔(分钟): 1-59 或 60 的整数倍(最大 1440), 默认: 5
  -d DIR       执行脚本安装目录, 默认: ~/.local/bin
  -b BOT_TOKEN Telegram Bot Token (可选, 需与 -c 同时提供)
  -c CHAT_ID   Telegram Chat ID (可选, 需与 -b 同时提供)

Run Options:
  -f FORCE     是否强制更新 (true/false), 默认: false
  -h HOSTNAME  仅运行指定域名实例 (可选)
  -t TYPE      仅运行指定记录类型 A/AAAA (可选)
  -d DIR       指定安装目录 (可选)

Remove / Status Options:
  -h HOSTNAME  仅操作指定域名实例 (可选, 默认全部)
  -t TYPE      仅操作指定记录类型 A/AAAA (可选)
  -d DIR       指定安装目录 (可选)

Examples:
  $0 install -k your_api_token -z example.com -h server.example.com
  $0 install -k your_api_token -z example.com -h server.example.com -t AAAA
  $0 install -k your_api_token -z example.com -h server.example.com -b bot_token -c chat_id
  $0 run
  $0 run -f true
  $0 status
  $0 remove
EOF
    exit 1
}

run_privileged() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        return 1
    fi
}

normalize_domain() {
    local val="$1"
    val="${val%.}"
    printf '%s' "$val" | tr '[:upper:]' '[:lower:]'
}

normalize_fqdn() {
    local hostname
    local zone
    hostname=$(normalize_domain "$1")
    zone=$(normalize_domain "$2")

    if [ "$hostname" = "@" ] || [ "$hostname" = "$zone" ]; then
        printf '%s' "$zone"
    elif [[ "$hostname" == *".$zone" ]]; then
        printf '%s' "$hostname"
    else
        printf '%s.%s' "$hostname" "$zone"
    fi
}

make_instance_id() {
    local fqdn="$1"
    local record_type="$2"
    local safe_fqdn="${fqdn//\*/wildcard}"
    safe_fqdn=$(printf '%s' "$safe_fqdn" | sed 's/[^a-zA-Z0-9._-]/_/g')
    printf '%s_%s' "$safe_fqdn" "$record_type"
}

get_file_mtime() {
    local file="$1"
    if [ ! -e "$file" ]; then
        printf '未知'
        return 0
    fi
    if stat -c '%y' "$file" >/dev/null 2>&1; then
        stat -c '%y' "$file" 2>/dev/null | cut -d. -f1
    elif stat -f '%Sm' -t '%Y-%m-%d %H:%M:%S' "$file" >/dev/null 2>&1; then
        stat -f '%Sm' -t '%Y-%m-%d %H:%M:%S' "$file" 2>/dev/null
    else
        printf '未知'
    fi
}

emit_ip_helpers() {
    cat <<'IP_EOF'
is_valid_ipv4() {
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS='.'
    local octets=()
    read -r -a octets <<< "$ip"
    local o
    for o in "${octets[@]}"; do
        [[ $((10#$o)) -le 255 ]] || return 1
    done
    return 0
}

is_valid_ipv6() {
    local ip="$1"
    [[ ${#ip} -le 45 ]] || return 1
    [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]] || return 1
    [[ "$ip" == *:* ]] || return 1
    [[ "$ip" != *:::* ]] || return 1

    local after_dc="${ip#*::}"
    if [[ "$after_dc" != "$ip" ]] && [[ "$after_dc" == *::* ]]; then
        return 1
    fi
    [[ "$ip" =~ ^:[^:] ]] && return 1
    [[ "$ip" =~ [^:]:$ ]] && return 1

    local IFS=':'
    local groups=()
    read -r -a groups <<< "$ip"
    if [[ "$after_dc" == "$ip" ]]; then
        [[ ${#groups[@]} -eq 8 ]] || return 1
    else
        [[ ${#groups[@]} -le 9 ]] || return 1
    fi
    local g
    for g in ${groups[@]+"${groups[@]}"}; do
        [[ ${#g} -le 4 ]] || return 1
    done
    return 0
}

fetch_public_ip() {
    local record_type="$1"
    local quiet="${2:-false}"
    local services=()
    local curl_flag="-4"

    if [ "$record_type" = "AAAA" ]; then
        services=(
            "https://api64.ipify.org"
            "https://ipv6.icanhazip.com"
            "https://ident.me"
            "https://ifconfig.me"
        )
        curl_flag="-6"
    else
        services=(
            "https://api.ipify.org"
            "https://ipv4.icanhazip.com"
            "https://ident.me"
            "https://ifconfig.me"
        )
    fi

    local service ip
    for service in "${services[@]}"; do
        ip=$(curl "$curl_flag" -fsSL --connect-timeout 5 --max-time 10 "$service" 2>/dev/null | tr -d '[:space:]' || true)
        if [ -z "$ip" ]; then
            continue
        fi
        if [ "$record_type" = "AAAA" ]; then
            if is_valid_ipv6 "$ip"; then
                printf '%s' "$ip"
                return 0
            fi
        else
            if is_valid_ipv4 "$ip"; then
                printf '%s' "$ip"
                return 0
            fi
        fi
        if [ "$quiet" != "true" ]; then
            printf '%s: 警告: %s 返回了无效的 IP 格式: %.80s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$service" "$ip" >&2
        fi
    done
    return 1
}
IP_EOF
}
eval "$(emit_ip_helpers)"

build_cron_schedule() {
    local interval="$1"
    if [ "$interval" -eq 1 ]; then
        printf '* * * * *'
    elif [ "$interval" -lt 60 ]; then
        printf '*/%s * * * *' "$interval"
    elif [ "$interval" -eq 60 ]; then
        printf '0 * * * *'
    elif [ "$interval" -eq 1440 ]; then
        printf '0 0 * * *'
    else
        printf '0 */%s * * *' "$((interval / 60))"
    fi
}

select_log_file() {
    local preferred="/var/log/ddns.log"
    if ( : >> "$preferred" ) 2>/dev/null; then
        printf '%s' "$preferred"
    else
        (
            umask 077
            mkdir -p "$DDNS_STATE_DIR"
        )
        printf '%s' "$DDNS_STATE_DIR/ddns.log"
    fi
}

install_cron_service() {
    echo "正在检测系统类型并安装 cron..."

    if command -v apt-get >/dev/null 2>&1; then
        echo "检测到 Debian/Ubuntu 系统，使用 apt 安装 cron"
        if run_privileged apt-get update >/dev/null 2>&1 && run_privileged apt-get install -y cron >/dev/null 2>&1; then
            run_privileged systemctl enable cron >/dev/null 2>&1 || true
            run_privileged systemctl start cron >/dev/null 2>&1 || run_privileged service cron start >/dev/null 2>&1 || true
            return 0
        fi
    elif command -v dnf >/dev/null 2>&1; then
        echo "检测到 Fedora/RHEL 8+ 系统，使用 dnf 安装 cronie"
        if run_privileged dnf install -y cronie >/dev/null 2>&1; then
            run_privileged systemctl enable crond >/dev/null 2>&1 || true
            run_privileged systemctl start crond >/dev/null 2>&1 || true
            return 0
        fi
    elif command -v yum >/dev/null 2>&1; then
        echo "检测到 RHEL/CentOS 系统，使用 yum 安装 cronie"
        if run_privileged yum install -y cronie >/dev/null 2>&1; then
            run_privileged systemctl enable crond >/dev/null 2>&1 || true
            run_privileged systemctl start crond >/dev/null 2>&1 || true
            return 0
        fi
    elif command -v pacman >/dev/null 2>&1; then
        echo "检测到 Arch Linux 系统，使用 pacman 安装 cronie"
        if run_privileged pacman -S --noconfirm cronie >/dev/null 2>&1; then
            run_privileged systemctl enable cronie >/dev/null 2>&1 || true
            run_privileged systemctl start cronie >/dev/null 2>&1 || true
            return 0
        fi
    elif command -v apk >/dev/null 2>&1; then
        echo "检测到 Alpine Linux 系统，使用 apk 安装 dcron"
        if run_privileged apk add --no-cache dcron >/dev/null 2>&1; then
            run_privileged rc-update add dcron default >/dev/null 2>&1 || true
            run_privileged rc-service dcron start >/dev/null 2>&1 || true
            return 0
        fi
    elif command -v zypper >/dev/null 2>&1; then
        echo "检测到 openSUSE 系统，使用 zypper 安装 cron"
        if run_privileged zypper install -y cron >/dev/null 2>&1; then
            run_privileged systemctl enable cron >/dev/null 2>&1 || true
            run_privileged systemctl start cron >/dev/null 2>&1 || true
            return 0
        fi
    else
        echo "无法识别包管理器，请手动安装 cron 服务"
        return 1
    fi

    echo "cron 安装失败，请检查管理员权限或网络连接"
    return 1
}

is_cron_running() {
    if [[ "${OSTYPE:-}" == darwin* ]]; then
        return 0
    fi
    if (command -v systemctl >/dev/null 2>&1 && (
            systemctl is-active --quiet crond 2>/dev/null ||
            systemctl is-active --quiet cron 2>/dev/null ||
            systemctl is-active --quiet cronie 2>/dev/null
        )) ||
        (command -v service >/dev/null 2>&1 && service cron status >/dev/null 2>&1) ||
        (command -v rc-service >/dev/null 2>&1 && rc-service dcron status >/dev/null 2>&1) ||
        pgrep -x cron >/dev/null 2>&1 ||
        pgrep -x crond >/dev/null 2>&1 ||
        pgrep -x dcron >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

start_cron_service() {
    if run_privileged systemctl start crond >/dev/null 2>&1 ||
        run_privileged systemctl start cron >/dev/null 2>&1 ||
        run_privileged systemctl start cronie >/dev/null 2>&1 ||
        run_privileged service cron start >/dev/null 2>&1 ||
        run_privileged rc-service dcron start >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

remove_cron_matching() {
    local pattern="$1"
    command -v crontab >/dev/null 2>&1 || return 1

    local current_cron=""
    current_cron=$(crontab -l 2>/dev/null || true)
    [ -n "$current_cron" ] || return 1

    if ! printf '%s\n' "$current_cron" | grep -F "$pattern" >/dev/null 2>&1; then
        return 1
    fi

    local filtered_cron=""
    filtered_cron=$(printf '%s\n' "$current_cron" | grep -v -F "$pattern" || true)
    if [ -n "$filtered_cron" ]; then
        printf '%s\n' "$filtered_cron" | crontab -
    else
        crontab -r 2>/dev/null || printf '' | crontab -
    fi
    return 0
}

setup_cron_with_checks() {
    local exec_script="$1"
    local interval="$2"
    local instance_id="$3"
    local log_file="$4"

    if ! command -v crontab >/dev/null 2>&1; then
        echo "检测到系统未安装 cron 服务，尝试自动安装..."
        if ! install_cron_service; then
            return 1
        fi
        echo "✓ cron 服务安装成功"
    fi

    if ! is_cron_running; then
        echo "检测到 cron 服务未运行，尝试启动..."
        if start_cron_service; then
            echo "✓ cron 服务启动成功"
        else
            echo "警告: 无法自动启动 cron 服务，请检查 crond/cron 守护进程状态"
        fi
    fi

    local schedule
    schedule=$(build_cron_schedule "$interval")
    local marker="# ${SCRIPT_NAME}:${instance_id}"
    local cron_cmd="${schedule} \"${exec_script}\" >> \"${log_file}\" 2>&1 ${marker}"

    local current_cron=""
    current_cron=$(crontab -l 2>/dev/null || true)
    local filtered_cron=""
    if [ -n "$current_cron" ]; then
        filtered_cron=$(printf '%s\n' "$current_cron" | grep -v -F "$marker" | grep -v -F "$exec_script" || true)
    fi

    local new_cron
    if [ -n "$filtered_cron" ]; then
        new_cron=$(printf '%s\n%s' "$filtered_cron" "$cron_cmd")
    else
        new_cron="$cron_cmd"
    fi

    if printf '%s\n' "$new_cron" | crontab - 2>/dev/null; then
        echo "cron 定时任务: 每 $interval 分钟执行一次"
        echo "日志文件: $log_file"
        return 0
    fi
    return 1
}

create_systemd_timer() {
    local exec_script="$1"
    local interval="$2"
    local service_name="$3"

    local user_systemd_dir="$HOME/.config/systemd/user"
    if ! mkdir -p "$user_systemd_dir" 2>/dev/null; then
        echo "错误: 无法创建 systemd 用户目录"
        return 1
    fi

    cat > "$user_systemd_dir/${service_name}.service" <<EOF
[Unit]
Description=${service_name} DDNS execution service
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart="${exec_script}"
StandardOutput=journal
StandardError=journal
Environment="HOME=${HOME}"
EOF

    cat > "$user_systemd_dir/${service_name}.timer" <<EOF
[Unit]
Description=${service_name} DDNS timer

[Timer]
OnBootSec=1min
OnUnitActiveSec=${interval}min
Persistent=true

[Install]
WantedBy=timers.target
EOF

    if systemctl --user daemon-reload 2>/dev/null &&
        systemctl --user enable --now "${service_name}.timer" 2>/dev/null; then
        echo "systemd timer 已创建并启动: ${service_name}.timer"
        if command -v loginctl >/dev/null 2>&1; then
            local linger
            linger=$(loginctl show-user "${USER:-$(id -un)}" -p Linger --value 2>/dev/null || true)
            if [ "$linger" = "no" ]; then
                loginctl enable-linger "${USER:-$(id -un)}" >/dev/null 2>&1 ||
                    run_privileged loginctl enable-linger "${USER:-$(id -un)}" >/dev/null 2>&1 || true
                linger=$(loginctl show-user "${USER:-$(id -un)}" -p Linger --value 2>/dev/null || true)
                if [ "$linger" = "no" ]; then
                    echo "提示: 当前用户未开启 systemd linger，退出 SSH 后 timer 可能暂停；建议执行: sudo loginctl enable-linger ${USER:-$(id -un)}"
                fi
            fi
        fi
        return 0
    fi

    echo "错误: systemd timer 启动失败"
    return 1
}

remove_systemd_timer() {
    local service_name="$1"
    command -v systemctl >/dev/null 2>&1 || return 0

    if systemctl --user is-enabled "${service_name}.timer" >/dev/null 2>&1 ||
        systemctl --user is-active "${service_name}.timer" >/dev/null 2>&1; then
        systemctl --user disable --now "${service_name}.timer" >/dev/null 2>&1 || true
        echo "已停止并禁用 systemd timer: ${service_name}.timer"
    fi

    local user_systemd_dir="$HOME/.config/systemd/user"
    local removed_unit=false
    if [ -f "$user_systemd_dir/${service_name}.service" ]; then
        rm -f "$user_systemd_dir/${service_name}.service"
        removed_unit=true
    fi
    if [ -f "$user_systemd_dir/${service_name}.timer" ]; then
        rm -f "$user_systemd_dir/${service_name}.timer"
        removed_unit=true
    fi
    if [ "$removed_unit" = "true" ]; then
        systemctl --user daemon-reload >/dev/null 2>&1 || true
        echo "已删除 systemd 单元文件: ${service_name}"
    fi
}

show_manual_setup_guide() {
    local exec_script="$1"
    local interval="$2"
    local service_name="$3"
    local log_file="$4"
    local schedule
    schedule=$(build_cron_schedule "$interval")

    cat <<EOF

==================== 手动配置指南 ====================

方案1: 手动添加 cron 任务（推荐）
  运行: crontab -e
  添加: ${schedule} "${exec_script}" >> "${log_file}" 2>&1

方案2: 创建 systemd 用户 timer
  单元目录: ~/.config/systemd/user/${service_name}.{service,timer}
  启用命令: systemctl --user enable --now ${service_name}.timer

======================================================
EOF
}

setup_scheduler() {
    local exec_script="$1"
    local interval="$2"
    local instance_id="$3"
    local log_file="$4"
    local service_name="${SCRIPT_NAME}-${instance_id}"

    echo "正在设置定时任务..."
    if setup_cron_with_checks "$exec_script" "$interval" "$instance_id" "$log_file"; then
        remove_systemd_timer "$service_name"
        echo "✓ cron 定时任务设置成功"
        return 0
    fi

    echo "cron 设置失败，尝试 systemd user timer..."
    if command -v systemctl >/dev/null 2>&1 && systemctl --user list-timers >/dev/null 2>&1; then
        if create_systemd_timer "$exec_script" "$interval" "$service_name"; then
            echo "✓ systemd timer 设置成功"
            return 0
        fi
    fi

    echo "⚠️  无法自动设置定时任务，请手动配置："
    show_manual_setup_guide "$exec_script" "$interval" "$service_name" "$log_file"
    return 1
}

create_execution_script() {
    local install_dir="$1"
    local instance_id="$2"
    local token="$3"
    local zone="$4"
    local fqdn="$5"
    local record_type="$6"
    local ttl="$7"
    local bot_token="$8"
    local chat_id="$9"
    local log_file="${10}"

    local exec_script="$install_dir/${SCRIPT_NAME}-${instance_id}.sh"

    (
        umask 077
        {
            cat <<'HEADER'
#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

# CloudFlare DDNS Execution Script (Auto-generated)
HEADER
            printf 'INSTANCE_ID=%q\n' "$instance_id"
            printf 'CFTOKEN=%q\n' "$token"
            printf 'CFZONE_NAME=%q\n' "$zone"
            printf 'CFRECORD_NAME=%q\n' "$fqdn"
            printf 'CFRECORD_TYPE=%q\n' "$record_type"
            printf 'CFTTL=%q\n' "$ttl"
            printf 'TG_BOT_TOKEN=%q\n' "$bot_token"
            printf 'TG_CHAT_ID=%q\n' "$chat_id"
            printf 'LOG_FILE=%q\n' "$log_file"
            echo ""
            emit_ip_helpers

            cat <<'BODY'
FORCE="false"

OPTIND=1
while getopts ":f:" opts; do
    case "${opts}" in
        f) FORCE="${OPTARG}" ;;
        *) ;;
    esac
done

rotate_logs_if_needed() {
    local log_file="$1"
    local max_lines="${2:-1000}"
    local keep_lines="${3:-500}"

    [ -f "$log_file" ] || return 0
    local current_lines
    current_lines=$(wc -l < "$log_file" 2>/dev/null | tr -d '[:space:]' || echo 0)
    [[ "$current_lines" =~ ^[0-9]+$ ]] || return 0

    if [ "$current_lines" -gt "$max_lines" ]; then
        local tmp_file="${log_file}.tmp.$$"
        if tail -n "$keep_lines" "$log_file" > "$tmp_file" 2>/dev/null; then
            if cat "$tmp_file" > "$log_file" 2>/dev/null; then
                printf '%s: 日志已轮转，从 %s 行压缩至 %s 行\n' \
                    "$(date '+%Y-%m-%d %H:%M:%S')" "$current_lines" "$keep_lines" >> "$log_file"
            fi
        fi
        rm -f "$tmp_file" 2>/dev/null || true
    fi
}

send_telegram_message() {
    local message="$1"
    local success="${2:-true}"

    if [ -z "$TG_BOT_TOKEN" ] || [ -z "$TG_CHAT_ID" ]; then
        return 0
    fi

    local emoji="✅"
    [ "$success" = "false" ] && emoji="❌"

    local full_message="${emoji} DDNS 通知

🌐 域名: ${CFRECORD_NAME} (${CFRECORD_TYPE})
📍 IP地址: ${WAN_IP:-未知}
⏰ 时间: $(date '+%Y-%m-%d %H:%M:%S')

📝 消息: ${message}"

    curl -fsSL --connect-timeout 5 --max-time 10 \
        -X POST "https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage" \
        --data-urlencode "chat_id=${TG_CHAT_ID}" \
        --data-urlencode "text=${full_message}" \
        >/dev/null 2>&1 || true
}

cf_json_query() {
    local mode="$1"
    local target="${2:-}"
    awk -v mode="$mode" -v target="$target" '
    function flush_prim() {
        if (prim == "") return
        if (want_top_val && mode == "success" && top_key == "success") {
            print prim
            found = 1
            exit 0
        }
        if (want_res_val && mode == "result" && res_key == target) {
            print prim
            found = 1
            exit 0
        }
        prim = ""
        want_top_val = 0
        want_res_val = 0
        want_err_val = 0
    }
    BEGIN {
        brace = 0; bracket = 0; in_str = 0; esc = 0
        buf = ""; last_str = ""; has_str = 0; prim = ""
        top_key = ""; res_key = ""; err_key = ""
        want_top_val = 0; want_res_val = 0; want_err_val = 0
        result_done = 0; found = 0
    }
    {
        len = length($0)
        for (i = 1; i <= len; i++) {
            c = substr($0, i, 1)
            if (in_str) {
                if (esc) {
                    buf = buf c
                    esc = 0
                } else if (c == "\\") {
                    esc = 1
                } else if (c == "\"") {
                    in_str = 0
                    if (want_top_val && mode == "success" && top_key == "success") {
                        print buf; found = 1; exit 0
                    } else if (want_res_val && mode == "result" && res_key == target) {
                        print buf; found = 1; exit 0
                    } else if (want_err_val && mode == "error" && err_key == "message") {
                        print buf; found = 1; exit 0
                    }
                    want_top_val = 0; want_res_val = 0; want_err_val = 0
                    last_str = buf
                    has_str = 1
                    buf = ""
                } else {
                    buf = buf c
                }
                continue
            }

            if (c ~ /[[:space:]]/) {
                flush_prim()
                continue
            }

            if (c == "\"") {
                flush_prim()
                in_str = 1
                buf = ""
                continue
            }

            if (c == ":") {
                if (brace == 1 && bracket == 0 && has_str) {
                    top_key = last_str
                    want_top_val = 1
                } else if (top_key == "result" && brace == 2 && !result_done && has_str) {
                    res_key = last_str
                    want_res_val = 1
                } else if (top_key == "errors" && brace == 2 && has_str) {
                    err_key = last_str
                    want_err_val = 1
                }
                has_str = 0
                continue
            }

            if (c == "{") {
                flush_prim()
                want_top_val = 0; want_res_val = 0; want_err_val = 0
                has_str = 0
                brace++
                continue
            }

            if (c == "}") {
                flush_prim()
                has_str = 0
                if (top_key == "result" && brace == 2) {
                    result_done = 1
                }
                brace--
                if (brace == 1 && bracket == 0) {
                    top_key = ""
                }
                continue
            }

            if (c == "[") {
                flush_prim()
                if (brace > 1) {
                    want_res_val = 0; want_err_val = 0
                }
                want_top_val = 0
                has_str = 0
                bracket++
                continue
            }

            if (c == "]") {
                flush_prim()
                has_str = 0
                bracket--
                if (brace == 1 && bracket == 0) {
                    top_key = ""
                }
                continue
            }

            if (c == ",") {
                flush_prim()
                has_str = 0
                if (brace == 1 && bracket == 0) {
                    top_key = ""
                }
                continue
            }

            if (want_top_val || want_res_val || want_err_val) {
                prim = prim c
            }
        }
        flush_prim()
    }
    '
}

resolve_cloudflare_ids() {
    local zone_resp
    zone_resp=$(curl -sS --connect-timeout 10 --max-time 20 -G \
        "https://api.cloudflare.com/client/v4/zones" \
        -H "Authorization: Bearer ${CFTOKEN}" \
        -H "Content-Type: application/json" \
        --data-urlencode "name=${CFZONE_NAME}" \
        --data-urlencode "status=active" 2>/dev/null || true)

    local zone_ok
    zone_ok=$(printf '%s' "$zone_resp" | cf_json_query "success")
    CFZONE_ID=$(printf '%s' "$zone_resp" | cf_json_query "result" "id")

    if [ "$zone_ok" != "true" ] || [ -z "$CFZONE_ID" ]; then
        local err_msg
        err_msg=$(printf '%s' "$zone_resp" | cf_json_query "error")
        printf '%s: 错误: 无法获取区域 ID (%s)%s\n' \
            "$(date '+%Y-%m-%d %H:%M:%S')" "$CFZONE_NAME" "${err_msg:+: $err_msg}" >&2
        send_telegram_message "无法获取 CloudFlare 区域 ID (${CFZONE_NAME})${err_msg:+: $err_msg}" "false"
        return 1
    fi

    local rec_resp
    rec_resp=$(curl -sS --connect-timeout 10 --max-time 20 -G \
        "https://api.cloudflare.com/client/v4/zones/${CFZONE_ID}/dns_records" \
        -H "Authorization: Bearer ${CFTOKEN}" \
        -H "Content-Type: application/json" \
        --data-urlencode "type=${CFRECORD_TYPE}" \
        --data-urlencode "name=${CFRECORD_NAME}" 2>/dev/null || true)

    local rec_ok
    rec_ok=$(printf '%s' "$rec_resp" | cf_json_query "success")
    CFRECORD_ID=$(printf '%s' "$rec_resp" | cf_json_query "result" "id")
    CFRECORD_PROXIED=$(printf '%s' "$rec_resp" | cf_json_query "result" "proxied")
    [ -z "$CFRECORD_PROXIED" ] && CFRECORD_PROXIED="false"

    if [ "$rec_ok" != "true" ] || [ -z "$CFRECORD_ID" ]; then
        local err_msg
        err_msg=$(printf '%s' "$rec_resp" | cf_json_query "error")
        printf '%s: 错误: 无法获取 %s 记录 ID (%s)%s\n' \
            "$(date '+%Y-%m-%d %H:%M:%S')" "$CFRECORD_TYPE" "$CFRECORD_NAME" "${err_msg:+: $err_msg}" >&2
        send_telegram_message "无法获取 DNS 记录 ID (${CFRECORD_NAME} ${CFRECORD_TYPE})${err_msg:+: $err_msg}" "false"
        return 1
    fi

    (
        umask 077
        {
            printf '%s\n' "$CFZONE_ID"
            printf '%s\n' "$CFRECORD_ID"
            printf '%s\n' "$CFRECORD_PROXIED"
            printf '%s\n' "$CFZONE_NAME"
            printf '%s:%s\n' "$CFRECORD_NAME" "$CFRECORD_TYPE"
        } > "${ID_FILE}.tmp.$$"
        mv -f "${ID_FILE}.tmp.$$" "$ID_FILE"
    )
}

patch_dns_record() {
    local payload
    if [ "$CFRECORD_PROXIED" = "true" ]; then
        payload=$(printf '{"content":"%s"}' "$WAN_IP")
    else
        payload=$(printf '{"content":"%s","ttl":%s}' "$WAN_IP" "$CFTTL")
    fi

    UPDATE_RESPONSE=$(curl -sS --connect-timeout 10 --max-time 20 \
        -X PATCH "https://api.cloudflare.com/client/v4/zones/${CFZONE_ID}/dns_records/${CFRECORD_ID}" \
        -H "Authorization: Bearer ${CFTOKEN}" \
        -H "Content-Type: application/json" \
        --data "$payload" 2>/dev/null || true)

    local ok
    ok=$(printf '%s' "$UPDATE_RESPONSE" | cf_json_query "success")
    [ "$ok" = "true" ]
}

DDNS_DIR="$HOME/.ddns"
(
    umask 077
    mkdir -p "$DDNS_DIR"
)

if [ -n "${LOG_FILE:-}" ]; then
    rotate_logs_if_needed "$LOG_FILE" 1000 500
fi

WAN_IP=""
if ! WAN_IP=$(fetch_public_ip "$CFRECORD_TYPE" "false") || [ -z "$WAN_IP" ]; then
    printf '%s: 错误: 无法获取公网 %s 地址\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$CFRECORD_TYPE" >&2
    send_telegram_message "无法获取公网 ${CFRECORD_TYPE} 地址" "false"
    exit 1
fi

WAN_IP_FILE="$DDNS_DIR/.cf-wan_ip_${INSTANCE_ID}.txt"
LEGACY_WAN_IP_FILE="$DDNS_DIR/.cf-wan_ip_${CFRECORD_NAME}.txt"
OLD_WAN_IP=""
if [ -f "$WAN_IP_FILE" ]; then
    OLD_WAN_IP=$(tr -d '[:space:]' < "$WAN_IP_FILE" 2>/dev/null || true)
elif [ "$CFRECORD_TYPE" = "A" ] && [ -f "$LEGACY_WAN_IP_FILE" ]; then
    OLD_WAN_IP=$(tr -d '[:space:]' < "$LEGACY_WAN_IP_FILE" 2>/dev/null || true)
fi

if [ "$WAN_IP" = "$OLD_WAN_IP" ] && [ "$FORCE" != "true" ]; then
    printf '%s: IP 地址未变化 (%s)，跳过更新\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$WAN_IP"
    exit 0
fi

ID_FILE="$DDNS_DIR/.cf-id_${INSTANCE_ID}.txt"
CFZONE_ID=""
CFRECORD_ID=""
CFRECORD_PROXIED="false"
USED_ID_CACHE="false"

if [ -f "$ID_FILE" ] &&
    [ "$(wc -l < "$ID_FILE" | tr -d '[:space:]')" = "5" ] &&
    [ "$(sed -n '4p' "$ID_FILE")" = "$CFZONE_NAME" ] &&
    [ "$(sed -n '5p' "$ID_FILE")" = "${CFRECORD_NAME}:${CFRECORD_TYPE}" ]; then
    CFZONE_ID=$(sed -n '1p' "$ID_FILE")
    CFRECORD_ID=$(sed -n '2p' "$ID_FILE")
    CFRECORD_PROXIED=$(sed -n '3p' "$ID_FILE")
    if [ -n "$CFZONE_ID" ] && [ -n "$CFRECORD_ID" ]; then
        USED_ID_CACHE="true"
    fi
fi

if [ "$USED_ID_CACHE" != "true" ]; then
    resolve_cloudflare_ids || exit 1
fi

UPDATE_RESPONSE=""
if ! patch_dns_record; then
    if [ "$USED_ID_CACHE" = "true" ]; then
        rm -f "$ID_FILE"
        resolve_cloudflare_ids || exit 1
        if ! patch_dns_record; then
            ERR_MSG=$(printf '%s' "$UPDATE_RESPONSE" | cf_json_query "error")
            printf '%s: DNS 更新失败: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "${ERR_MSG:-$UPDATE_RESPONSE}" >&2
            send_telegram_message "DNS 更新失败: ${ERR_MSG:-未知错误}" "false"
            exit 1
        fi
    else
        ERR_MSG=$(printf '%s' "$UPDATE_RESPONSE" | cf_json_query "error")
        printf '%s: DNS 更新失败: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "${ERR_MSG:-$UPDATE_RESPONSE}" >&2
        send_telegram_message "DNS 更新失败: ${ERR_MSG:-未知错误}" "false"
        exit 1
    fi
fi

(
    umask 077
    printf '%s\n' "$WAN_IP" > "${WAN_IP_FILE}.tmp.$$"
    mv -f "${WAN_IP_FILE}.tmp.$$" "$WAN_IP_FILE"
)

printf '%s: DNS 更新成功: %s (%s) -> %s\n' \
    "$(date '+%Y-%m-%d %H:%M:%S')" "$CFRECORD_NAME" "$CFRECORD_TYPE" "$WAN_IP"

if [ -n "$OLD_WAN_IP" ] && [ "$OLD_WAN_IP" != "$WAN_IP" ]; then
    send_telegram_message "DNS 记录更新成功！IP 地址从 ${OLD_WAN_IP} 变更为 ${WAN_IP}" "true"
elif [ "$FORCE" = "true" ]; then
    send_telegram_message "强制更新 DNS 记录成功！" "true"
fi
BODY
        } > "${exec_script}.tmp.$$"
        chmod 700 "${exec_script}.tmp.$$"
        mv -f "${exec_script}.tmp.$$" "$exec_script"
    )

    printf '%s' "$exec_script"
}

save_instance_meta() {
    local instance_id="$1"
    local exec_script="$2"
    local zone="$3"
    local fqdn="$4"
    local record_type="$5"
    local ttl="$6"
    local interval="$7"
    local log_file="$8"
    local tg_enabled="$9"

    (
        umask 077
        mkdir -p "$DDNS_INSTANCES_DIR"
        local meta_file="$DDNS_INSTANCES_DIR/${instance_id}.env"
        {
            printf 'META_INSTANCE_ID=%q\n' "$instance_id"
            printf 'META_EXEC_SCRIPT=%q\n' "$exec_script"
            printf 'META_ZONE=%q\n' "$zone"
            printf 'META_FQDN=%q\n' "$fqdn"
            printf 'META_RECORD_TYPE=%q\n' "$record_type"
            printf 'META_TTL=%q\n' "$ttl"
            printf 'META_INTERVAL=%q\n' "$interval"
            printf 'META_LOG_FILE=%q\n' "$log_file"
            printf 'META_TG_ENABLED=%q\n' "$tg_enabled"
        } > "${meta_file}.tmp.$$"
        mv -f "${meta_file}.tmp.$$" "$meta_file"
    )
}

cleanup_legacy_if_matching() {
    local fqdn="$1"
    local record_type="$2"
    [ -f "$LEGACY_EXEC_SCRIPT" ] || return 0

    local legacy_zone legacy_name legacy_type legacy_fqdn
    legacy_zone=$(grep '^CFZONE_NAME=' "$LEGACY_EXEC_SCRIPT" 2>/dev/null | head -1 | cut -d'"' -f2 || true)
    legacy_name=$(grep '^CFRECORD_NAME=' "$LEGACY_EXEC_SCRIPT" 2>/dev/null | head -1 | cut -d'"' -f2 || true)
    legacy_type=$(grep '^CFRECORD_TYPE=' "$LEGACY_EXEC_SCRIPT" 2>/dev/null | head -1 | cut -d'"' -f2 || true)

    if [ -n "$legacy_zone" ] && [ -n "$legacy_name" ]; then
        legacy_fqdn=$(normalize_fqdn "$legacy_name" "$legacy_zone")
        if [ "$legacy_fqdn" = "$fqdn" ] && [ "${legacy_type:-A}" = "$record_type" ]; then
            remove_systemd_timer "$SCRIPT_NAME"
            remove_cron_matching "$LEGACY_EXEC_SCRIPT" >/dev/null 2>&1 || true
            rm -f "$LEGACY_EXEC_SCRIPT"
            rm -f "$DDNS_STATE_DIR/.cf-id_${legacy_fqdn}.txt" "$DDNS_STATE_DIR/.cf-id_${legacy_name}.txt"
        fi
    fi
}

install_ddns() {
    local token="" zone="" hostname="" record_type="A" ttl="120" interval="5" install_dir="$HOME/.local/bin"
    local bot_token="" chat_id=""

    OPTIND=1
    while getopts ":k:z:h:t:l:i:d:b:c:" opts; do
        case "${opts}" in
            k) token="${OPTARG}" ;;
            z) zone="${OPTARG}" ;;
            h) hostname="${OPTARG}" ;;
            t) record_type="${OPTARG}" ;;
            l) ttl="${OPTARG}" ;;
            i) interval="${OPTARG}" ;;
            d) install_dir="${OPTARG}" ;;
            b) bot_token="${OPTARG}" ;;
            c) chat_id="${OPTARG}" ;;
            :)
                echo "错误: 选项 -${OPTARG} 需要参数" >&2
                exit 1
                ;;
            \?)
                echo "错误: 未知选项 -${OPTARG}" >&2
                show_usage
                ;;
        esac
    done

    local missing_params=()
    [ -z "$token" ] && missing_params+=("API Token (-k)")
    [ -z "$zone" ] && missing_params+=("Zone Name (-z)")
    [ -z "$hostname" ] && missing_params+=("Hostname (-h)")

    if [ "${#missing_params[@]}" -gt 0 ]; then
        echo "错误: 缺少必需参数:" >&2
        printf '  %s\n' "${missing_params[@]}" >&2
        exit 1
    fi

    record_type=$(printf '%s' "$record_type" | tr '[:lower:]' '[:upper:]')
    if [ "$record_type" != "A" ] && [ "$record_type" != "AAAA" ]; then
        echo "错误: 记录类型 (-t) 仅支持 A 或 AAAA，当前值: $record_type" >&2
        exit 1
    fi

    if ! [[ "$ttl" =~ ^[0-9]+$ ]] || { [ "$ttl" -ne 1 ] && { [ "$ttl" -lt 60 ] || [ "$ttl" -gt 86400 ]; }; }; then
        echo "错误: TTL (-l) 必须为 1 (自动) 或 60-86400 之间的整数，当前值: $ttl" >&2
        exit 1
    fi

    if ! [[ "$interval" =~ ^[0-9]+$ ]] || [ "$interval" -lt 1 ] || [ "$interval" -gt 1440 ] ||
        { [ "$interval" -gt 59 ] && [ $((interval % 60)) -ne 0 ]; }; then
        echo "错误: 间隔时间 (-i) 需为 1-59 分钟，或 60 的整数倍（最大 1440），当前值: $interval" >&2
        exit 1
    fi

    if [ -n "$bot_token" ] && [ -z "$chat_id" ]; then
        echo "错误: 设置了 Bot Token 但缺少 Chat ID (-c)" >&2
        exit 1
    elif [ -z "$bot_token" ] && [ -n "$chat_id" ]; then
        echo "错误: 设置了 Chat ID 但缺少 Bot Token (-b)" >&2
        exit 1
    fi

    zone=$(normalize_domain "$zone")
    if ! [[ "$zone" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]]; then
        echo "错误: Zone 格式无效 (-z): $zone" >&2
        exit 1
    fi

    local norm_host
    norm_host=$(normalize_domain "$hostname")
    if [ "$norm_host" != "@" ] && [ "$norm_host" != "*" ] &&
        ! [[ "$norm_host" =~ ^(\*\.)?[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*$ ]]; then
        echo "错误: Hostname 格式无效 (-h): $hostname" >&2
        exit 1
    fi

    local fqdn
    fqdn=$(normalize_fqdn "$hostname" "$zone")
    local instance_id
    instance_id=$(make_instance_id "$fqdn" "$record_type")

    mkdir -p "$install_dir"
    install_dir=$(cd "$install_dir" && pwd)

    cleanup_legacy_if_matching "$fqdn" "$record_type"

    local old_meta="$DDNS_INSTANCES_DIR/${instance_id}.env"
    if [ -f "$old_meta" ]; then
        local META_EXEC_SCRIPT=""
        # shellcheck disable=SC1090
        source "$old_meta"
        if [ -n "$META_EXEC_SCRIPT" ] && [ "$META_EXEC_SCRIPT" != "$install_dir/${SCRIPT_NAME}-${instance_id}.sh" ]; then
            remove_cron_matching "$META_EXEC_SCRIPT" >/dev/null 2>&1 || true
            rm -f "$META_EXEC_SCRIPT"
        fi
    fi

    local log_file
    log_file=$(select_log_file)

    echo "正在创建执行脚本..."
    local exec_script
    exec_script=$(create_execution_script "$install_dir" "$instance_id" "$token" "$zone" "$fqdn" "$record_type" "$ttl" "$bot_token" "$chat_id" "$log_file")

    local tg_enabled="false"
    [ -n "$bot_token" ] && [ -n "$chat_id" ] && tg_enabled="true"
    save_instance_meta "$instance_id" "$exec_script" "$zone" "$fqdn" "$record_type" "$ttl" "$interval" "$log_file" "$tg_enabled"

    if ! setup_scheduler "$exec_script" "$interval" "$instance_id" "$log_file"; then
        echo "定时任务自动配置未完成，但执行脚本已安装，可手动测试: $0 run"
    fi

    echo ""
    echo "安装完成！"
    echo "执行脚本: $exec_script"
    echo "定时任务: 每 $interval 分钟执行一次"
    echo "域名记录: $fqdn ($record_type, TTL: $ttl)"
    if [ "$tg_enabled" = "true" ]; then
        echo "Telegram 通知: 已启用"
    else
        echo "Telegram 通知: 未启用"
    fi

    echo ""
    echo "正在执行首次更新测试..."
    if "$exec_script"; then
        echo "测试成功！"
    else
        echo "测试失败，请检查 API Token 权限及域名解析记录是否已预先创建" >&2
        exit 1
    fi
}

match_instance_filter() {
    local meta_fqdn="$1"
    local meta_zone="$2"
    local meta_type="$3"
    local meta_exec="$4"
    local filter_host="$5"
    local filter_type="$6"
    local filter_dir="$7"

    if [ -n "$filter_type" ] && [ "$meta_type" != "$filter_type" ]; then
        return 1
    fi
    if [ -n "$filter_dir" ] && [ "$(dirname "$meta_exec")" != "$filter_dir" ]; then
        return 1
    fi
    if [ -n "$filter_host" ]; then
        local norm_filter
        norm_filter=$(normalize_fqdn "$filter_host" "$meta_zone")
        if [ "$meta_fqdn" != "$norm_filter" ] && [ "$meta_fqdn" != "$(normalize_domain "$filter_host")" ]; then
            return 1
        fi
    fi
    return 0
}

collect_meta_files() {
    if [ -d "$DDNS_INSTANCES_DIR" ]; then
        local f
        for f in "$DDNS_INSTANCES_DIR"/*.env; do
            [ -f "$f" ] || continue
            printf '%s\n' "$f"
        done
    fi
}

run_ddns() {
    local force="false" filter_host="" filter_type="" filter_dir=""

    OPTIND=1
    while getopts ":f:h:t:d:" opts; do
        case "${opts}" in
            f) force="${OPTARG}" ;;
            h) filter_host="${OPTARG}" ;;
            t) filter_type=$(printf '%s' "${OPTARG}" | tr '[:lower:]' '[:upper:]') ;;
            d)
                if [ -d "${OPTARG}" ]; then
                    filter_dir=$(cd "${OPTARG}" && pwd)
                else
                    filter_dir="${OPTARG%/}"
                fi
                ;;
            :)
                echo "错误: 选项 -${OPTARG} 需要参数" >&2
                exit 1
                ;;
            \?)
                echo "错误: 未知选项 -${OPTARG}" >&2
                show_usage
                ;;
        esac
    done

    local meta_files=()
    while IFS= read -r line; do
        [ -n "$line" ] && meta_files+=("$line")
    done < <(collect_meta_files)

    if [ "${#meta_files[@]}" -eq 0 ]; then
        local fallback_script="${filter_dir:-$HOME/.local/bin}/${SCRIPT_NAME}-exec.sh"
        if [ -f "$fallback_script" ]; then
            [ -x "$fallback_script" ] || { echo "错误: 执行脚本没有执行权限: $fallback_script" >&2; exit 1; }
            echo "正在执行 DDNS 更新 (兼容模式)..."
            if [ "$force" = "true" ]; then
                "$fallback_script" -f true
            else
                "$fallback_script"
            fi
            return 0
        fi
        echo "错误: 未找到已安装的 DDNS 实例，请先运行 install 命令" >&2
        exit 1
    fi

    local matched=0 failed=0 meta_file
    for meta_file in "${meta_files[@]}"; do
        local META_INSTANCE_ID="" META_EXEC_SCRIPT="" META_ZONE="" META_FQDN="" META_RECORD_TYPE=""
        # shellcheck disable=SC1090
        source "$meta_file"
        if ! match_instance_filter "$META_FQDN" "$META_ZONE" "$META_RECORD_TYPE" "$META_EXEC_SCRIPT" "$filter_host" "$filter_type" "$filter_dir"; then
            continue
        fi
        matched=$((matched + 1))

        if [ ! -f "$META_EXEC_SCRIPT" ]; then
            echo "错误: 执行脚本不存在: $META_EXEC_SCRIPT" >&2
            failed=$((failed + 1))
            continue
        fi
        if [ ! -x "$META_EXEC_SCRIPT" ]; then
            echo "错误: 执行脚本没有执行权限: $META_EXEC_SCRIPT" >&2
            failed=$((failed + 1))
            continue
        fi

        echo "正在执行 DDNS 更新: $META_FQDN ($META_RECORD_TYPE)..."
        if [ "$force" = "true" ]; then
            "$META_EXEC_SCRIPT" -f true || failed=$((failed + 1))
        else
            "$META_EXEC_SCRIPT" || failed=$((failed + 1))
        fi
    done

    if [ "$matched" -eq 0 ]; then
        echo "错误: 未匹配到符合条件的 DDNS 实例" >&2
        exit 1
    fi
    [ "$failed" -eq 0 ] || exit 1
}

remove_ddns() {
    local filter_host="" filter_type="" filter_dir=""

    OPTIND=1
    while getopts ":h:t:d:" opts; do
        case "${opts}" in
            h) filter_host="${OPTARG}" ;;
            t) filter_type=$(printf '%s' "${OPTARG}" | tr '[:lower:]' '[:upper:]') ;;
            d)
                if [ -d "${OPTARG}" ]; then
                    filter_dir=$(cd "${OPTARG}" && pwd)
                else
                    filter_dir="${OPTARG%/}"
                fi
                ;;
            :)
                echo "错误: 选项 -${OPTARG} 需要参数" >&2
                exit 1
                ;;
            \?)
                echo "错误: 未知选项 -${OPTARG}" >&2
                show_usage
                ;;
        esac
    done

    echo "正在移除 DDNS 服务..."
    local removed_any=false

    local meta_files=()
    while IFS= read -r line; do
        [ -n "$line" ] && meta_files+=("$line")
    done < <(collect_meta_files)

    local meta_file
    for meta_file in ${meta_files[@]+"${meta_files[@]}"}; do
        local META_INSTANCE_ID="" META_EXEC_SCRIPT="" META_ZONE="" META_FQDN="" META_RECORD_TYPE=""
        # shellcheck disable=SC1090
        source "$meta_file"
        if ! match_instance_filter "$META_FQDN" "$META_ZONE" "$META_RECORD_TYPE" "$META_EXEC_SCRIPT" "$filter_host" "$filter_type" "$filter_dir"; then
            continue
        fi

        remove_systemd_timer "${SCRIPT_NAME}-${META_INSTANCE_ID}"
        if remove_cron_matching "# ${SCRIPT_NAME}:${META_INSTANCE_ID}" || remove_cron_matching "$META_EXEC_SCRIPT"; then
            echo "已移除 cron 定时任务: $META_FQDN ($META_RECORD_TYPE)"
        fi
        if [ -f "$META_EXEC_SCRIPT" ]; then
            rm -f "$META_EXEC_SCRIPT"
            echo "已删除执行脚本: $META_EXEC_SCRIPT"
        fi
        rm -f "$DDNS_STATE_DIR/.cf-id_${META_INSTANCE_ID}.txt" \
              "$DDNS_STATE_DIR/.cf-wan_ip_${META_INSTANCE_ID}.txt" \
              "$meta_file"
        removed_any=true
    done

    if [ -z "$filter_host" ] && [ -z "$filter_type" ]; then
        local legacy_exec="${filter_dir:-$HOME/.local/bin}/${SCRIPT_NAME}-exec.sh"
        remove_systemd_timer "$SCRIPT_NAME"
        if remove_cron_matching "$legacy_exec"; then
            echo "已移除旧版 cron 定时任务"
            removed_any=true
        fi
        if [ -f "$legacy_exec" ]; then
            rm -f "$legacy_exec"
            echo "已删除旧版执行脚本: $legacy_exec"
            removed_any=true
        fi
    fi

    if [ "$removed_any" = "true" ]; then
        echo "DDNS 服务移除完成"
    else
        echo "未找到匹配的已安装 DDNS 服务"
    fi
}

show_instance_status() {
    local instance_id="$1"
    local exec_script="$2"
    local fqdn="$3"
    local record_type="$4"
    local ttl="$5"
    local log_file="$6"
    local tg_enabled="$7"
    local current_ip="$8"

    echo ""
    echo "实例: ${fqdn} (${record_type})"
    echo "--------------------------"
    if [ -f "$exec_script" ]; then
        echo "  ✓ 执行脚本: $exec_script"
    else
        echo "  ✗ 执行脚本缺失: $exec_script"
    fi

    if [ "$ttl" = "1" ]; then
        echo "  TTL: 1 (自动)"
    else
        echo "  TTL: ${ttl}s"
    fi

    if [ "$tg_enabled" = "true" ]; then
        echo "  ✓ Telegram 通知: 已配置"
    else
        echo "  - Telegram 通知: 未配置"
    fi

    local has_scheduler=false
    local marker="# ${SCRIPT_NAME}:${instance_id}"
    local current_cron=""
    if command -v crontab >/dev/null 2>&1; then
        current_cron=$(crontab -l 2>/dev/null || true)
    fi

    local cron_line=""
    if [ -n "$current_cron" ]; then
        cron_line=$(printf '%s\n' "$current_cron" | grep -F "$marker" | head -1 || true)
        if [ -z "$cron_line" ]; then
            cron_line=$(printf '%s\n' "$current_cron" | grep -F "$exec_script" | head -1 || true)
        fi
    fi

    if [ -n "$cron_line" ]; then
        echo "  ✓ 调度方式: cron"
        echo "    规则: ${cron_line%" $marker"}"
        has_scheduler=true
    fi

    local service_name="${SCRIPT_NAME}-${instance_id}"
    if command -v systemctl >/dev/null 2>&1 && systemctl --user is-enabled "${service_name}.timer" >/dev/null 2>&1; then
        local timer_status
        timer_status=$(systemctl --user is-active "${service_name}.timer" 2>/dev/null || echo "inactive")
        echo "  ✓ 调度方式: systemd user timer (${timer_status})"
        has_scheduler=true
    fi

    if [ "$has_scheduler" = "false" ]; then
        echo "  ✗ 定时任务: 未发现配置"
    fi

    if [ -n "$log_file" ] && [ -f "$log_file" ]; then
        local log_lines
        log_lines=$(wc -l < "$log_file" 2>/dev/null | tr -d '[:space:]' || echo 0)
        echo "  日志文件: $log_file (${log_lines} 行, 最后修改: $(get_file_mtime "$log_file"))"
    fi

    if [ -n "$current_ip" ]; then
        echo "  当前公网 ${record_type}: $current_ip"
    else
        echo "  当前公网 ${record_type}: 无法获取"
    fi

    local ip_cache_file="$DDNS_STATE_DIR/.cf-wan_ip_${instance_id}.txt"
    if [ ! -f "$ip_cache_file" ] && [ "$record_type" = "A" ] && [ -f "$DDNS_STATE_DIR/.cf-wan_ip_${fqdn}.txt" ]; then
        ip_cache_file="$DDNS_STATE_DIR/.cf-wan_ip_${fqdn}.txt"
    fi

    if [ -f "$ip_cache_file" ]; then
        local cached_ip
        cached_ip=$(tr -d '[:space:]' < "$ip_cache_file" 2>/dev/null || true)
        if [ -n "$cached_ip" ]; then
            echo "  缓存记录 IP: $cached_ip (更新于: $(get_file_mtime "$ip_cache_file"))"
            if [ -n "$current_ip" ]; then
                if [ "$current_ip" = "$cached_ip" ]; then
                    echo "  同步状态: ✓ 已同步"
                else
                    echo "  同步状态: ⚠️  待更新"
                fi
            fi
        else
            echo "  缓存记录 IP: 空"
        fi
    else
        echo "  缓存记录 IP: 未缓存（首次运行前或缓存已清理）"
    fi
}

show_status() {
    local filter_host="" filter_type="" filter_dir=""

    OPTIND=1
    while getopts ":h:t:d:" opts; do
        case "${opts}" in
            h) filter_host="${OPTARG}" ;;
            t) filter_type=$(printf '%s' "${OPTARG}" | tr '[:lower:]' '[:upper:]') ;;
            d)
                if [ -d "${OPTARG}" ]; then
                    filter_dir=$(cd "${OPTARG}" && pwd)
                else
                    filter_dir="${OPTARG%/}"
                fi
                ;;
            :)
                echo "错误: 选项 -${OPTARG} 需要参数" >&2
                exit 1
                ;;
            \?)
                echo "错误: 未知选项 -${OPTARG}" >&2
                show_usage
                ;;
        esac
    done

    echo "CloudFlare DDNS 服务状态 (v${SCRIPT_VERSION})"
    echo "=========================================="

    local meta_files=()
    while IFS= read -r line; do
        [ -n "$line" ] && meta_files+=("$line")
    done < <(collect_meta_files)

    local need_v4=false need_v6=false
    local matched_metas=()
    local meta_file
    for meta_file in ${meta_files[@]+"${meta_files[@]}"}; do
        local META_INSTANCE_ID="" META_EXEC_SCRIPT="" META_ZONE="" META_FQDN="" META_RECORD_TYPE=""
        # shellcheck disable=SC1090
        source "$meta_file"
        if match_instance_filter "$META_FQDN" "$META_ZONE" "$META_RECORD_TYPE" "$META_EXEC_SCRIPT" "$filter_host" "$filter_type" "$filter_dir"; then
            matched_metas+=("$meta_file")
            [ "$META_RECORD_TYPE" = "AAAA" ] && need_v6=true || need_v4=true
        fi
    done

    if [ "${#matched_metas[@]}" -eq 0 ] && [ "${#meta_files[@]}" -eq 0 ] && [ -f "$LEGACY_EXEC_SCRIPT" ]; then
        local legacy_zone legacy_name legacy_type legacy_ttl legacy_fqdn legacy_tg="false"
        legacy_zone=$(grep '^CFZONE_NAME=' "$LEGACY_EXEC_SCRIPT" 2>/dev/null | head -1 | cut -d'"' -f2 || true)
        legacy_name=$(grep '^CFRECORD_NAME=' "$LEGACY_EXEC_SCRIPT" 2>/dev/null | head -1 | cut -d'"' -f2 || true)
        legacy_type=$(grep '^CFRECORD_TYPE=' "$LEGACY_EXEC_SCRIPT" 2>/dev/null | head -1 | cut -d'"' -f2 || echo "A")
        legacy_ttl=$(grep '^CFTTL=' "$LEGACY_EXEC_SCRIPT" 2>/dev/null | head -1 | cut -d'=' -f2 || echo "120")
        if grep -q '^TG_BOT_TOKEN=' "$LEGACY_EXEC_SCRIPT" 2>/dev/null && ! grep -q '^TG_BOT_TOKEN=""' "$LEGACY_EXEC_SCRIPT" 2>/dev/null; then
            legacy_tg="true"
        fi
        legacy_fqdn=$(normalize_fqdn "${legacy_name:-unknown}" "${legacy_zone:-unknown}")
        local live_ip=""
        live_ip=$(fetch_public_ip "$legacy_type" "true" || true)
        show_instance_status "legacy" "$LEGACY_EXEC_SCRIPT" "$legacy_fqdn" "$legacy_type" "$legacy_ttl" "" "$legacy_tg" "$live_ip"
        return 0
    fi

    if [ "${#matched_metas[@]}" -eq 0 ]; then
        echo "未发现已安装的 DDNS 实例"
        return 0
    fi

    local live_ipv4="" live_ipv6=""
    if [ "$need_v4" = "true" ]; then
        live_ipv4=$(fetch_public_ip "A" "true" || true)
    fi
    if [ "$need_v6" = "true" ]; then
        live_ipv6=$(fetch_public_ip "AAAA" "true" || true)
    fi

    for meta_file in ${matched_metas[@]+"${matched_metas[@]}"}; do
        local META_INSTANCE_ID="" META_EXEC_SCRIPT="" META_ZONE="" META_FQDN="" META_RECORD_TYPE="" META_TTL="" META_INTERVAL="" META_LOG_FILE="" META_TG_ENABLED=""
        # shellcheck disable=SC1090
        source "$meta_file"
        local cur_ip="$live_ipv4"
        [ "$META_RECORD_TYPE" = "AAAA" ] && cur_ip="$live_ipv6"
        show_instance_status "$META_INSTANCE_ID" "$META_EXEC_SCRIPT" "$META_FQDN" "$META_RECORD_TYPE" "$META_TTL" "$META_LOG_FILE" "$META_TG_ENABLED" "$cur_ip"
    done
}

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
        shift
        remove_ddns "$@"
        ;;
    status)
        shift
        show_status "$@"
        ;;
    *)
        show_usage
        ;;
esac
