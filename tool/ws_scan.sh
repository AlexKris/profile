#!/bin/bash
#
# ws_scan.sh - 扫描 VPS 是否暴露了 WebSocket 端口
# 仅使用 macOS 自带工具 (curl)
# 注意: 不使用 nc -z，因为云主机 SYN 代理会导致误报
#

set -euo pipefail

# 默认值
TIMEOUT=3
PATHS=("/" "/ws" "/websocket")
DEFAULT_PORTS="80,443,8080,8443,2052,2053,2082,2083,2086,2087,2095,2096,10000-10010"

usage() {
    cat <<EOF
用法: $0 <IP> [选项]

选项:
  -p <端口>       端口范围，如 80,443,8080-8090 (默认: 常见端口)
  -w <路径>       WebSocket 路径，可多次指定 (默认: / /ws /websocket)
  -t <秒>         超时时间 (默认: 3)
  -f              全端口扫描 1-65535 (慢)
  -h              显示帮助

示例:
  $0 1.2.3.4
  $0 1.2.3.4 -p 80,443,8080-8090
  $0 1.2.3.4 -p 443 -w /my-ws-path
  $0 1.2.3.4 -f
EOF
    exit 0
}

# 解析端口字符串为列表
expand_ports() {
    local input="$1"
    local ports=()
    IFS=',' read -ra segments <<< "$input"
    for seg in "${segments[@]}"; do
        if [[ "$seg" == *-* ]]; then
            local start="${seg%-*}"
            local end="${seg#*-}"
            for ((p=start; p<=end; p++)); do
                ports+=("$p")
            done
        else
            ports+=("$seg")
        fi
    done
    echo "${ports[@]}"
}

# 检查端口是否开放（用 curl 替代 nc，避免云主机 SYN 代理误报）
check_port() {
    local ip="$1" port="$2"
    local result
    result=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" \
        --max-time "$TIMEOUT" \
        "http://${ip}:${port}/" 2>/dev/null) && return 0
    # curl 返回非 0 但有连接响应（如 connection reset）也算开放
    # 只有完全超时（无任何字节返回）才算关闭
    local exit_code=$?
    # exit 28 = timeout（无响应，端口关闭或被 DROP）
    # exit 52 = empty reply（端口开放但无 HTTP 响应）
    # exit 56 = recv failure（端口开放但连接被重置）
    [[ $exit_code -ne 28 ]]
}

# 检查是否为 WebSocket 服务
check_ws() {
    local ip="$1" port="$2" path="$3" scheme="$4"
    local url="${scheme}://${ip}:${port}${path}"
    local response
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        --max-time "$TIMEOUT" \
        -H "Connection: Upgrade" \
        -H "Upgrade: websocket" \
        -H "Sec-WebSocket-Version: 13" \
        -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
        ${scheme:+$([ "$scheme" = "https" ] && echo "-k" || true)} \
        "$url" 2>/dev/null) || true
    echo "$response"
}

# ---- 主逻辑 ----

[[ $# -lt 1 ]] && usage

IP="$1"
shift

PORT_INPUT="$DEFAULT_PORTS"
CUSTOM_PATHS=()

while getopts "p:w:t:fh" opt; do
    case $opt in
        p) PORT_INPUT="$OPTARG" ;;
        w) CUSTOM_PATHS+=("$OPTARG") ;;
        t) TIMEOUT="$OPTARG" ;;
        f) PORT_INPUT="1-65535" ;;
        h) usage ;;
        *) usage ;;
    esac
done

[[ ${#CUSTOM_PATHS[@]} -gt 0 ]] && PATHS=("${CUSTOM_PATHS[@]}")

PORTS=($(expand_ports "$PORT_INPUT"))
TOTAL=${#PORTS[@]}

echo "======================================"
echo " WS 端口扫描器"
echo "======================================"
echo " 目标: $IP"
echo " 端口数: $TOTAL"
echo " 超时: ${TIMEOUT}s"
echo " WS 路径: ${PATHS[*]}"
echo "======================================"
echo ""

# 阶段 1: 端口扫描
echo "[*] 阶段 1: 扫描开放端口..."
OPEN_PORTS=()
scanned=0

for port in "${PORTS[@]}"; do
    scanned=$((scanned + 1))
    # 进度显示（每 100 个端口或最后一个）
    if [[ $((scanned % 100)) -eq 0 ]] || [[ $scanned -eq $TOTAL ]]; then
        printf "\r    进度: %d/%d" "$scanned" "$TOTAL"
    fi
    if check_port "$IP" "$port"; then
        OPEN_PORTS+=("$port")
        printf "\r    [+] 端口 %d 开放\n" "$port"
    fi
done
echo ""

if [[ ${#OPEN_PORTS[@]} -eq 0 ]]; then
    echo "[!] 未发现开放端口"
    exit 0
fi

echo "[*] 开放端口: ${OPEN_PORTS[*]}"
echo ""

# 阶段 2: WebSocket 探测
echo "[*] 阶段 2: 探测 WebSocket 服务..."
WS_FOUND=0

for port in "${OPEN_PORTS[@]}"; do
    for scheme in http https; do
        for path in "${PATHS[@]}"; do
            code=$(check_ws "$IP" "$port" "$path" "$scheme")
            if [[ "$code" == "101" ]]; then
                echo "    [!!!] WS 确认: ${scheme}://${IP}:${port}${path} (101 Switching Protocols)"
                WS_FOUND=$((WS_FOUND + 1))
            elif [[ "$code" == "200" || "$code" == "400" || "$code" == "426" ]]; then
                echo "    [?]  可疑:    ${scheme}://${IP}:${port}${path} (HTTP $code)"
            fi
        done
    done
done

echo ""
echo "======================================"
if [[ $WS_FOUND -gt 0 ]]; then
    echo " 结果: 发现 $WS_FOUND 个 WebSocket 服务!"
else
    echo " 结果: 未发现明确的 WebSocket 服务"
    echo " 提示: 如果用了自定义路径，请用 -w 指定"
fi
echo "======================================"
