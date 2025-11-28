#!/bin/bash

# 多 CDN 回源白名单脚本（iptables + ipset）
# 目标：只允许配置的 CDN/自定义白名单访问 80/443，其余拒绝
# Version: 1.0.0

set -euo pipefail

readonly SCRIPT_VERSION="1.0.0"
readonly COMMENT_TAG="cdn-allow"
readonly LOG_FILE="/var/log/cdn-allow.log"

# 保护的端口
PROTECT_PORTS=(80 443)

# 配置 CDN 源（name|ipv4_url|ipv6_url，可为空）
CDN_SOURCES=(
  "cloudflare|https://www.cloudflare.com/ips-v4|https://www.cloudflare.com/ips-v6"
  # 在此追加更多 CDN: "vendor|https://example.com/ipv4.txt|https://example.com/ipv6.txt"
)

# 自定义白名单（运维/监控 IP/CIDR），IPv4/IPv6 均可
WHITELIST_IPS=(
  "127.0.0.1/32"
)

# 是否同时保护 Docker 发布的端口（需要 DOCKER-USER 链）
APPLY_DOCKER_USER="true"

# 全局记录已创建的集合名
CDN_V4_SETS=()
CDN_V6_SETS=()
WHITELIST_V4_SET="cdn_whitelist_v4"
WHITELIST_V6_SET="cdn_whitelist_v6"

log() {
  local level="${1:-INFO}"
  local msg="${2:-}"
  local ts
  [ -z "$msg" ] && return 1
  ts=$(date '+%Y-%m-%d %H:%M:%S')
  printf '[%s] %s\n' "$level" "$msg"
  if [ -n "${LOG_FILE:-}" ]; then
    local dir
    dir=$(dirname "$LOG_FILE")
    [ -d "$dir" ] || mkdir -p "$dir" 2>/dev/null || true
    printf '[%s][%s] %s\n' "$ts" "$level" "$msg" >>"$LOG_FILE" 2>/dev/null || true
  fi
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    log ERROR "需要 root 权限运行"
    exit 1
  fi
}

require_cmds() {
  for c in ipset iptables curl; do
    command -v "$c" >/dev/null 2>&1 || { log ERROR "缺少命令: $c"; exit 1; }
  done
}

sanitize_name() {
  echo "$1" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9_' '_'
}

is_ipv4_cidr() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[12][0-9]|3[0-2]))?$ ]] || return 1
  IFS='./' read -r a b c d _ <<<"$ip"
  for o in "$a" "$b" "$c" "$d"; do
    [ "$o" -ge 0 ] && [ "$o" -le 255 ] || return 1
  done
  return 0
}

is_ipv6_cidr() {
  local ip="$1"
  [[ "$ip" =~ : ]] || return 1
  # 基础校验，详尽性留给内核
  if [[ "$ip" =~ / ]]; then
    local prefix=${ip#*/}
    [[ "$prefix" =~ ^([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8])$ ]] || return 1
  fi
  return 0
}

ensure_ipset() {
  local name="$1" family="$2"
  ipset list "$name" >/dev/null 2>&1 && return 0
  ipset create "$name" hash:net family "$family" maxelem 262144 || {
    log ERROR "创建 ipset 失败: $name"
    exit 1
  }
}

rebuild_ipset_from_url() {
  local name="$1" family="$2" url="$3"
  [ -z "$url" ] && return 0
  local tmp="${name}_tmp_$$"
  local data

  log INFO "拉取 $url -> $name ($family)"
  data=$(curl -fsSL --connect-timeout 10 --max-time 30 "$url" || true)
  if [ -z "$data" ]; then
    log ERROR "获取失败或为空: $url"
    return 1
  fi

  ensure_ipset "$name" "$family"
  ipset create "$tmp" hash:net family "$family" maxelem 262144 2>/dev/null || ipset flush "$tmp"

  local added=0
  while IFS= read -r line; do
    line="${line%%#*}"
    line="${line//$'\r'/}"
    line="${line//[[:space:]]/}"
    [ -z "$line" ] && continue

    if [ "$family" = "inet" ]; then
      is_ipv4_cidr "$line" || { log WARNING "跳过无效 IPv4: $line"; continue; }
    else
      is_ipv6_cidr "$line" || { log WARNING "跳过无效 IPv6: $line"; continue; }
    fi

    ipset add "$tmp" "$line" -exist && added=$((added + 1))
  done <<<"$data"

  if [ "$added" -eq 0 ]; then
    log ERROR "集合 $name 没有有效条目，跳过更新"
    ipset destroy "$tmp" 2>/dev/null || true
    return 1
  fi

  ipset swap "$tmp" "$name"
  ipset destroy "$tmp" 2>/dev/null || true
  log INFO "更新完成: $name 共 $added 条"
}

refresh_whitelist_sets() {
  ensure_ipset "$WHITELIST_V4_SET" inet
  ensure_ipset "$WHITELIST_V6_SET" inet6
  ipset flush "$WHITELIST_V4_SET"
  ipset flush "$WHITELIST_V6_SET"

  local added_v4=0 added_v6=0
  for ip in "${WHITELIST_IPS[@]:-}"; do
    ip="${ip//[[:space:]]/}"
    [ -z "$ip" ] && continue
    if is_ipv4_cidr "$ip"; then
      ipset add "$WHITELIST_V4_SET" "$ip" -exist && added_v4=$((added_v4 + 1))
    elif is_ipv6_cidr "$ip"; then
      ipset add "$WHITELIST_V6_SET" "$ip" -exist && added_v6=$((added_v6 + 1))
    else
      log WARNING "跳过无效白名单: $ip"
    fi
  done
  log INFO "白名单刷新: IPv4 $added_v4 条, IPv6 $added_v6 条"
}

delete_tagged_rules() {
  local cmd="$1" chain="$2"
  while true; do
    local num
    num=$($cmd -L "$chain" -n --line-numbers 2>/dev/null | grep "$COMMENT_TAG" | head -1 | awk '{print $1}')
    [ -z "$num" ] && break
    $cmd -D "$chain" "$num" 2>/dev/null || break
  done
}

apply_rules_for_family() {
  local cmd="$1" chain="$2" whitelist_set="$3" sets_var="$4" allow_target="${5:-ACCEPT}"
  local -n cdn_sets="$sets_var"

  delete_tagged_rules "$cmd" "$chain"

  local has_allow=0
  for port in "${PROTECT_PORTS[@]}"; do
    # 白名单优先
    if ipset list "$whitelist_set" >/dev/null 2>&1; then
      local cnt
      cnt=$(ipset list "$whitelist_set" 2>/dev/null | awk '/Number of entries:/ {print $4}')
      if [ "${cnt:-0}" -gt 0 ]; then
        has_allow=1
        $cmd -I "$chain" -p tcp --dport "$port" -m set --match-set "$whitelist_set" src -j "$allow_target" -m comment --comment "$COMMENT_TAG"
      fi
    fi
    for set in "${cdn_sets[@]}"; do
      ipset list "$set" >/dev/null 2>&1 || continue
      local cnt
      cnt=$(ipset list "$set" 2>/dev/null | awk '/Number of entries:/ {print $4}')
      if [ "${cnt:-0}" -gt 0 ]; then
        has_allow=1
        $cmd -I "$chain" -p tcp --dport "$port" -m set --match-set "$set" src -j "$allow_target" -m comment --comment "$COMMENT_TAG"
      fi
    done
    # 末尾阻断
    if [ "$has_allow" -eq 0 ]; then
      log ERROR "链 $chain 缺少有效白名单/CDN 集合，跳过添加 DROP 以避免误阻断"
      return 1
    fi
    $cmd -A "$chain" -p tcp --dport "$port" -j DROP -m comment --comment "$COMMENT_TAG"
  done
}

apply_rules() {
  log INFO "应用 iptables 规则..."
  apply_rules_for_family iptables INPUT "$WHITELIST_V4_SET" CDN_V4_SETS || log WARNING "跳过 IPv4 INPUT 规则写入"
  if command -v ip6tables >/dev/null 2>&1; then
    apply_rules_for_family ip6tables INPUT "$WHITELIST_V6_SET" CDN_V6_SETS || log WARNING "跳过 IPv6 INPUT 规则写入"
  fi

  if [ "$APPLY_DOCKER_USER" = "true" ] && iptables -L DOCKER-USER -n >/dev/null 2>&1; then
    log INFO "检测到 DOCKER-USER，写入容器转发规则"
    apply_rules_for_family iptables DOCKER-USER "$WHITELIST_V4_SET" CDN_V4_SETS RETURN || log WARNING "跳过 DOCKER-USER 规则写入"
  fi
}

init_cdn_set_names() {
  CDN_V4_SETS=()
  CDN_V6_SETS=()
  for entry in "${CDN_SOURCES[@]}"; do
    IFS='|' read -r raw_name v4_url v6_url <<<"$entry"
    local name
    name=$(sanitize_name "$raw_name")
    [ -z "$name" ] && continue
    [ -n "${v4_url:-}" ] && CDN_V4_SETS+=("cdn_${name}_v4")
    [ -n "${v6_url:-}" ] && CDN_V6_SETS+=("cdn_${name}_v6")
  done
}

update_cdn_sets() {
  init_cdn_set_names
  local errors=0

  for entry in "${CDN_SOURCES[@]}"; do
    IFS='|' read -r raw_name v4_url v6_url <<<"$entry"
    local name
    name=$(sanitize_name "$raw_name")
    [ -z "$name" ] && { log WARNING "跳过空名称配置: $entry"; continue; }

    local set_v4="cdn_${name}_v4"
    local set_v6="cdn_${name}_v6"

    if [ -n "${v4_url:-}" ]; then
      rebuild_ipset_from_url "$set_v4" inet "$v4_url" || errors=$((errors + 1))
    fi
    if [ -n "${v6_url:-}" ] && command -v ip6tables >/dev/null 2>&1; then
      rebuild_ipset_from_url "$set_v6" inet6 "$v6_url" || errors=$((errors + 1))
    fi
  done

  refresh_whitelist_sets
  return "$errors"
}

show_status() {
  init_cdn_set_names
  echo "==== cdn.sh 状态 ===="
  echo "版本: $SCRIPT_VERSION"
  echo "保护端口: ${PROTECT_PORTS[*]}"
  echo "CDN 集合:"
  for set in "${CDN_V4_SETS[@]}" "${CDN_V6_SETS[@]}"; do
    [ -z "$set" ] && continue
    if ipset list "$set" >/dev/null 2>&1; then
      local cnt
      cnt=$(ipset list "$set" 2>/dev/null | awk '/Number of entries:/ {print $4}')
      echo "  - $set: ${cnt:-0} 条"
    fi
  done
  if ipset list "$WHITELIST_V4_SET" >/dev/null 2>&1; then
    echo "白名单 v4 条数: $(ipset list "$WHITELIST_V4_SET" | awk '/Number of entries:/ {print $4}')"
  fi
  if ipset list "$WHITELIST_V6_SET" >/dev/null 2>&1; then
    echo "白名单 v6 条数: $(ipset list "$WHITELIST_V6_SET" | awk '/Number of entries:/ {print $4}')"
  fi
  echo ""
  echo "iptables 规则 (带 $COMMENT_TAG):"
  iptables -S 2>/dev/null | grep "$COMMENT_TAG" || echo "  无"
  if command -v ip6tables >/dev/null 2>&1; then
    echo "ip6tables 规则 (带 $COMMENT_TAG):"
    ip6tables -S 2>/dev/null | grep "$COMMENT_TAG" || echo "  无"
  fi
}

usage() {
  cat <<'EOF'
用法: cdn.sh [--apply|--update-sets|--rules|--status|--help]
  --apply        拉取 CDN/白名单并应用 iptables 规则（常用）
  --update-sets  仅更新 ipset，不改规则
  --rules        使用现有 ipset 重新写规则
  --status       查看当前集合与规则
  --help         显示帮助
EOF
}

main() {
  local action="${1:-}"
  case "$action" in
    --apply)
      require_root
      require_cmds
      update_cdn_sets
      apply_rules
      ;;
    --update-sets)
      require_root
      require_cmds
      update_cdn_sets
      ;;
    --rules)
      require_root
      require_cmds
      refresh_whitelist_sets
      apply_rules
      ;;
    --status)
      show_status
      ;;
    --help|-h|"")
      usage
      ;;
    *)
      log ERROR "未知参数: $action"
      usage
      exit 1
      ;;
  esac
}

main "$@"
