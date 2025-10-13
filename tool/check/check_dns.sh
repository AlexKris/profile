#!/bin/bash

echo "================================"
echo "  海外VPS DNS速度测试工具"
echo "================================"
echo ""

# 自动安装dig
install_dig() {
    echo "未检测到dig命令，正在自动安装..."
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    else
        echo "错误: 无法检测操作系统"
        return 1
    fi
    
    case $OS in
        ubuntu|debian)
            echo "系统: Ubuntu/Debian"
            sudo apt-get update -qq > /dev/null 2>&1
            sudo apt-get install -y dnsutils > /dev/null 2>&1
            ;;
        centos|rhel|fedora|rocky|almalinux)
            echo "系统: CentOS/RHEL/Fedora"
            sudo yum install -y bind-utils > /dev/null 2>&1
            ;;
        alpine)
            echo "系统: Alpine"
            sudo apk add bind-tools > /dev/null 2>&1
            ;;
        *)
            echo "错误: 不支持的系统 ($OS)"
            echo ""
            echo "请手动安装dig:"
            echo "  Ubuntu/Debian: sudo apt-get install dnsutils"
            echo "  CentOS/RHEL: sudo yum install bind-utils"
            echo "  Alpine: sudo apk add bind-tools"
            return 1
            ;;
    esac
    
    if command -v dig &> /dev/null; then
        echo "dig 安装成功！"
        echo ""
        return 0
    else
        echo "错误: dig 安装失败"
        return 1
    fi
}

# 检查dig
if ! command -v dig &> /dev/null; then
    install_dig || exit 1
fi

# DNS服务器列表
DNS_SERVERS=(
    "1.1.1.1|Cloudflare-Primary"
    "1.0.0.1|Cloudflare-Secondary"
    "8.8.8.8|Google-Primary"
    "8.8.4.4|Google-Secondary"
    "94.140.14.14|AdGuard-DNS"
    "94.140.15.15|AdGuard-Secondary"
    "9.9.9.9|Quad9"
    "208.67.222.222|OpenDNS"
)

# 测试域名
TEST_DOMAINS=("google.com" "github.com" "cloudflare.com" "amazon.com" "reddit.com")

TEST_COUNT=3

echo "测试配置:"
echo "  域名数量: ${#TEST_DOMAINS[@]}"
echo "  每DNS测试: $((${#TEST_DOMAINS[@]} * TEST_COUNT)) 次"
echo ""

# 使用数组存储结果
declare -a result_lines=()

for dns_entry in "${DNS_SERVERS[@]}"; do
    IFS='|' read -r dns_ip dns_name <<< "$dns_entry"
    
    echo "正在测试: $dns_name ($dns_ip)"
    
    total_time=0
    success_count=0
    failed_count=0
    min_time=999999
    max_time=0
    
    for domain in "${TEST_DOMAINS[@]}"; do
        for i in $(seq 1 $TEST_COUNT); do
            query_result=$(dig @$dns_ip $domain +time=3 +tries=1 2>/dev/null)
            query_time=$(echo "$query_result" | grep "Query time" | awk '{print $4}')
            
            if [ ! -z "$query_time" ] && [ "$query_time" -gt 0 ] 2>/dev/null; then
                total_time=$((total_time + query_time))
                ((success_count++))
                
                if [ $query_time -lt $min_time ]; then
                    min_time=$query_time
                fi
                if [ $query_time -gt $max_time ]; then
                    max_time=$query_time
                fi
            else
                ((failed_count++))
            fi
        done
    done
    
    if [ $success_count -gt 0 ]; then
        avg_time=$((total_time / success_count))
        success_rate=$((success_count * 100 / (success_count + failed_count)))
        
        echo "  平均: ${avg_time}ms | 范围: ${min_time}-${max_time}ms | 成功率: ${success_rate}%"
        
        # 格式化为9位数，便于排序
        sort_key=$(printf "%09d" $avg_time)
        result_lines+=("${sort_key}|${avg_time}|${dns_name}|${dns_ip}|${min_time}|${max_time}|${success_rate}")
    else
        echo "  所有查询失败"
    fi
    echo ""
done

echo "================================"
echo "   排名结果"
echo "================================"
echo ""

# 排序并显示结果
rank=1
while IFS='|' read -r sort_key avg_time dns_name dns_ip min_time max_time success_rate; do
    echo "$rank. $dns_name ($dns_ip)"
    echo "   平均: ${avg_time}ms | 范围: ${min_time}-${max_time}ms | 成功率: ${success_rate}%"
    
    if [ $rank -eq 1 ]; then
        echo "   (推荐使用)"
    fi
    
    echo ""
    ((rank++))
done < <(printf '%s\n' "${result_lines[@]}" | sort -n)

echo "测试完成！"
echo ""
echo "建议: 选择前3名作为主/备用DNS"