#!/bin/bash

# 颜色定义
Font_Black="\033[30m"
Font_Red="\033[31m"
Font_Green="\033[32m"
Font_Yellow="\033[33m"
Font_Blue="\033[34m"
Font_Purple="\033[35m"
Font_SkyBlue="\033[36m"
Font_White="\033[37m"
Font_Suffix="\033[0m"

# User Agent
UA_Browser="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 Edg/112.0.1722.64"

# curl参数
curlArgs="--max-time 10"

# 下载IATA代码数据（用于CDN检测）
echo "正在下载IATA代码数据..."
IATACode=$(curl -s --retry 3 --max-time 10 "https://raw.githubusercontent.com/1-stream/RegionRestrictionCheck/main/reference/IATACode.txt" || echo "")

# YouTube Premium检测函数
function MediaUnlockTest_YouTube_Premium() {
    echo -e "${Font_SkyBlue}正在检测 YouTube Premium...${Font_Suffix}"
    
    local tmpresult1=$(curl $curlArgs --user-agent "${UA_Browser}" -${1} --max-time 10 -sSL -H "Accept-Language: en" -b "YSC=BiCUU3-5Gdk; CONSENT=YES+cb.20220301-11-p0.en+FX+700; GPS=1; VISITOR_INFO1_LIVE=4VwPMkB7W5A; PREF=tz=Asia.Shanghai; _gcl_au=1.1.1809531354.1646633279" "https://www.youtube.com/premium" 2>&1)
    local tmpresult2=$(curl $curlArgs --user-agent "${UA_Browser}" -${1} --max-time 10 -sSL -H "Accept-Language: en" "https://www.youtube.com/premium" 2>&1)
    local tmpresult="$tmpresult1:$tmpresult2"

    if [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r YouTube Premium:\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local isCN=$(echo $tmpresult | grep 'www.google.cn')
    if [ -n "$isCN" ]; then
        echo -n -e "\r YouTube Premium:\t\t\t${Font_Red}No${Font_Suffix} ${Font_Green} (Region: CN)${Font_Suffix} \n"
        return
    fi

    local region=$(echo $tmpresult | grep "countryCode" | sed 's/.*"countryCode"//' | cut -f2 -d'"')
    local isAvailable=$(echo $tmpresult | grep 'purchaseButtonOverride')
    local isAvailable2=$(echo $tmpresult | grep "Start trial")

    if [ -n "$isAvailable" ] || [ -n "$isAvailable2" ] || [ -n "$region" ]; then
        if [ -n "$region" ]; then
            echo -n -e "\r YouTube Premium:\t\t\t${Font_Green}Yes (Region: $region)${Font_Suffix}\n"
            return
        else
            echo -n -e "\r YouTube Premium:\t\t\t${Font_Green}Yes${Font_Suffix}\n"
            return
        fi
    else
        if [ -n "$region" ]; then
            echo -n -e "\r YouTube Premium:\t\t\t${Font_Red}No  (Region: $region)${Font_Suffix} \n"
            return
        else
            echo -n -e "\r YouTube Premium:\t\t\t${Font_Red}No${Font_Suffix} \n"
            return
        fi
    fi
    echo -n -e "\r YouTube Premium:\t\t\t${Font_Red}Failed${Font_Suffix}\n"
}

# YouTube CDN检测函数
function MediaUnlockTest_YouTube_CDN() {
    echo -e "${Font_SkyBlue}正在检测 YouTube CDN...${Font_Suffix}"
    
    local tmpresult=$(curl $curlArgs -${1} -sS --max-time 10 "https://redirector.googlevideo.com/report_mapping?di=no" 2>&1)

    if [[ "$tmpresult" == "curl"* ]]; then
        echo -n -e "\r YouTube CDN:\t\t\t\t${Font_Red}Check Failed (Network Connection)${Font_Suffix}\n"
        return
    fi

    local cdn_node=$(echo $tmpresult | awk '{print $3}')
    if [[ "$cdn_node" == *"-"* ]]; then
        local CDN_ISP=$(echo $cdn_node | cut -f1 -d"-" | tr [:lower:] [:upper:])
        local CDN_LOC=$(echo $cdn_node | cut -f2 -d"-" | sed 's/[^a-z]//g')
        
        if [ -n "$IATACode" ]; then
            local lineNo=$(echo "${IATACode}" | cut -f3 -d"|" | sed -n "/${CDN_LOC^^}/=")
            local location=$(echo "${IATACode}" | awk "NR==${lineNo}" | cut -f1 -d"|" | sed -e 's/^[[:space:]]*//' | sed 's/\s*$//')
            if [ -n "$location" ]; then
                echo -n -e "\r YouTube CDN:\t\t\t\t${Font_Yellow}$CDN_ISP in $location ($cdn_node)${Font_Suffix}\n"
            else
                echo -n -e "\r YouTube CDN:\t\t\t\t${Font_Yellow}$CDN_ISP ($cdn_node)${Font_Suffix}\n"
            fi
        else
            echo -n -e "\r YouTube CDN:\t\t\t\t${Font_Yellow}$CDN_ISP ($cdn_node)${Font_Suffix}\n"
        fi
        return
    fi
    
    if [[ "$cdn_node" == *"s"* ]]; then
        local CDN_LOC=$(echo $cdn_node | cut -f2 -d"-" | cut -c1-3)
        
        if [ -n "$IATACode" ]; then
            local lineNo=$(echo "${IATACode}" | cut -f3 -d"|" | sed -n "/${CDN_LOC^^}/=")
            local location=$(echo "${IATACode}" | awk "NR==${lineNo}" | cut -f1 -d"|" | sed -e 's/^[[:space:]]*//' | sed 's/\s*$//')
            if [ -n "$location" ]; then
                echo -n -e "\r YouTube CDN:\t\t\t\t${Font_Green}$location ($cdn_node)${Font_Suffix}\n"
            else
                echo -n -e "\r YouTube CDN:\t\t\t\t${Font_Green}($cdn_node)${Font_Suffix}\n"
            fi
        else
            echo -n -e "\r YouTube CDN:\t\t\t\t${Font_Green}($cdn_node)${Font_Suffix}\n"
        fi
        return
    fi
    
    echo -n -e "\r YouTube CDN:\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
    return
}

# 检测网络连接性
function checkNetwork() {
    echo -e "${Font_SkyBlue}检测网络连接...${Font_Suffix}"
    
    # 检测IPv4
    local ipv4_test=$(curl -4 -s --max-time 5 cloudflare.com/cdn-cgi/trace 2>/dev/null | grep ip)
    if [ -n "$ipv4_test" ]; then
        local ipv4=$(echo "$ipv4_test" | awk -F= '{print $2}')
        echo -e "IPv4 地址: ${Font_Green}$ipv4${Font_Suffix}"
        has_ipv4=1
    else
        echo -e "IPv4: ${Font_Red}不可用${Font_Suffix}"
        has_ipv4=0
    fi
    
    # 检测IPv6
    local ipv6_test=$(curl -6 -s --max-time 5 cloudflare.com/cdn-cgi/trace 2>/dev/null | grep ip)
    if [ -n "$ipv6_test" ]; then
        local ipv6=$(echo "$ipv6_test" | awk -F= '{print $2}')
        echo -e "IPv6 地址: ${Font_Green}$ipv6${Font_Suffix}"
        has_ipv6=1
    else
        echo -e "IPv6: ${Font_Red}不可用${Font_Suffix}"
        has_ipv6=0
    fi
    
    echo ""
}

# 主函数
function main() {
    echo -e "${Font_Blue}===============================================${Font_Suffix}"
    echo -e "${Font_Blue}        YouTube 地区检测脚本${Font_Suffix}"
    echo -e "${Font_Blue}===============================================${Font_Suffix}"
    echo ""
    
    # 检测网络
    checkNetwork
    
    if [[ $has_ipv4 -eq 0 ]] && [[ $has_ipv6 -eq 0 ]]; then
        echo -e "${Font_Red}错误: 无法连接到互联网${Font_Suffix}"
        exit 1
    fi
    
    # IPv4 检测
    if [[ $has_ipv4 -eq 1 ]]; then
        echo -e "${Font_Blue}========== IPv4 检测结果 ==========${Font_Suffix}"
        MediaUnlockTest_YouTube_Premium 4
        MediaUnlockTest_YouTube_CDN 4
        echo ""
    fi
    
    # IPv6 检测
    if [[ $has_ipv6 -eq 1 ]]; then
        echo -e "${Font_Blue}========== IPv6 检测结果 ==========${Font_Suffix}"
        MediaUnlockTest_YouTube_Premium 6
        MediaUnlockTest_YouTube_CDN 6
        echo ""
    fi
    
    echo -e "${Font_Green}检测完成!${Font_Suffix}"
}

# 运行主函数
main