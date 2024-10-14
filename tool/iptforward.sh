#!/bin/bash

# 更新系统包并安装必要的软件
echo "更新系统包..."
sudo apt update && sudo apt upgrade -y && sudo apt full-upgrade -y && sudo apt autoclean -y && sudo apt autoremove -y

update_shell(){
    wget -N "https://raw.githubusercontent.com/AlexKris/profile/main/tool/iptforward.sh" -O iptforward.sh && bash iptforward.sh
}

# 查询当前的转发规则
list_port_forwarding() {
    echo "当前的端口转发规则："
    iptables -t nat -L PREROUTING --line-numbers
}

# 删除指定监听端口的转发规则
delete_port_forwarding() {
    local port=$1
    iptables -t nat -D PREROUTING -p tcp --dport $port -j DNAT 2>/dev/null
    iptables -t nat -D PREROUTING -p udp --dport $port -j DNAT 2>/dev/null
    echo "已删除端口 $port 的转发规则。"
}

# 添加端口转发规则
add_port_forwarding() {
    read -p "输入监听端口: " listen_port
    read -p "输入目标 IP: " dest_ip
    read -p "输入目标端口: " dest_port

    # 检查是否已存在规则
    existing_rule=$(iptables -t nat -L PREROUTING --line-numbers | grep -w "dpt:$listen_port ")
    if [[ -n "$existing_rule" ]]; then
        echo "已存在针对端口 $listen_port 的转发规则:"
        echo "$existing_rule"
        echo "是否要覆盖它？(yes/no)"
        read answer
        if [[ $answer == "yes" ]]; then
            delete_port_forwarding $listen_port
            add_rule $listen_port $dest_ip $dest_port
        else
            echo "添加规则操作已取消。"
            return
        fi
    else
        add_rule $listen_port $dest_ip $dest_port
    fi
}

add_rule() {
    local listen_port=$1
    local dest_ip=$2
    local dest_port=$3

    # 添加 TCP 和 UDP 转发规则
    iptables -t nat -A PREROUTING -p tcp --dport $listen_port -j DNAT --to-destination $dest_ip:$dest_port
    iptables -t nat -A PREROUTING -p udp --dport $listen_port -j DNAT --to-destination $dest_ip:$dest_port
    iptables -t nat -A POSTROUTING -p tcp -d $dest_ip --dport $dest_port -j MASQUERADE
    iptables -t nat -A POSTROUTING -p udp -d $dest_ip --dport $dest_port -j MASQUERADE

    echo "已添加针对 TCP/UDP 端口 $listen_port 的转发规则到 $dest_ip:$dest_port"
}

# 主逻辑
echo "选择一个选项："
echo "1) 更新脚本"
echo "2) 列出所有端口转发规则"
echo "3) 删除端口转发规则"
echo "4) 添加端口转发规则"
read -p "请输入选择: " action

case $action in
    1)
        update_shell
        ;;
    2)
        list_port_forwarding
        ;;
    3)
        read -p "输入要删除规则的端口: " port
        delete_port_forwarding $port
        ;;
    4)
        add_port_forwarding
        ;;
    *)
        echo "输入无效，退出..."
        exit 1
        ;;
esac