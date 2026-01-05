#!/usr/bin/env bash

# bash <(curl -L -s https://cdn.skk.moe/sh/optimize.sh)
echo=echo
for cmd in echo /bin/echo; do
    $cmd >/dev/null 2>&1 || continue

    if ! $cmd -e "" | grep -qE '^-e'; then
        echo=$cmd
        break
    fi
done

CSI=$($echo -e "\033[")
CEND="${CSI}0m"
CDGREEN="${CSI}32m"
CRED="${CSI}1;31m"
CGREEN="${CSI}1;32m"
CYELLOW="${CSI}1;33m"
CBLUE="${CSI}1;34m"
CMAGENTA="${CSI}1;35m"
CCYAN="${CSI}1;36m"

OUT_ALERT() {
    echo -e "${CYELLOW}$1${CEND}"
}

OUT_ERROR() {
    echo -e "${CRED}$1${CEND}"
}

OUT_INFO() {
    echo -e "${CCYAN}$1${CEND}"
}

if [[ -f /etc/redhat-release ]]; then
    release="centos"
elif cat /etc/issue | grep -q -E -i "debian|raspbian"; then
    release="debian"
elif cat /etc/issue | grep -q -E -i "ubuntu"; then
    release="ubuntu"
elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
    release="centos"
elif cat /proc/version | grep -q -E -i "raspbian|debian"; then
    release="debian"
elif cat /proc/version | grep -q -E -i "ubuntu"; then
    release="ubuntu"
elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
    release="centos"
else
    OUT_ERROR "[错误] 不支持的操作系统！"
    exit 1
fi

OUT_ALERT "[信息] 优化性能中！"

if [[ -z "$(command -v haveged)" ]]; then
    OUT_INFO "安装 haveged 改善随机数生成器性能"
    apt install haveged -y
    systemctl enable haveged
fi
if [[ -z "$(command -v rngd)" ]]; then
    OUT_INFO "安装 rng-tools 改善随机数生成器性能"
    apt install rng-tools -y
    systemctl enable rng-tools
fi

if [[ ! -z "$(command -v ksmtuned)" ]]; then
    OUT_INFO "禁用 ksmtuned"
    echo 2 > /sys/kernel/mm/ksm/run

    apt purge tuned --autoremove -y || true
    apt purge ksmtuned --autoremove -y || true

    rm -rf /etc/systemd/system/ksmtuned.service
    mv /usr/sbin/ksmtuned /usr/sbin/ksmtuned.bak || true
    touch /usr/sbin/ksmtuned
    echo "# KSMTUNED DISABLED" > /usr/sbin/ksmtuned
    # chattr +i /usr/sbin/ksmtuned
fi

OUT_INFO "禁用 hugepage"
cat > /etc/systemd/system/disable-transparent-huge-pages.service << EOF
[Unit]
Description=Disable Transparent Huge Pages (THP)
DefaultDependencies=no
After=sysinit.target local-fs.target
Before=mongod.service
[Service]
Type=oneshot
ExecStart=/bin/sh -c 'echo never | tee /sys/kernel/mm/transparent_hugepage/enabled > /dev/null'
ExecStart=/bin/sh -c 'echo never | tee /sys/kernel/mm/transparent_hugepage/defrag > /dev/null'
[Install]
WantedBy=basic.target
EOF

systemctl daemon-reload
systemctl start disable-transparent-huge-pages
systemctl enable disable-transparent-huge-pages

OUT_INFO "启用 tls 和 nf_conntrack 内核模块"

echo nf_conntrack > /usr/lib/modules-load.d/sukka-network-optimized.conf
echo tls >> /usr/lib/modules-load.d/sukka-network-optimized.conf

OUT_INFO "优化参数中！"

cat > /etc/sysctl.d/99-z-sukka-optimized.conf << EOF
kernel.panic = 1
kernel.task_delayacct = 1
# increase the maximum length of processor input queues
net.core.netdev_max_backlog = 32768
# fq is recommended for BBR
net.core.default_qdisc = fq
net.core.somaxconn = 32768
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.ip_default_ttl = 128
net.ipv4.ip_forward = 1
net.ipv4.ip_local_port_range = 10240 65535
net.ipv4.tcp_abort_on_overflow = 0
net.ipv4.tcp_adv_win_scale = -2
net.ipv4.tcp_autocorking = 1
net.ipv4.tcp_base_mss = 1024
net.ipv4.tcp_collapse_max_bytes = 6291456
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_dsack = 1
net.ipv4.tcp_ecn = 1
net.ipv4.tcp_fastopen = 1027
net.ipv4.tcp_fastopen_blackhole_timeout_sec = 10
net.ipv4.tcp_fin_timeout = 3
net.ipv4.tcp_frto = 1
net.ipv4.tcp_keepalive_intvl = 2
net.ipv4.tcp_keepalive_probes = 2
net.ipv4.tcp_keepalive_time = 120
net.ipv4.tcp_max_orphans = 8192
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_max_tw_buckets = 4096
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_no_ssthresh_metrics_save = 1
net.ipv4.tcp_slow_start_after_idle = 0
# can't set to 0, it will then default to 8: https://serverfault.com/a/408882/1029887
net.ipv4.tcp_orphan_retries = 4
net.ipv4.tcp_retries1 = 2
net.ipv4.tcp_retries2 = 2
net.ipv4.tcp_rfc1337 = 1
net.core.rmem_default = 262144
net.core.rmem_max = 536870912
net.ipv4.tcp_rmem = 8192 262144 536870912
net.core.wmem_default = 16384
net.core.wmem_max = 536870912
net.ipv4.tcp_wmem = 4096 16384 536870912
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_sack = 1
# net.ipv4.tcp_shrink_window = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_no_metrics_save = 0
net.ipv4.tcp_notsent_lowat = 131072
# disable naggle algorithm to reach true 0-rtt by enabling tcp_low_latency
net.ipv4.tcp_low_latency = 1
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 4096
net.ipv4.route.flush = 1
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
net.netfilter.nf_conntrack_generic_timeout = 10
net.netfilter.nf_conntrack_gre_timeout = 5
net.netfilter.nf_conntrack_gre_timeout_stream = 30
net.netfilter.nf_conntrack_icmp_timeout = 5
net.netfilter.nf_conntrack_icmpv6_timeout = 5
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_close = 5
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 5
net.netfilter.nf_conntrack_tcp_timeout_established = 600
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_last_ack = 5
net.netfilter.nf_conntrack_tcp_timeout_max_retrans = 5
net.netfilter.nf_conntrack_tcp_timeout_syn_recv = 5
net.netfilter.nf_conntrack_tcp_timeout_syn_sent = 5
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 15
net.netfilter.nf_conntrack_tcp_timeout_unacknowledged = 5
net.netfilter.nf_conntrack_udp_timeout = 5
net.netfilter.nf_conntrack_udp_timeout_stream = 60
vm.overcommit_memory = 1
vm.swappiness = 0
EOF

mems=$(free --bytes | grep Mem | awk '{print $2}')
page=$(getconf PAGESIZE)
size=$((mems/page))
echo "net.ipv4.tcp_mem = $((size/100*12)) $((size/100*50)) $((size/100*70))" >> /etc/sysctl.d/99-z-sukka-optimized.conf

sort -n /etc/sysctl.d/99-z-sukka-optimized.conf -o /etc/sysctl.d/99-z-sukka-optimized.conf
sysctl --system > /dev/null 2>&1

OUT_INFO "禁用 nofile nproc 限制"

cat <<'EOF' > /etc/security/limits.conf
* soft nofile unlimited
* hard nofile unlimited
* soft nproc unlimited
* hard nproc unlimited
root soft nofile unlimited
root hard nofile unlimited
root soft nproc unlimited
root hard nproc unlimited
EOF

cat <<'EOF' > /etc/systemd/system.conf
[Manager]
DefaultCPUAccounting=yes
DefaultIOAccounting=yes
DefaultIPAccounting=yes
DefaultMemoryAccounting=yes
DefaultTasksAccounting=yes
DefaultLimitCORE=infinity
DefaultLimitNPROC=infinity
DefaultLimitNOFILE=infinity
EOF

OUT_INFO "调整 journald"

cat > /etc/systemd/journald.conf <<EOF
[Journal]
SystemMaxUse=384M
SystemMaxFileSize=128M
SystemMaxFiles=3
RuntimeMaxUse=256M
RuntimeMaxFileSize=128M
RuntimeMaxFiles=3
MaxRetentionSec=86400
MaxFileSec=259200
ForwardToSyslog=no
EOF

OUT_INFO "[信息] 优化完毕！"
exit 0
