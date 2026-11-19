#!/bin/bash
# VPS状态检查脚本 - 用于在执行setup.sh前收集环境信息

echo "=== 系统信息 ==="
grep '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d'"' -f2 || cat /etc/debian_version 2>/dev/null || true
uname -r

echo -e "\n=== 当前用户和sudo组 ==="
whoami
echo "sudo组: $(getent group sudo 2>/dev/null || echo '不存在')"

echo -e "\n=== SSH配置 ==="
sshd_bin=""
[ -x /usr/sbin/sshd ] && sshd_bin="/usr/sbin/sshd" || sshd_bin=$(command -v sshd 2>/dev/null || true)
if [ -n "$sshd_bin" ]; then
    "$sshd_bin" -T -C user=root,host=localhost,addr=127.0.0.1 2>/dev/null \
        | grep -E "^(port|permitrootlogin|passwordauthentication|pubkeyauthentication) "
fi
echo "sshd_config.d/:"
ls /etc/ssh/sshd_config.d/ 2>/dev/null || echo "  目录不存在"

echo -e "\n=== SSH密钥 ==="
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
    [ -f "$f" ] && echo "$f: $(wc -l < "$f") 行"
done

echo -e "\n=== NTP服务 ==="
(systemctl is-active --quiet chrony 2>/dev/null || systemctl is-active --quiet chronyd 2>/dev/null) && echo "chrony: 运行中" || echo "chrony: 未运行"
systemctl is-active --quiet systemd-timesyncd 2>/dev/null && echo "timesyncd: 运行中" || echo "timesyncd: 未运行"
systemctl is-masked --quiet chrony 2>/dev/null && echo "chrony: MASKED"

echo -e "\n=== fail2ban ==="
ls /etc/fail2ban/jail.d/ /etc/fail2ban/jail.local 2>/dev/null || true

echo -e "\n=== 防火墙/iptables ==="
iptables -L -n 2>/dev/null | head -40

echo -e "\n=== sysctl ==="
for f in /etc/sysctl.d/*.conf /etc/sysctl.conf; do
    if [ -f "$f" ]; then
        echo "--- $f ---"
        grep -Ev '^[[:space:]]*(#|$)' "$f" || true
    fi
done

echo -e "\n=== crontab ==="
crontab -l 2>/dev/null || echo "无crontab"
