#!/bin/bash
# VPS状态检查脚本 - 用于在执行setup.sh前收集环境信息

echo "=== 系统信息 ==="
cat /etc/debian_version 2>/dev/null || cat /etc/redhat-release 2>/dev/null
uname -r

echo -e "\n=== 当前用户和sudo组 ==="
whoami
echo "sudo组: $(getent group sudo 2>/dev/null || echo '不存在')"
echo "wheel组: $(getent group wheel 2>/dev/null || echo '不存在')"

echo -e "\n=== SSH配置 ==="
sshd -T 2>/dev/null | grep -E "^(port|permitrootlogin|passwordauthentication|pubkeyauthentication)"
echo "sshd_config.d/:"
ls /etc/ssh/sshd_config.d/ 2>/dev/null || echo "  目录不存在"

echo -e "\n=== SSH密钥 ==="
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
    [ -f "$f" ] && echo "$f: $(wc -l < "$f") 个密钥"
done

echo -e "\n=== NTP服务 ==="
systemctl is-active chrony 2>/dev/null && echo "chrony: 运行中" || echo "chrony: 未运行"
systemctl is-active systemd-timesyncd 2>/dev/null && echo "timesyncd: 运行中" || echo "timesyncd: 未运行"
systemctl is-masked chrony 2>/dev/null && echo "chrony: MASKED"

echo -e "\n=== fail2ban ==="
ls /etc/fail2ban/jail.d/ /etc/fail2ban/jail.local 2>/dev/null

echo -e "\n=== 防火墙/iptables ==="
iptables -L -n 2>/dev/null | head -40

echo -e "\n=== sysctl ==="
cat /etc/sysctl.conf 2>/dev/null || echo "文件不存在"

echo -e "\n=== crontab ==="
crontab -l 2>/dev/null || echo "无crontab"
