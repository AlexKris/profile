#!/usr/bin/env bash
# filename: disable_debian_user.sh
set -euxo pipefail

TARGET=debian                     # 要禁用的账户

# 1️⃣ 结束该用户的全部会话与进程
pkill -u "$TARGET"  || true       # 普通方式
loginctl terminate-user "$TARGET" || true  # systemd 用户会话

# 2️⃣ 彻底锁定账号，禁止登录
passwd  -l   "$TARGET"            # 锁定密码
usermod -L   "$TARGET"            # 锁定 shadow 条目
chsh -s /usr/sbin/nologin "$TARGET"  # 无交互 shell

# 3️⃣ 移除 sudo 权限
deluser "$TARGET" sudo  || true

# 4️⃣ SSH 层面再加保险
if ! grep -q "^DenyUsers" /etc/ssh/sshd_config; then
  echo "DenyUsers $TARGET" >> /etc/ssh/sshd_config
else
  sed -i "s/^DenyUsers.*/& $TARGET/" /etc/ssh/sshd_config
fi
systemctl reload sshd

# 5️⃣ cloud-init 侧禁止再次创建/启用 debian 用户
sed -Ei 's/^(\s*name:\s*).*/\1root/'       /etc/cloud/cloud.cfg
sed -Ei 's/^(\s*lock_password:\s*).*/\1true/' /etc/cloud/cloud.cfg

echo "[ OK ] $TARGET 已被彻底禁用。"
