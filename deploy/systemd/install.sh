#!/bin/sh
# Installs a FreeSftpSharp release archive as a systemd service (Linux, run as root).
#   sudo ./install.sh freesftpsharp-1.2.3-linux-x64.tar.gz
# An upgrade is the same command: the binaries are replaced, /var/lib/freesftpsharp and /etc/freesftpsharp are kept.
set -eu

archive="${1:?usage: install.sh <freesftpsharp-VERSION-linux-ARCH.tar.gz>}"
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
tar -xzf "$archive" -C "$tmp"
src="$(find "$tmp" -mindepth 1 -maxdepth 1 -type d | head -n 1)"

id -u freesftpsharp >/dev/null 2>&1 || useradd --system --home-dir /var/lib/freesftpsharp --shell /usr/sbin/nologin freesftpsharp

# Binaries (replaced on every install). The previous version is kept in /opt/freesftpsharp.previous for a rollback.
rm -rf /opt/freesftpsharp.previous
[ -d /opt/freesftpsharp ] && mv /opt/freesftpsharp /opt/freesftpsharp.previous
mkdir -p /opt/freesftpsharp
cp -a "$src/FxSshSftpServer" "$src/ServerConsoleApp" /opt/freesftpsharp/
chmod 0755 /opt/freesftpsharp/FxSshSftpServer/FxSshSftpServer /opt/freesftpsharp/ServerConsoleApp/ServerConsoleApp
# The relative log paths of appsettings.json (logs/...) are below the program directory: send them to /var/log.
ln -sfn /var/log/freesftpsharp /opt/freesftpsharp/FxSshSftpServer/logs

install -d -m 0750 -o root -g freesftpsharp /etc/freesftpsharp
if [ ! -f /etc/freesftpsharp/freesftpsharp.env ]; then
    password="$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 20)"
    hash="$(printf '%s\n' "$password" | /opt/freesftpsharp/FxSshSftpServer/FxSshSftpServer --hash-admin-password | sed -n 's/^AdminAuth__PasswordHash=//p')"
    umask 027
    {
        echo "AdminAuth__UserName=admin"
        echo "AdminAuth__PasswordHash=$hash"
        echo "# Admin UI on localhost only; put HTTPS in front of it (docs/deployment.md)."
        echo "Kestrel__Endpoints__Http__Url=http://127.0.0.1:5000"
        echo "Observability__Health__Enabled=true"
    } > /etc/freesftpsharp/freesftpsharp.env
    chown root:freesftpsharp /etc/freesftpsharp/freesftpsharp.env
    echo "Admin UI user 'admin', generated password (shown once): $password"
fi

install -m 0644 "$here/freesftpsharp.service" /etc/systemd/system/freesftpsharp.service
systemctl daemon-reload
systemctl enable freesftpsharp.service
systemctl restart freesftpsharp.service
echo "Installed. Status: systemctl status freesftpsharp"
