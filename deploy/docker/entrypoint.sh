#!/bin/bash
# Container entry point. It prepares the first run, then starts the web host (SFTP server and admin UI).
#
# Admin password (the UI is closed without one):
#   - AdminAuth__PasswordHash set:           used as it is.
#   - FREESFTPSHARP_ADMIN_PASSWORD set:      hashed at every start.
#   - neither:                               a password is generated at the first start, printed once to the log,
#                                            and its hash is kept in /data/admin-password.hash.
# Optional first SFTP user (only when it does not exist; the root is /data/files/<name>):
#   FREESFTPSHARP_USER=alice  FREESFTPSHARP_USER_PASSWORD=...
set -euo pipefail

web=(dotnet /app/web/FxSshSftpServer.dll)
data="${FREESFTPSHARP_DATA:-/data}"
mkdir -p "$data" "$data/logs" "$data/keys" "$data/files"

hash_password() {
    printf '%s\n' "$1" | "${web[@]}" --hash-admin-password | sed -n 's/^AdminAuth__PasswordHash=//p'
}

if [ -z "${AdminAuth__PasswordHash:-}" ]; then
    if [ -n "${FREESFTPSHARP_ADMIN_PASSWORD:-}" ]; then
        AdminAuth__PasswordHash="$(hash_password "$FREESFTPSHARP_ADMIN_PASSWORD")"
    elif [ -s "$data/admin-password.hash" ]; then
        AdminAuth__PasswordHash="$(cat "$data/admin-password.hash")"
    else
        generated="$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 20)"
        AdminAuth__PasswordHash="$(hash_password "$generated")"
        (umask 077 && printf '%s' "$AdminAuth__PasswordHash" > "$data/admin-password.hash")
        echo "================================================================"
        echo " First start: the admin UI user is 'admin'."
        echo " Generated admin password (shown only this once): $generated"
        echo " Set FREESFTPSHARP_ADMIN_PASSWORD to choose your own."
        echo "================================================================"
    fi
    export AdminAuth__PasswordHash
fi
export AdminAuth__UserName="${AdminAuth__UserName:-admin}"

if [ -n "${FREESFTPSHARP_USER:-}" ] && [ -n "${FREESFTPSHARP_USER_PASSWORD:-}" ]; then
    if ! freesftpsharp-user list 2>/dev/null | grep -qw -- "$FREESFTPSHARP_USER"; then
        printf '%s\n' "$FREESFTPSHARP_USER_PASSWORD" |
            freesftpsharp-user add "$FREESFTPSHARP_USER" --root "$data/files/$FREESFTPSHARP_USER" --password-stdin
    fi
fi

echo "Admin UI: http://<host>:80 (plain HTTP: put HTTPS in front of it or mount a certificate, see docs/deployment.md)"
exec "${web[@]}" "$@"
