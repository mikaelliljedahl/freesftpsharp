#!/bin/bash
# Smoke test of the container image: start it with no configuration (plus a first user), wait for /healthz, check
# the first-run admin password and --version, upload and download one file with the OpenSSH sftp client, then
# remove the container. Usage: deploy/docker/smoke-test.sh <image> [expected-version]
set -euo pipefail

image="${1:?usage: smoke-test.sh <image> [expected-version]}"
expected_version="${2:-}"
name="freesftpsharp-smoke-$$"
work="$(mktemp -d)"
ssh_port="${SMOKE_SSH_PORT:-2222}"
http_port="${SMOKE_HTTP_PORT:-8080}"
password="smoke-Test-Pass-1"

cleanup() {
    docker logs "$name" 2>&1 | tail -n 40 || true
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker volume rm -f "$name-data" >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT

if [ -n "$expected_version" ]; then
    actual="$(docker run --rm --entrypoint dotnet "$image" /app/web/FxSshSftpServer.dll --version)"
    [ "$actual" = "$expected_version" ] || { echo "version is '$actual', expected '$expected_version'"; exit 1; }
    echo "version ok: $actual"
fi

docker run -d --name "$name" -p "$ssh_port:22" -p "$http_port:80" -v "$name-data:/data" \
    -e FREESFTPSHARP_USER=smoke -e FREESFTPSHARP_USER_PASSWORD="$password" "$image" >/dev/null

for _ in $(seq 1 60); do
    if curl -fsS "http://127.0.0.1:$http_port/healthz" >/dev/null 2>&1; then healthy=1; break; fi
    sleep 1
done
[ "${healthy:-0}" = 1 ] || { echo "/healthz did not answer 200"; exit 1; }
echo "healthz ok"

docker logs "$name" 2>&1 | grep -q "Generated admin password" || { echo "no generated admin password in the log"; exit 1; }
[ "$(docker exec "$name" id -u)" != "0" ] || { echo "the container runs as root"; exit 1; }
for _ in $(seq 1 30); do
    state="$(docker inspect -f '{{.State.Health.Status}}' "$name")"
    [ "$state" = healthy ] && break
    sleep 2
done
[ "$state" = healthy ] || { echo "the container health is '$state'"; exit 1; }

# The password goes to ssh through SSH_ASKPASS, no sshpass needed.
printf '#!/bin/sh\necho "%s"\n' "$password" > "$work/askpass" && chmod +x "$work/askpass"
echo "smoke test payload" > "$work/up.txt"
export SSH_ASKPASS="$work/askpass" SSH_ASKPASS_REQUIRE=force DISPLAY=:0
sftp -q -P "$ssh_port" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no \
    -o PreferredAuthentications=password smoke@127.0.0.1 <<SFTP
put $work/up.txt up.txt
get up.txt $work/down.txt
SFTP
cmp "$work/up.txt" "$work/down.txt"
docker exec "$name" test -f /data/files/smoke/up.txt
echo "sftp upload and download ok"
