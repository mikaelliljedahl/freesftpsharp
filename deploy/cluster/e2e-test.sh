#!/bin/bash
# End-to-end test of the cluster example (docker-compose.yml, issue #149): starts PostgreSQL, two nodes and HAProxy with
# an image of this version, creates a user through node A with the "user" command, logs in over SFTP through HAProxy
# (PROXY protocol v2 to the nodes) and uploads and downloads a file, checks that both nodes serve logins and that the
# connection list of node B shows the client, then removes everything (containers, volumes, network).
# Usage: deploy/cluster/e2e-test.sh <image>     (for example an image built with: docker build -t freesftpsharp:e2e .)
set -euo pipefail

image="${1:?usage: e2e-test.sh <image>}"
here="$(cd "$(dirname "$0")" && pwd)"
project="freesftpsharp-e2e-$$"
work="$(mktemp -d)"
password="e2e-Test-Pass-1"
admin_password="e2e-Admin-Pass-1"

export FREESFTPSHARP_IMAGE="$image" FREESFTPSHARP_ADMIN_PASSWORD="$admin_password" POSTGRES_PASSWORD="e2e-postgres-only"
# The REST API on, for the connection list (the example leaves it off).
cat >"$work/compose.e2e.yml" <<'YAML'
services:
  node-a:
    environment:
      Api__Enabled: "true"
  node-b:
    environment:
      Api__Enabled: "true"
YAML
compose=(docker compose -p "$project" -f "$here/docker-compose.yml" -f "$work/compose.e2e.yml")

cleanup() {
    status=$?
    if [ "$status" != 0 ]; then
        "${compose[@]}" ps -a || true
        "${compose[@]}" logs --no-color --tail 60 || true
    fi
    "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$work"
    exit "$status"
}
trap cleanup EXIT

"${compose[@]}" up -d

# Both nodes up: the admin UI of each answers through its own port inside the network (HAProxy checks them too).
for node in node-a node-b; do
    for _ in $(seq 1 90); do
        if "${compose[@]}" exec -T "$node" /usr/local/bin/healthcheck.sh >/dev/null 2>&1; then ready=1; break; fi
        sleep 1
    done
    [ "${ready:-0}" = 1 ] || { echo "$node did not become healthy"; exit 1; }
    ready=0
    echo "$node healthy"
done

# The user, through node A: the same settings database as both nodes.
printf '%s\n' "$password" | "${compose[@]}" exec -T node-a freesftpsharp-user add alice --root /data/files/alice --password-stdin
# Captured first: with pipefail, "cmd | grep -q" fails when grep exits early and cmd gets SIGPIPE.
users="$("${compose[@]}" exec -T node-b freesftpsharp-user list)"
grep -qw alice <<<"$users" || { echo "node B does not list alice: $users"; exit 1; }
echo "user created on node A, seen by node B"

# The password goes to ssh through SSH_ASKPASS, no sshpass needed.
printf '#!/bin/sh\necho "%s"\n' "$password" > "$work/askpass" && chmod +x "$work/askpass"
export SSH_ASKPASS="$work/askpass" SSH_ASKPASS_REQUIRE=force DISPLAY=:0
ssh_options=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no
    -o PreferredAuthentications=password -o ConnectTimeout=10)

echo "e2e payload $$" > "$work/up.txt"
for _ in $(seq 1 30); do
    if sftp -q -P 2222 "${ssh_options[@]}" alice@127.0.0.1 >/dev/null 2>&1 <<SFTP
put $work/up.txt up.txt
get up.txt $work/down.txt
SFTP
    then uploaded=1; break; fi
    sleep 2
done
[ "${uploaded:-0}" = 1 ] || { echo "no SFTP login through HAProxy"; exit 1; }
cmp "$work/up.txt" "$work/down.txt"
"${compose[@]}" exec -T node-b test -f /data/files/alice/up.txt
echo "sftp upload and download through HAProxy ok"

# Several logins: HAProxy (leastconn) gives them to both nodes, once its health checks have both nodes up.
served=""
for i in $(seq 1 40); do
    sftp -q -P 2222 "${ssh_options[@]}" alice@127.0.0.1 >/dev/null 2>&1 <<SFTP || true
get up.txt $work/again-$i.txt
SFTP
    served=""
    for node in node-a node-b; do
        log="$("${compose[@]}" logs --no-color "$node" 2>&1)"
        grep -q "LoginOk user alice" <<<"$log" && served="$served $node"
    done
    [ "$served" = " node-a node-b" ] && break
    sleep 1
done
[ "$served" = " node-a node-b" ] || { echo "not both nodes served a login of alice (only:$served)"; exit 1; }
echo "both nodes served logins"

# An open session on one node is listed by the other nodes too (the Connections table), with the client address of the
# PROXY header and not the address of HAProxy (172.28.0.10): GET /api/v1/connections through HAProxy, on either node.
token="$(curl -fsS -X POST http://127.0.0.1:8080/api/v1/token -H 'Content-Type: application/json' \
    -d "{\"username\":\"admin\",\"password\":\"$admin_password\"}" | sed -n 's/.*"accessToken":"\([^"]*\)".*/\1/p')"
[ -n "$token" ] || { echo "no API token"; exit 1; }
mkfifo "$work/session"
sftp -q -P 2222 "${ssh_options[@]}" alice@127.0.0.1 <"$work/session" >/dev/null 2>&1 &
session=$!
exec 3>"$work/session"
for _ in $(seq 1 30); do
    connections="$(curl -fsS http://127.0.0.1:8080/api/v1/connections -H "Authorization: Bearer $token" || true)"
    if grep -q '"alice"' <<<"$connections"; then listed=1; break; fi
    sleep 1
done
echo "bye" >&3
exec 3>&-
wait "$session" || true
[ "${listed:-0}" = 1 ] || { echo "the open session is not in GET /api/v1/connections: $connections"; exit 1; }
if grep -q '172\.28\.0\.10:' <<<"$connections"; then echo "a node has the address of HAProxy instead of the client: $connections"; exit 1; fi
echo "the open session is listed with the client address"

# No node logged an error or a fatal error (for example a failed start that the restart policy hid).
for node in node-a node-b; do
    log="$("${compose[@]}" logs --no-color "$node" 2>&1)"
    if grep -E "\[[0-9:]+ (ERR|FTL)\]|Unhandled exception" <<<"$log"; then echo "$node logged an error"; exit 1; fi
    restarts="$(docker inspect -f '{{.RestartCount}}' "$("${compose[@]}" ps -q "$node")")"
    [ "$restarts" = 0 ] || { echo "$node restarted $restarts time(s)"; exit 1; }
done
echo "no errors in the node logs"

echo "cluster e2e ok"
