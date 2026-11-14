#!/bin/bash
# Container health check: GET /healthz of the web host (the image has no curl). Exit 0 when it answers 200.
port="${HEALTHCHECK_PORT:-80}"
exec 3<>"/dev/tcp/127.0.0.1/${port}" || exit 1
printf 'GET /healthz HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n' >&3
read -r -t 4 _ status _ <&3
[ "$status" = "200" ]
