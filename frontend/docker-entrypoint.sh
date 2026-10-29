#!/bin/sh
set -e

# Do not block nginx on API health — uvicorn --reload can hang during shutdown and
# wget would wait forever, leaving :3000 with ERR_EMPTY_RESPONSE.
echo "[frontend] starting nginx (api readiness checked in background)..."

CONF=/etc/nginx/conf.d/default.conf
: "${AETHERIS_API_UPSTREAM:=http://api:8080}"
if grep -q "__AETHERIS_API_UPSTREAM__" "$CONF" 2>/dev/null; then
    sed -i "s#__AETHERIS_API_UPSTREAM__#${AETHERIS_API_UPSTREAM}#" "$CONF"
fi
if [ -n "${AETHERIS_MALWARE_UPSTREAM:-}" ]; then
    cat > /etc/nginx/conf.d/malware.inc <<EOF_INC
location /api/malware/ {
    set \$malware_upstream ${AETHERIS_MALWARE_UPSTREAM};
    proxy_pass \$malware_upstream;
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header Authorization \$http_authorization;
    proxy_set_header X-Tenant \$http_x_tenant;
    proxy_set_header X-Aetheris-Service mobile-malware;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_buffering off;
    proxy_read_timeout 1h;
    client_max_body_size 0;
    error_page 502 = @malware_unreachable;
}
location @malware_unreachable {
    default_type application/json;
    add_header Cache-Control "no-store" always;
    return 502 '{"error":{"code":"service_unreachable","service":"mobile-malware","message":"Malware Detection is not reachable from this UI: the malware-api container is stopped, still starting, or failed to start. Start it with scripts/start-stack.ps1 -Service mobile-malware."}}';
}
EOF_INC
else
    cat > /etc/nginx/conf.d/malware.inc <<'EOF_INC'
location /api/malware/ {
    default_type application/json;
    return 503 '{"error":{"code":"malware_not_connected","message":"Malware Detection is not connected to this UI (set AETHERIS_MALWARE_UPSTREAM)"}}';
}
EOF_INC
fi
API_HOST=$(echo "$AETHERIS_API_UPSTREAM" | sed -E 's#^https?://([^/:]+).*#\1#')

# When the api container is recreated it gets a new IP. Reload nginx so the
# static upstream re-resolves `api` (no per-request Docker DNS lookups).
watch_api_ip() {
    last_ip=""
    while true; do
        sleep 15
        if ! wget -q -T 5 -t 1 -O- "${AETHERIS_API_UPSTREAM}/health" >/dev/null 2>&1; then
            continue
        fi
        ip=$(getent ahostsv4 "$API_HOST" 2>/dev/null | awk '{print $1; exit}')
        if [ -n "$ip" ] && [ "$ip" != "$last_ip" ]; then
            echo "[frontend] api resolved to $ip — reloading nginx"
            nginx -s reload 2>/dev/null || true
            last_ip="$ip"
        fi
    done
}

watch_api_ip &

exec "$@"
