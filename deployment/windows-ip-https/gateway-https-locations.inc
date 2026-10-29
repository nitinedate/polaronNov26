location ^~ /.well-known/acme-challenge/ {
    root /var/www/certbot;
    default_type text/plain;
    try_files $uri =404;
}

location = /health {
    set $api_upstream http://vuln-api:8080;
    include /etc/nginx/conf.d/gateway-proxy.inc;
}

location /api/acquisition/ {
    set $api_upstream $hdr_upstream;
    include /etc/nginx/conf.d/gateway-proxy.inc;
}

# Mobile Malware Detection: its own product API, selected by path.
location /api/malware/ {
    set $api_upstream http://malware-api:8080;
    include /etc/nginx/conf.d/gateway-proxy.inc;
    error_page 502 = @malware_unreachable;
}
location @malware_unreachable {
    default_type application/json;
    add_header Cache-Control "no-store" always;
    return 502 '{"error":{"code":"service_unreachable","service":"mobile-malware","message":"Malware Detection is not reachable: the malware-api container is stopped, still starting, or failed to start. Run scripts/check-malware-stack.ps1 to see why."}}';
}

location /api/vuln/ { set $api_upstream http://vuln-api:8080; include /etc/nginx/conf.d/gateway-proxy.inc; }
location /api/scanners { set $api_upstream http://vuln-api:8080; include /etc/nginx/conf.d/gateway-proxy.inc; }
location /api/scanner-agent/ { set $api_upstream http://vuln-api:8080; include /etc/nginx/conf.d/gateway-proxy.inc; }
location /api/scan-jobs { set $api_upstream http://vuln-api:8080; include /etc/nginx/conf.d/gateway-proxy.inc; }
location /api/scan-policies { set $api_upstream http://vuln-api:8080; include /etc/nginx/conf.d/gateway-proxy.inc; }
location /api/assets { set $api_upstream http://vuln-api:8080; include /etc/nginx/conf.d/gateway-proxy.inc; }
location /api/remediation-tasks { set $api_upstream http://vuln-api:8080; include /etc/nginx/conf.d/gateway-proxy.inc; }

location /api/ {
    set $api_upstream $hdr_upstream;
    include /etc/nginx/conf.d/gateway-proxy.inc;
}

location /assets/ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    try_files $uri =404;
}

location / {
    add_header Cache-Control "no-store, no-cache, must-revalidate";
    expires -1;
    try_files $uri $uri/ /index.html;
}
