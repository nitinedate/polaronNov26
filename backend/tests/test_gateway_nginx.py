from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def test_gateway_nginx_routes_three_backends():
    conf = (REPO / "frontend" / "nginx-gateway.conf").read_text(encoding="utf-8")
    assert "forensic-api:8080" in conf
    assert "android-api:8080" in conf
    assert "vuln-api:8080" in conf
    assert "location /api/acquisition/" in conf
    assert "location /api/vuln/" in conf
    assert "X-Aetheris-Service" in (REPO / "frontend" / "gateway-proxy.inc").read_text(encoding="utf-8")


def test_gateway_compose_is_single_ui():
    yml = (REPO / "services" / "gateway" / "docker-compose.yml").read_text(encoding="utf-8")
    assert "VITE_AETHERIS_SERVICE: unified" in yml
    assert '"3000:80"' in yml


def test_gateway_uses_private_docker_network_aliases():
    conf = Path("frontend/nginx-gateway.conf").read_text()
    assert "forensic-api:8080" in conf
    assert "ios-api:8080" in conf
    assert "host.docker.internal:8083" not in conf


def test_gateway_and_product_apis_share_private_network():
    gateway = (REPO / "services" / "gateway" / "docker-compose.yml").read_text(encoding="utf-8")
    forensic = (REPO / "docker-compose.yml").read_text(encoding="utf-8")
    android = (REPO / "services" / "mobile-android" / "docker-compose.yml").read_text(encoding="utf-8")
    ios = (REPO / "services" / "mobile-ios" / "docker-compose.yml").read_text(encoding="utf-8")
    vuln = (REPO / "services" / "vuln" / "docker-compose.yml").read_text(encoding="utf-8")
    assert "aetheris-common" in gateway
    assert "forensic-api" in forensic
    assert "android-api" in android
    assert "ios-api" in ios
    assert "vuln-api" in vuln

def test_gateway_does_not_route_product_apis_through_windows_loopback():
    files = [
        REPO / "frontend" / "nginx-gateway.conf",
        REPO / "deployment" / "windows-ip-https" / "nginx.gateway.https.conf",
        REPO / "deployment" / "windows-ip-https" / "gateway-https-locations.inc",
    ]
    combined = "\n".join(p.read_text(encoding="utf-8") for p in files)
    for port in (8081, 8082, 8083, 8084):
        assert f"host.docker.internal:{port}" not in combined
