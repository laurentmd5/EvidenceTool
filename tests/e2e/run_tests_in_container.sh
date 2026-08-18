#!/bin/bash
set -e

echo "=== Starting E2E Tests ==="

# Wait for systemd to fully boot
sleep 5

# Re-apply ACLs at runtime. POSIX ACLs set during `docker build` (overlayfs layers)
# are notoriously stripped or ignored when the container starts depending on the host's
# kernel and docker storage driver. Since the README instructions are for runtime,
# we simulate them accurately here.
setfacl -m g:evidencetool:r /etc/nginx/ssl/nginx.key
setfacl -m g:evidencetool:r /etc/nginx/ssl/nginx.crt
setfacl -m d:g:evidencetool:r /etc/nginx/ssl

echo "=== Diagnostic Nginx Modules ==="
nginx -V 2>&1 | tr ' ' '\n' | grep prefix || true
ls -la /usr/share/nginx/modules || true
ls -la /etc/nginx/modules || true
nginx -t || true
nginx -t -p /etc/nginx || true
echo "================================="

PYTHON="/opt/EvidenceTool/.venv/bin/python3"
DIAGNOSE_CMD="sudo -u evidencetool /opt/EvidenceTool/.venv/bin/evidencetool diagnose nginx --policy /opt/EvidenceTool/policies/nginx-v2.yaml --catalog /opt/EvidenceTool/catalogs/nginx.yaml -a config_path=/etc/nginx/nginx.conf -a certificate_path=/etc/nginx/ssl/nginx.crt -a private_key_path=/etc/nginx/ssl/nginx.key -a service=nginx --output json"

check_result() {
    local out="$1"
    local expected_status="$2"
    local expected_situation="$3"
    
    local status=$(echo "$out" | jq -r '.decision.status')
    local reason=$(echo "$out" | jq -r '.decision.reason')
    
    if [ "$status" != "$expected_status" ]; then
        echo "FAIL: Expected status $expected_status, got $status"
        echo "Output: $out"
        exit 1
    fi
    
    if [[ ! "$reason" == *"$expected_situation"* ]]; then
        echo "FAIL: Expected situation $expected_situation not found in reason: $reason"
        echo "Output: $out"
        exit 1
    fi
    echo "PASS"
}

# --- Scenario A: Broken config ---
echo "Running Scenario A: NGINX_CONFIG_INVALID"
echo "invalid_directive;" >> /etc/nginx/nginx.conf
OUT=$(eval $DIAGNOSE_CMD) || true
sed -i '$d' /etc/nginx/nginx.conf
check_result "$OUT" "BLOCK" "NGINX_CONFIG_INVALID"

# --- Scenario B: Expired Certificate ---
echo "Running Scenario B: TLS_CERTIFICATE_EXPIRED"
# Replace only the cert with an expired one, signed by the EXISTING key so that
# tls.key_matches_certificate stays PASS and only tls.certificate_valid triggers FAIL.
mv /etc/nginx/ssl/nginx.crt /etc/nginx/ssl/nginx.crt.bak
$PYTHON -c "
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import NameOID

# Load the existing private key — cert must be signed with the SAME key
with open('/etc/nginx/ssl/nginx.key', 'rb') as f:
    key = load_pem_private_key(f.read(), password=None)

name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
now = datetime.datetime.now(datetime.timezone.utc)
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=10))
        .not_valid_after(now - datetime.timedelta(days=1))
        .sign(key, hashes.SHA256()))
open('/etc/nginx/ssl/nginx.crt', 'wb').write(cert.public_bytes(serialization.Encoding.PEM))
"
# Restore correct ownership so evidencetool can read the new cert
chown root:evidencetool /etc/nginx/ssl/nginx.crt && chmod 644 /etc/nginx/ssl/nginx.crt
OUT=$(eval $DIAGNOSE_CMD) || true
# Restore
mv /etc/nginx/ssl/nginx.crt.bak /etc/nginx/ssl/nginx.crt
check_result "$OUT" "BLOCK" "TLS_CERTIFICATE_EXPIRED"

# --- Scenario C: Missing Certificate ---
echo "Running Scenario C: TLS_CERTIFICATE_MISSING"
mv /etc/nginx/ssl/nginx.crt /etc/nginx/ssl/nginx.crt.bak
OUT=$(eval $DIAGNOSE_CMD) || true
mv /etc/nginx/ssl/nginx.crt.bak /etc/nginx/ssl/nginx.crt
check_result "$OUT" "BLOCK" "TLS_CERTIFICATE_MISSING"

# --- Scenario D: Service Stopped ---
echo "Running Scenario D: NGINX_SERVICE_DOWN"
systemctl stop nginx
OUT=$(eval $DIAGNOSE_CMD) || true
systemctl start nginx
check_result "$OUT" "ALLOW" "NGINX_SERVICE_DOWN"

echo "=== All E2E Tests Passed ==="
