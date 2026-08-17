#!/bin/bash
set -e

echo "=== Starting E2E Tests ==="

# Wait for systemd to fully boot
sleep 5

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
# Move valid cert, create an expired one
mv /etc/nginx/ssl/nginx.crt /etc/nginx/ssl/nginx.crt.bak
python3 -c "
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
now = datetime.datetime.now(datetime.timezone.utc)
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=10))
        .not_valid_after(now - datetime.timedelta(days=1))
        .sign(key, hashes.SHA256()))
open('/etc/nginx/ssl/nginx.crt','wb').write(cert.public_bytes(serialization.Encoding.PEM))
open('/etc/nginx/ssl/nginx.key.tmp','wb').write(key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))
"
setfacl -m g:evidencetool:r /etc/nginx/ssl/nginx.crt
OUT=$(eval $DIAGNOSE_CMD) || true
# Restore
mv /etc/nginx/ssl/nginx.crt.bak /etc/nginx/ssl/nginx.crt
rm -f /etc/nginx/ssl/nginx.key.tmp
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
