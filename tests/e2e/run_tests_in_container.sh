#!/bin/bash
set -e

echo "=== Starting Full Operational E2E Test Suite (All Providers) ==="

# Wait for systemd to fully boot
sleep 5

# Re-apply ACLs at runtime for least-privilege evidencetool user
setfacl -m g:evidencetool:r /etc/nginx/ssl/nginx.key
setfacl -m g:evidencetool:r /etc/nginx/ssl/nginx.crt
setfacl -m d:g:evidencetool:r /etc/nginx/ssl

PYTHON="/opt/EvidenceTool/.venv/bin/python3"
BASE_DIAGNOSE="sudo -u evidencetool PYTHONPATH=/opt/EvidenceTool/src /opt/EvidenceTool/.venv/bin/python3 -m evidencetool.cli.main diagnose"

check_result() {
    local out="$1"
    local expected_status="$2"
    local expected_situation="$3"
    
    local status
    local reason

    status=$($PYTHON -c "import sys, json; d=json.loads(sys.argv[1]); print(d.get('decision',{}).get('status',''))" "$out" 2>/dev/null || true)
    reason=$($PYTHON -c "import sys, json; d=json.loads(sys.argv[1]); print(d.get('decision',{}).get('reason',''))" "$out" 2>/dev/null || true)

    if [ "$status" != "$expected_status" ]; then
        echo "FAIL: Expected status $expected_status, got $status"
        echo "Output: $out"
        exit 1
    fi
    
    if [ -n "$expected_situation" ] && [[ ! "$reason" == *"$expected_situation"* ]]; then
        echo "FAIL: Expected situation $expected_situation not found in reason: $reason"
        echo "Output: $out"
        exit 1
    fi
    echo "  -> PASS: Status=$status ($expected_situation)"
}

# =========================================================================
# 1. NGINX PROVIDER E2E
# =========================================================================
echo ">>> [1/6] NGINX PROVIDER E2E <<<"

echo "Scenario 1.1: Invalid syntax in nginx.conf (NGINX_CONFIG_INVALID)"
echo "invalid_directive_syntax_error;" >> /etc/nginx/nginx.conf
OUT=$($BASE_DIAGNOSE nginx --catalog /opt/EvidenceTool/catalogs/nginx.yaml -a config_path=/etc/nginx/nginx.conf -a certificate_path=/etc/nginx/ssl/nginx.crt -a private_key_path=/etc/nginx/ssl/nginx.key -a service=nginx --output json) || true
sed -i '$d' /etc/nginx/nginx.conf
check_result "$OUT" "BLOCK" "NGINX_CONFIG_INVALID"

# =========================================================================
# 2. TLS PROVIDER E2E
# =========================================================================
echo ">>> [2/6] TLS PROVIDER E2E <<<"

echo "Scenario 2.1: Expired Certificate (TLS_CERTIFICATE_EXPIRED)"
mv /etc/nginx/ssl/nginx.crt /etc/nginx/ssl/nginx.crt.bak
$PYTHON -c "
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import NameOID

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
chown root:evidencetool /etc/nginx/ssl/nginx.crt && chmod 644 /etc/nginx/ssl/nginx.crt
OUT=$($BASE_DIAGNOSE nginx --catalog /opt/EvidenceTool/catalogs/nginx.yaml -a config_path=/etc/nginx/nginx.conf -a certificate_path=/etc/nginx/ssl/nginx.crt -a private_key_path=/etc/nginx/ssl/nginx.key -a service=nginx --output json) || true
mv /etc/nginx/ssl/nginx.crt.bak /etc/nginx/ssl/nginx.crt
check_result "$OUT" "BLOCK" "TLS_CERTIFICATE_EXPIRED"

echo "Scenario 2.2: Missing Certificate (TLS_CERTIFICATE_MISSING)"
mv /etc/nginx/ssl/nginx.crt /etc/nginx/ssl/nginx.crt.bak
OUT=$($BASE_DIAGNOSE nginx --catalog /opt/EvidenceTool/catalogs/nginx.yaml -a config_path=/etc/nginx/nginx.conf -a certificate_path=/etc/nginx/ssl/nginx.crt -a private_key_path=/etc/nginx/ssl/nginx.key -a service=nginx --output json) || true
mv /etc/nginx/ssl/nginx.crt.bak /etc/nginx/ssl/nginx.crt
check_result "$OUT" "BLOCK" "TLS_CERTIFICATE_MISSING"

echo "Scenario 2.3: Key Mismatch (TLS_KEY_MISMATCH)"
mv /etc/nginx/ssl/nginx.key /etc/nginx/ssl/nginx.key.bak
openssl genrsa -out /etc/nginx/ssl/nginx.key 2048 2>/dev/null
setfacl -m g:evidencetool:r /etc/nginx/ssl/nginx.key
OUT=$($BASE_DIAGNOSE nginx --catalog /opt/EvidenceTool/catalogs/nginx.yaml -a config_path=/etc/nginx/nginx.conf -a certificate_path=/etc/nginx/ssl/nginx.crt -a private_key_path=/etc/nginx/ssl/nginx.key -a service=nginx --output json) || true
mv /etc/nginx/ssl/nginx.key.bak /etc/nginx/ssl/nginx.key
check_result "$OUT" "BLOCK" "TLS_KEY_MISMATCH"

# =========================================================================
# 3. SYSTEMD PROVIDER E2E
# =========================================================================
echo ">>> [3/6] SYSTEMD PROVIDER E2E <<<"

echo "Scenario 3.1: Service Stopped (NGINX_SERVICE_DOWN)"
systemctl stop nginx
OUT=$($BASE_DIAGNOSE nginx --catalog /opt/EvidenceTool/catalogs/nginx.yaml -a config_path=/etc/nginx/nginx.conf -a certificate_path=/etc/nginx/ssl/nginx.crt -a private_key_path=/etc/nginx/ssl/nginx.key -a service=nginx --output json) || true
systemctl start nginx
check_result "$OUT" "ALLOW" "NGINX_SERVICE_DOWN"

echo "Scenario 3.2: Service Not Installed (NGINX_SERVICE_NOT_INSTALLED)"
OUT=$($BASE_DIAGNOSE nginx --catalog /opt/EvidenceTool/catalogs/nginx.yaml -a config_path=/etc/nginx/nginx.conf -a certificate_path=/etc/nginx/ssl/nginx.crt -a private_key_path=/etc/nginx/ssl/nginx.key -a service=nonexistent_dummy_service --output json) || true
check_result "$OUT" "BLOCK" "NGINX_SERVICE_NOT_INSTALLED"

# =========================================================================
# 4. FILESYSTEM PROVIDER E2E
# =========================================================================
echo ">>> [4/6] FILESYSTEM PROVIDER E2E <<<"

echo "Scenario 4.1: Disk Space Available (Normal)"
OUT=$($BASE_DIAGNOSE nginx --catalog /opt/EvidenceTool/catalogs/nginx.yaml -a config_path=/etc/nginx/nginx.conf -a certificate_path=/etc/nginx/ssl/nginx.crt -a private_key_path=/etc/nginx/ssl/nginx.key -a service=nginx -a path=/ -a min_free_bytes=1048576 --output json) || true
# Check that filesystem evidence is PASS
FS_STATUS=$($PYTHON -c "import sys, json; d=json.loads(sys.argv[1]); print(next(e['status'] for e in d.get('evidence',[]) if e['id']=='filesystem.disk_space_available'))" "$OUT")
if [ "$FS_STATUS" != "PASS" ]; then
    echo "FAIL: Expected filesystem.disk_space_available=PASS, got $FS_STATUS"
    exit 1
fi
echo "  -> PASS: filesystem.disk_space_available=PASS"

echo "Scenario 4.2: Disk Pressure / Full Threshold Exceeded (DISK_PRESSURE / DISK_FULL)"
OUT=$($BASE_DIAGNOSE nginx --catalog /opt/EvidenceTool/catalogs/nginx.yaml -a config_path=/etc/nginx/nginx.conf -a certificate_path=/etc/nginx/ssl/nginx.crt -a private_key_path=/etc/nginx/ssl/nginx.key -a service=nginx -a path=/ -a min_free_bytes=999999999999999 --output json) || true
check_result "$OUT" "BLOCK" "DISK_FULL"

# =========================================================================
# 5. NETWORK PROVIDER E2E
# =========================================================================
echo ">>> [5/6] NETWORK PROVIDER E2E <<<"

echo "Scenario 5.1: Real Port Reachable (Nginx HTTPS port 443)"
OUT=$($BASE_DIAGNOSE nginx --catalog /opt/EvidenceTool/catalogs/system.yaml --policy /opt/EvidenceTool/policies/nginx.yaml -a target_host=127.0.0.1 -a port=443 --output json) || true
PORT_STATUS=$($PYTHON -c "import sys, json; d=json.loads(sys.argv[1]); print(next(e['status'] for e in d.get('evidence',[]) if e['id']=='network.port_reachable'))" "$OUT")
if [ "$PORT_STATUS" != "PASS" ]; then
    echo "FAIL: Expected network.port_reachable=PASS on active port 443, got $PORT_STATUS"
    exit 1
fi
echo "  -> PASS: network.port_reachable=PASS (port 443)"

echo "Scenario 5.2: Closed Port Unreachable (port 59999)"
OUT=$($BASE_DIAGNOSE nginx --catalog /opt/EvidenceTool/catalogs/system.yaml --policy /opt/EvidenceTool/policies/nginx.yaml -a target_host=127.0.0.1 -a port=59999 --output json) || true
PORT_CLOSED_STATUS=$($PYTHON -c "import sys, json; d=json.loads(sys.argv[1]); print(next(e['status'] for e in d.get('evidence',[]) if e['id']=='network.port_reachable'))" "$OUT")
if [ "$PORT_CLOSED_STATUS" != "FAIL" ]; then
    echo "FAIL: Expected network.port_reachable=FAIL on closed port 59999, got $PORT_CLOSED_STATUS"
    exit 1
fi
echo "  -> PASS: network.port_reachable=FAIL (port 59999 closed)"

echo "Scenario 5.3: Unroutable / Dead Host (NETWORK_UNREACHABLE)"
OUT=$($BASE_DIAGNOSE nginx --catalog /opt/EvidenceTool/catalogs/system.yaml --policy /opt/EvidenceTool/policies/nginx.yaml -a target_host=192.0.2.1 -a port=80 --output json) || true
HOST_STATUS=$($PYTHON -c "import sys, json; d=json.loads(sys.argv[1]); print(next(e['status'] for e in d.get('evidence',[]) if e['id']=='network.host_reachable'))" "$OUT")
if [ "$HOST_STATUS" != "FAIL" ]; then
    echo "FAIL: Expected network.host_reachable=FAIL on unreachable IP 192.0.2.1, got $HOST_STATUS"
    exit 1
fi
echo "  -> PASS: network.host_reachable=FAIL (192.0.2.1 unreachable)"

# =========================================================================
# 6. PROCESS PROVIDER E2E
# =========================================================================
echo ">>> [6/6] PROCESS PROVIDER E2E <<<"

echo "Scenario 6.1: Active Running Process (nginx master/worker)"
OUT=$($BASE_DIAGNOSE nginx --catalog /opt/EvidenceTool/catalogs/system.yaml --policy /opt/EvidenceTool/policies/nginx.yaml -a process=nginx --output json) || true
PROC_STATUS=$($PYTHON -c "import sys, json; d=json.loads(sys.argv[1]); print(next(e['status'] for e in d.get('evidence',[]) if e['id']=='process.running'))" "$OUT")
PIDS=$($PYTHON -c "import sys, json; d=json.loads(sys.argv[1]); print(next(e['observation']['value']['pids'] for e in d.get('evidence',[]) if e['id']=='process.running'))" "$OUT")
if [ "$PROC_STATUS" != "PASS" ]; then
    echo "FAIL: Expected process.running=PASS for nginx, got $PROC_STATUS"
    exit 1
fi
echo "  -> PASS: process.running=PASS (PIDs: $PIDS)"

echo "Scenario 6.2: Non-Existent Process (fake_daemon_process)"
OUT=$($BASE_DIAGNOSE nginx --catalog /opt/EvidenceTool/catalogs/system.yaml --policy /opt/EvidenceTool/policies/nginx.yaml -a process=fake_daemon_process --output json) || true
PROC_MISSING_STATUS=$($PYTHON -c "import sys, json; d=json.loads(sys.argv[1]); print(next(e['status'] for e in d.get('evidence',[]) if e['id']=='process.running'))" "$OUT")
if [ "$PROC_MISSING_STATUS" != "FAIL" ]; then
    echo "FAIL: Expected process.running=FAIL for fake_daemon_process, got $PROC_MISSING_STATUS"
    exit 1
fi
echo "  -> PASS: process.running=FAIL (process absent)"

echo "Scenario 6.3: Real Zombie Process Detection in Linux Process Table"
# Spawn a real zombie process: parent forks child that exits, while parent sleeps 10s without wait()
$PYTHON -c "
import os, time, sys
pid = os.fork()
if pid == 0:
    # Child exits immediately to become a zombie
    sys.exit(0)
else:
    # Parent sleeps, keeping child in zombie state in OS process table
    time.sleep(8)
" &
ZOMBIE_PARENT_PID=$!
sleep 1

# Check if process provider detects the zombie state
OUT=$($BASE_DIAGNOSE nginx --catalog /opt/EvidenceTool/catalogs/system.yaml --policy /opt/EvidenceTool/policies/nginx.yaml -a process=python3 --output json) || true
ZOMBIE_STATUS=$($PYTHON -c "import sys, json; d=json.loads(sys.argv[1]); print(next(e['status'] for e in d.get('evidence',[]) if e['id']=='process.zombie'))" "$OUT")

kill -9 $ZOMBIE_PARENT_PID 2>/dev/null || true
wait $ZOMBIE_PARENT_PID 2>/dev/null || true

if [ "$ZOMBIE_STATUS" != "FAIL" ]; then
    echo "FAIL: Expected process.zombie=FAIL when zombie process exists, got $ZOMBIE_STATUS"
    exit 1
fi
echo "  -> PASS: process.zombie=FAIL (real OS zombie successfully caught)"

echo "=== All Operational E2E Tests for All Providers Passed Successfully! ==="
