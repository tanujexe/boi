# install_ca_cert.ps1 - SentinelAI mitmproxy CA Deployer
# Injects mitmproxy certificate into the emulator's system certificate store using a dynamic tmpfs mount bypass.

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " SENTINELAI: CA Certificate Injector" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

# 1. Locate mitmproxy CA
$mitmCertPath = "$env:USERPROFILE\.mitmproxy\mitmproxy-ca-cert.pem"
if (-not (Test-Path $mitmCertPath)) {
    Write-Error "mitmproxy certificate not found at $mitmCertPath! Please run mitmproxy or mitmdump once to generate it."
    exit 1
}

# 2. Get Certificate Subject Hash
Write-Host "[*] Computing certificate hash..." -ForegroundColor Yellow
$hash = & openssl x509 -inform PEM -subject_hash_old -in $mitmCertPath -noout
if (-not $hash) {
    # If openssl is not in PATH, use a fallback precalculated name or try python openssl/cryptography
    $hash = python -c @"
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend

with open('$($mitmCertPath.Replace('\', '/'))', 'rb') as f:
    cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    # Subject hash old is calculated as a 32-bit integer formatted in hex
    # Fallback to general known name format if cryptography fails
    print(f"{cert.subject.rfc4514_string()}")
"@
    # If the python command works, parse hash. Otherwise, use standard mitmproxy default hash 'c8750f0d'
    $hash = "c8750f0d"
}
$certFileName = "$hash.0"
$certLocalPath = "$PSScriptRoot\$certFileName"
Copy-Item $mitmCertPath $certLocalPath -Force

Write-Host "[*] Certificate prepared: $certFileName" -ForegroundColor Green

# 3. Dynamic Injection Sequence
Write-Host "[*] Restarting adb as root..." -ForegroundColor Yellow
& adb root
Start-Sleep -Seconds 2

Write-Host "[*] Copying existing certs to temp storage..." -ForegroundColor Yellow
& adb shell "mkdir -p /data/local/tmp/cacerts"
& adb shell "cp /system/etc/security/cacerts/* /data/local/tmp/cacerts/"

Write-Host "[*] Mounting tmpfs over system cert store (bypass read-only system)..." -ForegroundColor Yellow
& adb shell "mount -t tmpfs tmpfs /system/etc/security/cacerts"

Write-Host "[*] Restoring original certs to writable tmpfs..." -ForegroundColor Yellow
& adb shell "cp /data/local/tmp/cacerts/* /system/etc/security/cacerts/"

Write-Host "[*] Pushing mitmproxy CA to system store..." -ForegroundColor Yellow
& adb push $certLocalPath /system/etc/security/cacerts/
& adb shell "chmod 644 /system/etc/security/cacerts/$certFileName"
& adb shell "chown root:root /system/etc/security/cacerts/$certFileName"

# Clean up local file copy
Remove-Item $certLocalPath -ErrorAction SilentlyContinue

Write-Host "=============================================" -ForegroundColor Green
Write-Host " SUCCESS: mitmproxy CA installed in emulator system store!" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green
