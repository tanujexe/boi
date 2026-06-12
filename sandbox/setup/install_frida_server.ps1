# install_frida_server.ps1 - SentinelAI Frida Server Deployer
# Downloads and installs the correct frida-server inside the running emulator.

$fridaVersion = "16.2.1"
$arch = "android-x86_64"
$downloadUrl = "https://github.com/frida/frida/releases/download/$fridaVersion/frida-server-$fridaVersion-$arch.xz"
$tempXz = "$PSScriptRoot\frida-server.xz"
$tempBin = "$PSScriptRoot\frida-server"

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " SENTINELAI: Frida-Server Deployer" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

# 1. Check ADB connection
$devices = & adb devices | Select-String -Pattern "device\b"
if (-not $devices) {
    Write-Error "No running Android emulator detected! Start your emulator first."
    exit 1
}

Write-Host "[*] Connected emulator detected: $($devices[0])" -ForegroundColor Green

# 2. Download frida-server archive
Write-Host "[*] Downloading frida-server $fridaVersion for $arch..." -ForegroundColor Yellow
Invoke-WebRequest -Uri $downloadUrl -OutFile $tempXz

# 3. Extract xz archive (using .NET framework or 7zip if available, or python if available)
Write-Host "[*] Extracting frida-server..." -ForegroundColor Yellow
if (Get-Command tar -ErrorAction SilentlyContinue) {
    # Windows 10/11 tar command can extract xz
    & tar -xf $tempXz -C $PSScriptRoot
    # Rename matching file to frida-server
    $extracted = Get-ChildItem "$PSScriptRoot\frida-server-*" | Select-Object -First 1
    if ($extracted) {
        Rename-Item $extracted.FullName "frida-server" -Force
    }
} else {
    # Fallback to python extraction if tar is missing
    python -c @"
import lzma
with lzma.open('$tempXz', 'rb') as f_in:
    with open('$tempBin', 'wb') as f_out:
        f_out.write(f_in.read())
"@
}

if (-not (Test-Path $tempBin)) {
    Write-Error "Extraction failed. Please extract $tempXz manually to $tempBin"
    exit 1
}

# 4. Push and set permissions
Write-Host "[*] Pushing frida-server to emulator /data/local/tmp/..." -ForegroundColor Yellow
& adb push $tempBin /data/local/tmp/frida-server
& adb shell chmod 755 /data/local/tmp/frida-server

# 5. Clean up temporary files
Write-Host "[*] Cleaning up download cache..." -ForegroundColor Yellow
Remove-Item $tempXz -ErrorAction SilentlyContinue
Remove-Item $tempBin -ErrorAction SilentlyContinue

Write-Host "=============================================" -ForegroundColor Green
Write-Host " SUCCESS: frida-server deployed to emulator!" -ForegroundColor Green
Write-Host " Start the server with:" -ForegroundColor Yellow
Write-Host " adb shell /data/local/tmp/frida-server &" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Green
