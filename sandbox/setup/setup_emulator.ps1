# setup_emulator.ps1 - SentinelAI Android AVD Creator
# Installs API 30 Android image and sets up the sandbox emulator.

$avdName = "sentinel_sandbox"

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " SENTINELAI: Android AVD Setup Script (v2)" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

# 1. Path detection
$sdkPath = $env:ANDROID_HOME
if (-not $sdkPath) {
    $sdkPath = "$env:LOCALAPPDATA\Android\Sdk"
}

if (-not (Test-Path $sdkPath)) {
    Write-Error "Android SDK not found! Please set ANDROID_HOME environment variable or ensure SDK is at $sdkPath"
    exit 1
}

$sdkmanager = "$sdkPath\cmdline-tools\latest\bin\sdkmanager.bat"
if (-not (Test-Path $sdkmanager)) {
    $sdkmanager = Get-Command sdkmanager.bat -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
}

$avdmanager = "$sdkPath\cmdline-tools\latest\bin\avdmanager.bat"
if (-not (Test-Path $avdmanager)) {
    $avdmanager = Get-Command avdmanager.bat -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
}

if (-not $sdkmanager -or -not (Test-Path $sdkmanager)) {
    Write-Error "sdkmanager tool not found! Please install Command-line Tools in Android Studio."
    exit 1
}

# 2. Download System Image (API 30 Google APIs x86_64)
Write-Host "[*] Checking and downloading API 30 system image (Google APIs x86_64)..." -ForegroundColor Yellow
& $sdkmanager "system-images;android-30;google_apis;x86_64"

# 3. Create AVD
Write-Host "[*] Creating Android Virtual Device: $avdName..." -ForegroundColor Yellow
$avdExists = & $avdmanager list avd | Select-String -Pattern "Name: $avdName"

if ($avdExists) {
    Write-Host "[!] AVD '$avdName' already exists. Recreating to ensure clean state..." -ForegroundColor Cyan
    & $avdmanager delete avd -n $avdName
}

# Create new AVD with Pixel 5 hardware profile
& $avdmanager create avd -n $avdName -k "system-images;android-30;google_apis;x86_64" -d "pixel_5" --force

Write-Host "=============================================" -ForegroundColor Green
Write-Host " SUCCESS: Android Emulator '$avdName' Created!" -ForegroundColor Green
Write-Host " To start the emulator in writable-system mode (required for cert installation):" -ForegroundColor Yellow
Write-Host " emulator -avd $avdName -writable-system" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Green
