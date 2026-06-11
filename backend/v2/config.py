import os

# Base Directories
V2_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.dirname(V2_DIR)
PROJECT_ROOT = os.path.dirname(BACKEND_DIR)

# AVD Settings
EMULATOR_AVD_NAME = os.environ.get("SENTINEL_AVD_NAME", "sentinel_sandbox")
ANALYSIS_TIMEOUT = int(os.environ.get("SENTINEL_TIMEOUT", "180"))
MITMPROXY_PORT = int(os.environ.get("SENTINEL_MITMPROXY_PORT", "8080"))

# Upload Directory
UPLOAD_DIR = os.path.join(BACKEND_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Frida Settings
FRIDA_SCRIPT_PATH = os.path.join(PROJECT_ROOT, "sandbox", "frida_scripts", "hook_all.js")

# Database Path
DB_PATH = os.path.join(BACKEND_DIR, "sentinel_v2.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"

# Android SDK Path Detection
android_home = os.environ.get("ANDROID_HOME")
if not android_home:
    # Try common Windows path
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    if local_app_data:
        default_sdk = os.path.join(local_app_data, "Android", "Sdk")
        if os.path.exists(default_sdk):
            android_home = default_sdk

ADB_PATH = "adb"
EMULATOR_PATH = "emulator"

if android_home:
    potential_adb = os.path.join(android_home, "platform-tools", "adb.exe")
    if os.path.exists(potential_adb):
        ADB_PATH = potential_adb
    
    potential_emu = os.path.join(android_home, "emulator", "emulator.exe")
    if os.path.exists(potential_emu):
        EMULATOR_PATH = potential_emu
