import subprocess
import time
import random
from v2.config import ADB_PATH

def grant_app_permissions(package_name: str):
    """Automatically grant critical permissions to the target app via ADB."""
    permissions = [
        "android.permission.READ_PHONE_STATE",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION"
    ]
    print(f"[Automation] Granting security permissions to: {package_name}")
    for perm in permissions:
        try:
            subprocess.run([ADB_PATH, "shell", "pm", "grant", package_name, perm], capture_output=True)
            # Randomized delay between grants to avoid sandbox fingerprinting.
            # Malware checks if all permissions were granted within <1s (sandbox indicator).
            time.sleep(random.uniform(0.3, 1.2))
        except Exception:
            pass

    # Allow overlay drawing permission via AppOps
    try:
        subprocess.run([ADB_PATH, "shell", "appops", "set", package_name, "SYSTEM_ALERT_WINDOW", "allow"], capture_output=True)
    except Exception:
        pass

def force_enable_accessibility(package_name: str):
    """Enables accessibility services for the package using secure settings."""
    try:
        # Fetch accessibility services list to find target service name
        res = subprocess.run([ADB_PATH, "shell", "pm", "list", "services", package_name], capture_output=True, text=True)
        services = []
        for line in res.stdout.splitlines():
            if "accessibility" in line.lower() or "service" in line.lower():
                parts = line.split(":")[-1].strip()
                if "/" in parts:
                    services.append(parts)
                    
        if not services:
            # Try to query services mapping
            res_query = subprocess.run([ADB_PATH, "shell", "dumpsys", "accessibility"], capture_output=True, text=True)
            for line in res_query.stdout.splitlines():
                if package_name in line and "/" in line:
                    parts = line.strip().split()
                    for p in parts:
                        if package_name in p and "/" in p:
                            services.append(p)
                            break
                            
        # If any found, enable them via secure settings writes
        if services:
            active_service = services[0]
            print(f"[Automation] Activating Accessibility Service: {active_service}")
            subprocess.run([ADB_PATH, "shell", "settings", "put", "secure", "enabled_accessibility_services", active_service], capture_output=True)
            subprocess.run([ADB_PATH, "shell", "settings", "put", "secure", "accessibility_enabled", "1"], capture_output=True)
    except Exception as e:
        print("[Automation] Failed to force accessibility settings: ", e)

def trigger_deep_links(package_name: str, urls: list):
    """Triggers custom deep link browser intent sequences to exercise url routing handlers."""
    print(f"[Automation] Sending intent URL callbacks to app...")
    for url in urls[:5]:
        if url.startswith("http"):
            try:
                subprocess.run([
                    ADB_PATH, "shell", "am", "start", 
                    "-a", "android.intent.action.VIEW", 
                    "-d", url, 
                    package_name
                ], capture_output=True, timeout=5)
                time.sleep(1)
            except Exception:
                pass

def automate_ui_interactions(package_name: str):
    """Traverses UI inputs and dialogs using UI automaton exercises."""
    print(f"[Automation] Exercising package: {package_name}")
    # 1. Dismiss initial permissions request dialogs by clicking standard coordinates or keys
    # Keycode 61: Tab, Keycode 66: Enter, Keycode 4: Back
    for _ in range(3):
        subprocess.run([ADB_PATH, "shell", "input", "keyevent", "66"], capture_output=True)
        time.sleep(random.uniform(0.4, 0.8))  # Human-like variable delay

    # 2. Trigger random activity layout focus moves
    for _ in range(5):
        subprocess.run([ADB_PATH, "shell", "input", "keyevent", "61"], capture_output=True)
        time.sleep(random.uniform(0.2, 0.5))
        
    # 3. Input dummy characters into focused text input boxes
    subprocess.run([ADB_PATH, "shell", "input", "text", "admin@sentinel.sec"], capture_output=True)
    time.sleep(random.uniform(0.4, 0.8))
    subprocess.run([ADB_PATH, "shell", "input", "keyevent", "66"], capture_output=True)
    
    # 4. Trigger UI Monkey interactions sequence
    subprocess.run([
        ADB_PATH, "shell", "monkey", 
        "-p", package_name, 
        "--pct-touch", "70", 
        "--pct-motion", "20", 
        "--pct-nav", "10", 
        "15"
    ], capture_output=True)
