import os
import zipfile

def create_test_files():
    target_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_apks")
    os.makedirs(target_dir, exist_ok=True)
    
    print(f"[*] Creating test files inside: {target_dir}")
    
    # Case 1: simulated_anubis.apk (triggers Anubis simulation)
    anubis_path = os.path.join(target_dir, "simulated_anubis.apk")
    with open(anubis_path, "w") as f:
        f.write("Simulated Anubis Banking Trojan Trigger File")
    print(f"[+] Created: {os.path.basename(anubis_path)}")

    # Case 2: simulated_sharkbot.apk (triggers SharkBot simulation)
    shark_path = os.path.join(target_dir, "simulated_sharkbot.apk")
    with open(shark_path, "w") as f:
        f.write("Simulated SharkBot Trojan Trigger File")
    print(f"[+] Created: {os.path.basename(shark_path)}")

    # Case 3: test_clean.apk (A valid ZIP archive representing a clean APK structure)
    clean_path = os.path.join(target_dir, "test_clean.apk")
    with zipfile.ZipFile(clean_path, "w") as zf:
        # Add a mock AndroidManifest.xml
        manifest_data = (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.clean.utility">\n'
            '    <uses-permission android:name="android.permission.INTERNET" />\n'
            '    <application>\n'
            '        <activity android:name=".MainActivity">\n'
            '            <intent-filter>\n'
            '                <action android:name="android.intent.action.MAIN" />\n'
            '                <category android:name="android.intent.category.LAUNCHER" />\n'
            '            </intent-filter>\n'
            '        </activity>\n'
            '    </application>\n'
            '</manifest>'
        )
        zf.writestr("AndroidManifest.xml", manifest_data)
        zf.writestr("classes.dex", "base64 classes dex dummy text data")
    print(f"[+] Created: {os.path.basename(clean_path)}")
    
    print("\n[+] All test files successfully compiled.")

if __name__ == "__main__":
    create_test_files()
