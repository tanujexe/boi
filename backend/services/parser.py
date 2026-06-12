import os
import re
import zipfile
import string
import subprocess
import shutil
import tempfile
import base64
import xml.etree.ElementTree as ET
from typing import Dict, Any, List

# Try to import Androguard safely with multi-version imports
try:
    from androguard.core.bytecoded.apk import APK
    HAS_ANDROGUARD = True
except ImportError:
    try:
        from androguard.core.apk import APK
        HAS_ANDROGUARD = True
    except ImportError:
        HAS_ANDROGUARD = False

# Regex definitions for static analysis
URL_PATTERN = re.compile(r"https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::\d+)?(?:/[^\s\"']*)?")
IP_PATTERN = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
BASE64_PATTERN = re.compile(r"[a-zA-Z0-9+/]{24,}={0,2}")

# Upgraded Structured Rules for Static Signature Matching
STATIC_RULES = [
    {
        "id": "ACCESSIBILITY_ABUSE",
        "category": "accessibility",
        "description": "AccessibilityService registration or performGlobalAction calls detected. Commonly abused by banking trojans for dynamic keylogging and overlay interface injection.",
        "patterns": [
            r"onAccessibilityEvent", r"performGlobalAction", r"AccessibilityService", 
            r"AccessibilityServiceInfo", r"accessibility_service_config"
        ],
        "severity": "High"
    },
    {
        "id": "OVERLAY_ATTACK",
        "category": "overlay",
        "description": "System Overlay alert layout creation detected. Commonly used for draw-over-app overlay phishing screens.",
        "patterns": [
            r"TYPE_APPLICATION_OVERLAY", r"TYPE_SYSTEM_ALERT", r"SYSTEM_ALERT_WINDOW",
            r"WindowManager\.LayoutParams", r"WindowManager;->addView"
        ],
        "severity": "High"
    },
    {
        "id": "REFLECTION_USAGE",
        "category": "obfuscation",
        "description": "Java Reflection dynamic methods lookup detected. Often used to hide sensitive system API interactions from static signature detectors.",
        "patterns": [
            r"Method\.invoke", r"Class\.forName", r"Method;->invoke", r"getDeclaredMethod"
        ],
        "severity": "Medium"
    },
    {
        "id": "DYNAMIC_LOADING",
        "category": "execution",
        "description": "Dynamic Dalvik bytecode loading detected. Allows executing unverified payloads (DEX/JAR) compiled or downloaded at runtime.",
        "patterns": [
            r"DexClassLoader", r"PathClassLoader", r"InMemoryDexClassLoader", r"DexFile\.loadDex"
        ],
        "severity": "High"
    },
    {
        "id": "PROCESS_CREATION",
        "category": "execution",
        "description": "Spawning native terminal command shell executors.",
        "patterns": [
            r"Runtime\.getRuntime\(\)\.exec", r"ProcessBuilder", r"/system/bin/sh", r"/system/bin/su"
        ],
        "severity": "Medium"
    },
    {
        "id": "EVASION_SANDBOX",
        "category": "evasion",
        "description": "Static indicators of emulator, root, or debugger environment checking.",
        "patterns": [
            r"Build\.FINGERPRINT", r"Build\.HARDWARE", r"Build\.PRODUCT", r"goldfish", 
            r"qemu", r"isDebuggerConnected", r"frida-server"
        ],
        "severity": "High"
    },
    {
        "id": "EMBEDDED_SECRETS",
        "category": "secrets",
        "description": "Hardcoded sensitive tokens, credentials, or API secret patterns.",
        "patterns": [
            r"xox[pbo]-[0-9]{12}", r"AIza[0-9A-Za-z-_]{35}", r"https://hooks\.slack\.com/services/",
            r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}", r"AWS_ACCESS_KEY_ID", r"AWS_SECRET_ACCESS_KEY"
        ],
        "severity": "High"
    },
    {
        "id": "WEBVIEW_HIJACK",
        "category": "phishing",
        "description": "WebView URL loading or JavaScript injection detected. Banking trojans inject spoofed login portals into embedded WebViews to harvest credentials.",
        "patterns": [
            r"WebView;->loadUrl", r"WebViewClient", r"shouldOverrideUrlLoading",
            r"evaluateJavascript", r"addJavascriptInterface"
        ],
        "severity": "High"
    },
    {
        "id": "NATIVE_LOADER",
        "category": "execution",
        "description": "Native shared library loading detected. Malware uses JNI to execute encrypted C/C++ payloads that bypass Java-level instrumentation.",
        "patterns": [
            r"System\.loadLibrary", r"System\.load\(", r"Runtime\.loadLibrary",
            r"dlopen", r"dlsym"
        ],
        "severity": "Medium"
    },
    {
        "id": "NOTIFICATION_LISTENER",
        "category": "spyware",
        "description": "NotificationListenerService registration detected. Used by spyware to intercept 2FA OTP tokens and suppress security app notifications.",
        "patterns": [
            r"NotificationListenerService", r"onNotificationPosted",
            r"StatusBarNotification", r"cancelNotification"
        ],
        "severity": "High"
    }
]

def extract_strings_from_binary(binary_data: bytes) -> str:
    """Helper to extract ASCII strings from binary files (e.g. dex)."""
    printable = set(string.printable.encode('ascii'))
    result = []
    current = []
    for char in binary_data:
        if char in printable:
            current.append(chr(char))
        else:
            if len(current) >= 4:
                result.append("".join(current))
            current = []
    if len(current) >= 4:
        result.append("".join(current))
    return "\n".join(result)

def scan_text_with_rules(content: str, file_path: str) -> List[Dict[str, Any]]:
    """Scans content using custom signature rules."""
    findings = []
    for rule in STATIC_RULES:
        for pattern in rule["patterns"]:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                # Get snippet
                lines = content.splitlines()
                snippet = ""
                for line in lines:
                    if re.search(pattern, line, re.IGNORECASE):
                        snippet = line.strip()[:120]
                        break
                findings.append({
                    "rule_id": rule["id"],
                    "category": rule["category"],
                    "description": rule["description"],
                    "severity": rule["severity"],
                    "file": os.path.basename(file_path),
                    "match": match.group(0),
                    "snippet": snippet
                })
                break  # match once per rule category per file
    return findings

def decode_base64_payloads(text: str) -> List[str]:
    """Scans for base64 blocks and decodes dynamic payloads."""
    payloads = []
    for match in BASE64_PATTERN.finditer(text):
        candidate = match.group(0)
        try:
            decoded = base64.b64decode(candidate).decode('utf-8', errors='ignore')
            # Filter decoded string to see if it holds meaningful payload info
            if any(kw in decoded for kw in ["http", "classes", "su", "sh", "android"]):
                payloads.append(decoded.strip())
        except Exception:
            pass
    return payloads

def parse_apk(apk_path: str, package_only: bool = False) -> Dict[str, Any]:
    """
    Main APK Analysis Engine.
    Uses: Androguard, APKTool, and JADX to decompile and extract evidence.
    Gracefully falls back to pure-Python parsing if external tools are missing.
    """
    evidence = {
        "package_name": "unknown.package",
        "manifest": {
            "package": "unknown.package",
            "permissions": [],
            "activities": [],
            "services": [],
            "receivers": []
        },
        "permissions": [],
        "apis_detected": [],
        "apis": [],
        "urls": [],
        "services": [],
        "activities": [],
        "certificate_info": {
            "issuer": "unknown",
            "subject": "unknown",
            "serial_number": "unknown",
            "hash_algorithm": "unknown"
        },
        "obfuscation_indicators": [],
        "native_libraries": [],
        "suspicious_correlations": [],
        "file_tree": []
    }

    # High-fidelity simulated APK analysis reports
    if "simulated_" in apk_path:
        filename = os.path.basename(apk_path).lower()
        if "anubis" in filename:
            evidence.update({
                "package_name": "com.banking.trojan.anubis",
                "manifest": {
                    "package": "com.banking.trojan.anubis",
                    "permissions": [
                        "android.permission.RECEIVE_SMS",
                        "android.permission.BIND_ACCESSIBILITY_SERVICE",
                        "android.permission.SYSTEM_ALERT_WINDOW",
                        "android.permission.INTERNET"
                    ],
                    "activities": ["com.banking.trojan.anubis.MainActivity"],
                    "services": ["com.banking.trojan.anubis.AccessibilityServiceHijacker"],
                    "receivers": ["com.banking.trojan.anubis.SMSReceiver"]
                },
                "permissions": [
                    "android.permission.RECEIVE_SMS",
                    "android.permission.BIND_ACCESSIBILITY_SERVICE",
                    "android.permission.SYSTEM_ALERT_WINDOW",
                    "android.permission.INTERNET"
                ],
                "apis_detected": ["ACCESSIBILITY_ABUSE", "SMS_RECEIVE"],
                "urls": ["http://194.26.135.84/api/v2"],
                "services": ["com.banking.trojan.anubis.AccessibilityServiceHijacker"],
                "activities": ["com.banking.trojan.anubis.MainActivity"],
                "certificate_info": {
                    "issuer": "CN=Anubis Developer",
                    "subject": "CN=Anubis Developer",
                    "serial_number": "987654321",
                    "hash_algorithm": "sha256"
                },
                "obfuscation_indicators": ["Reflection dynamic API invocation", "Self-signed developer certificate detected."],
                "suspicious_correlations": ["Accessibility Permission + Overlay Permission declared (Phishing Overlay Risk)"],
                "native_libraries": [],
                "file_tree": ["AndroidManifest.xml", "classes.dex"]
            })
        elif "sharkbot" in filename:
            evidence.update({
                "package_name": "com.helper.update.utility",
                "manifest": {
                    "package": "com.helper.update.utility",
                    "permissions": [
                        "android.permission.READ_SMS",
                        "android.permission.RECEIVE_SMS",
                        "android.permission.SYSTEM_ALERT_WINDOW",
                        "android.permission.INTERNET"
                    ],
                    "activities": ["com.helper.update.utility.UpdateActivity"],
                    "services": ["com.helper.update.utility.OverlayLoader"],
                    "receivers": ["com.helper.update.utility.BootReceiver"]
                },
                "permissions": [
                    "android.permission.READ_SMS",
                    "android.permission.RECEIVE_SMS",
                    "android.permission.SYSTEM_ALERT_WINDOW",
                    "android.permission.INTERNET"
                ],
                "apis_detected": ["SMS_RECEIVE", "DYNAMIC_LOADING"],
                "urls": ["fast-update-bank.online"],
                "services": ["com.helper.update.utility.OverlayLoader"],
                "activities": ["com.helper.update.utility.UpdateActivity"],
                "certificate_info": {
                    "issuer": "CN=Android Signer",
                    "subject": "CN=Android Signer",
                    "serial_number": "123456789",
                    "hash_algorithm": "sha256"
                },
                "obfuscation_indicators": ["Dynamic Code Loading (DexClassLoader) usage", "Self-signed developer certificate detected."],
                "suspicious_correlations": ["SMS Permissions + Internet Connection (SMS Exfiltration Risk)"],
                "native_libraries": ["libprotect.so"],
                "file_tree": ["AndroidManifest.xml", "classes.dex", "lib/x86/libprotect.so"]
            })
        elif "cerberus" in filename:
            evidence.update({
                "package_name": "com.flash.utility.service",
                "manifest": {
                    "package": "com.flash.utility.service",
                    "permissions": [
                        "android.permission.RECEIVE_SMS",
                        "android.permission.BIND_ACCESSIBILITY_SERVICE",
                        "android.permission.PROCESS_OUTGOING_CALLS",
                        "android.permission.INTERNET"
                    ],
                    "activities": ["com.flash.utility.service.MainActivity"],
                    "services": ["com.flash.utility.service.KeylogService"],
                    "receivers": ["com.flash.utility.service.SmsHook"]
                },
                "permissions": [
                    "android.permission.RECEIVE_SMS",
                    "android.permission.BIND_ACCESSIBILITY_SERVICE",
                    "android.permission.PROCESS_OUTGOING_CALLS",
                    "android.permission.INTERNET"
                ],
                "apis_detected": ["ACCESSIBILITY_ABUSE", "SMS_RECEIVE"],
                "urls": ["http://phish-guard-portal.xyz"],
                "services": ["com.flash.utility.service.KeylogService"],
                "activities": ["com.flash.utility.service.MainActivity"],
                "certificate_info": {
                    "issuer": "CN=System Signer",
                    "subject": "CN=System Signer",
                    "serial_number": "456789012",
                    "hash_algorithm": "sha256"
                },
                "obfuscation_indicators": ["Reflection dynamic API invocation", "Self-signed developer certificate detected."],
                "suspicious_correlations": ["Accessibility Permission + SMS Read/Receive (Accessibility-based Keylogging & SMS Intercept Risk)"],
                "native_libraries": [],
                "file_tree": ["AndroidManifest.xml", "classes.dex"]
            })
        
        if package_only:
            return {
                "package_name": evidence["package_name"],
                "manifest": {"package": evidence["package_name"]},
                "permissions": [],
                "apis_detected": [],
                "apis": [],
                "urls": [],
                "services": [],
                "activities": [],
                "certificate_info": {},
                "obfuscation_indicators": [],
                "native_libraries": [],
                "suspicious_correlations": [],
                "file_tree": []
            }
        return evidence
            
    if not zipfile.is_zipfile(apk_path):
        raise ValueError("Invalid file format. File is not a valid ZIP/APK archive.")
        
    if package_only:
        if HAS_ANDROGUARD:
            try:
                apk_obj = APK(apk_path)
                evidence["package_name"] = apk_obj.get_package()
                evidence["manifest"]["package"] = apk_obj.get_package()
            except Exception:
                pass
        return evidence
        
    temp_dir = tempfile.mkdtemp(prefix="sentinel_analysis_")
    
    try:
        # --- 1. ANDROGUARD PARSING (Primary Metadata) ---
        if HAS_ANDROGUARD:
            try:
                apk_obj = APK(apk_path)
                evidence["package_name"] = apk_obj.get_package()
                evidence["manifest"]["package"] = apk_obj.get_package()
                evidence["permissions"] = apk_obj.get_permissions()
                evidence["manifest"]["permissions"] = apk_obj.get_permissions()
                
                # Component extraction
                evidence["activities"] = apk_obj.get_activities()
                evidence["manifest"]["activities"] = apk_obj.get_activities()
                evidence["services"] = apk_obj.get_services()
                evidence["manifest"]["services"] = apk_obj.get_services()
                
                receivers = apk_obj.get_receivers()
                evidence["manifest"]["receivers"] = receivers
                
                # Check certificates
                certs = apk_obj.get_certificates()
                if certs:
                    c = certs[0]
                    evidence["certificate_info"] = {
                        "issuer": str(c.issuer),
                        "subject": str(c.subject),
                        "serial_number": str(c.serial_number),
                        "hash_algorithm": c.signature_hash_algorithm
                    }
                    
                    # Flag self-signed developer certificate
                    if c.issuer == c.subject:
                        evidence["obfuscation_indicators"].append("Self-signed developer certificate detected.")
            except Exception as e:
                print(f"[Androguard Warning] Failed to parse: {str(e)}")
                
        # --- 2. ZIP HEADERS & NATIVE LIBRARIES ---
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                file_list = zf.namelist()
                evidence["file_tree"] = file_list[:80]
                
                # Extract native library (.so) files
                native_libs = [f for f in file_list if f.startswith("lib/") and f.endswith(".so")]
                evidence["native_libraries"] = native_libs
                
                # Check for common packers or obfuscator libs
                for lib in native_libs:
                    lib_lower = lib.lower()
                    if any(p in lib_lower for p in ["jiagu", "protect", "secexe", "secshell", "txg", "libnlog"]):
                        evidence["obfuscation_indicators"].append(f"Hardened APK packer library detected: {os.path.basename(lib)}")
        except Exception as e:
            print(f"[Zip Read Warning] Failed to inspect zip files: {str(e)}")

        # --- 3. APKTOOL DECOMPILATION (Resource & Manifest Extraction) ---
        apktool_dir = os.path.join(temp_dir, "apktool")
        apktool_success = False
        try:
            res = subprocess.run(
                ["apktool", "d", "-f", "-o", apktool_dir, apk_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=180
            )
            if res.returncode == 0 and os.path.exists(apktool_dir):
                apktool_success = True
                manifest_path = os.path.join(apktool_dir, "AndroidManifest.xml")
                if os.path.exists(manifest_path):
                    tree = ET.parse(manifest_path)
                    root = tree.getroot()
                    evidence["manifest"]["package"] = root.attrib.get("package", evidence["package_name"])
                    
                    xml_perms = []
                    for child in root.findall("uses-permission"):
                        name = child.attrib.get("{http://schemas.android.com/apk/res/android}name")
                        if name:
                            xml_perms.append(name)
                    if xml_perms:
                        evidence["permissions"] = sorted(list(set(evidence["permissions"] + xml_perms)))
                        evidence["manifest"]["permissions"] = evidence["permissions"]
        except Exception as e:
            print(f"[APKTool Skip] Command execution skipped/failed: {str(e)}")
            
        # --- 4. JADX DECOMPILATION (Java Source Extraction & Scan) ---
        jadx_dir = os.path.join(temp_dir, "jadx")
        jadx_success = False
        scan_findings = []
        detected_urls = set()
        decoded_payloads = []

        try:
            res = subprocess.run(
                ["jadx", "-d", jadx_dir, "--no-res", apk_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=300
            )
            if res.returncode == 0 and os.path.exists(jadx_dir):
                jadx_success = True
                
                for root_dir, _, files in os.walk(jadx_dir):
                    for file in files:
                        if file.endswith(".java"):
                            file_path = os.path.join(root_dir, file)
                            try:
                                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                                    content = f.read()
                                    
                                # Scan using upgraded rules matcher
                                file_findings = scan_text_with_rules(content, file_path)
                                scan_findings.extend(file_findings)
                                    
                                # Scan for domains & IPs
                                urls = URL_PATTERN.findall(content)
                                ips = IP_PATTERN.findall(content)
                                for u in urls:
                                    if not any(x in u for x in ["schema.android.com", "w3.org", "android.support"]):
                                        detected_urls.add(u)
                                for ip in ips:
                                    detected_urls.add(f"http://{ip}")

                                # Base64 scanner
                                base64_payloads = decode_base64_payloads(content)
                                decoded_payloads.extend(base64_payloads)
                            except Exception:
                                continue
        except Exception as e:
            print(f"[JADX Skip] Command execution skipped/failed: {str(e)}")
            
        # --- 5. FALLBACK STATIC SCANNER (Pure Python Zip Analysis) ---
        if not jadx_success:
            evidence["obfuscation_indicators"].append("Pure-Python dex scan fallback (JADX unavailable)")
            try:
                with zipfile.ZipFile(apk_path, 'r') as zf:
                    file_list = zf.namelist()
                    dex_files = [f for f in file_list if f.startswith("classes") and f.endswith(".dex")]
                    
                    for dex in dex_files:
                        dex_data = zf.read(dex)
                        dex_text = extract_strings_from_binary(dex_data)
                        
                        # URL / IP scan
                        urls = URL_PATTERN.findall(dex_text)
                        ips = IP_PATTERN.findall(dex_text)
                        for u in urls:
                            if not any(x in u for x in ["schema.android.com", "w3.org", "android.support"]):
                                detected_urls.add(u)
                        for ip in ips:
                            detected_urls.add(f"http://{ip}")
                            
                        # Rule matches
                        file_findings = scan_text_with_rules(dex_text, dex)
                        scan_findings.extend(file_findings)

                        # Base64 Scanner
                        base64_payloads = decode_base64_payloads(dex_text)
                        decoded_payloads.extend(base64_payloads)
            except Exception as e:
                print(f"[Fallback Parser Error] Failed to scan zip files: {str(e)}")

        # Convert findings to apis_detected list format
        apis_detected_set = set()
        formatted_apis = []
        for finding in scan_findings:
            apis_detected_set.add(finding["rule_id"])
            formatted_apis.append({
                "name": finding["rule_id"],
                "class": finding["file"],
                "method": finding["match"],
                "snippet": finding["snippet"]
            })
            
        evidence["apis_detected"] = list(apis_detected_set)
        evidence["apis"] = formatted_apis
        evidence["urls"] = sorted(list(detected_urls))[:40]

        if decoded_payloads:
            evidence["obfuscation_indicators"].append(f"Embedded Base64 decoded payload fragments: {', '.join(list(set(decoded_payloads))[:3])}")

        # --- 6. SUSPICIOUS PERMISSION CORRELATION ---
        perms_set = {p.upper() for p in evidence["permissions"]}
        
        # Accessibility + Overlay
        if "ANDROID.PERMISSION.BIND_ACCESSIBILITY_SERVICE" in perms_set or any("ACCESSIBILITY" in p for p in perms_set):
            if "ANDROID.PERMISSION.SYSTEM_ALERT_WINDOW" in perms_set:
                evidence["suspicious_correlations"].append("Accessibility Service + Window Overlay permissions (Inherent Phishing Overlay Risk)")
                
        # SMS Read/Send + Internet
        sms_perms = {"ANDROID.PERMISSION.SEND_SMS", "ANDROID.PERMISSION.RECEIVE_SMS", "ANDROID.PERMISSION.READ_SMS"}
        if perms_set.intersection(sms_perms):
            if "ANDROID.PERMISSION.INTERNET" in perms_set:
                evidence["suspicious_correlations"].append("SMS Access + Internet permissions (SMS Intercept / OTP Theft Risk)")
                
        # Boot completed + Service running
        if "ANDROID.PERMISSION.RECEIVE_BOOT_COMPLETED" in perms_set:
            evidence["suspicious_correlations"].append("Autostart on Boot permission (Persistence / Background Trojan Risk)")

        # Native libraries + Obfuscation (JNI packer staging)
        if evidence["native_libraries"] and evidence["obfuscation_indicators"]:
            evidence["suspicious_correlations"].append("Native Libraries + Code Obfuscation (JNI Packed Payload Staging Risk)")

        # Notification listener detection via services list
        if any("notification" in s.lower() for s in evidence.get("services", [])):
            evidence["suspicious_correlations"].append("NotificationListenerService detected (2FA OTP Interception Risk)")
                
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
        
    return evidence
